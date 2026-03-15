"""
Workflow orchestration engine
Coordinates agents and manages pentest execution flow
"""

import asyncio
import re
import os
import ipaddress
from urllib.parse import urlparse
import yaml
from typing import Dict, Any, Optional, List
from pathlib import Path
from datetime import datetime

from core.agent import BaseAgent
from core.planner import PlannerAgent
from core.memory import PentestMemory, ToolExecution, Finding
from ai.provider_factory import get_llm_client
from utils.logger import get_logger
from utils.session_paths import apply_session_paths
from utils.scope_validator import ScopeValidator
from utils.error_handler import ErrorHandler, with_error_handling, GuardianError, ToolExecutionError
from utils.circuit_breaker import EnhancedErrorHandler


class WorkflowEngine:
    """Orchestrates the penetration testing workflow"""

    def __init__(self, config: Dict[str, Any], target: Optional[str] = None, memory: Optional[PentestMemory] = None, source: Optional[str] = None):
        self.config = config or {}
        self.source_path = source  # Optional path to source code for whitebox analysis

        # Initialize session memory early so output paths can use session id.
        if memory is None:
            if not target:
                raise ValueError("target is required when memory is not provided")
            self.memory = PentestMemory(target)
        else:
            self.memory = memory

        self.target = self.memory.target or (target or "")
        self._configure_session_outputs()

        self.logger = get_logger(self.config)

        # Whitebox analysis results (populated if source code provided)
        self.whitebox_findings = None
        self.correlation_engine = None

        # Initialize LLM logging
        from utils.llm_logger import init_llm_logger
        init_llm_logger(self.config)

        # Preflight checks for common LLM auth failures so we fail early with actionable guidance.
        self._preflight_llm_auth()
        
        # Initialize components
        self.scope_validator = ScopeValidator(self.config)
        self.llm_client = get_llm_client(self.config)
        self.error_handler = ErrorHandler(self.config)
        self.enhanced_error_handler = EnhancedErrorHandler(self.config)

        # Initialize all agents
        from core.planner import PlannerAgent
        from core.tool_agent import ToolAgent
        from core.analyst_agent import AnalystAgent
        from core.reporter_agent import ReporterAgent

        self.planner = PlannerAgent(self.config, self.llm_client, self.memory)
        self.tool_agent = ToolAgent(self.config, self.llm_client, self.memory)
        self.analyst = AnalystAgent(self.config, self.llm_client, self.memory)
        self.reporter = ReporterAgent(self.config, self.llm_client, self.memory)

        # Log tool availability up front
        try:
            self.tool_agent.log_tool_availability()
        except Exception as e:
            self.logger.warning(f"Tool availability check failed: {e}")
        
        # Workflow state
        self.is_running = False
        self.current_step = 0
        self.max_steps = self.config.get("workflows", {}).get("max_steps", 20)
        self._step_durations: List[float] = []
        self._scope_cache: Dict[str, bool] = {}
        self.stop_reason: Optional[str] = None
        self.stop_resume_command: Optional[str] = None
        self.stop_file: Optional[str] = None

    def _configure_session_outputs(self) -> None:
        apply_session_paths(self.config, self.memory.session_id)

    def _log_tool_execution(self, tool: str, args: Dict[str, Any], result: Optional[Dict[str, Any]]) -> None:
        logging_cfg = (self.config or {}).get("logging", {}) or {}
        if not logging_cfg.get("log_tool_executions", False):
            return

        result_text = ""
        if isinstance(result, dict):
            result_text = result.get("raw_output") or result.get("error") or ""
        elif result is not None:
            result_text = str(result)

        self.logger.log_tool_execution(tool=tool, args=args or {}, result=result_text or None)

    def _get_tool_summary(self) -> List[Dict[str, Any]]:
        summary: Dict[str, Dict[str, Any]] = {}
        ordered_tools: List[str] = []
        for execution in self.memory.tool_executions:
            tool = execution.tool
            if tool not in summary:
                summary[tool] = {
                    "tool": tool,
                    "runs": 0,
                    "success": 0,
                    "failed": 0,
                    "skipped": 0,
                    "last_exit_code": execution.exit_code,
                }
                ordered_tools.append(tool)

            entry = summary[tool]
            entry["runs"] += 1
            entry["last_exit_code"] = execution.exit_code
            output_lower = (execution.output or "").lower()
            if "skipped:" in output_lower:
                entry["skipped"] += 1
            elif execution.exit_code == 0:
                entry["success"] += 1
            else:
                entry["failed"] += 1

        return [summary[t] for t in ordered_tools]

    def _log_tool_summary(self) -> None:
        summary = self._get_tool_summary()
        if not summary:
            return
        self.logger.info("Tool execution summary:")
        for item in summary:
            if item["skipped"] and not item["success"] and not item["failed"]:
                status = "skipped"
            elif item["failed"]:
                status = "failed"
            else:
                status = "success"
            self.logger.info(
                f"- {item['tool']}: {status} (runs={item['runs']}, "
                f"success={item['success']}, failed={item['failed']}, skipped={item['skipped']})"
            )

    def _preflight_llm_auth(self) -> None:
        ai_cfg = (self.config or {}).get("ai", {}) or {}
        provider = (ai_cfg.get("provider") or "gemini").lower()

        if provider != "gemini":
            return

        vertexai = bool(ai_cfg.get("vertexai", False) or ai_cfg.get("use_vertexai", False))
        has_api_key = bool(os.getenv("GOOGLE_API_KEY"))

        # If vertexai is explicitly enabled, or no API key is present, users likely intend ADC.
        if not vertexai and has_api_key:
            return

        project = (
            ai_cfg.get("project")
            or ai_cfg.get("project_id")
            or ai_cfg.get("gcp_project")
            or os.getenv("GOOGLE_CLOUD_PROJECT")
        )
        if not project:
            self.logger.error(
                "Gemini is configured without GOOGLE_API_KEY. For Vertex AI/ADC, set `ai.project` "
                "(project id or project number) in your config and run `gcloud auth application-default login`."
            )
            raise ValueError("Missing Gemini project for Vertex AI/ADC auth.")

        # Fast local check for ADC file. (Google auth will still be the source of truth.)
        adc_env = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
        adc_default = Path.home() / ".config" / "gcloud" / "application_default_credentials.json"
        has_adc = bool(adc_env and Path(adc_env).exists()) or adc_default.exists()
        if not has_adc:
            self.logger.error(
                "Gemini Vertex AI requires Application Default Credentials (ADC) but none were found. "
                "Run `gcloud auth application-default login` and re-run Guardian."
            )
            raise ValueError("Missing ADC credentials for Gemini Vertex AI.")
    
    async def _run_whitebox_analysis(self, workflow_config: Dict[str, Any]) -> None:
        """
        Run whitebox source code analysis phase

        Args:
            workflow_config: Workflow configuration containing whitebox settings
        """
        if not self.source_path:
            return

        whitebox_config = workflow_config.get("whitebox", {})
        if not whitebox_config.get("enabled_if_source", True):
            return

        self.logger.info("="*60)
        self.logger.info("WHITEBOX ANALYSIS PHASE")
        self.logger.info("="*60)

        try:
            from core.source_analyzer import SourceCodeAnalyzer
            from core.correlation_engine import CorrelationEngine

            # Run source code analysis
            analyzer = SourceCodeAnalyzer(
                self.source_path,
                self.config,
                self.logger,
                self.llm_client
            )

            self.whitebox_findings = await analyzer.analyze()

            # Store whitebox findings in memory
            self.memory.metadata["whitebox_analysis"] = {
                "source_path": self.source_path,
                "timestamp": datetime.now().isoformat(),
                "findings_count": analyzer._get_findings_count(),
                "frameworks": self.whitebox_findings.get("attack_surface", {}).get("frameworks", []),
                "endpoints_found": len(self.whitebox_findings.get("attack_surface", {}).get("endpoints", [])),
                "secrets_found": len(self.whitebox_findings.get("attack_surface", {}).get("secrets", []))
            }
            # Store full SAST results so the reporter can surface per-tool detail
            self.memory.metadata["sast_results"] = self.whitebox_findings.get("sast_results", {})

            # Initialize correlation engine
            self.correlation_engine = CorrelationEngine(
                self.whitebox_findings,
                self.config,
                self.logger,
                self.llm_client
            )

            # Log summary
            self.logger.info(f"\nWhitebox Analysis Summary:")
            self.logger.info(f"  Source Path: {self.source_path}")
            self.logger.info(f"  Frameworks Detected: {', '.join(self.whitebox_findings.get('attack_surface', {}).get('frameworks', [])) or 'None'}")
            self.logger.info(f"  API Endpoints Found: {len(self.whitebox_findings.get('attack_surface', {}).get('endpoints', []))}")
            self.logger.info(f"  Secrets Found: {len(self.whitebox_findings.get('attack_surface', {}).get('secrets', []))}")

            # Log SAST findings
            semgrep_summary = self.whitebox_findings.get("sast_results", {}).get("semgrep", {}).get("summary", {})
            if semgrep_summary.get("total", 0) > 0:
                self.logger.info(f"  Semgrep Issues: {semgrep_summary['total']}")
                for severity, count in semgrep_summary.get("by_severity", {}).items():
                    self.logger.info(f"    {severity}: {count}")

            trivy_summary = self.whitebox_findings.get("sast_results", {}).get("trivy", {}).get("summary", {})
            if trivy_summary.get("total_vulns", 0) > 0:
                self.logger.info(f"  Trivy Vulnerabilities: {trivy_summary['total_vulns']}")
                critical_count = len(trivy_summary.get("critical_cves", []))
                if critical_count > 0:
                    self.logger.info(f"    CRITICAL CVEs: {critical_count}")

            self.logger.info("="*60)
            self.logger.info("")

            # Seed the shared URL pool with source-discovered endpoints so that
            # httpx, ZAP, gobuster and all downstream scanners can consume them.
            self._persist_whitebox_endpoints()
            self._refresh_master_seed_file()

            # Elevate high-severity SAST findings to memory.findings so they
            # appear in the Technical Findings section of the report.
            self._elevate_sast_findings()

        except Exception as e:
            self.logger.error(f"Whitebox analysis failed: {e}")
            self.logger.warning("Continuing with blackbox testing only")

    def _elevate_sast_findings(self) -> None:
        """Convert high-severity SAST results into Finding objects in memory.findings.

        Semgrep ERRORs and detected secrets are actionable security issues that
        belong in the Technical Findings section of the report alongside dynamic
        findings. This method bridges the gap between metadata-only storage and
        the findings list consumed by the reporter.
        """
        sast = self.memory.metadata.get("sast_results", {})
        if not sast:
            return

        ts = datetime.now().isoformat()
        source = self.source_path or "source code"

        # --- Semgrep ERROR-severity findings ---
        semgrep = sast.get("semgrep", {})
        semgrep_findings = semgrep.get("findings", [])
        # Group by category to avoid one Finding per line hit; keep top 5 per category.
        from collections import defaultdict
        by_category: dict = defaultdict(list)
        for f in semgrep_findings:
            if f.get("severity", "").upper() == "ERROR":
                by_category[f.get("category", "unknown")].append(f)

        for category, hits in by_category.items():
            sample = hits[0]
            file_loc = f"{sample.get('file', '')}:{sample.get('line', '')}"
            snippet = (sample.get("code_snippet") or "")[:300]
            evidence = f"{file_loc} — {snippet}" if snippet else file_loc
            cwe_ids = []
            if sample.get("cwe"):
                cwes = sample["cwe"] if isinstance(sample["cwe"], list) else [sample["cwe"]]
                cwe_ids = [str(c) for c in cwes if c]

            self.memory.add_finding(Finding(
                id=f"sast_semgrep_{category}_{ts}",
                severity="high",
                title=f"SAST: {category.replace('-', ' ').title()} ({len(hits)} instance{'s' if len(hits) > 1 else ''})",
                description=(
                    f"Semgrep static analysis detected {len(hits)} ERROR-severity "
                    f"{category} issue{'s' if len(hits) > 1 else ''} in {source}. "
                    f"Example: {sample.get('message', '')[:300]}"
                ),
                evidence=evidence,
                tool="semgrep",
                target=source,
                timestamp=ts,
                cwe_ids=cwe_ids,
                owasp_categories=sample.get("owasp", []) if isinstance(sample.get("owasp"), list) else [],
                confidence="high",
                metadata={"hit_count": len(hits), "category": category},
            ))
            self.logger.info(f"  Elevated semgrep finding: {category} ({len(hits)} hits)")

        # --- Secret scanning (gitleaks + trufflehog consolidated) ---
        gl_count = sast.get("gitleaks", {}).get("count", 0)
        th_count = sast.get("trufflehog", {}).get("count", 0)
        total_secrets = gl_count + th_count

        if total_secrets > 0:
            # Sample a few secret types for the evidence field.
            # gitleaks parser stores results under "leaks" (not "secrets").
            # trufflehog DetectorName can be None for some detectors.
            samples = []
            for secret in (sast.get("gitleaks", {}).get("leaks", []) or [])[:3]:
                rule = secret.get("RuleID") or secret.get("Description") or secret.get("rule_id") or "secret"
                if rule and str(rule) not in samples:
                    samples.append(str(rule))
            for secret in (sast.get("trufflehog", {}).get("findings", []) or [])[:3]:
                det = secret.get("DetectorName") or secret.get("detector_name")
                if det and str(det) not in samples:
                    samples.append(str(det))

            evidence = f"{total_secrets} secrets detected"
            if samples:
                evidence += f" (types: {', '.join(samples[:5])})"

            self.memory.add_finding(Finding(
                id=f"sast_secrets_{ts}",
                severity="critical",
                title=f"Hardcoded Secrets in Source Code ({total_secrets} detected)",
                description=(
                    f"Secret scanning tools found {total_secrets} credential{'s' if total_secrets > 1 else ''} "
                    f"embedded in {source} "
                    f"({gl_count} by Gitleaks, {th_count} by TruffleHog). "
                    "Exposed secrets enable direct unauthorized access to connected services."
                ),
                evidence=evidence,
                tool="gitleaks/trufflehog",
                target=source,
                timestamp=ts,
                cwe_ids=["CWE-798"],
                owasp_categories=["A07:2021"],
                confidence="high",
                metadata={"gitleaks_count": gl_count, "trufflehog_count": th_count},
            ))
            self.logger.info(f"  Elevated secrets finding: {total_secrets} total secrets")

    async def run_workflow(self, workflow_name: str) -> Dict[str, Any]:
        """
        Run a predefined workflow

        Args:
            workflow_name: Name of workflow (recon, web_pentest, network_pentest)

        Returns:
            Workflow results and findings
        """
        self.logger.info(f"Starting workflow: {workflow_name} for target: {self.target}")

        # Validate target
        is_valid, reason = self.scope_validator.validate_target_resolved(self.target)
        if not is_valid:
            self.logger.error(f"Target validation failed: {reason}")
            raise ValueError(f"Invalid target: {reason}")

        self.is_running = True
        if self.memory.completed_actions:
            self.logger.info(
                f"Resuming session {self.memory.session_id} with {len(self.memory.completed_actions)} completed steps"
            )
        else:
            self.memory.update_phase(f"{workflow_name}_workflow")
        
        try:
            # Load workflow steps and configuration
            steps = self._load_workflow(workflow_name)
            if not steps:
                raise ValueError(f"No workflow found for '{workflow_name}'")

            # Load full workflow config for whitebox settings and per-workflow overrides
            workflow_config = self._load_workflow_config(workflow_name)
            self._apply_workflow_settings(workflow_config)

            # Run whitebox analysis phase if source code provided
            if self.source_path and workflow_config is not None:
                await self._run_whitebox_analysis(workflow_config)

            # Execute workflow steps
            for step in steps:
                if not self.is_running:
                    break
                if self.memory.is_action_completed(step["name"]):
                    self.logger.info(f"Skipping step: {step['name']} (already completed)")
                    self.current_step += 1
                    continue
                self._log_progress(prefix="Workflow", total=len(steps), current=self.current_step)
                self.logger.info(f"Executing step: {step['name']}")
                step_started = datetime.now()
                await self._execute_step(step, workflow_name)
                if not self.is_running and self.stop_reason:
                    break
                if self._should_run_planner(step):
                    decision = await self.planner.decide_next_action()
                    self.logger.info(f"Planner checkpoint decision after {step['name']}: {decision.get('next_action')}")
                self._record_step_duration(step_started)
                self.current_step += 1
                self._save_progress_if_enabled()
                step_delay = self.config.get("pentest", {}).get("step_delay", 0)
                if step_delay > 0:
                    self.logger.debug(f"Step delay: sleeping {step_delay}s before next step")
                    await asyncio.sleep(step_delay)

            if not self.is_running and self.stop_reason:
                self._save_session()
                self._log_tool_summary()
                tool_summary = self._get_tool_summary()
                return {
                    "status": "stopped",
                    "findings": len(self.memory.findings),
                    "session_id": self.memory.session_id,
                    "stop_reason": self.stop_reason,
                    "resume_command": self.stop_resume_command,
                    "stop_file": self.stop_file,
                    "tool_summary": tool_summary,
                }
            
            # Generate final analysis
            analysis = await self.planner.analyze_results()
            
            # Save final state
            self._save_session()

            # Summarize tool outcomes
            self._log_tool_summary()
            tool_summary = self._get_tool_summary()
            
            return {
                "status": "completed",
                "findings": len(self.memory.findings),
                "analysis": analysis,
                "session_id": self.memory.session_id,
                "tool_summary": tool_summary,
            }
            
        except Exception as e:
            self.logger.error(f"Workflow failed: {e}")
            error_result = self.error_handler.handle_error(e, {"workflow": workflow_name, "target": self.target})
            self._save_session()
            if error_result["can_continue"]:
                self._log_tool_summary()
                tool_summary = self._get_tool_summary()
                return {
                    "status": "completed_with_errors",
                    "findings": len(self.memory.findings),
                    "error": str(e),
                    "recovery": error_result["recovery"],
                    "tool_summary": tool_summary,
                }
            raise
        finally:
            self.is_running = False
    
    async def run_autonomous(self) -> Dict[str, Any]:
        """
        Run autonomous pentest where AI decides each step

        Returns:
            Final results
        """
        self.logger.info(f"Starting autonomous pentest for target: {self.target}")

        # Validate target
        is_valid, reason = self.scope_validator.validate_target_resolved(self.target)
        if not is_valid:
            raise ValueError(f"Invalid target: {reason}")

        self.is_running = True
        if self.memory.completed_actions:
            self.logger.info(
                f"Resuming session {self.memory.session_id} with {len(self.memory.completed_actions)} completed actions"
            )
        else:
            self.memory.update_phase("reconnaissance")

        try:
            # Load autonomous workflow config (used for whitebox + pre_steps)
            workflow_config = self._load_workflow_config("autonomous")

            # Run whitebox analysis if source code provided
            if self.source_path and workflow_config is not None:
                await self._run_whitebox_analysis(workflow_config)

                # Inject whitebox findings into AI context
                if self.whitebox_findings:
                    self.logger.info("Feeding whitebox findings to autonomous AI agent...")
                    self.memory.metadata["whitebox_context_injected"] = True

            # Run pre_steps (e.g. httpx → zap → gobuster) before the AI loop
            pre_steps = (workflow_config or {}).get("pre_steps", [])
            if pre_steps:
                self.logger.info(f"Running {len(pre_steps)} autonomous pre-steps (ZAP early scan, etc.)")
                for step in pre_steps:
                    if not self.is_running:
                        break
                    if self.memory.is_action_completed(step["name"]):
                        self.logger.info(f"Skipping pre-step: {step['name']} (already completed)")
                        continue
                    self.logger.info(f"Pre-step: {step['name']}")
                    await self._execute_step(step, "autonomous")

            while self.is_running and self.current_step < self.max_steps:
                # Ask planner for next action
                decision = await self.planner.decide_next_action()
                
                self.logger.info(f"AI Decision: {decision.get('next_action')}")
                self.logger.debug(f"Reasoning: {decision.get('reasoning', 'N/A')}")
                self._log_progress(prefix="Autonomous", total=self.max_steps, current=self.current_step)
                
                # Check if we should stop
                if decision.get("next_action", "").lower() in ["done", "complete", "finish"]:
                    self.logger.info("Planner decided workflow is complete")
                    break
                
                # Execute the decided action
                step_started = datetime.now()
                await self._execute_ai_decision(decision)
                self._record_step_duration(step_started)
                
                self.current_step += 1
                self._save_progress_if_enabled()
                
                # Progress phase if needed
                self._maybe_advance_phase()
            
            # Final analysis
            analysis = await self.planner.analyze_results()
            
            self._save_session()

            # Summarize tool outcomes
            self._log_tool_summary()
            tool_summary = self._get_tool_summary()
            
            return {
                "status": "completed",
                "findings": len(self.memory.findings),
                "analysis": analysis,
                "session_id": self.memory.session_id,
                "tool_summary": tool_summary,
            }
            
        except Exception as e:
            self.logger.exception(f"Autonomous workflow failed: {e}")
            self._save_session()
            raise
        finally:
            self.is_running = False
    
    def get_system_health(self) -> Dict[str, Any]:
        """Get overall system health status"""
        return {
            "workflow_running": self.is_running,
            "current_step": self.current_step,
            "max_steps": self.max_steps,
            "component_health": self.enhanced_error_handler.get_component_health(),
            "memory_usage": {
                "findings": len(self.memory.findings),
                "tool_executions": len(self.memory.tool_executions)
            }
        }
    
    def stop(self):
        """Stop the workflow"""
        self.logger.info("Stopping workflow")
        self.is_running = False
    
    async def _execute_step(self, step: Dict[str, Any], workflow_name: Optional[str] = None):
        """Execute a workflow step"""
        step_type = step.get("type", "tool")
        condition = step.get("condition")
        
        # Check conditional steps
        if condition == "zap_available":
            zap_config = self.config.get("tools", {}).get("zap", {})
            if not zap_config.get("run_additional_scan", True):
                self.logger.info(f"Skipping {step['name']}: ZAP additional scan disabled in config")
                return
            if "zap" not in self.tool_agent.available_tools:
                self.logger.info(f"Skipping {step['name']}: ZAP not available")
                return
        elif self._should_skip_for_condition(condition, step.get("name", "step")):
            return
        
        if step_type == "tool":
            if self._is_web_workflow(workflow_name):
                if not await self._ensure_web_target_responding(step.get("name") or step.get("tool") or "tool", workflow_name):
                    return
            # Use Tool Agent to select and execute tool
            tool_name = self._select_tool_for_step(step, workflow_name)
            if not tool_name:
                self.logger.warning("No available tool found for this step, skipping")
                return
            result = await self._execute_tool_step(
                tool_name=tool_name,
                tool_kwargs=step.get("parameters", {}) or {},
                step_name=step.get("name", tool_name),
                workflow_name=workflow_name,
            )
            if result is None:
                return

        elif step_type == "multi_tool":
            tools = step.get("tools") or []
            if not isinstance(tools, list) or not tools:
                self.logger.warning("No tools configured for multi_tool step, skipping")
                return

            snmp_community = None
            for entry in tools:
                if isinstance(entry, dict):
                    tool_name = entry.get("tool")
                    tool_kwargs = entry.get("parameters", {}) or {}
                    entry_condition = entry.get("condition")
                else:
                    tool_name = str(entry)
                    tool_kwargs = {}
                    entry_condition = None

                if not tool_name:
                    continue
                if self._should_skip_for_condition(entry_condition, f"{step.get('name', 'multi_tool')}:{tool_name}"):
                    continue
                if self._is_web_workflow(workflow_name):
                    if not await self._ensure_web_target_responding(f"{step.get('name', 'multi_tool')}:{tool_name}", workflow_name):
                        return

                if tool_name == "snmpwalk" and snmp_community and "community" not in tool_kwargs:
                    tool_kwargs = dict(tool_kwargs)
                    tool_kwargs["community"] = snmp_community

                result = await self._execute_tool_step(
                    tool_name=tool_name,
                    tool_kwargs=tool_kwargs,
                    step_name=f"{step.get('name', 'multi_tool')}:{tool_name}",
                    workflow_name=workflow_name,
                )

                if tool_name == "onesixtyone" and isinstance(result, dict):
                    parsed = result.get("parsed") if isinstance(result.get("parsed"), dict) else {}
                    matches = parsed.get("matches") or []
                    if matches and isinstance(matches, list):
                        comm = matches[0].get("community") if isinstance(matches[0], dict) else None
                        if comm:
                            snmp_community = comm

        elif step_type == "action":
            action = step.get("action") or step.get("name")
            if action == "ip_enrichment":
                from utils.helpers import is_valid_ip, extract_domain_from_url
                host = extract_domain_from_url(self.target) or self.target
                if is_valid_ip(host):
                    self._run_ip_enrichment(host)
                else:
                    self.logger.info(f"Skipping ip_enrichment: {self.target} is not an IP target")
            elif action == "metadata_extraction":
                self._run_metadata_extraction(self.target)
            else:
                self.logger.warning(f"Unknown action step: {action}")
            
        elif step_type == "analysis":
            # AI analysis step
            self.logger.info("Running correlation analysis...")
            analysis = await self.analyst.correlate_findings()
            self.logger.info("Correlation analysis complete")
            
        elif step_type == "report":
            # Generate report
            output_dir = Path(self.config.get("output", {}).get("save_path", "./reports"))
            output_dir.mkdir(parents=True, exist_ok=True)

            # Always generate markdown and html
            for fmt, ext in (("markdown", "md"), ("html", "html")):
                self.logger.info(f"Generating {fmt} report...")
                report = await self.reporter.execute(format=fmt)
                report_file = output_dir / f"report_{self.memory.session_id}.{ext}"
                with open(report_file, 'w', encoding='utf-8') as f:
                    f.write(report["content"])
                self.logger.info(f"Report saved to: {report_file}")
        
        self.memory.mark_action_complete(step["name"])

    def _is_web_workflow(self, workflow_name: Optional[str]) -> bool:
        key = self._normalize_workflow_key(workflow_name or "")
        return key == "web"

    async def _ensure_web_target_responding(self, step_name: str, workflow_name: Optional[str]) -> bool:
        if self._target_is_path():
            return True

        base_url = self._get_target_base_url()
        if not base_url:
            return True

        urls = [base_url]
        if "://" not in (self.target or "") and base_url.startswith("https://"):
            urls.append(base_url.replace("https://", "http://", 1))

        attempts = 12
        timeout_s = 10.0
        sleep_s = 10.0
        last_error: Optional[Exception] = None

        for attempt in range(1, attempts + 1):
            for url in urls:
                try:
                    import httpx
                    async with httpx.AsyncClient(timeout=timeout_s, follow_redirects=True) as client:
                        resp = await client.get(url)
                    if resp is not None:
                        return True
                except Exception as exc:
                    last_error = exc
            if attempt < attempts:
                self.logger.warning(
                    f"Target not responding (attempt {attempt}/{attempts}), retrying in {sleep_s:.0f}s..."
                )
                await asyncio.sleep(sleep_s)

        self._stop_for_unresponsive_target(step_name, workflow_name, attempts, last_error)
        return False

    def _stop_for_unresponsive_target(
        self,
        step_name: str,
        workflow_name: Optional[str],
        attempts: int,
        error: Optional[Exception],
    ) -> None:
        resume_name = workflow_name or "web"
        resume_cmd = f"guardian workflow run --name {resume_name} --resume {self.memory.session_id}"
        err_text = f" ({error})" if error else ""
        message = (
            f"Site was not responding after {attempts} attempts before step '{step_name}'."
            f"{err_text} You can resume from the previous successful step with: {resume_cmd}"
        )

        output_dir = Path(self.config.get("output", {}).get("save_path", "./reports"))
        output_dir.mkdir(parents=True, exist_ok=True)
        stop_file = output_dir / f"site_unresponsive_{self.memory.session_id}.txt"
        try:
            stop_file.write_text(
                f"{datetime.now().isoformat()} - {message}\n",
                encoding="utf-8",
            )
        except Exception:
            pass

        self.stop_reason = message
        self.stop_resume_command = resume_cmd
        self.stop_file = str(stop_file)
        self.memory.metadata["stop_reason"] = message
        self.memory.metadata["resume_command"] = resume_cmd
        self.memory.metadata["stop_file"] = str(stop_file)
        self.logger.error(message)
        self.logger.info(f"Resume with: {resume_cmd}")
        self.is_running = False

    def _select_tool_for_step(self, step: Dict[str, Any], workflow_name: Optional[str]) -> Optional[str]:
        primary_tool = step.get("tool")
        preferred: list[str] = []

        step_pref = step.get("preferred_tool") or step.get("preferred_tools")
        if isinstance(step_pref, str):
            preferred.append(step_pref)
        elif isinstance(step_pref, list):
            preferred.extend([str(t) for t in step_pref if str(t).strip()])

        workflows_cfg = (self.config or {}).get("workflows", {}) or {}
        tool_prefs = workflows_cfg.get("tool_preferences", {}) or {}
        if workflow_name and isinstance(tool_prefs, dict):
            wf_prefs = tool_prefs.get(workflow_name, {}) or {}
            step_cfg = wf_prefs.get(step.get("name"), {})
            if isinstance(step_cfg, str):
                preferred.append(step_cfg)
            elif isinstance(step_cfg, list):
                preferred.extend([str(t) for t in step_cfg if str(t).strip()])
            elif isinstance(step_cfg, dict):
                cfg_primary = step_cfg.get("primary")
                if isinstance(cfg_primary, str) and cfg_primary.strip():
                    primary_tool = cfg_primary
                cfg_pref = step_cfg.get("preferred")
                if isinstance(cfg_pref, str):
                    preferred.append(cfg_pref)
                elif isinstance(cfg_pref, list):
                    preferred.extend([str(t) for t in cfg_pref if str(t).strip()])

        candidates = []
        for tool in preferred + ([primary_tool] if primary_tool else []):
            tool = str(tool).strip()
            if not tool or tool in candidates:
                continue
            candidates.append(tool)

        for tool in candidates:
            if tool in self.tool_agent.available_tools:
                if primary_tool and tool != primary_tool:
                    self.logger.info(f"Using preferred tool '{tool}' instead of primary '{primary_tool}'")
                return tool

        return None

    def _get_discovered_urls(self) -> List[str]:
        urls = self.memory.context.get("urls") or []
        if not isinstance(urls, list):
            return []
        # De-dupe and cap to keep downstream tools manageable.
        seen = set()
        out: list[str] = []
        for u in urls:
            if not isinstance(u, str):
                continue
            u = u.strip()
            if not u or u in seen:
                continue
            seen.add(u)
            out.append(u)
            if len(out) >= 2000:
                break
        return self._filter_urls_in_scope(out)

    def _filter_urls_in_scope(self, urls: List[str]) -> List[str]:
        filtered: list[str] = []
        for url in urls:
            if self._scope_allows(url):
                filtered.append(url)
        return filtered

    def _scope_allows(self, target: str) -> bool:
        cached = self._scope_cache.get(target)
        if cached is not None:
            return cached
        is_valid, _reason = self.scope_validator.validate_target_resolved(target)
        self._scope_cache[target] = bool(is_valid)
        return bool(is_valid)

    def _target_is_network(self, target: str) -> bool:
        if not target:
            return False
        try:
            import ipaddress
            if "/" in target:
                ipaddress.ip_network(target, strict=False)
                return True
            if "-" in target:
                parts = [p.strip() for p in target.split("-")]
                if len(parts) == 2:
                    ipaddress.ip_address(parts[0])
                    ipaddress.ip_address(parts[1])
                    return True
        except Exception:
            return False
        return False

    def _target_is_single_ip(self) -> bool:
        """Return True only for a single IP (not CIDR/range)."""
        target = (self.target or "").strip()
        if not target:
            return False

        host = target
        if "://" in target:
            try:
                parsed = urlparse(target)
                if parsed.hostname:
                    host = parsed.hostname
            except Exception:
                pass
        elif "/" not in target:
            try:
                parsed = urlparse(f"//{target}")
                if parsed.hostname:
                    host = parsed.hostname
            except Exception:
                pass

        try:
            if "/" in host or "-" in host:
                return False
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    async def _execute_tool_step(
        self,
        tool_name: str,
        tool_kwargs: Dict[str, Any],
        step_name: str,
        workflow_name: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        # Check if tool is available, skip if not
        if tool_name not in self.tool_agent.available_tools:
            self.logger.warning(f"Tool {tool_name} not available on this platform, skipping step")
            return None

        # Special-case network discovery for non-network targets.
        if step_name == "network_discovery":
            from utils.helpers import extract_domain_from_url
            host = extract_domain_from_url(self.target) or self.target
            if not self._target_is_network(host):
                self.logger.info(f"Skipping network_discovery: target is not a CIDR/range ({host})")
                return None

        # Skip domain-only tools for IP targets.
        from utils.helpers import is_valid_ip, extract_domain_from_url
        target_host = extract_domain_from_url(self.target) or self.target
        domain_only_tools = {
            "amass",
            "subfinder",
            "dnsrecon",
            "dnsx",
            "shuffledns",
            "puredns",
            # "altdns",  # REMOVED - replaced by dnsgen + puredns
            "asnmap",
            "whois",
        }
        if is_valid_ip(target_host) and tool_name in domain_only_tools:
            self.logger.info(f"Skipping {tool_name}: domain-only tool on IP target ({target_host})")
            return None

        if tool_name == "ffuf" and step_name == "vhost_enumeration":
            base_domain = extract_domain_from_url(self.target) or self.target
            if is_valid_ip(base_domain):
                base_domain = None
                discovered = self.memory.context.get("discovered_assets") or []
                for asset in discovered:
                    host = extract_domain_from_url(str(asset)) or str(asset)
                    if host and not is_valid_ip(host):
                        base_domain = host
                        break
            if not base_domain:
                self.logger.info("Skipping vhost_enumeration: no domain available for Host header fuzzing")
                return None
            ffuf_cfg = (self.config or {}).get("tools", {}).get("ffuf", {}) or {}
            tool_kwargs = dict(tool_kwargs or {})
            tool_kwargs.setdefault("append_fuzz", False)
            tool_kwargs.setdefault("headers", [f"Host: FUZZ.{base_domain}"])
            if "wordlist" not in tool_kwargs:
                vhost_wordlist = ffuf_cfg.get("vhost_wordlist")
                if vhost_wordlist:
                    tool_kwargs["wordlist"] = vhost_wordlist
            output_dir = Path(self.config.get("output", {}).get("save_path", "./reports"))
            output_dir.mkdir(parents=True, exist_ok=True)
            tool_kwargs.setdefault(
                "output_file",
                str(output_dir / f"ffuf_{step_name}_{self.memory.session_id}.json"),
            )
        elif tool_name == "ffuf":
            whitebox_wordlist = (self.memory.metadata or {}).get("whitebox_endpoints_wordlist")
            if whitebox_wordlist and "wordlist" not in (tool_kwargs or {}):
                tool_kwargs = dict(tool_kwargs or {})
                tool_kwargs["wordlist"] = whitebox_wordlist

        config_key = tool_name.replace("-", "_")
        tool_cfg = (self.config or {}).get("tools", {}).get(config_key, {}) or {}
        if tool_name in {"graphql-cop", "upload-scanner", "csrf-tester"}:
            args = tool_kwargs.get("args") if isinstance(tool_kwargs, dict) else None
            args = args or tool_cfg.get("args")
            if not args:
                self.logger.info(f"Skipping {step_name}: {tool_name} args not configured")
                return None
        if tool_name == "jwt_tool":
            args = tool_kwargs.get("args") if isinstance(tool_kwargs, dict) else None
            token = tool_kwargs.get("token") if isinstance(tool_kwargs, dict) else None
            if not (args or token or tool_cfg.get("args") or tool_cfg.get("token")):
                # Try to extract a JWT from previous tool outputs (ZAP, httpx, auth-scanner, etc.)
                token = self._extract_jwt_from_tool_outputs()
                if token:
                    self.logger.info("jwt_tool: extracted JWT from previous tool output — proceeding")
                    tool_kwargs = dict(tool_kwargs or {})
                    tool_kwargs["token"] = token
                else:
                    self.logger.info(f"Skipping {step_name}: jwt_tool token/args not configured and no JWT found in tool outputs")
                    return None
        if tool_name == "hydra":
            args = tool_kwargs.get("args") if isinstance(tool_kwargs, dict) else None
            userlist = tool_kwargs.get("userlist") if isinstance(tool_kwargs, dict) else None
            passlist = tool_kwargs.get("passlist") if isinstance(tool_kwargs, dict) else None
            service = tool_kwargs.get("service") if isinstance(tool_kwargs, dict) else None
            if not args:
                userlist = userlist or tool_cfg.get("userlist")
                passlist = passlist or tool_cfg.get("passlist")
                service = service or tool_cfg.get("service")
                if not (userlist and passlist and service):
                    self.logger.info(f"Skipping {step_name}: hydra args/userlist/passlist/service not configured")
                    return None

        if tool_name == "zap":
            zap_cfg = (self.config or {}).get("tools", {}).get("zap", {}) or {}
            if zap_cfg.get("seed_urls_from_context", True) and "seed_urls_file" not in tool_kwargs:
                # Use the master seed file so ZAP starts from the union of all
                # previously discovered URLs (whitebox endpoints, httpx, etc.)
                seed = self.memory.metadata.get("master_seed_file")
                if seed and Path(seed).exists():
                    tool_kwargs = dict(tool_kwargs or {})
                    tool_kwargs.setdefault("seed_urls_file", seed)
                else:
                    urls = self._get_discovered_urls()
                    if urls:
                        url_file = self._refresh_master_seed_file()
                        if url_file:
                            tool_kwargs = dict(tool_kwargs or {})
                            tool_kwargs.setdefault("seed_urls_file", str(url_file))

        if tool_name == "gobuster":
            tool_kwargs = dict(tool_kwargs or {})
            if "wordlist" not in tool_kwargs:
                enriched = self._build_gobuster_wordlist()
                if enriched:
                    tool_kwargs["wordlist"] = str(enriched)
            if "exclude_length" not in tool_kwargs:
                wildcard_len = self._detect_gobuster_wildcard_length(self.target)
                if wildcard_len is not None:
                    self.logger.info(
                        f"gobuster: wildcard 200 detected (length={wildcard_len}) — setting --exclude-length"
                    )
                    tool_kwargs["exclude_length"] = wildcard_len

        if tool_name == "retire" and isinstance(tool_kwargs, dict):
            script_urls = tool_kwargs.get("script_urls")
            if not script_urls:
                cached = self.memory.context.get("client_side_scripts") or []
                if cached:
                    tool_kwargs = dict(tool_kwargs)
                    tool_kwargs["script_urls"] = cached

        self.logger.info(f"Tool Agent selecting tool: {tool_name}")

        # Tool Agent executes the tool
        tool_kwargs = tool_kwargs or {}

        if tool_name == "schemathesis":
            api_cfg = (self.config or {}).get("tools", {}).get("schemathesis", {}) or {}
            if not api_cfg.get("enabled", True):
                self.logger.info(f"Skipping {step_name}: Schemathesis disabled in config")
                return None
            schema = tool_kwargs.get("schema") or api_cfg.get("schema") or api_cfg.get("openapi")
            if not schema:
                self.logger.info(f"Skipping {step_name}: Schemathesis schema/openapi not configured")
                return None
            tool_kwargs = dict(tool_kwargs)
            if isinstance(schema, str) and "{target}" in schema:
                schema = schema.replace("{target}", self.target)
                if "://" not in schema:
                    schema = f"https://{schema}"
            # Probe the schema URL; if it doesn't return valid JSON try common
            # alternative paths so we don't run schemathesis against an HTML page.
            _OPENAPI_PROBES = [
                schema,
                f"{self.target}/api-docs/swagger-ui-init.js",
                f"{self.target}/swagger.json",
                f"{self.target}/api/swagger.json",
                f"{self.target}/api-docs",
                f"{self.target}/docs/openapi.json",
            ]
            import urllib.request as _ur
            import tempfile as _tf
            import re as _re
            resolved_schema = None
            for _url in _OPENAPI_PROBES:
                if not _url:
                    continue
                try:
                    with _ur.urlopen(_url, timeout=8) as _r:
                        _body = _r.read(1 << 20)  # up to 1 MB
                    _stripped = _body.strip()
                    if _stripped[:1] in (b"{", b"["):
                        resolved_schema = _url
                        break
                    # swagger-ui-init.js embeds spec as `"swaggerDoc": { ... }` — extract JSON
                    if _url.endswith(".js") and b'"openapi"' in _body:
                        _js_text = _body.decode("utf-8", errors="replace")
                        _m = _re.search(r'"swaggerDoc"\s*:\s*(\{.*)', _js_text, _re.DOTALL)
                        if _m:
                            # Find the balanced closing brace
                            _depth, _end = 0, None
                            for _i, _ch in enumerate(_m.group(1)):
                                if _ch == "{":
                                    _depth += 1
                                elif _ch == "}":
                                    _depth -= 1
                                    if _depth == 0:
                                        _end = _i + 1
                                        break
                            if _end:
                                _spec_json = _m.group(1)[:_end]
                                _tmp = _tf.NamedTemporaryFile(
                                    suffix=".json", delete=False, mode="w", encoding="utf-8"
                                )
                                _tmp.write(_spec_json)
                                _tmp.close()
                                resolved_schema = _tmp.name
                                self.logger.info(
                                    f"Extracted embedded OpenAPI spec from {_url} → {_tmp.name}"
                                )
                                break
                except Exception:
                    continue
            if not resolved_schema:
                self.logger.warning(
                    f"Skipping schemathesis: no valid OpenAPI/Swagger JSON found at "
                    f"{schema} or common alternative paths"
                )
                return None
            schema = resolved_schema
            tool_kwargs.setdefault("schema", schema)
            base_url = tool_kwargs.get("base_url") or api_cfg.get("base_url") or api_cfg.get("url")
            if isinstance(base_url, str) and "{target}" in base_url:
                base_url = base_url.replace("{target}", self.target)
                if "://" not in base_url:
                    base_url = f"https://{base_url}"
            if base_url:
                tool_kwargs.setdefault("base_url", base_url)
            for key in ("workers", "checks", "max_examples"):
                if key not in tool_kwargs and api_cfg.get(key) is not None:
                    tool_kwargs[key] = api_cfg.get(key)

        run_nmap_per_host = False
        nmap_host_ports: Dict[str, List[int]] = {}

        # Allow steps to derive nmap ports from discovered open ports (speeds up vuln scripts).
        if tool_name == "nmap":
            if tool_kwargs.get("ports_from_context") and not tool_kwargs.get("ports"):
                ports_filter = tool_kwargs.get("ports_filter")
                wanted: set[int] = set()
                if ports_filter:
                    if isinstance(ports_filter, str):
                        wanted = {int(x.strip()) for x in ports_filter.split(",") if x.strip()}
                    elif isinstance(ports_filter, list):
                        wanted = {int(x) for x in ports_filter}

                target_for_mode = extract_domain_from_url(self.target) or self.target
                host_ports_ctx = self.memory.context.get("host_open_ports") or {}
                if self._target_is_network(target_for_mode) and isinstance(host_ports_ctx, dict) and host_ports_ctx:
                    for host, ports_list in host_ports_ctx.items():
                        if not isinstance(ports_list, list):
                            continue
                        normalized = []
                        for p in ports_list:
                            try:
                                port_int = int(p)
                                if not wanted or port_int in wanted:
                                    normalized.append(port_int)
                            except Exception:
                                continue
                        if normalized:
                            nmap_host_ports[str(host)] = sorted(set(normalized))
                    run_nmap_per_host = bool(nmap_host_ports)
                    if not run_nmap_per_host:
                        self.logger.info(
                            f"Skipping {step_name}: no matching discovered host ports for CIDR/range target"
                        )
                        return None
                else:
                    open_ports = self.memory.context.get("open_ports") or []
                    if isinstance(open_ports, list) and open_ports:
                        ports = []
                        for p in open_ports:
                            try:
                                port_int = int(p)
                                if not wanted or port_int in wanted:
                                    ports.append(str(port_int))
                            except Exception:
                                continue
                        if ports:
                            tool_kwargs = dict(tool_kwargs)
                            tool_kwargs["ports"] = ",".join(sorted(set(ports), key=int))
                        else:
                            self.logger.info(
                                f"Skipping {step_name}: no matching open ports for filtered scan"
                            )
                            return None
                tool_kwargs = dict(tool_kwargs)
                tool_kwargs.pop("ports_from_context", None)
                tool_kwargs.pop("ports_filter", None)

        # If we have discovered URLs, pass the master seed file to URL-first scanners.
        # The master seed file (urls_{session_id}.txt) is the single source of truth:
        # whitebox endpoints + ZAP spider + gobuster paths all feed into it.
        # NOTE: only enable for tools that accept a `from_file` input in our wrappers.
        if tool_name in {"nuclei", "dalfox", "subjs", "xnlinkfinder", "httpx", "waybackurls"}:
            if "from_file" not in tool_kwargs:
                seed = self.memory.metadata.get("master_seed_file")
                if seed and Path(seed).exists():
                    tool_kwargs = dict(tool_kwargs)
                    tool_kwargs["from_file"] = seed
                else:
                    # Master seed not written yet (very early in the run); build it now.
                    url_file = self._refresh_master_seed_file()
                    if url_file:
                        tool_kwargs = dict(tool_kwargs)
                        tool_kwargs["from_file"] = str(url_file)

        # nuclei template scanning only benefits from live, meaningful endpoints.
        # The master seed is dominated by static assets from subjs/ZAP spider
        # (often 90%+ JS/CSS/ICO) that can never match a vulnerability template.
        # Write a focused nuclei seed that strips noise and surfaces the URLs
        # nuclei templates are actually designed to test.
        if tool_name == "nuclei" and "from_file" in tool_kwargs:
            nuclei_seed = self._write_nuclei_seed_file(tool_kwargs["from_file"])
            if nuclei_seed:
                tool_kwargs = dict(tool_kwargs)
                tool_kwargs["from_file"] = str(nuclei_seed)
            # If seed is None the master seed is already set; nuclei will run
            # against it (degenerate case: very early in the workflow with no
            # URL intelligence yet, just use what we have)

        # dalfox only benefits from URLs that can reflect input: those with query
        # parameters or path segments that look like dynamic values.  Feeding it
        # the full 1000+ URL master seed floods the target with payloads against
        # static assets, 401-only endpoints, and redirects — wasted effort that
        # can overwhelm a lightweight target.  Write a focused XSS seed instead.
        if tool_name == "dalfox" and "from_file" in tool_kwargs:
            xss_seed = self._write_xss_seed_file(tool_kwargs["from_file"])
            if xss_seed:
                tool_kwargs = dict(tool_kwargs)
                tool_kwargs["from_file"] = str(xss_seed)
                # When none of the selected URLs have query params the app likely
                # uses REST-style paths.  Enable parameter mining so dalfox can
                # discover injectable params; it may be slower but at least has
                # a chance of finding XSS surfaces.  Only skip mining when we
                # already have parameterized URLs (mining would be redundant).
                param_count = self.memory.metadata.get("xss_seed_param_count", 0)
                if param_count > 0:
                    tool_kwargs.setdefault("skip_mining", True)
                # Always skip headless browser and BAV to reduce scan time
                tool_kwargs.setdefault("skip_headless", True)
                tool_kwargs.setdefault("skip_bav", True)
            else:
                # No seed file could be produced — skip dalfox entirely
                self.logger.info("XSS seed is empty — skipping dalfox")
                return None

        # Custom HTTP scanners that only accept a single URL in get_command() benefit from
        # being run across the full discovered endpoint list.  If we have a master seed
        # file, pass the top non-static endpoints so each scanner probes real app
        # surfaces rather than just the root URL.
        _MULTI_URL_SCANNERS = {
            "ssrf-scanner", "xxe-scanner", "deserialization-scanner",
            "auth-scanner", "idor-scanner", "error-detector", "cors-scanner",
        }
        if tool_name in _MULTI_URL_SCANNERS and "endpoints" not in (tool_kwargs or {}):
            seed = self.memory.metadata.get("master_seed_file")
            if seed and Path(seed).exists():
                import re as _re2
                _STATIC_EXT_RE = _re2.compile(
                    r"\.(js|css|ico|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot|map|txt|xml|json)(\?.*)?$",
                    _re2.IGNORECASE,
                )
                with open(seed) as _sf:
                    _all_urls = [l.strip() for l in _sf if l.strip() and l.startswith("http")]
                _endpoints = [u for u in _all_urls if not _STATIC_EXT_RE.search(u)]
                # Deduplicate while preserving order
                _seen: set = set()
                _deduped = []
                for _u in _endpoints:
                    if _u not in _seen:
                        _seen.add(_u)
                        _deduped.append(_u)
                if _deduped:
                    tool_kwargs = dict(tool_kwargs or {})
                    tool_kwargs["endpoints"] = _deduped[:40]
                    self.logger.info(
                        f"{tool_name}: passing {len(tool_kwargs['endpoints'])} endpoints from master seed"
                    )

        # Apply accumulated analyst hints — LLM-identified priority targets and
        # parameter suggestions flow into tool configuration here.
        tool_kwargs = self._apply_tool_hints(tool_name, tool_kwargs)

        if not self._scope_allows(self.target):
            self.logger.error(f"Target validation failed before tool execution: {self.target}")
            return None

        try:
            if tool_name == "nmap" and run_nmap_per_host:
                commands: List[str] = []
                outputs: List[str] = []
                errors: List[str] = []
                aggregated_open_ports: set[int] = set()
                aggregated_services: List[Dict[str, Any]] = []
                hosts_up: List[str] = []
                host_ports_seen: Dict[str, List[int]] = {}
                any_success = False

                for host, host_ports in sorted(nmap_host_ports.items()):
                    if not self._scope_allows(host):
                        self.logger.warning(f"Skipping out-of-scope discovered host: {host}")
                        continue
                    host_kwargs = dict(tool_kwargs or {})
                    host_kwargs["ports"] = ",".join(str(p) for p in sorted(set(host_ports)))
                    host_result = await self.tool_agent.execute_tool(
                        tool_name=tool_name,
                        target=host,
                        **host_kwargs
                    )
                    if host_result.get("command"):
                        commands.append(host_result.get("command", ""))
                    if host_result.get("raw_output"):
                        outputs.append(host_result.get("raw_output", ""))
                    if host_result.get("error"):
                        errors.append(host_result.get("error", ""))
                    if host_result.get("success"):
                        any_success = True

                    parsed_host = host_result.get("parsed") if isinstance(host_result.get("parsed"), dict) else {}
                    for p in parsed_host.get("open_ports") or []:
                        try:
                            aggregated_open_ports.add(int(p))
                        except Exception:
                            continue
                    services = parsed_host.get("services") or []
                    if isinstance(services, list):
                        aggregated_services.extend(services)
                    host_up_list = parsed_host.get("hosts_up") or []
                    if isinstance(host_up_list, list):
                        for hup in host_up_list:
                            if hup and hup not in hosts_up:
                                hosts_up.append(hup)
                    if host_result.get("success"):
                        host_ports_seen[host] = sorted(set(host_ports))

                if not commands:
                    self.logger.info(f"Skipping {step_name}: no discovered hosts with open ports to scan")
                    return None

                result = {
                    "success": any_success,
                    "tool": tool_name,
                    "target": self.target,
                    "command": "\n".join(commands),
                    "raw_output": "\n\n".join(outputs)[:200000],
                    "error": "\n".join(e for e in errors if e)[:20000] or None,
                    "duration": 0,
                    "exit_code": 0 if any_success else 1,
                    "parsed": {
                        "open_ports": sorted(aggregated_open_ports),
                        "services": aggregated_services,
                        "hosts_up": hosts_up,
                        "host_ports": host_ports_seen,
                    },
                }
            else:
                result = await self.tool_agent.execute_tool(
                    tool_name=tool_name,
                    target=self.target,
                    **tool_kwargs
                )
        except Exception as e:
            self.logger.warning(f"Tool {tool_name} failed with exception: {e}")
            result = {"success": False, "tool": tool_name, "error": str(e), "exit_code": 1}

        self._log_tool_execution(tool=tool_name, args=tool_kwargs, result=result)

        # Track tools that timed out with zero output — surfaced in report coverage section
        if result.get("exit_code") == 124:
            timed_out = self.memory.metadata.setdefault("timed_out_tools", [])
            # Extract timeout value from error string e.g. "Tool zap timed out after 900s"
            import re as _re
            _m = _re.search(r"after (\d+)s", result.get("error", ""))
            timeout_s = int(_m.group(1)) if _m else "?"
            entry = {"tool": tool_name, "timeout_s": timeout_s}
            if entry not in timed_out:
                timed_out.append(entry)
        elif result.get("skipped"):
            # Track tools that were skipped (health check failure, not installed, pre-condition unmet)
            skipped = self.memory.metadata.setdefault("skipped_tools", [])
            reason = (result.get("error") or "pre-execution check failed")[:120]
            entry = {"tool": tool_name, "reason": reason}
            if entry not in skipped:
                skipped.append(entry)
        elif not result.get("success") and result.get("exit_code") not in (0, None, 124):
            # Track tools that crashed (non-zero exit, not a graceful skip or timeout)
            crashed = self.memory.metadata.setdefault("crashed_tools", [])
            entry = {
                "tool": tool_name,
                "exit_code": result.get("exit_code"),
                "error": (result.get("error") or "")[:120],
            }
            if entry not in crashed:
                crashed.append(entry)

        if result.get("success"):
            parsed = result.get("parsed") if isinstance(result.get("parsed"), dict) else {}

            # Persist high-signal context from discovery tools.
            # All tools that return a "urls" list feed into the shared URL context
            # so subsequent tools (nuclei, dalfox, ffuf, etc.) can use them.
            _URL_DISCOVERY_TOOLS = {
                "httpx", "zap", "gobuster",
                "linkfinder", "xnlinkfinder",
                "waybackurls", "subjs", "paramspider",
            }
            if tool_name in _URL_DISCOVERY_TOOLS:
                urls = parsed.get("urls") or []
                if tool_name == "gobuster" and isinstance(urls, list) and urls:
                    # gobuster returns path segments (/admin, /api/v1) — convert to full URLs
                    base = self._get_target_base_url()
                    if base:
                        from urllib.parse import urljoin
                        urls = [urljoin(base, p) for p in urls if isinstance(p, str) and p]
                if isinstance(urls, list) and urls:
                    self.memory.update_context("urls", urls)
                    self.memory.update_context("discovered_assets", urls)
                    # Rewrite the single master seed file so downstream tools always
                    # consume the union of whitebox + ZAP + gobuster + crawl URLs.
                    self._refresh_master_seed_file()

            if tool_name == "nmap":
                open_ports = parsed.get("open_ports") or []
                services = parsed.get("services") or []
                hosts_up = parsed.get("hosts_up") or []
                host_ports = parsed.get("host_ports") or {}
                host_dns = parsed.get("host_dns") or {}
                if isinstance(open_ports, list) and open_ports:
                    self.memory.update_context("open_ports", open_ports)
                if isinstance(services, list) and services:
                    self.memory.update_context("services", services)
                if isinstance(hosts_up, list) and hosts_up:
                    self.memory.update_context("discovered_assets", hosts_up)
                if isinstance(host_ports, dict) and host_ports:
                    merged_host_ports = self.memory.context.get("host_open_ports") or {}
                    if not isinstance(merged_host_ports, dict):
                        merged_host_ports = {}
                    for host, ports_list in host_ports.items():
                        existing = merged_host_ports.get(host) or []
                        normalized = []
                        for p in ports_list:
                            try:
                                normalized.append(int(p))
                            except Exception:
                                continue
                        merged_host_ports[host] = sorted(set(existing + normalized))
                    self.memory.context["host_open_ports"] = merged_host_ports
                if isinstance(host_dns, dict) and host_dns:
                    merged_host_dns = self.memory.context.get("host_dns") or {}
                    if not isinstance(merged_host_dns, dict):
                        merged_host_dns = {}
                    merged_host_dns.update(host_dns)
                    self.memory.context["host_dns"] = merged_host_dns
            if tool_name == "dnsrecon":
                # Parse dnsrecon JSON records into per-domain DNS context
                records = parsed.get("records") or []
                if isinstance(records, list) and records:
                    self._merge_dns_records(records)
            if tool_name == "dnsx":
                # dnsx JSONL records — each line has host + A/AAAA/MX/NS/CNAME/TXT
                records = parsed.get("records") or []
                if isinstance(records, list) and records:
                    self._merge_dnsx_records(records)
            # jsparser removed - use linkfinder/xnlinkfinder instead
            if tool_name in ("linkfinder", "xnlinkfinder"):
                scripts = parsed.get("scripts") or []
                if isinstance(scripts, list) and scripts:
                    self.memory.update_context("client_side_scripts", scripts)
            if tool_name == "testssl":
                # Store certificate information including SAN
                cert_info = parsed.get("certificate_info") or {}
                if isinstance(cert_info, dict) and cert_info:
                    # Update certificate_info in memory context
                    current_cert = self.memory.context.get("certificate_info") or {}
                    current_cert.update(cert_info)
                    self.memory.context["certificate_info"] = current_cert
            if tool_name == "naabu":
                open_ports = parsed.get("open_ports") or []
                if isinstance(open_ports, list) and open_ports:
                    ports = []
                    hosts = set()
                    for entry in open_ports:
                        if isinstance(entry, dict):
                            port = entry.get("port")
                            host = entry.get("host")
                            if host:
                                hosts.add(host)
                            if port is not None:
                                try:
                                    ports.append(int(port))
                                except Exception:
                                    continue
                    if ports:
                        self.memory.update_context("open_ports", ports)
                    if hosts:
                        self.memory.update_context("discovered_assets", sorted(hosts))
            if tool_name == "masscan":
                open_ports = parsed.get("open_ports") or []
                hosts_map = parsed.get("hosts") or {}
                if isinstance(open_ports, list) and open_ports:
                    ports = []
                    hosts = set()
                    for entry in open_ports:
                        if isinstance(entry, dict):
                            port = entry.get("port")
                            host = entry.get("host")
                            if host:
                                hosts.add(host)
                            if port is not None:
                                try:
                                    ports.append(int(port))
                                except Exception:
                                    continue
                    if ports:
                        self.memory.update_context("open_ports", ports)
                    if hosts:
                        self.memory.update_context("discovered_assets", sorted(hosts))
                if isinstance(hosts_map, dict) and hosts_map:
                    merged_host_ports = self.memory.context.get("host_open_ports") or {}
                    if not isinstance(merged_host_ports, dict):
                        merged_host_ports = {}
                    for host, ports_list in hosts_map.items():
                        if not isinstance(ports_list, list):
                            continue
                        normalized = []
                        for p in ports_list:
                            try:
                                normalized.append(int(p))
                            except Exception:
                                continue
                        if normalized:
                            existing = merged_host_ports.get(host) or []
                            merged_host_ports[host] = sorted(set(existing + normalized))
                    self.memory.context["host_open_ports"] = merged_host_ports
            # udp-proto-scanner removed - UDP scanning now handled by nmap -sU
            # No special parsing needed as nmap output is already handled above

            # Use Analyst Agent to interpret results
            self.logger.info("Analyst Agent analyzing results...")
            analysis = await self.analyst.interpret_output(
                tool=tool_name,
                target=self.target,
                command=result.get("command", ""),
                output=result.get("raw_output", "")
            )

            self.logger.info(f"Found {len(analysis['findings'])} findings from {tool_name}")

            # Update last tool execution with findings count
            if self.memory.tool_executions:
                self.memory.tool_executions[-1].findings_count = len(analysis["findings"])

            # Check if auto-exploit is enabled and attempt exploitation
            if analysis.get("findings"):
                await self._auto_exploit_findings(analysis["findings"])
        else:
            self.logger.warning(f"Tool execution failed: {result.get('error')}")

        return result

    async def _auto_exploit_findings(self, findings: List[Finding]) -> None:
        """
        Automatically attempt exploitation of findings when auto_exploit is enabled.

        Args:
            findings: List of Finding objects to potentially exploit
        """
        exploit_config = self.config.get("exploits", {})

        # Check if auto-exploit is enabled
        if not exploit_config.get("auto_exploit", False):
            return

        # Check if exploits are enabled at all
        if not exploit_config.get("enabled", True):
            self.logger.warning("Auto-exploit requested but exploits are disabled")
            return

        # Get configuration
        require_confirmation = exploit_config.get("auto_exploit_require_confirmation", True)
        min_severity = exploit_config.get("auto_exploit_min_severity", "critical")
        max_attempts = exploit_config.get("auto_exploit_max_attempts", 5)

        # Track attempts in this session
        if not hasattr(self, '_auto_exploit_attempts'):
            self._auto_exploit_attempts = 0

        # Check if we've hit the max attempts limit
        if self._auto_exploit_attempts >= max_attempts:
            self.logger.info(f"Auto-exploit max attempts ({max_attempts}) reached for this session")
            return

        # Filter findings by severity
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        min_severity_value = severity_order.get(min_severity.lower(), 4)

        exploitable_findings = []
        for finding in findings:
            finding_severity = severity_order.get(finding.severity.lower(), 0)
            if finding_severity >= min_severity_value:
                # Check if finding has CVE or is exploitable
                if finding.cve_ids or finding.metadata.get("exploitable"):
                    exploitable_findings.append(finding)

        if not exploitable_findings:
            self.logger.debug("No exploitable findings meeting severity criteria")
            return

        self.logger.info(f"Found {len(exploitable_findings)} potentially exploitable findings")

        # Attempt exploitation for each finding
        for finding in exploitable_findings:
            if self._auto_exploit_attempts >= max_attempts:
                self.logger.info(f"Auto-exploit max attempts ({max_attempts}) reached")
                break

            # Get confirmation if required
            if require_confirmation:
                severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(finding.severity.lower(), "⚪")

                print(f"\n{severity_emoji} Auto-Exploit Opportunity Detected:")
                print(f"  Severity: {finding.severity.upper()}")
                print(f"  Title: {finding.title}")
                print(f"  Target: {finding.target}")
                if finding.cve_ids:
                    print(f"  CVEs: {', '.join(finding.cve_ids)}")

                response = input("\nAttempt exploitation? [y/N]: ").strip().lower()
                if response not in ['y', 'yes']:
                    self.logger.info(f"Skipping exploitation of: {finding.title}")
                    continue

            self.logger.info(f"Attempting auto-exploit for: {finding.title}")
            self._auto_exploit_attempts += 1

            try:
                # Use exploit cache to find matching exploits
                from utils.exploit_cache import ExploitCache
                cache = ExploitCache(self.config)

                # Load exploit databases
                exploitdb_items, _ = cache.load_exploitdb()
                metasploit_items, _ = cache.load_metasploit()

                # Find matching exploits by CVE
                msf_exploits = []
                edb_exploits = []

                for cve_id in finding.cve_ids:
                    cve_upper = cve_id.upper()

                    # Search Metasploit modules
                    for msf_item in metasploit_items:
                        if cve_upper in [c.upper() for c in msf_item.get("cves", [])]:
                            msf_item["type"] = "metasploit"
                            msf_exploits.append(msf_item)

                    # Search Exploit-DB
                    for edb_item in exploitdb_items:
                        if cve_upper in [c.upper() for c in edb_item.get("cves", [])]:
                            edb_item["type"] = "exploitdb"
                            edb_exploits.append(edb_item)

                if not msf_exploits and not edb_exploits:
                    self.logger.info(f"No exploits found in cache for {finding.title}")
                    continue

                total_exploits = len(msf_exploits) + len(edb_exploits)
                self.logger.info(f"Found {total_exploits} potential exploits ({len(msf_exploits)} Metasploit, {len(edb_exploits)} Exploit-DB)")

                # Try Metasploit exploits first (they can be auto-executed)
                if msf_exploits:
                    # Use the first Metasploit exploit
                    exploit = msf_exploits[0]
                    module_name = exploit.get("module") or exploit.get("name", "")

                    if module_name:
                        self.logger.info(f"Attempting Metasploit module: {module_name}")

                        # Execute Metasploit exploit
                        result = await self.tool_agent.execute(
                            objective=f"Exploit {finding.title} using Metasploit module {module_name}",
                            target=finding.target,
                            tool_name="metasploit",
                            extra_args={"module": module_name}
                        )

                        if result.get("success"):
                            self.logger.info(f"✓ Exploitation successful: {finding.title}")

                            # Add exploitation success to finding metadata
                            finding.metadata["exploitation_attempted"] = True
                            finding.metadata["exploitation_successful"] = True
                            finding.metadata["exploit_module"] = module_name
                            finding.metadata["exploit_type"] = "metasploit"
                        else:
                            self.logger.warning(f"Exploitation failed: {result.get('error', 'Unknown error')}")
                            finding.metadata["exploitation_attempted"] = True
                            finding.metadata["exploitation_successful"] = False
                            finding.metadata["exploit_type"] = "metasploit"

                # If no Metasploit exploits available, log Exploit-DB alternatives
                elif edb_exploits:
                    self.logger.info(f"Found {len(edb_exploits)} Exploit-DB exploits (manual execution required):")
                    for i, edb_exploit in enumerate(edb_exploits[:3], 1):  # Show first 3
                        edb_id = edb_exploit.get("id", "Unknown")
                        edb_desc = edb_exploit.get("description", "No description")
                        edb_file = edb_exploit.get("file", "")
                        edb_path = f"/usr/share/exploitdb/exploits/{edb_file}" if edb_file else ""

                        self.logger.info(f"  {i}. EDB-{edb_id}: {edb_desc}")
                        if edb_path:
                            self.logger.info(f"     Path: {edb_path}")

                    # Store Exploit-DB references in metadata for manual use
                    finding.metadata["exploitation_attempted"] = False
                    finding.metadata["exploitdb_available"] = True
                    finding.metadata["exploitdb_ids"] = [e.get("id") for e in edb_exploits]
                    finding.metadata["exploitdb_exploits"] = [
                        {
                            "id": e.get("id"),
                            "description": e.get("description"),
                            "file": e.get("file"),
                            "path": f"/usr/share/exploitdb/exploits/{e.get('file')}" if e.get("file") else None
                        }
                        for e in edb_exploits[:5]  # Store first 5
                    ]

            except Exception as e:
                self.logger.error(f"Auto-exploit error for {finding.title}: {str(e)}")
                finding.metadata["exploitation_attempted"] = True
                finding.metadata["exploitation_error"] = str(e)

    def _detect_gobuster_wildcard_length(self, target: str) -> int | None:
        """
        Probe the target with a random non-existent path. If the server returns HTTP 200,
        it has catch-all/wildcard routing (common in SPAs). Returns the response Content-Length
        so gobuster can filter it out via --exclude-length, or None if no wildcard is detected.
        """
        import uuid
        import urllib.request
        import urllib.error
        probe_path = f"/{uuid.uuid4().hex}"
        url = target.rstrip("/") + probe_path
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Guardian-Gobuster-Probe/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    body = resp.read()
                    return len(body)
        except Exception:
            pass
        return None

    def _extract_jwt_from_tool_outputs(self) -> str | None:
        """
        Scan all previous tool execution outputs for a JWT (eyJ... pattern).
        Returns the first JWT found, or None.
        """
        import re
        jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
        for execution in self.memory.tool_executions:
            output = getattr(execution, "output", "") or ""
            match = jwt_pattern.search(output)
            if match:
                return match.group(0)
        return None

    def _build_gobuster_wordlist(self) -> Optional[Path]:
        """
        Build an enriched wordlist for gobuster by combining:
          1. The configured base wordlist (dirb/common.txt or similar)
          2. Path segments extracted from all URLs discovered so far
             (ZAP spider, katana crawl, waybackurls, etc.)

        Writes a deduplicated file to the session output dir and returns its path.
        Returns None if no base wordlist is available and no URLs exist.
        """
        from urllib.parse import urlparse as _urlparse

        cfg = (self.config or {}).get("tools", {}).get("gobuster", {}) or {}
        base_wordlist = cfg.get("wordlist") or "/usr/share/wordlists/dirb/common.txt"

        words: set = set()

        # 1. Load base wordlist
        base_path = Path(base_wordlist)
        if base_path.is_file():
            try:
                for line in base_path.read_text(encoding="utf-8", errors="replace").splitlines():
                    w = line.strip()
                    if w and not w.startswith("#"):
                        words.add(w)
            except Exception:
                pass

        # 2. Extract path components from discovered URLs
        urls = self._get_discovered_urls()
        for url in urls:
            try:
                path = _urlparse(url).path
                # Strip leading slash and split into segments
                parts = [p for p in path.strip("/").split("/") if p]
                for part in parts:
                    # Add bare segment (e.g. "api", "v1", "admin")
                    words.add(part)
                    # Also add without extension (e.g. "index" from "index.php")
                    stem = part.rsplit(".", 1)[0] if "." in part else part
                    if stem:
                        words.add(stem)
            except Exception:
                continue

        if not words:
            return None

        output_dir = Path(self.config.get("output", {}).get("save_path", "./reports"))
        output_dir.mkdir(parents=True, exist_ok=True)
        wordlist_path = output_dir / f"gobuster_wordlist_{self.memory.session_id}.txt"

        with open(wordlist_path, "w", encoding="utf-8") as f:
            f.write("\n".join(sorted(words)) + "\n")

        self.logger.info(
            f"Built gobuster wordlist: {len(words)} words "
            f"(base={base_path.name}, urls={len(urls)})"
        )
        return wordlist_path

    def _write_urls_file(self, urls: List[str], name: str) -> Path:
        output_dir = Path(self.config.get("output", {}).get("save_path", "./reports"))
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / name
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(urls) + "\n")
        return path

    def _refresh_master_seed_file(self) -> Optional[Path]:
        """Rewrite the single master URL seed file from the current URL pool.

        Called after every major URL discovery event (whitebox, ZAP, gobuster,
        katana …). All downstream scanners consume from this one file so they
        always see the union of every source discovered so far.

        File name: urls_{session_id}.txt
        Metadata key: master_seed_file
        """
        urls = self._get_discovered_urls()
        if not urls:
            return None
        urls = self._filter_urls_to_target(urls)
        if not urls:
            return None
        path = self._write_urls_file(urls, name=f"urls_{self.memory.session_id}.txt")
        self.memory.metadata["master_seed_file"] = str(path)
        self.logger.info(f"Master seed updated: {len(urls)} URLs → {path.name}")
        return path

    def _write_xss_seed_file(self, seed_path: str) -> Optional[Path]:
        """Score and rank URLs for XSS testing using all accumulated session intelligence.

        Rather than naive pattern-matching on URL strings, this cross-references
        every signal the workflow has already gathered to score each candidate URL
        by its actual likelihood of reflecting user-controlled input:

        POSITIVE signals (things we already know):
          +6  confirmed params (arjun/paramspider found real parameters here)
          +5  ZAP already raised an alert on this URL (high-signal endpoint)
          +5  existing finding references this URL (another tool flagged it)
          +4  whitebox source analysis lists this as an input-handling endpoint
          +3  httpx content-type is text/html (rendered → XSS lands in browser)
          +3  URL has a query string with key=value pairs
          +2  httpx status 200 (endpoint is actually live and reachable)
          +1  path contains a token that suggests user-driven navigation

        NEGATIVE signals (things that make XSS implausible or wasteful):
          -10 static asset extension (.js, .css, .png, .ico, .woff, .map …)
          -5  httpx status 401/403 (dalfox has no auth token to bypass this)
          -3  httpx status 404/410 (dead endpoint)
          -2  path is a bare API collection with no params (/api/Foo with no ?)

        URLs are sorted descending by score; only those with score > 0 are kept,
        capped at MAX_XSS_TARGETS to prevent overwhelming lightweight targets.
        """
        import re as _re
        import json as _json

        MAX_XSS_TARGETS = 80

        _static_ext = _re.compile(
            r"\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|"
            r"pdf|zip|tar|gz|mp4|mp3|webp|avif|otf)(\?.*)?$",
            _re.IGNORECASE,
        )
        _dynamic_token = _re.compile(
            r"/(?:search|q|query|find|filter|login|register|signup|reset|forgot|"
            r"profile|user|account|comment|review|feedback|message|checkout|"
            r"order|product|item|page|redirect|url|next|return|callback|token|"
            r"id|slug|name|email|error|confirm|verify|invite|share|embed)\b",
            _re.IGNORECASE,
        )

        try:
            raw_urls = [u.strip() for u in Path(seed_path).read_text(encoding="utf-8").splitlines() if u.strip()]
        except Exception:
            return None

        if not raw_urls:
            return None

        # ------------------------------------------------------------------ #
        # Build intelligence sets from accumulated session data               #
        # ------------------------------------------------------------------ #

        # 1. URLs with confirmed parameters from arjun / paramspider
        param_confirmed: set[str] = set()
        for te in self.memory.tool_executions:
            if te.tool not in {"arjun", "paramspider"}:
                continue
            for line in (te.output or "").splitlines():
                line = line.strip()
                if line.startswith("http") and ("?" in line or "=" in line):
                    param_confirmed.add(line.split("?")[0])
                    param_confirmed.add(line)

        # 2. URLs already flagged by ZAP (alerts target field + evidence text)
        zap_flagged: set[str] = set()
        for f in self.memory.findings:
            if f.tool == "zap":
                t = (f.target or "").strip()
                if t:
                    zap_flagged.add(t)
                    zap_flagged.add(t.split("?")[0])

        # 3. URLs referenced in any existing finding (cross-tool signal)
        finding_urls: set[str] = set()
        for f in self.memory.findings:
            t = (f.target or "").strip()
            if t:
                finding_urls.add(t)
                finding_urls.add(t.split("?")[0])

        # 4. Whitebox source endpoints (paths the source code actually handles)
        whitebox_paths: set[str] = set()
        wb = self.memory.metadata.get("whitebox", {})
        for ep in wb.get("endpoints", []):
            path = ep if isinstance(ep, str) else (ep.get("path") or ep.get("url") or "")
            if path:
                whitebox_paths.add(path.split("?")[0])

        # 5. Analyst-confirmed priority URLs (highest confidence — LLM identified
        #    these as input-reflecting from actual tool output evidence)
        analyst_priority: set[str] = set()
        for url in (self.memory.metadata.get("tool_hints") or {}).get("dalfox", {}).get("priority_urls", []):
            analyst_priority.add(url.strip())
            analyst_priority.add(url.strip().split("?")[0])

        # 6. Per-URL httpx intelligence: status code and content-type
        httpx_status: dict[str, int] = {}
        httpx_html: set[str] = set()
        for te in self.memory.tool_executions:
            if te.tool != "httpx":
                continue
            for line in (te.output or "").splitlines():
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    obj = _json.loads(line)
                    u = obj.get("url") or obj.get("input") or ""
                    sc = obj.get("status_code") or obj.get("status") or 0
                    ct = obj.get("content_type") or obj.get("content-type") or ""
                    if u:
                        httpx_status[u] = int(sc) if sc else 0
                        if "text/html" in ct:
                            httpx_html.add(u)
                            httpx_html.add(u.split("?")[0])
                except Exception:
                    continue

        # ------------------------------------------------------------------ #
        # Score every candidate URL                                           #
        # ------------------------------------------------------------------ #

        scores: list[tuple[int, str]] = []
        for url in raw_urls:
            parsed = urlparse(url)
            base = url.split("?")[0]
            score = 0

            # Hard disqualifiers first
            if _static_ext.search(parsed.path):
                score -= 10

            # Positive signals
            if url in analyst_priority or base in analyst_priority:
                score += 8  # LLM confirmed this URL reflects input — highest confidence
            if url in param_confirmed or base in param_confirmed:
                score += 6
            if url in zap_flagged or base in zap_flagged:
                score += 5
            if url in finding_urls or base in finding_urls:
                score += 5
            if base in whitebox_paths or parsed.path in whitebox_paths:
                score += 4
            if url in httpx_html or base in httpx_html:
                score += 3
            if parsed.query and "=" in parsed.query:
                score += 3
            status = httpx_status.get(url) or httpx_status.get(base) or 0
            if status == 200:
                score += 2
            if _dynamic_token.search(parsed.path):
                score += 1

            # Negative signals
            if status in {401, 403}:
                score -= 5
            elif status in {404, 410}:
                score -= 3

            # Parameterless endpoints without any high-confidence signal are poor
            # XSS candidates — dalfox will just do slow parameter mining and stall.
            has_params = bool(parsed.query and "=" in parsed.query)
            high_conf = (url in analyst_priority or base in analyst_priority
                         or url in zap_flagged or base in zap_flagged
                         or url in param_confirmed or base in param_confirmed)
            if not has_params and not high_conf:
                score -= 4

            scores.append((score, url))

        scores.sort(key=lambda x: x[0], reverse=True)
        selected = [url for score, url in scores if score > 0][:MAX_XSS_TARGETS]

        if not selected:
            # Fallback 1: at minimum keep URLs with query params regardless of score
            selected = [u for u in raw_urls if "?" in u and "=" in urlparse(u).query][:MAX_XSS_TARGETS]

        if not selected:
            # Fallback 2: the app likely uses REST-style paths with no query params
            # (e.g., OWASP Juice Shop).  Pick the best-scoring non-static URLs down to
            # score >= -2 so dalfox can probe them with parameter mining enabled.
            selected = [
                url for score, url in scores
                if score >= -2 and not _static_ext.search(urlparse(url).path)
            ][:20]

        if not selected:
            return None

        # Count parameterized URLs in final selection
        param_count = sum(1 for u in selected if "?" in u and "=" in urlparse(u).query)

        # Log score distribution for visibility
        if scores:
            top = scores[:5]
            self.logger.info(
                f"XSS seed: {len(selected)}/{len(raw_urls)} URLs selected "
                f"({param_count} with query params, scores {scores[0][0]}→{scores[len(selected)-1][0] if len(selected) > 1 else scores[0][0]}) "
                f"| signals: zap={len(zap_flagged)} params={len(param_confirmed)} "
                f"whitebox={len(whitebox_paths)} html={len(httpx_html)}"
            )
            for sc, u in top:
                self.logger.debug(f"  XSS score {sc:+d}: {u}")

        # Store param_count on memory so the dalfox wrapper can skip mining
        self.memory.metadata["xss_seed_param_count"] = param_count

        path = self._write_urls_file(selected, name=f"xss_seed_{self.memory.session_id}.txt")
        return path

    def _write_nuclei_seed_file(self, seed_path: str) -> Optional[Path]:
        """Score and rank URLs for nuclei template scanning using accumulated session intelligence.

        Nuclei templates test for concrete vulnerability classes (CVEs, default
        credentials, exposed configs, open redirects …).  Feeding it the full
        master seed — which is dominated by static assets from subjs/ZAP spider —
        wastes the entire time budget on JS/CSS/ICO files that can never match a
        template.  This method strips the noise and surfaces the URLs that nuclei
        templates are actually designed to hit.

        HARD EXCLUSIONS (zero nuclei value — dropped before scoring):
          • Static assets  (.js .css .ico .png .woff .map .txt .xml .yml …)
          • Path-template placeholders  /:param or /{param}  — nuclei sends
            these literally and receives 404s; they need real IDs to be useful
          • Joke / Easter-egg paths  — excessively deep paths with no meaningful
            segments (>7 segments and score stays ≤ 0 after full evaluation)
          • Duplicate base paths  — deduplicated before scoring

        POSITIVE signals (things we already know from session data):
          +10  analyst nuclei priority_urls  — LLM explicitly flagged for scanning
          +7   ZAP raised an alert on this URL  — already known interesting
          +7   existing finding targets this URL  — another tool confirmed it
          +6   whitebox source code handles this path  — confirmed endpoint
          +5   httpx confirmed status 200  — live and reachable
          +5   admin / management surface  (/admin /metrics /actuator /swagger
               /api-docs /graphql /debug /config /env /health /status /management)
          +5   authentication surface  (/login /logout /auth /oauth /token
               /password /reset /2fa /verify /register /signup /session)
          +4   sensitive data / file ops  (/upload /export /import /download
               /backup /dump /data /attachment /file /report)
          +4   injection-prone surface  (/search /query /find /filter /redirect
               /url /callback /next /return /goto /link /open /proxy)
          +3   API / REST collection endpoint  (path starts with /api/ or /rest/)
          +3   tech-stack match  (detected technology maps to a nuclei tag —
               e.g. node/express/jquery/angular/react/wordpress/drupal/laravel)
          +2   chatbot / AI / web3 endpoints  (newer template coverage)
          +1   short path depth (≤ 3 segments — broad-coverage templates prefer root-ish paths)

        NEGATIVE signals:
          -8   static asset extension  (hard disqualifier, brings score negative)
          -6   path-template placeholder  (/api/Foo/:id)
          -4   httpx status 401/403  (auth-bypass templates exist but low yield
               without credentials; keep only if also admin/auth/finding signal)
          -3   httpx status 404/410  — dead endpoint
          -2   path depth > 6 segments  — deep paths rarely match templates
          -1   path looks like a numeric ID segment  (/foo/12345/bar)

        URLs are sorted descending by score.  Only those with score > 0 are kept,
        capped at MAX_NUCLEI_TARGETS.  A fallback keeps the root URL if nothing
        else qualifies.
        """
        import re as _re
        import json as _json

        cfg_nuclei = (self.config or {}).get("tools", {}).get("nuclei", {}) or {}
        MAX_NUCLEI_TARGETS: int = int(cfg_nuclei.get("seed_max_urls", 60))

        # ------------------------------------------------------------------ #
        # Compiled patterns                                                    #
        # ------------------------------------------------------------------ #

        _static_ext = _re.compile(
            r"\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|"
            r"pdf|zip|tar|gz|mp4|mp3|webp|avif|otf|txt|xml|json|yaml|yml|"
            r"md|csv|log|bak|swp|DS_Store)(\?.*)?$",
            _re.IGNORECASE,
        )
        # Path segments that are unresolved route parameters
        _path_template = _re.compile(r"/:[A-Za-z_][A-Za-z0-9_]*|/\{[A-Za-z_][A-Za-z0-9_]*\}")

        # High-value path tokens for nuclei — maps to template categories
        _admin_surface = _re.compile(
            r"/(?:admin|management|manager|actuator|metrics|prometheus|swagger|"
            r"api-?docs?|openapi|graphql|graph|debug|config|configuration|"
            r"env|environment|health|healthz|status|info|server-status|"
            r"console|dashboard|panel|cp|controlpanel|phpmyadmin|adminer|"
            r"wp-admin|wp-login|\.git|\.env|\.htaccess|web\.config|"
            r"backup|dump|database|db|sql|bak|old|tmp|temp|test)\b",
            _re.IGNORECASE,
        )
        _auth_surface = _re.compile(
            r"/(?:login|logout|signin|signout|signup|register|auth|oauth|"
            r"token|password|passwd|reset|forgot|change-password|2fa|mfa|"
            r"verify|verification|session|sso|saml|ldap|jwt|api-?key|"
            r"authentication|authorize|callback|connect|disconnect)\b",
            _re.IGNORECASE,
        )
        _file_surface = _re.compile(
            r"/(?:upload|file|files|import|export|download|attachment|"
            r"attachments|backup|restore|snapshot|archive|report|reports|"
            r"data-export|transfer|share|storage|media|assets/private)\b",
            _re.IGNORECASE,
        )
        _inject_surface = _re.compile(
            r"/(?:search|query|q|find|filter|redirect|redir|url|link|goto|"
            r"open|next|return|callback|forward|proxy|fetch|load|render|"
            r"include|require|src|dest|target)\b",
            _re.IGNORECASE,
        )
        # Detect natural-language sentence paths — sequences of plain English
        # words with no technical tokens (common in Easter-egg / joke routes).
        # Match paths where every non-empty segment is a lowercase word and
        # there are no digits, hyphens, or recognised API tokens.
        _sentence_path = _re.compile(
            r"^(?:/[a-z]{2,}){4,}$"
        )
        _ai_web3_surface = _re.compile(
            r"/(?:chatbot|chat|ai|llm|gpt|bot|assistant|web3|nft|wallet|"
            r"blockchain|crypto|token|smart-?contract|defi|mint)\b",
            _re.IGNORECASE,
        )
        _numeric_segment = _re.compile(r"/\d{2,}")

        # ------------------------------------------------------------------ #
        # Load URLs                                                            #
        # ------------------------------------------------------------------ #

        try:
            raw_urls = [u.strip() for u in Path(seed_path).read_text(encoding="utf-8").splitlines() if u.strip()]
        except Exception:
            return None

        if not raw_urls:
            return None

        # Deduplicate preserving order
        seen: set[str] = set()
        deduped: list[str] = []
        for u in raw_urls:
            if u not in seen:
                seen.add(u)
                deduped.append(u)
        raw_urls = deduped

        # ------------------------------------------------------------------ #
        # Build intelligence sets from accumulated session data               #
        # ------------------------------------------------------------------ #

        # 1. Analyst-confirmed nuclei priority URLs (highest confidence)
        analyst_priority: set[str] = set()
        all_hints: dict = self.memory.metadata.get("tool_hints") or {}
        for url in all_hints.get("nuclei", {}).get("priority_urls", []):
            analyst_priority.add(url.strip())
            analyst_priority.add(url.strip().split("?")[0])

        # 2. ZAP-flagged URLs (existing alerts — high-signal endpoints)
        zap_flagged: set[str] = set()
        for f in self.memory.findings:
            if f.tool == "zap":
                t = (f.target or "").strip()
                if t:
                    zap_flagged.add(t)
                    zap_flagged.add(t.split("?")[0])

        # 3. Any URL referenced by an existing finding (cross-tool signal)
        finding_urls: set[str] = set()
        for f in self.memory.findings:
            t = (f.target or "").strip()
            if t:
                finding_urls.add(t)
                finding_urls.add(t.split("?")[0])

        # 4. Whitebox source endpoints (code actually routes to these)
        whitebox_paths: set[str] = set()
        wb = self.memory.metadata.get("whitebox", {})
        for ep in wb.get("endpoints", []):
            path = ep if isinstance(ep, str) else (ep.get("path") or ep.get("url") or "")
            if path:
                whitebox_paths.add(path.split("?")[0])

        # 5. Per-URL httpx data: status code + detected technologies
        httpx_status: dict[str, int] = {}
        detected_techs: set[str] = set()
        for te in self.memory.tool_executions:
            if te.tool not in {"httpx", "whatweb", "cmseek"}:
                continue
            for line in (te.output or "").splitlines():
                line = line.strip()
                if te.tool == "httpx" and line.startswith("{"):
                    try:
                        obj = _json.loads(line)
                        u = obj.get("url") or obj.get("input") or ""
                        sc = obj.get("status_code") or obj.get("status") or 0
                        if u:
                            httpx_status[u] = int(sc) if sc else 0
                        # Collect technology names for template matching
                        for tech in (obj.get("tech") or obj.get("technologies") or []):
                            if isinstance(tech, str):
                                detected_techs.add(tech.lower().split(":")[0].strip())
                            elif isinstance(tech, dict):
                                n = tech.get("name") or tech.get("tech") or ""
                                if n:
                                    detected_techs.add(n.lower().split(":")[0].strip())
                    except Exception:
                        continue
                elif te.tool in {"whatweb", "cmseek"}:
                    # Rough tech extraction from text output
                    for token in _re.findall(r'\b(wordpress|drupal|joomla|laravel|django|rails|express|angular|react|vue|jquery|bootstrap|nginx|apache|iis|tomcat|spring|struts|flask)\b', line, _re.IGNORECASE):
                        detected_techs.add(token.lower())

        # Map detected techs to nuclei tag relevance
        _tech_tag_map = {
            "wordpress": True, "drupal": True, "joomla": True,
            "laravel": True, "django": True, "rails": True,
            "spring": True, "struts": True, "express": True,
            "jquery": True, "angular": True, "react": True,
        }
        has_tech_templates = any(t in _tech_tag_map for t in detected_techs)

        # ------------------------------------------------------------------ #
        # Score every candidate URL                                            #
        # ------------------------------------------------------------------ #

        scores: list[tuple[int, str]] = []
        for url in raw_urls:
            parsed = urlparse(url)
            path = parsed.path
            base = url.split("?")[0]
            score = 0

            # --- Hard disqualifiers (applied first, end scoring early) ---
            if _static_ext.search(path):
                score -= 8
                scores.append((score, url))
                continue

            if _path_template.search(path):
                score -= 6
                scores.append((score, url))
                continue

            # --- Positive signals ---
            if url in analyst_priority or base in analyst_priority:
                score += 10

            if url in zap_flagged or base in zap_flagged:
                score += 7

            if url in finding_urls or base in finding_urls:
                score += 7

            if base in whitebox_paths or path in whitebox_paths:
                score += 6

            status = httpx_status.get(url) or httpx_status.get(base) or 0
            if status == 200:
                score += 5

            if _admin_surface.search(path):
                score += 5

            if _auth_surface.search(path):
                score += 5

            if _file_surface.search(path):
                score += 4

            if _inject_surface.search(path):
                score += 4

            if path.startswith("/api/") or "/rest/" in path:
                score += 3

            # Tech-stack bonus: target runs a framework with dedicated nuclei templates
            if has_tech_templates:
                score += 3

            if _ai_web3_surface.search(path):
                score += 2

            # Short paths are preferred — root-ish endpoints match fingerprint/
            # default-login/exposure templates better than deep API paths
            depth = len([s for s in path.split("/") if s])
            if depth <= 3:
                score += 1

            # --- Negative signals ---
            if status in {401, 403}:
                # Keep auth-bypass candidates but penalise if no other high signal
                has_high = (url in analyst_priority or base in analyst_priority
                            or url in zap_flagged or base in zap_flagged
                            or url in finding_urls or base in finding_urls
                            or _auth_surface.search(path) or _admin_surface.search(path))
                if not has_high:
                    score -= 4

            if status in {404, 410}:
                score -= 3

            if depth > 6:
                score -= 2

            if _numeric_segment.search(path):
                score -= 1

            # Natural-language sentence paths (Easter-egg / joke routes) have
            # no technical tokens and score negatively on depth, but shallow
            # ones can slip through.  Only penalise at depth >= 5 to avoid
            # catching legitimate API paths like /dashboard/users/active/list.
            if depth >= 5 and _sentence_path.match(path):
                score -= 4

            scores.append((score, url))

        scores.sort(key=lambda x: x[0], reverse=True)
        selected = [url for sc, url in scores if sc > 0][:MAX_NUCLEI_TARGETS]

        # Fallback: always include root URL so nuclei fingerprinting templates fire
        root = self.target if self.target and self.target.startswith("http") else None
        if root and root not in selected:
            selected.insert(0, root)

        if not selected:
            return None

        # ------------------------------------------------------------------ #
        # Log score distribution                                               #
        # ------------------------------------------------------------------ #
        excluded_static = sum(1 for sc, _ in scores if sc <= -8)
        excluded_template = sum(1 for sc, u in scores if -7 <= sc <= -6 and _path_template.search(urlparse(u).path))
        self.logger.info(
            f"Nuclei seed: {len(selected)}/{len(raw_urls)} URLs selected "
            f"(excluded: {excluded_static} static assets, {excluded_template} path templates) "
            f"| signals: analyst={len(analyst_priority)} zap={len(zap_flagged)} "
            f"findings={len(finding_urls)} whitebox={len(whitebox_paths)} "
            f"techs={{{','.join(sorted(detected_techs)[:5])}}}"
        )
        for sc, u in scores[:10]:
            self.logger.debug(f"  Nuclei score {sc:+d}: {u}")
        if len(scores) > 10:
            self.logger.debug(f"  ... ({len(scores) - 10} more URLs scored)")

        path = self._write_urls_file(selected, name=f"nuclei_seed_{self.memory.session_id}.txt")
        return path

    def _apply_tool_hints(self, tool_name: str, tool_kwargs: dict) -> dict:
        """Merge accumulated analyst tool hints into tool kwargs before execution.

        The analyst emits TOOL_HINTS after interpreting each tool's output.
        Those hints accumulate in memory.metadata["tool_hints"] and are applied
        here so every tool benefits from the full intelligence gathered so far:

        - nuclei: analyst-suggested extra tags get appended to the tag list
        - sqlmap/commix/xsstrike: analyst-confirmed injectable URLs get passed
          as hint_urls (wrappers can pick the best candidate)
        - rate_hint: if the analyst detected target stress, reduce concurrency
          for tools that support it

        dalfox priority_urls are handled separately inside _write_xss_seed_file
        where they receive the highest scoring weight (+8) in the URL scorer.
        """
        all_hints: dict = self.memory.metadata.get("tool_hints") or {}
        tool_hints: dict = all_hints.get(tool_name, {})

        if not tool_hints and "rate_hint" not in all_hints:
            return tool_kwargs

        tool_kwargs = dict(tool_kwargs)

        # nuclei: append analyst-suggested tags
        if tool_name == "nuclei":
            extra_tags = tool_hints.get("extra_tags", [])
            if extra_tags:
                existing = tool_kwargs.get("tags") or tool_kwargs.get("tags_filter") or ""
                if isinstance(existing, list):
                    existing = ",".join(existing)
                merged = ",".join(
                    dict.fromkeys(
                        t.strip() for t in (existing + "," + ",".join(extra_tags)).split(",") if t.strip()
                    )
                )
                tool_kwargs["tags"] = merged
                self.logger.info(f"[Hints] nuclei tags enriched → {merged}")

        # injection tools: pass analyst-confirmed URLs as hint_urls
        if tool_name in {"sqlmap", "commix", "xsstrike"}:
            priority = tool_hints.get("priority_urls", [])
            if priority:
                tool_kwargs["hint_urls"] = priority
                self.logger.info(f"[Hints] {tool_name} priority URLs: {priority[:3]}")

        # rate_hint: reduce concurrency when analyst detected target stress
        rate_hint = float(all_hints.get("rate_hint", 1.0))
        if rate_hint < 1.0:
            if tool_name == "dalfox":
                w = max(1, int(tool_kwargs.get("workers", 5) * rate_hint))
                tool_kwargs["workers"] = w
                self.logger.info(f"[Hints] dalfox workers reduced to {w} (rate_hint={rate_hint})")
            elif tool_name == "nuclei":
                r = max(5, int(tool_kwargs.get("rate_limit", 50) * rate_hint))
                tool_kwargs["rate_limit"] = r
                self.logger.info(f"[Hints] nuclei rate_limit reduced to {r} (rate_hint={rate_hint})")

        return tool_kwargs

    def _filter_urls_to_target(self, urls: List[str]) -> List[str]:
        """Keep only URLs on the same host:port as the primary pentest target.

        Drops:
        - ZAP internal API calls (127.x.x.x)
        - External documentation / advisory URLs (github.com, owasp.org …)
        - Source-code line references embedded in paths (/foo.js:280:10)
        """
        import re as _re
        try:
            target_netloc = urlparse(self.target).netloc.lower()
        except Exception:
            target_netloc = ""

        if not target_netloc:
            return urls

        _line_ref = _re.compile(r"\.\w+:\d+:\d+$")
        out: list[str] = []
        for url in urls:
            if not isinstance(url, str):
                continue
            try:
                parsed = urlparse(url)
                if parsed.netloc.lower() != target_netloc:
                    continue
                if _line_ref.search(parsed.path):
                    continue
                out.append(url)
            except Exception:
                continue
        return out

    def _get_target_base_url(self) -> str:
        target = (self.target or "").strip()
        if not target:
            return ""
        if "://" not in target:
            target = f"https://{target}"
        try:
            from urllib.parse import urlparse
            parsed = urlparse(target)
        except Exception:
            return ""
        if not parsed.scheme or not parsed.netloc:
            return ""
        return f"{parsed.scheme}://{parsed.netloc}"

    def _persist_whitebox_endpoints(self) -> None:
        if not self.whitebox_findings:
            return
        endpoints = self.whitebox_findings.get("attack_surface", {}).get("endpoints", [])
        if not endpoints:
            return
        base_url = self._get_target_base_url()
        urls: list[str] = []
        for entry in endpoints:
            endpoint = None
            if isinstance(entry, dict):
                endpoint = entry.get("endpoint") or entry.get("url")
            elif isinstance(entry, str):
                endpoint = entry
            if not endpoint or not isinstance(endpoint, str):
                continue
            endpoint = endpoint.strip()
            if not endpoint:
                continue
            if endpoint.startswith("http://") or endpoint.startswith("https://"):
                url = endpoint
            else:
                if not base_url:
                    continue
                from urllib.parse import urljoin
                url = urljoin(base_url, endpoint)
            urls.append(url)

        if not urls:
            return

        # De-dupe and scope-filter
        seen = set()
        deduped: list[str] = []
        for url in urls:
            if url in seen:
                continue
            seen.add(url)
            deduped.append(url)
        deduped = self._filter_urls_in_scope(deduped)
        if not deduped:
            return

        # Add to context so downstream tools can reuse the URLs
        self.memory.update_context("urls", deduped)
        self.memory.update_context("discovered_assets", deduped)

        endpoints_file = self._write_urls_file(
            deduped,
            name=f"whitebox_endpoints_{self.memory.session_id}.txt",
        )
        self.memory.metadata["whitebox_endpoints_file"] = str(endpoints_file)
        self.logger.info(f"Saved whitebox endpoints to: {endpoints_file}")

        # Prepare a path-only wordlist for fuzzers (ffuf)
        fuzz_entries: list[str] = []
        from urllib.parse import urlparse
        for url in deduped:
            try:
                parsed = urlparse(url)
            except Exception:
                continue
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
            if path.startswith("/"):
                path = path[1:]
            path = path.strip()
            if path:
                fuzz_entries.append(path)

        if fuzz_entries:
            seen = set()
            deduped_paths: list[str] = []
            for entry in fuzz_entries:
                if entry in seen:
                    continue
                seen.add(entry)
                deduped_paths.append(entry)
            wordlist_file = self._write_urls_file(
                deduped_paths,
                name=f"whitebox_endpoints_paths_{self.memory.session_id}.txt",
            )
            self.memory.metadata["whitebox_endpoints_wordlist"] = str(wordlist_file)
            self.logger.info(f"Saved whitebox endpoint wordlist to: {wordlist_file}")

    def _run_ip_enrichment(self, target_ip: str) -> None:
        """Perform lightweight enrichment for IP targets (PTR + TLS cert name harvesting)."""
        from urllib.parse import urlparse
        from utils.helpers import reverse_lookup_ip, fetch_tls_names, is_valid_ip, extract_domain_from_url
        from core.memory import ToolExecution
        import socket

        if not is_valid_ip(target_ip):
            host = extract_domain_from_url(target_ip) or target_ip
            resolved: list[str] = []
            try:
                for res in socket.getaddrinfo(host, None):
                    ip = res[4][0]
                    if ip and ip not in resolved:
                        resolved.append(ip)
            except Exception:
                resolved = []

            if resolved:
                self.logger.info(f"Resolved {host} -> {', '.join(resolved)}")
                self.memory.update_context("discovered_assets", resolved)
                self.memory.add_tool_execution(ToolExecution(
                    tool="dns_resolve",
                    command=f"A/AAAA lookup {host}",
                    target=host,
                    timestamp=datetime.now().isoformat(),
                    exit_code=0,
                    output=", ".join(resolved),
                    duration=0.0
                ))
                for ip in resolved:
                    if ip == target_ip:
                        continue
                    self._run_ip_enrichment(ip)
            else:
                self.logger.info(f"DNS resolve for {host}: no A/AAAA records found")
            return

        hostname = reverse_lookup_ip(target_ip)
        if hostname:
            self.logger.info(f"Reverse DNS for {target_ip}: {hostname}")
            self.memory.update_context("discovered_assets", [hostname])
            self.memory.add_tool_execution(ToolExecution(
                tool="reverse_dns",
                command=f"PTR {target_ip}",
                target=target_ip,
                timestamp=datetime.now().isoformat(),
                exit_code=0,
                output=hostname,
                duration=0.0
            ))
        else:
            self.logger.info(f"Reverse DNS for {target_ip}: no PTR found")

        # Probe standard TLS port, plus an explicit port if the target URL included one.
        ports: list[int] = [443]
        try:
            parsed = urlparse(self.target if "://" in self.target else f"//{self.target}")
            if parsed.port and parsed.port not in ports:
                ports.append(int(parsed.port))
        except Exception:
            pass

        for port in ports:
            tls_names = fetch_tls_names(target_ip, port)
            if tls_names:
                self.logger.info(f"TLS names for {target_ip}:{port}: {', '.join(tls_names)}")
                self.memory.update_context("discovered_assets", tls_names)
                # Store per-host SANs for CSV export
                host_sans = self.memory.context.get("host_sans") or {}
                if not isinstance(host_sans, dict):
                    host_sans = {}
                existing_sans = host_sans.get(target_ip) or []
                host_sans[target_ip] = sorted(set(existing_sans + tls_names))
                self.memory.context["host_sans"] = host_sans
                self.memory.add_tool_execution(ToolExecution(
                    tool="tls_cert_probe",
                    command=f"TLS SAN/CN from {target_ip}:{port}",
                    target=target_ip,
                    timestamp=datetime.now().isoformat(),
                    exit_code=0,
                    output=", ".join(tls_names),
                    duration=0.0
                ))
            else:
                self.logger.info(f"TLS names for {target_ip}:{port}: none or TLS unavailable")

    def _run_metadata_extraction(self, target: str) -> None:
        """Fetch robots.txt, sitemap.xml, and HTML comments for a target."""
        import ssl
        import urllib.request
        from urllib.parse import urlparse
        from core.memory import ToolExecution

        def _fetch(url: str, timeout: int = 10) -> str:
            req = urllib.request.Request(url, headers={"User-Agent": "guardian-metadata/1.0"})
            ctx = ssl._create_unverified_context()
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.read().decode("utf-8", errors="replace")

        parsed = urlparse(target if "://" in target else f"//{target}")
        if parsed.scheme:
            bases = [f"{parsed.scheme}://{parsed.netloc}"]
        else:
            bases = [f"https://{target}", f"http://{target}"]

        results = {"robots": "", "sitemap": "", "comments": []}
        used_base = ""

        for base in bases:
            try:
                robots = _fetch(f"{base}/robots.txt")
                results["robots"] = robots
                used_base = base
                break
            except Exception:
                continue

        for base in bases:
            try:
                sitemap = _fetch(f"{base}/sitemap.xml")
                results["sitemap"] = sitemap
                used_base = used_base or base
                break
            except Exception:
                continue

        page_text = ""
        for base in bases:
            try:
                page_text = _fetch(base)
                used_base = used_base or base
                break
            except Exception:
                continue

        if page_text:
            comments = re.findall(r"<!--(.*?)-->", page_text, flags=re.DOTALL)
            results["comments"] = [c.strip() for c in comments if c.strip()][:50]

        self.memory.update_context("metadata", results)
        self.memory.add_tool_execution(ToolExecution(
            tool="metadata",
            command=f"metadata extraction ({used_base or target})",
            target=target,
            timestamp=datetime.now().isoformat(),
            exit_code=0,
            output=str(results)[:2000],
            duration=0.0,
        ))
    
    async def _execute_ai_decision(self, decision: Dict[str, Any]):
        """Execute an AI-decided action"""
        action = decision.get("next_action", "")
        
        self.logger.info(f"Executing AI decision: {action}")

        if not action or action == "unknown":
            self.logger.warning("Planner returned unknown/empty action; retrying once")
            retry = await self.planner.decide_next_action()
            action = retry.get("next_action", "")
            decision = retry
            if not action or action == "unknown":
                self.logger.warning("Planner still returned unknown; falling back to technology_detection")
                decision = {"next_action": "technology_detection", "parameters": "", "expected_outcome": ""}
                action = "technology_detection"
            self.logger.info(f"Recovered AI decision: {action}")

        if self.memory.is_action_completed(action):
            self.logger.info(f"Skipping AI decision: {action} (already completed)")
            return

        # Handle internal (non-tool) actions without routing through ToolSelector.
        output_dir = Path(self.config.get("output", {}).get("save_path", "./reports"))
        output_dir.mkdir(parents=True, exist_ok=True)

        if action == "correlate_findings":
            analysis = await self.analyst.correlate_findings()
            self.memory.update_context("correlate_findings", analysis)
            self.logger.info("Correlation analysis complete")
            self.memory.mark_action_complete(action)
            return

        if action == "risk_assessment":
            assessment = await self.planner.analyze_results()
            content = assessment.get("response", "")
            if content:
                out_file = output_dir / f"risk_assessment_{self.memory.session_id}.md"
                with open(out_file, "w", encoding="utf-8") as f:
                    f.write(content)
                self.logger.info(f"Risk assessment saved to: {out_file}")
            self.memory.update_context("risk_assessment", assessment)
            self.memory.mark_action_complete(action)
            return

        if action == "executive_summary":
            summary = await self.reporter.generate_executive_summary()
            out_file = output_dir / f"executive_summary_{self.memory.session_id}.md"
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(summary)
            self.logger.info(f"Executive summary saved to: {out_file}")
            self.memory.update_context("executive_summary", summary)
            self.memory.mark_action_complete(action)
            return

        if action == "remediation_plan":
            plan = await self.reporter.generate_remediation_plan()
            out_file = output_dir / f"remediation_plan_{self.memory.session_id}.md"
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(plan)
            self.logger.info(f"Remediation plan saved to: {out_file}")
            self.memory.update_context("remediation_plan", plan)
            self.memory.mark_action_complete(action)
            return

        if action == "generate_report":
            for fmt, ext in (("markdown", "md"), ("html", "html")):
                self.logger.info(f"Generating {fmt} report...")
                report = await self.reporter.execute(format=fmt)
                report_file = output_dir / f"report_{self.memory.session_id}.{ext}"
                with open(report_file, "w", encoding="utf-8") as f:
                    f.write(report["content"])
                self.logger.info(f"Report saved to: {report_file}")
            self.memory.mark_action_complete(action)
            return

        if action == "ssl_analysis":
            # If the target is a plain-HTTP IP:port and TLS handshakes fail, skip running heavy TLS scanners.
            from urllib.parse import urlparse
            from utils.helpers import is_valid_ip, extract_domain_from_url, fetch_tls_names
            from core.memory import ToolExecution

            host = extract_domain_from_url(self.target) or self.target
            parsed = urlparse(self.target) if "://" in self.target else urlparse(f"//{self.target}")
            scheme = parsed.scheme.lower()
            port = parsed.port

            if is_valid_ip(host) and scheme == "http":
                ports_to_try = [p for p in [port, 443] if p]
                tls_names: list[str] = []
                for p in ports_to_try:
                    tls_names = fetch_tls_names(host, int(p))
                    if tls_names:
                        break
                if not tls_names:
                    self.logger.info(f"Skipping ssl_analysis: {host} does not appear to support TLS on {ports_to_try}")
                    self.memory.add_tool_execution(ToolExecution(
                        tool="tls_probe",
                        command=f"TLS handshake probe {host}:{ports_to_try}",
                        target=host,
                        timestamp=datetime.now().isoformat(),
                        exit_code=0,
                        output="no tls",
                        duration=0.0
                    ))
                    self.memory.mark_action_complete(action)
                    return

        # Skip domain-only actions on IP targets but attempt reverse DNS for recon value
        from utils.helpers import is_valid_ip, extract_domain_from_url
        target_host = extract_domain_from_url(self.target) or self.target
        if is_valid_ip(target_host) and action in {"subdomain_enumeration", "dns_enumeration", "ip_enrichment"}:
            self._run_ip_enrichment(target_host)
            self.memory.mark_action_complete(action)
            return
        
        # Use Tool Agent to select appropriate tool
        try:
            tool_selection = await self.tool_agent.execute(
                objective=action,
                target=self.target
            )

            if not tool_selection.get("tool"):
                self.logger.warning("Tool selection returned no tool; skipping execution")
                self.memory.mark_action_complete(action)
                return
            
            # Execute selected tool with parsed arguments when possible
            tool_kwargs: Dict[str, Any] = {}
            args = tool_selection.get("arguments", "") or ""
            if tool_selection["tool"] == "nmap" and args:
                if "-p-" in args:
                    tool_kwargs["ports"] = "1-65535"
                else:
                    import re
                    port_match = re.search(r"-p\\s*([0-9,\\-]+)", args)
                    if port_match:
                        tool_kwargs["ports"] = port_match.group(1)
                if "-sS" in args:
                    tool_kwargs["scan_type"] = "-sS"

            # Normalize execution target for domain-only tools when the user provided a URL.
            # E.g. dnsrecon expects a bare domain, not "https://domain".
            exec_target = self.target
            domain_only_tools = {
                "subfinder",
                "dnsrecon",
                "dnsx",
                "shuffledns",
                "puredns",
                # "altdns",  # REMOVED - replaced by dnsgen + puredns
                "asnmap",
            }
            if tool_selection["tool"] in domain_only_tools:
                host = extract_domain_from_url(self.target) or self.target
                if host and host != self.target:
                    exec_target = host

            if not self._scope_allows(exec_target):
                self.logger.error(f"Target validation failed before tool execution: {exec_target}")
                self.memory.mark_action_complete(action)
                return

            result = await self.tool_agent.execute_tool(
                tool_name=tool_selection["tool"],
                target=exec_target,
                **tool_kwargs
            )

            self._log_tool_execution(tool=tool_selection["tool"], args=tool_kwargs, result=result)
            
            if result.get("success"):
                # Analyze with Analyst Agent
                analysis = await self.analyst.interpret_output(
                    tool=tool_selection["tool"],
                    target=exec_target,
                    command=result.get("command", ""),
                    output=result.get("raw_output", "")
                )
                self.logger.info(f"Found {len(analysis['findings'])} new findings")
                if self.memory.tool_executions:
                    self.memory.tool_executions[-1].findings_count = len(analysis["findings"])
            
        except Exception as e:
            self.logger.error(f"Failed to execute AI decision: {e}")
        
        self.memory.mark_action_complete(action)

    def _normalize_workflow_name(self, workflow_name: str) -> str:
        """Normalize user-provided workflow name to YAML canonical name."""
        name = (workflow_name or "").strip()
        if not name:
            return ""
        aliases = {
            "wordpress": "wordpress_audit",
            "web": "web_pentest",
            "network": "network_pentest",
            "reconnaissance": "recon",
        }
        return aliases.get(name, name)

    def _normalize_workflow_key(self, workflow_name: str) -> str:
        """Normalize workflow name to a built-in workflow key."""
        name = self._normalize_workflow_name(workflow_name)
        reverse_aliases = {
            "web_pentest": "web",
            "network_pentest": "network",
        }
        return reverse_aliases.get(name, name)
    
    def _apply_workflow_settings(self, workflow_config: Dict[str, Any]) -> None:
        """Apply the settings: block from a workflow YAML into the live config.

        Supported keys:
          max_parallel_tools  — cap on concurrent tool executions
          require_confirmation — whether to prompt before each tool
          save_intermediate   — whether to persist partial results
        """
        settings = (workflow_config or {}).get("settings") or {}
        if not settings:
            return

        pentest_cfg = self.config.setdefault("pentest", {})

        if "max_parallel_tools" in settings:
            try:
                pentest_cfg["max_parallel_tools"] = int(settings["max_parallel_tools"])
                self.logger.info(f"Workflow setting: max_parallel_tools={pentest_cfg['max_parallel_tools']}")
            except (ValueError, TypeError):
                pass

        if "require_confirmation" in settings:
            pentest_cfg["require_confirmation"] = bool(settings["require_confirmation"])

        if "save_intermediate" in settings:
            pentest_cfg["save_intermediate"] = bool(settings["save_intermediate"])

        if "step_delay" in settings:
            try:
                pentest_cfg["step_delay"] = float(settings["step_delay"])
                self.logger.info(f"Workflow setting: step_delay={pentest_cfg['step_delay']}s")
            except (ValueError, TypeError):
                pass

    def _load_workflow_config(self, workflow_name: str) -> Dict[str, Any]:
        """Load full workflow configuration from YAML file"""
        repo_root = Path(__file__).resolve().parent.parent
        workflows_dir = repo_root / "workflows"

        # Normalize alias (e.g. "web" -> "web_pentest") so we find the right YAML
        normalized = self._normalize_workflow_name(workflow_name)
        candidates = {workflow_name, workflow_name.replace("-", "_"), normalized, normalized.replace("-", "_")}
        for candidate in candidates:
            path = workflows_dir / f"{candidate}.yaml"
            if path.exists():
                try:
                    data = yaml.safe_load(path.read_text()) or {}
                    return data
                except Exception as exc:
                    self.logger.warning(f"Failed to load workflow config from {path}: {exc}")

        return {}

    def _load_workflow(self, workflow_name: str) -> List[Dict[str, Any]]:
        """Load workflow definition with OS-specific tool selection"""
        web_probing_tool = "httpx"

        # Predefined workflows
        workflows = {
            "recon": [
                {"name": "passive_osint", "type": "multi_tool", "tools": [
                    {"tool": "amass", "condition": "target_is_domain"},
                    {"tool": "whois"},
                    {"tool": "dnsrecon", "parameters": {"type": "std"}, "condition": "target_is_domain"},
                ]},
                {"name": "dns_enumeration", "type": "tool", "tool": "dnsrecon", "condition": "target_is_domain", "parameters": {"type": "std,axfr,zonewalk,brt"}},
                {
                    "name": "masscan_discovery_cidr",
                    "type": "tool",
                    "tool": "masscan",
                    "condition": "target_is_network",
                    "parameters": {
                        "ports": "21,22,23,25,53,67,68,69,80,81,88,110,111,123,135,137,138,139,143,161,162,179,389,427,443,445,465,500,514,515,520,548,554,587,623,631,636,691,993,995,1080,1194,1433,1434,1494,1521,1701,1723,1812,1813,1883,2000,2427,2727,3306,3389,3478,4443,4500,4786,5000,5060,5061,51820,5432,5555,5900,8080,8081,8443",
                        "rate": 5000,
                    },
                },
                {
                    "name": "masscan_discovery_single_node",
                    "type": "tool",
                    "tool": "masscan",
                    "condition": "target_is_single_ip",
                    "parameters": {"ports": "1-65535", "rate": 5000},
                },
                {"name": "godeye_recon", "type": "tool", "tool": "godeye", "condition": "target_is_domain", "parameters": {"enable_ai": True}},
                {"name": "ip_enrichment", "type": "action", "action": "ip_enrichment"},
                {"name": "port_scanning", "type": "tool", "tool": "nmap", "condition": "target_is_domain", "parameters": {"profile": "recon"}},
                {"name": "service_fingerprinting", "type": "tool", "tool": "nmap", "parameters": {"args": "-sV --version-all -sC", "ports_from_context": True}},
                {"name": "nmap_vuln_scan", "type": "tool", "tool": "nmap", "parameters": {"profile": "vuln", "ports_from_context": True, "tool_timeout": 900}},
                {"name": "ssl_tls_analysis", "type": "tool", "tool": "testssl", "parameters": {"fast": True, "severity": "HIGH"}},
                {"name": "technology_detection", "type": "multi_tool", "tools": [
                    {"tool": "whatweb"},
                    {"tool": "retire"},
                ]},
                {"name": "metadata_extraction", "type": "action", "action": "metadata_extraction"},
                {"name": "analysis", "type": "analysis"},
                {"name": "report", "type": "report"},
            ],
            "web": [
                {"name": "web_discovery", "type": "tool", "tool": web_probing_tool},
                {"name": "technology_detection", "type": "multi_tool", "tools": [
                    {"tool": "whatweb"},
                ]},
                {"name": "metadata_extraction", "type": "action", "action": "metadata_extraction"},
                {"name": "vhost_enumeration", "type": "tool", "tool": "ffuf", "parameters": {"append_fuzz": False}},
                {"name": "vulnerability_scan", "type": "tool", "tool": "nuclei", "parameters": {"tool_timeout": 900}},
                {"name": "api_testing", "type": "multi_tool", "tools": [
                    {"tool": "schemathesis", "parameters": {"tool_timeout": 900}},
                    {"tool": "graphql-cop"},
                ]},
                {"name": "authentication_testing", "type": "tool", "tool": "hydra"},
                {"name": "session_management_testing", "type": "tool", "tool": "jwt_tool"},
                {"name": "authorization_testing", "type": "tool", "tool": "nuclei", "parameters": {
                    "tags": ["auth", "auth-bypass", "idor", "default-login"],
                    "tool_timeout": 900
                }},
                {"name": "xss_scan", "type": "tool", "tool": "dalfox", "parameters": {"tool_timeout": 900}},
                {"name": "file_upload_testing", "type": "tool", "tool": "upload-scanner"},
                {"name": "csrf_testing", "type": "tool", "tool": "csrf-tester"},
                {"name": "ssl_tls_analysis", "type": "tool", "tool": "testssl", "parameters": {"fast": True, "severity": "HIGH"}},
                {"name": "client_side_testing", "type": "multi_tool", "tools": [
                    {"tool": "linkfinder"},  # or xnlinkfinder - modern replacement for jsparser
                    {"tool": "retire"},
                ]},
                {"name": "zap_scan", "type": "tool", "tool": "zap", "condition": "zap_available"},
                {"name": "analysis", "type": "analysis"},
                {"name": "report", "type": "report"},
            ],
            "network": [
                {"name": "network_discovery", "type": "tool", "tool": "masscan", "parameters": {"ports": "22,53,80,135,139,443,445,3389", "rate": 10000}},
                {"name": "port_scan", "type": "tool", "tool": "nmap", "parameters": {"profile": "recon"}},
                {"name": "ip_enrichment", "type": "action", "action": "ip_enrichment"},
                {"name": "service_enumeration", "type": "tool", "tool": "nmap", "parameters": {"profile": "recon", "ports_from_context": True}},
                {"name": "network_topology", "type": "tool", "tool": "nmap", "parameters": {"args": "-sn --traceroute"}},
                {"name": "share_enumeration", "type": "multi_tool", "tools": [
                    {"tool": "enum4linux-ng"},
                    {"tool": "smbclient"},
                    {"tool": "showmount"},
                ]},
                {"name": "snmp_enumeration", "type": "multi_tool", "tools": [
                    {"tool": "onesixtyone"},
                    {"tool": "snmpwalk"},
                ]},
                {"name": "nmap_vuln_scan", "type": "tool", "tool": "nmap", "parameters": {"profile": "vuln", "ports_from_context": True, "tool_timeout": 900}},
                {"name": "ssl_tls_analysis", "type": "tool", "tool": "testssl", "parameters": {"fast": True, "severity": "HIGH"}},
                {"name": "analysis", "type": "analysis"},
                {"name": "report", "type": "report"},
            ]
        }
        
        yaml_steps = self._load_yaml_workflow(workflow_name)
        if yaml_steps:
            return yaml_steps

        workflow_key = self._normalize_workflow_key(workflow_name)
        if workflow_key in workflows:
            return workflows[workflow_key]

        return workflows["recon"]
    
    def _maybe_advance_phase(self):
        """Advance to next phase based on progress"""
        phases = ["reconnaissance", "scanning", "analysis", "reporting"]
        current_idx = phases.index(self.memory.current_phase) if self.memory.current_phase in phases else 0

        if current_idx >= len(phases) - 1:
            return

        if self.current_step % 5 != 0:
            return

        # Before advancing from scanning to analysis, require that URL discovery has run.
        # Without a URL list, nuclei and other scanners have almost nothing to work with.
        if self.memory.current_phase == "scanning":
            completed = set(self.memory.completed_actions or [])
            web_crawl_done = bool(
                completed & {"web_crawling", "web_app_scanning"}
                or any(t.tool in {"zap", "katana", "waybackurls"} for t in self.memory.tool_executions)
            )
            discovered_urls = self._get_discovered_urls()
            if not web_crawl_done and len(discovered_urls) < 10:
                self.logger.info(
                    "Holding in scanning phase: URL discovery not yet complete "
                    f"({len(discovered_urls)} URLs found, web_crawling not in completed actions)"
                )
                return

        new_phase = phases[current_idx + 1]
        self.logger.info(f"Advancing to phase: {new_phase}")
        self.memory.update_phase(new_phase)

    def _target_is_ip(self) -> bool:
        """Return True if the target looks like an IP address or CIDR."""
        target = (self.target or "").strip()
        if not target:
            return False

        host = target
        if "://" in target:
            try:
                parsed = urlparse(target)
                if parsed.hostname:
                    host = parsed.hostname
            except Exception:
                pass
        elif "/" not in target:
            # Handle host:port without scheme
            try:
                parsed = urlparse(f"//{target}")
                if parsed.hostname:
                    host = parsed.hostname
            except Exception:
                pass

        try:
            if "/" in host:
                ipaddress.ip_network(host, strict=False)
            else:
                ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _target_is_url(self) -> bool:
        target = (self.target or "").strip()
        if not target:
            return False
        try:
            parsed = urlparse(target)
            return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
        except Exception:
            return False

    def _target_is_path(self) -> bool:
        target = (self.target or "").strip()
        if not target:
            return False
        if self._target_is_url():
            return False
        return Path(target).expanduser().exists()

    def _should_skip_for_condition(self, condition: Optional[str], name: str) -> bool:
        """Return True if a step should be skipped based on its condition."""
        if not condition:
            return False
        if condition == "target_is_domain":
            if self._target_is_ip():
                self.logger.info(f"Skipping {name}: target is IP")
                return True
        elif condition == "target_is_ip":
            if not self._target_is_ip():
                self.logger.info(f"Skipping {name}: target is not IP")
                return True
        elif condition == "target_is_network":
            from utils.helpers import extract_domain_from_url
            host = extract_domain_from_url(self.target) or self.target
            if not self._target_is_network(host):
                self.logger.info(f"Skipping {name}: target is not CIDR/range")
                return True
        elif condition == "target_is_single_ip":
            if not self._target_is_single_ip():
                self.logger.info(f"Skipping {name}: target is not a single IP")
                return True
        elif condition == "target_is_url":
            if not self._target_is_url():
                self.logger.info(f"Skipping {name}: target is not a URL")
                return True
        elif condition == "target_is_path":
            if not self._target_is_path():
                self.logger.info(f"Skipping {name}: target is not a local path")
                return True
        elif condition == "target_is_url_or_path":
            if not (self._target_is_url() or self._target_is_path()):
                self.logger.info(f"Skipping {name}: target is not a URL or local path")
                return True
        elif isinstance(condition, str) and condition.startswith("config_has:"):
            keys = [k.strip() for k in condition[len("config_has:"):].split(",") if k.strip()]
            for key in keys:
                cursor = self.config
                for part in key.split("."):
                    if not isinstance(cursor, dict) or part not in cursor:
                        self.logger.info(f"Skipping {name}: missing config {key}")
                        return True
                    cursor = cursor[part]
                if cursor in (None, "", [], {}):
                    self.logger.info(f"Skipping {name}: empty config {key}")
                    return True
        return False

    def _planner_config(self) -> tuple[bool, set[str]]:
        workflows_cfg = (self.config or {}).get("workflows", {}) or {}
        enabled = bool(workflows_cfg.get("use_planner", False))
        checkpoints = workflows_cfg.get("planner_checkpoints") or []
        if isinstance(checkpoints, str):
            checkpoints = [c.strip() for c in checkpoints.split(",") if c.strip()]
        checkpoints_set = {str(c).strip() for c in checkpoints if str(c).strip()}
        return enabled, checkpoints_set

    def _normalize_workflow_steps(self, steps: list[dict]) -> list[dict]:
        normalized: list[dict] = []
        for step in steps:
            if not isinstance(step, dict):
                continue
            step_type = step.get("type")
            if not step_type:
                if "tools" in step:
                    step_type = "multi_tool"
                elif "tool" in step:
                    step_type = "tool"
            if not step_type:
                continue

            parameters = step.get("parameters")
            if parameters is None and "args" in step:
                parameters = step.get("args")

            normalized_step: dict = {
                "name": step.get("name") or step.get("tool") or step_type,
                "type": step_type,
            }
            if "tool" in step:
                normalized_step["tool"] = step.get("tool")
            if "tools" in step:
                normalized_step["tools"] = step.get("tools")
            if parameters:
                normalized_step["parameters"] = parameters
            if "condition" in step:
                normalized_step["condition"] = step.get("condition")
            if "action" in step:
                normalized_step["action"] = step.get("action")
            if "agent" in step:
                normalized_step["agent"] = step.get("agent")
            objective = step.get("objective") or step.get("description")
            if objective:
                normalized_step["objective"] = objective
            normalized.append(normalized_step)
        return normalized

    def _load_yaml_workflow(self, workflow_name: str) -> list[dict]:
        name = self._normalize_workflow_name(workflow_name)
        if not name:
            return []

        repo_root = Path(__file__).resolve().parent.parent
        workflows_dir = repo_root / "workflows"
        if not workflows_dir.exists():
            return []

        for candidate in {name, name.replace("-", "_")}:
            path = workflows_dir / f"{candidate}.yaml"
            if not path.exists():
                continue
            try:
                data = yaml.safe_load(path.read_text()) or {}
            except Exception as exc:
                self.logger.warning(f"Failed to load workflow YAML {path}: {exc}")
                return []
            steps = data.get("steps") or []
            if isinstance(steps, list):
                return self._normalize_workflow_steps(steps)
        return []

    def _should_run_planner(self, step: Dict[str, Any]) -> bool:
        enabled, checkpoints = self._planner_config()
        if not enabled:
            return False
        if not checkpoints:
            return False
        if "all" in checkpoints:
            return True
        step_name = step.get("name")
        step_type = step.get("type")
        return step_name in checkpoints or step_type in checkpoints
    
    def _save_session(self):
        """Save session state"""
        output_dir = Path(self.config.get("output", {}).get("save_path", "./reports"))
        output_dir.mkdir(parents=True, exist_ok=True)
        
        state_file = output_dir / f"session_{self.memory.session_id}.json"
        self.memory.save_state(state_file)
        self.logger.info(f"Session saved to: {state_file}")

        # Refresh the master seed file (always filtered to in-scope target URLs).
        # This is the canonical source for downstream tools (nuclei, dalfox, …).
        # We do NOT write _extract_urls() here because that regex-scrapes raw tool
        # outputs (e.g. ZAP warnings containing 127.0.0.1:8080 proxy API calls) and
        # would overwrite the clean seed with out-of-scope noise, causing tools like
        # nuclei to time out scanning hundreds of unreachable ZAP proxy URLs.
        self._refresh_master_seed_file()

        commands = [te.command for te in self.memory.tool_executions if te.command]
        if commands:
            payloads_file = output_dir / f"payloads_{self.memory.session_id}.txt"
            with open(payloads_file, "w", encoding="utf-8") as f:
                f.write("\n".join(commands))
            self.logger.info(f"Exported tool commands: {payloads_file}")

        csv_path = self._export_host_csv(output_dir)
        if csv_path:
            self.logger.info(f"Exported host inventory CSV: {csv_path}")

        dns_csv_path = self._export_dns_csv(output_dir)
        if dns_csv_path:
            self.logger.info(f"Exported DNS inventory CSV: {dns_csv_path}")

    def _save_progress_if_enabled(self):
        workflows_cfg = (self.config or {}).get("workflows", {}) or {}
        if workflows_cfg.get("save_progress", True):
            self._save_session()

    def _extract_urls(self) -> List[str]:
        """Collect URLs from tool outputs and commands for export."""
        urls = []
        url_regex = re.compile(r"https?://[^\s\"'>]+")
        for te in self.memory.tool_executions:
            if te.command:
                urls.extend(url_regex.findall(te.command))
            if te.output:
                urls.extend(url_regex.findall(te.output))
        return urls

    def _export_host_csv(self, output_dir: Path) -> Optional[Path]:
        """
        Export a CSV of discovered hosts with columns:
            ip, dns_name, cname, ports, sans

        Sources:
        - host_open_ports  → {ip: [ports]}  (masscan + nmap per-host + nmap single)
        - host_dns         → {ip: dns_name} (nmap PTR / hostname)
        - host_sans        → {ip: [san,...]} (TLS cert SANs from tls_cert_probe)
        - dns_records      → {name: {CNAME: [...]}} (dnsrecon/dnsx)
        - discovered_assets / services for fallback IP list when host_open_ports is sparse
        """
        import csv
        import ipaddress

        ctx = self.memory.context
        host_open_ports: Dict[str, List[int]] = ctx.get("host_open_ports") or {}
        host_dns: Dict[str, str] = ctx.get("host_dns") or {}
        host_sans: Dict[str, List[str]] = ctx.get("host_sans") or {}
        dns_records: Dict[str, Any] = ctx.get("dns_records") or {}

        # Build a deduplicated IP set from all sources
        all_ips: set = set(host_open_ports.keys())

        # Add IPs from services (each service entry may have a "host" field)
        for svc in (ctx.get("services") or []):
            h = svc.get("host") if isinstance(svc, dict) else None
            if h:
                all_ips.add(h)

        # Add IPs from discovered_assets (filter to valid IPs only)
        for asset in (ctx.get("discovered_assets") or []):
            if not isinstance(asset, str):
                continue
            try:
                ipaddress.ip_address(asset)
                all_ips.add(asset)
            except ValueError:
                pass

        if not all_ips:
            return None

        # Sort IPs numerically
        def ip_sort_key(ip: str):
            try:
                return ipaddress.ip_address(ip)
            except ValueError:
                return ipaddress.ip_address("0.0.0.0")

        csv_path = output_dir / f"hosts_{self.memory.session_id}.csv"
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["ip", "dns_name", "cname", "ports", "sans"])
            for ip in sorted(all_ips, key=ip_sort_key):
                ports = host_open_ports.get(ip, [])
                dns_name = host_dns.get(ip, "")
                sans = host_sans.get(ip, [])
                # Look up CNAME for the PTR hostname (if known)
                cname = ""
                if dns_name:
                    cname_list = (dns_records.get(dns_name.lower(), {}) or {}).get("CNAME", [])
                    cname = ";".join(sorted(cname_list))
                writer.writerow([
                    ip,
                    dns_name,
                    cname,
                    ";".join(str(p) for p in sorted(ports)),
                    ";".join(sorted(sans)),
                ])
        return csv_path

    def _merge_dns_records(self, records: list) -> None:
        """
        Merge dnsrecon JSON records into context['dns_records'].
        Keyed by domain/name; values are sets of strings per record type.
        dnsrecon record format: {"type": "A", "name": "example.com", "address": "1.2.3.4"}
        """
        dns_records: Dict[str, Any] = self.memory.context.get("dns_records") or {}
        if not isinstance(dns_records, dict):
            dns_records = {}

        for rec in records:
            if not isinstance(rec, dict):
                continue
            rtype = str(rec.get("type", "")).upper()
            name = str(rec.get("name", rec.get("target", rec.get("domain", "")))).lower().rstrip(".")
            if not name or not rtype:
                continue

            entry = dns_records.setdefault(name, {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": [], "subdomains": []})

            if rtype == "A":
                addr = rec.get("address", "")
                if addr and addr not in entry["A"]:
                    entry["A"].append(addr)
            elif rtype == "AAAA":
                addr = rec.get("address", "")
                if addr and addr not in entry["AAAA"]:
                    entry["AAAA"].append(addr)
            elif rtype == "MX":
                mx = rec.get("exchange", rec.get("address", ""))
                if mx and mx not in entry["MX"]:
                    entry["MX"].append(mx)
            elif rtype == "NS":
                ns = rec.get("target", rec.get("address", ""))
                if ns and ns not in entry["NS"]:
                    entry["NS"].append(ns)
            elif rtype == "TXT":
                txt = rec.get("strings", rec.get("text", ""))
                if txt and txt not in entry["TXT"]:
                    entry["TXT"].append(txt)
            elif rtype == "CNAME":
                target = rec.get("target", "")
                if target and target not in entry["CNAME"]:
                    entry["CNAME"].append(target)
            elif rtype in ("A", "PTR"):
                pass  # already handled

            # Track subdomains — any record whose name differs from the base target
            base = (self.memory.context.get("target") or "").lower().rstrip(".")
            if base and name != base and name.endswith(f".{base}"):
                root = dns_records.setdefault(base, {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": [], "subdomains": []})
                if name not in root["subdomains"]:
                    root["subdomains"].append(name)

        self.memory.context["dns_records"] = dns_records

    def _merge_dnsx_records(self, records: list) -> None:
        """
        Merge dnsx JSONL records into context['dns_records'].
        dnsx -j format: {"host": "example.com", "a": ["1.2.3.4"], "mx": ["mail.example.com"], ...}
        """
        dns_records: Dict[str, Any] = self.memory.context.get("dns_records") or {}
        if not isinstance(dns_records, dict):
            dns_records = {}

        for rec in records:
            if not isinstance(rec, dict):
                continue
            name = str(rec.get("host", "")).lower().rstrip(".")
            if not name:
                continue

            entry = dns_records.setdefault(name, {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": [], "subdomains": []})

            for addr in (rec.get("a") or []):
                if addr and addr not in entry["A"]:
                    entry["A"].append(addr)
            for addr in (rec.get("aaaa") or []):
                if addr and addr not in entry["AAAA"]:
                    entry["AAAA"].append(addr)
            for mx in (rec.get("mx") or []):
                if mx and mx not in entry["MX"]:
                    entry["MX"].append(mx)
            for ns in (rec.get("ns") or []):
                if ns and ns not in entry["NS"]:
                    entry["NS"].append(ns)
            for txt in (rec.get("txt") or []):
                if txt and txt not in entry["TXT"]:
                    entry["TXT"].append(txt)
            for cname in (rec.get("cname") or []):
                if cname and cname not in entry["CNAME"]:
                    entry["CNAME"].append(cname)

        self.memory.context["dns_records"] = dns_records

    def _export_dns_csv(self, output_dir: Path) -> Optional[Path]:
        """
        Export a DNS-axis CSV with columns:
            domain, a_records, aaaa_records, cname, mx, ns, txt, subdomains

        Populated from dnsrecon/dnsx records stored in context['dns_records'].
        """
        import csv

        dns_records: Dict[str, Any] = self.memory.context.get("dns_records") or {}
        if not dns_records:
            return None

        csv_path = output_dir / f"dns_{self.memory.session_id}.csv"
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["domain", "a_records", "aaaa_records", "cname", "mx", "ns", "txt", "subdomains"])
            for domain in sorted(dns_records.keys()):
                entry = dns_records[domain]
                if not isinstance(entry, dict):
                    continue
                writer.writerow([
                    domain,
                    ";".join(sorted(entry.get("A", []))),
                    ";".join(sorted(entry.get("AAAA", []))),
                    ";".join(sorted(entry.get("CNAME", []))),
                    ";".join(sorted(entry.get("MX", []))),
                    ";".join(sorted(entry.get("NS", []))),
                    ";".join(sorted(entry.get("TXT", []))),
                    ";".join(sorted(entry.get("subdomains", []))),
                ])
        return csv_path

    def _record_step_duration(self, started_at: datetime):
        """Track step duration for rough ETA logging."""
        elapsed = (datetime.now() - started_at).total_seconds()
        self._step_durations.append(elapsed)
        # Keep the last 10 samples for rolling average
        if len(self._step_durations) > 10:
            self._step_durations.pop(0)

    def _log_progress(self, prefix: str, total: int, current: int):
        """Log a simple progress bar and ETA."""
        current_display = current + 1  # zero-based internal counter
        bar_width = 20
        pct = min(max(current / max(total, 1), 0), 1.0)
        filled = int(bar_width * pct)
        bar = "#" * filled + "-" * (bar_width - filled)

        avg = sum(self._step_durations) / len(self._step_durations) if self._step_durations else None
        remaining = max(total - current, 0)
        eta = f"ETA ~{int(avg * remaining)}s" if avg else "ETA n/a"

        self.logger.info(f"{prefix} Progress [{bar}] {current_display}/{total} ({int(pct*100)}%) {eta}")
