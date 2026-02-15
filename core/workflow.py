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

        except Exception as e:
            self.logger.error(f"Whitebox analysis failed: {e}")
            self.logger.warning("Continuing with blackbox testing only")

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

            # Load full workflow config for whitebox settings
            workflow_config = self._load_workflow_config(workflow_name)

            # Run whitebox analysis phase if source code provided
            if self.source_path and workflow_config:
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
            # Run whitebox analysis if source code provided
            if self.source_path:
                workflow_config = self._load_workflow_config("autonomous")
                if workflow_config:
                    await self._run_whitebox_analysis(workflow_config)

                    # Inject whitebox findings into AI context
                    if self.whitebox_findings:
                        self.logger.info("Feeding whitebox findings to autonomous AI agent...")
                        self.memory.metadata["whitebox_context_injected"] = True

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

        attempts = 3
        timeout_s = 10.0
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
                await asyncio.sleep(1.5)

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
        if tool_name == "kiterunner":
            args = tool_kwargs.get("args") if isinstance(tool_kwargs, dict) else None
            wordlist = tool_kwargs.get("wordlist") if isinstance(tool_kwargs, dict) else None
            if not (args or wordlist or tool_cfg.get("args") or tool_cfg.get("wordlist")):
                self.logger.info(f"Skipping {step_name}: kiterunner args/wordlist not configured")
                return None
        if tool_name == "jwt_tool":
            args = tool_kwargs.get("args") if isinstance(tool_kwargs, dict) else None
            token = tool_kwargs.get("token") if isinstance(tool_kwargs, dict) else None
            if not (args or token or tool_cfg.get("args") or tool_cfg.get("token")):
                self.logger.info(f"Skipping {step_name}: jwt_tool token/args not configured")
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
                urls = self._get_discovered_urls()
                if urls:
                    url_file = self._write_urls_file(
                        urls,
                        name=f"zap_seed_{self.memory.session_id}.txt",
                    )
                    tool_kwargs = dict(tool_kwargs or {})
                    tool_kwargs.setdefault("seed_urls_file", str(url_file))

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

        # If we have discovered URLs, run URL-first scanners using the URL list.
        # NOTE: only enable for tools that accept a `from_file` input in our wrappers.
        if tool_name in {"katana", "nuclei", "dalfox", "subjs", "xnlinkfinder", "httpx"}:
            urls = self._get_discovered_urls()
            if urls and "from_file" not in tool_kwargs:
                url_file = self._write_urls_file(urls, name=f"{tool_name}_{self.memory.session_id}.txt")
                tool_kwargs = dict(tool_kwargs)
                tool_kwargs["from_file"] = str(url_file)

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

        if result.get("success"):
            parsed = result.get("parsed") if isinstance(result.get("parsed"), dict) else {}

            # Persist high-signal context from discovery tools.
            if tool_name in {"httpx", "katana"}:
                urls = parsed.get("urls") or []
                if isinstance(urls, list) and urls:
                    self.memory.update_context("urls", urls)
                    self.memory.update_context("discovered_assets", urls)

            if tool_name == "nmap":
                open_ports = parsed.get("open_ports") or []
                services = parsed.get("services") or []
                hosts_up = parsed.get("hosts_up") or []
                host_ports = parsed.get("host_ports") or {}
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
            if tool_name == "kiterunner":
                urls = parsed.get("urls") or []
                paths = parsed.get("paths") or []
                combined = []
                if isinstance(urls, list):
                    combined.extend([u for u in urls if u])
                if paths:
                    try:
                        from urllib.parse import urlparse
                        parsed_target = urlparse(self.target if "://" in self.target else f"https://{self.target}")
                        base = f"{parsed_target.scheme}://{parsed_target.netloc}"
                        combined.extend([f"{base}{p}" for p in paths if str(p).startswith("/")])
                    except Exception:
                        pass
                if combined:
                    self.memory.update_context("urls", combined)
                    self.memory.update_context("discovered_assets", combined)
            # jsparser removed - use linkfinder/xnlinkfinder instead
            if tool_name in ("linkfinder", "xnlinkfinder"):
                urls = parsed.get("urls") or []
                scripts = parsed.get("scripts") or []
                if isinstance(urls, list) and urls:
                    self.memory.update_context("urls", urls)
                    self.memory.update_context("discovered_assets", urls)
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

    def _write_urls_file(self, urls: List[str], name: str) -> Path:
        output_dir = Path(self.config.get("output", {}).get("save_path", "./reports"))
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / name
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(urls) + "\n")
        return path

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
    
    def _load_workflow_config(self, workflow_name: str) -> Dict[str, Any]:
        """Load full workflow configuration from YAML file"""
        repo_root = Path(__file__).resolve().parent.parent
        workflows_dir = repo_root / "workflows"

        for candidate in {workflow_name, workflow_name.replace("-", "_")}:
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
        import platform
        is_macos = platform.system().lower() == "darwin"
        
        # Use unified tooling across platforms
        web_probing_tool = "httpx"
        crawl_tool = "katana"
        
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
                {"name": "crawl", "type": "tool", "tool": crawl_tool},
                {"name": "vhost_enumeration", "type": "tool", "tool": "ffuf", "parameters": {"append_fuzz": False}},
                {"name": "api_route_discovery", "type": "tool", "tool": "kiterunner"},
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
        
        # Simple heuristic: advance after certain number of steps
        if self.current_step % 5 == 0 and current_idx < len(phases) - 1:
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

        # Export helper files for manual testing (URLs, payloads/commands)
        urls = self._extract_urls()
        if urls:
            urls_file = output_dir / f"urls_{self.memory.session_id}.txt"
            with open(urls_file, "w", encoding="utf-8") as f:
                f.write("\n".join(sorted(set(urls))))
            self.logger.info(f"Exported URLs for manual testing: {urls_file}")

        commands = [te.command for te in self.memory.tool_executions if te.command]
        if commands:
            payloads_file = output_dir / f"payloads_{self.memory.session_id}.txt"
            with open(payloads_file, "w", encoding="utf-8") as f:
                f.write("\n".join(commands))
            self.logger.info(f"Exported tool commands: {payloads_file}")

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
