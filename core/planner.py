"""
Strategic Planner Agent
Decides next steps in the penetration testing workflow
"""

import json
import re
from typing import Dict, Any
from core.agent import BaseAgent
from utils.skill_loader import SkillLoader


class PlannerAgent(BaseAgent):
    """Strategic planner that decides next pentest steps"""
    
    def __init__(self, config, llm_client, memory):
        super().__init__("Planner", config, llm_client, memory)

        # Load planner prompts dynamically based on config
        self.skill_loader = SkillLoader(config)
        self.prompts = self.skill_loader.load_skill_prompts("planner")
    
    async def execute(self, **kwargs) -> Dict[str, Any]:
        """Decide the next action in the penetration test"""
        return await self.decide_next_action()
    
    async def decide_next_action(self) -> Dict[str, Any]:
        """
        Analyze current state and decide next action
        
        Returns:
            Dict with next_action, parameters, reasoning
        """
        # Build context
        context = self.memory.get_context_for_ai()
        findings_summary = self._format_findings()
        available_actions = self._get_available_actions()
        
        try:
            prompt = self.prompts["PLANNER_DECISION_PROMPT"].format(
                phase=self.memory.current_phase,
                target=self.memory.target,
                completed_actions="\n".join(f"- {a}" for a in self.memory.completed_actions) or "None",
                findings=findings_summary,
                available_actions=available_actions
            )
        except Exception as e:
            # Fail closed: avoid crashing autonomous runs due to prompt-template formatting issues.
            self.logger.error(f"[Planner] Failed to format decision prompt: {e}")
            decision = self._fallback_decision(available_actions)
            decision["reasoning"] = "Fallback action selected due to prompt formatting error."
            self.log_action("Decision", decision.get("next_action", "Unknown"))
            return decision
        
        # Get AI decision
        result = await self.think(prompt, self.prompts["PLANNER_SYSTEM_PROMPT"])
        
        # Parse the response (with a retry if the model did not follow the schema)
        decision = self._parse_decision(result["response"])
        decision["reasoning"] = result.get("reasoning", "")

        if decision.get("next_action") == "unknown":
            allowed = self._extract_action_tokens(available_actions)
            retry_prompt = (
                "Return ONLY a single JSON object with keys next_action, parameters, expected_outcome.\n"
                f"Allowed next_action values: {', '.join(allowed)}\n\n"
                "Previous response (do not repeat it; just fix the format):\n"
                f"{result.get('response', '')}\n"
            )
            retry = await self.think(retry_prompt, self.prompts["PLANNER_SYSTEM_PROMPT"])
            decision = self._parse_decision(retry.get("response", ""))
            decision["reasoning"] = retry.get("reasoning", "") or decision.get("reasoning", "")

        if decision.get("next_action") == "unknown":
            decision = self._fallback_decision(available_actions)
            decision["reasoning"] = decision.get("reasoning", "") or "Fallback action selected due to unparseable Planner output."
        
        self.log_action("Decision", decision.get("next_action", "Unknown"))
        
        return decision
    
    async def analyze_results(self) -> Dict[str, str]:
        """Provide strategic analysis of pentest results"""
        findings_summary = self._format_findings()
        tools_executed = "\n".join(
            f"- {t.tool} on {t.target}" for t in self.memory.tool_executions
        )
        
        prompt = self.prompts["PLANNER_ANALYSIS_PROMPT"].format(
            target=self.memory.target,
            phase=self.memory.current_phase,
            findings_summary=findings_summary,
            tools_executed=tools_executed or "None"
        )

        result = await self.think(prompt, self.prompts["PLANNER_SYSTEM_PROMPT"])
        
        return result
    
    def _format_findings(self) -> str:
        """Format findings for AI consumption"""
        if not self.memory.findings:
            return "No findings yet"
        
        findings_by_severity = {}
        for finding in self.memory.findings:
            if not finding.false_positive:
                severity = finding.severity.lower()
                if severity not in findings_by_severity:
                    findings_by_severity[severity] = []
                findings_by_severity[severity].append(finding.title)
        
        formatted = []
        for severity in ["critical", "high", "medium", "low", "info"]:
            if severity in findings_by_severity:
                formatted.append(f"\n{severity.upper()}:")
                for title in findings_by_severity[severity]:
                    formatted.append(f"  - {title}")
        
        return "\n".join(formatted)
    
    def _get_available_actions(self) -> str:
        """Get list of available actions based on current phase"""
        from utils.helpers import is_valid_ip, extract_domain_from_url

        all_actions = {
            "reconnaissance": [
                "subdomain_enumeration - Discover subdomains (domains only)",
                "dns_enumeration - Gather DNS records (domains only)",
                "technology_detection - Identify web technologies",
                "port_scanning - Scan for open ports"
            ],
            "scanning": [
                "service_detection - Identify services on open ports",
                "vulnerability_scanning - Run vulnerability scanners",
                "web_probing - Probe web services",
                "ssl_analysis - Analyze SSL/TLS configuration"
            ],
            "analysis": [
                "correlate_findings - Combine data from multiple tools",
                "risk_assessment - Analyze security posture",
                "false_positive_filter - Filter out false positives",
                "prioritize_vulns - Rank vulnerabilities by risk"
            ],
            "reporting": [
                "generate_report - Create final report",
                "executive_summary - Write executive summary",
                "remediation_plan - Create fix recommendations"
            ]
        }
        
        phase = self.memory.current_phase
        actions = all_actions.get(phase, all_actions["reconnaissance"])

        # If the target is an IP (including URL-with-IP), remove domain-only actions and
        # prefer IP enrichment instead.
        host = extract_domain_from_url(self.memory.target) or self.memory.target
        if host and is_valid_ip(host):
            actions = [
                a for a in actions
                if not a.startswith("subdomain_enumeration")
                and not a.startswith("dns_enumeration")
            ]
            # Ensure ip_enrichment is present in recon; other phases can still keep their actions.
            if phase == "reconnaissance" and not any(a.startswith("ip_enrichment") for a in actions):
                actions.insert(0, "ip_enrichment - Reverse DNS & TLS cert names (IP targets)")
        
        return "\n".join(f"- {action}" for action in actions)

    def _extract_action_tokens(self, available_actions: str) -> list[str]:
        tokens: list[str] = []
        for line in available_actions.splitlines():
            line = line.strip()
            if not line.startswith("-"):
                continue
            item = line.lstrip("-").strip()
            token = item.split(" - ", 1)[0].strip()
            if token:
                tokens.append(token)
        return tokens

    def _fallback_decision(self, available_actions: str) -> Dict[str, Any]:
        tokens = self._extract_action_tokens(available_actions)
        completed = set(self.memory.completed_actions or [])

        # Prefer an action we haven't done yet; otherwise just take the first available token.
        next_action = ""
        for t in tokens:
            if t not in completed:
                next_action = t
                break
        if not next_action and tokens:
            next_action = tokens[0]

        if not next_action:
            next_action = "technology_detection"

        return {
            "next_action": next_action,
            "parameters": "",
            "expected_outcome": "",
        }

    def _parse_decision(self, response: str) -> Dict[str, Any]:
        """Parse AI response into structured decision"""
        decision = {
            "next_action": "unknown",
            "parameters": {},
            "expected_outcome": ""
        }

        if not response:
            return decision

        # Prefer strict JSON parsing when available.
        try:
            # Handle common "extra text" by extracting the first JSON object.
            start = response.find("{")
            end = response.rfind("}")
            if start != -1 and end != -1 and end > start:
                payload = response[start : end + 1]
                parsed = json.loads(payload)
                if isinstance(parsed, dict):
                    if "next_action" in parsed:
                        decision["next_action"] = str(parsed.get("next_action", "")).strip()
                    if "parameters" in parsed:
                        decision["parameters"] = parsed.get("parameters", "")
                    if "expected_outcome" in parsed:
                        decision["expected_outcome"] = str(parsed.get("expected_outcome", "")).strip()
        except Exception:
            pass

        # Fall back to tolerant label parsing (supports markdown like '**NEXT_ACTION**:')
        if decision["next_action"] == "unknown":
            def _extract(label: str) -> str:
                pattern = rf"(?:^|\n)\s*(?:\d+[\.\)]\s*)?\**\s*{label}\s*\**\s*:\s*(.+)"
                m = re.search(pattern, response, re.IGNORECASE)
                if not m:
                    return ""
                value = m.group(1).strip()
                # Stop at the next labeled section if present
                value = re.split(r"\n\s*(?:\d+[\.\)]\s*)?\**\s*(?:REASONING|NEXT_ACTION|PARAMETERS|EXPECTED_OUTCOME)\s*\**\s*:", value, flags=re.IGNORECASE)[0].strip()
                return value

            decision["next_action"] = _extract("NEXT_ACTION") or decision["next_action"]
            decision["parameters"] = _extract("PARAMETERS") or decision["parameters"]
            decision["expected_outcome"] = _extract("EXPECTED_OUTCOME") or decision["expected_outcome"]
        
        # Simple parsing of the AI response
        if decision["next_action"] == "unknown" and "NEXT_ACTION:" in response:
            start = response.find("NEXT_ACTION:") + len("NEXT_ACTION:")
            end = response.find("PARAMETERS:", start) if "PARAMETERS:" in response else len(response)
            decision["next_action"] = response[start:end].strip()
        
        if not decision["parameters"] and "PARAMETERS:" in response:
            start = response.find("PARAMETERS:") + len("PARAMETERS:")
            end = response.find("EXPECTED_OUTCOME:", start) if "EXPECTED_OUTCOME:" in response else len(response)
            decision["parameters"] = response[start:end].strip()
        
        if not decision["expected_outcome"] and "EXPECTED_OUTCOME:" in response:
            start = response.find("EXPECTED_OUTCOME:") + len("EXPECTED_OUTCOME:")
            decision["expected_outcome"] = response[start:].strip()
        
        # Normalize common variants and extract known action tokens
        aliases = {
            "automated_web_scanning": "web_probing",
            "exploitation": "vulnerability_scanning",
            "web_scanning": "web_probing",
            "report": "generate_report",
            "port_scan": "port_scanning",
            "port_scans": "port_scanning",
            "portscanner": "port_scanning",
            "dns_scan": "dns_enumeration",
            "subdomain_scan": "subdomain_enumeration",
            "vuln_scan": "vulnerability_scanning",
            "vuln_scanning": "vulnerability_scanning",
            "web_scan": "web_probing",
            "tech_detection": "technology_detection",
        }

        valid_actions = {
            "subdomain_enumeration",
            "dns_enumeration",
            "ip_enrichment",
            "technology_detection",
            "port_scanning",
            "service_detection",
            "vulnerability_scanning",
            "web_probing",
            "ssl_analysis",
            "correlate_findings",
            "risk_assessment",
            "false_positive_filter",
            "prioritize_vulns",
            "generate_report",
            "executive_summary",
            "remediation_plan",
            "fuzzing",
            "analysis",
        }

        action_clean = decision["next_action"].strip().lower()
        # Strip common markdown formatting without breaking underscore-delimited action names.
        action_clean = re.sub(r"[*`]+", "", action_clean).strip().strip("_").strip()
        # Normalize common natural-language variants like "Web Probing" -> "web_probing".
        action_clean = re.sub(r"[\s\-]+", "_", action_clean)
        action_clean = re.sub(r"[^a-z0-9_]+", "", action_clean)
        action_clean = re.sub(r"_+", "_", action_clean).strip("_")

        # Extract known action if embedded in numbering/formatting
        if action_clean and action_clean not in valid_actions:
            pattern = "|".join(sorted(valid_actions, key=len, reverse=True))
            match = re.search(pattern, action_clean)
            if match:
                action_clean = match.group(0)

        # Apply aliases on cleaned action
        if action_clean in aliases:
            action_clean = aliases[action_clean]
        else:
            for key, value in aliases.items():
                if key in action_clean:
                    action_clean = value
                    break

        decision["next_action"] = action_clean

        # Validate next_action against known actions; if invalid, mark unknown
        if decision["next_action"] not in valid_actions:
            decision["next_action"] = "unknown"
            decision["expected_outcome"] = ""
            decision["parameters"] = {}

        return decision
