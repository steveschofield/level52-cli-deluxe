"""
Analyst Agent
Interprets scan results and identifies security vulnerabilities
"""

import re
import json
import html
from typing import Dict, Any, List, Optional
from datetime import datetime
from core.agent import BaseAgent
from core.memory import Finding
from utils.skill_loader import SkillLoader
from utils.standards import infer_cwe_owasp, normalize_owasp_labels
from utils.cvss_handler import CVSSHandler
from utils.vulnerability_taxonomy import VulnerabilityTaxonomy
from utils.confidence_scorer import ConfidenceScorer, ConfidenceLevel


class AnalystAgent(BaseAgent):
    """Agent that analyzes scan results and extracts security findings"""
    
    def __init__(self, config, llm_client, memory):
        super().__init__("Analyst", config, llm_client, memory)
        self._taxonomy = None
        self._cvss_handler = None
        self._confidence_scorer = None

        # Load analyst prompts dynamically based on config
        self.skill_loader = SkillLoader(config)
        self.prompts = self.skill_loader.load_skill_prompts("analyst")
        self.logger.debug(f"[Analyst] Loaded {len(self.prompts)} prompts")
    
    async def execute(self, tool_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze tool output and extract findings
        
        Args:
            tool_result: Results from a tool execution
        
        Returns:
            Dict with extracted findings and analysis
        """
        return await self.interpret_output(
            tool=tool_result["tool"],
            target=tool_result.get("target", "unknown"),
            command=tool_result.get("command", ""),
            output=tool_result.get("raw_output", "")
        )
    
    async def interpret_output(
        self,
        tool: str,
        target: str,
        command: str,
        output: str
    ) -> Dict[str, Any]:
        """
        Interpret tool output and extract security findings
        
        Returns:
            Dict with findings, summary, and analysis
        """
        # Short-circuit on empty/error-only output
        if not output.strip() or "Output file format specified without a name" in output:
            msg = "No actionable output from tool; skipping findings."
            self.log_action("AnalysisComplete", msg)
            return {
                "findings": [],
                "summary": msg,
                "reasoning": msg,
                "tool": tool
            }

        # Reduce prompt bloat for Nmap XML by extracting only high-signal elements.
        if tool == "nmap" and output.lstrip().startswith("<?xml") and "<nmaprun" in output:
            hostscript_findings = self._extract_nmap_hostscript_findings(output, target)
            output = self._condense_nmap_xml(output)
        else:
            hostscript_findings = []

        # Reduce prompt bloat for Nuclei JSONL by stripping huge fields (request/response/template-encoded)
        # and keeping only high-signal, evidence-friendly elements.
        if tool == "nuclei":
            output = self._condense_nuclei_jsonl(output)

        # Special handling for ZAP: smart filter alerts before AI analysis
        if tool == "zap":
            try:
                parsed = json.loads(output, strict=False) if output else {}
                if parsed.get("alerts"):
                    original_count = len(parsed["alerts"])
                    parsed["alerts"] = self._smart_filter_zap_alerts(parsed["alerts"])
                    filtered_count = len(parsed["alerts"])
                    self.logger.info(f"ZAP smart filter: {original_count} → {filtered_count} alerts")
                    output = json.dumps(parsed, indent=2)
            except Exception as e:
                self.logger.warning(f"Failed to smart filter ZAP alerts: {e}")

        # Truncate very long outputs (configurable)
        ai_cfg = (self.config or {}).get("ai", {}) or {}
        max_chars = ai_cfg.get("max_tool_output_chars", 20000)
        try:
            max_chars = int(max_chars)
        except Exception:
            max_chars = 20000
        if max_chars > 0 and len(output) > max_chars:
            output = output[:max_chars] + "\n... (truncated)"
        
        prompt = self.prompts["ANALYST_INTERPRET_PROMPT"].format(
            tool=tool,
            target=target,
            command=command,
            output=output
        )

        try:
            result = await self.think(prompt, self.prompts["ANALYST_SYSTEM_PROMPT"])
        except Exception as e:
            msg = f"Analysis skipped due to LLM backend error: {e}"
            self.logger.warning(f"[Analyst] {msg}")
            self.log_action("AnalysisComplete", msg)
            return {
                "findings": [],
                "summary": msg,
                "reasoning": msg,
                "tool": tool
            }
        
        # Parse findings from AI response
        findings = self._parse_findings(result["response"], tool, target)

        # Drop findings whose evidence isn't in the raw output (reduces hallucinations)
        filtered = []
        output_lower = output.lower()
        low_signal_tools = {"nmap", "whatweb", "httpx"}
        for f in findings:
            if not f.evidence:
                continue

            evidence = f.evidence.strip()
            candidates = [
                evidence,
                evidence.strip("`"),
                evidence.strip("\"'"),
                evidence.strip("`\"'"),
            ]

            def _grounded(ev: str) -> bool:
                """Return True if ev (or a meaningful chunk of it) appears in output."""
                ev = ev.strip()
                if not ev:
                    return False
                if ev.lower() in output_lower:
                    return True
                # LLMs sometimes reformat JSON as standalone objects — try matching
                # the longest contiguous alphanumeric+punctuation run ≥40 chars.
                words = re.split(r'[\s{}\[\]]+', ev)
                chunks = [w.strip('",') for w in words if len(w.strip('",')) >= 40]
                return any(c.lower() in output_lower for c in chunks)

            if not any(_grounded(c) for c in candidates):
                continue

            # High/medium severity from low-signal tools is often speculative; downgrade unless we have a strong signature.
            if f.tool in low_signal_tools and f.severity in {"critical", "high", "medium"}:
                has_cve = bool(re.search(r"\bCVE-\d{4}-\d+\b", output, re.IGNORECASE) or re.search(r"\bCVE-\d{4}-\d+\b", evidence, re.IGNORECASE))
                has_strong_flag = any(token in evidence.lower() for token in ["cve", "vulnerab", "exploit", "sqli", "sql injection", "rce", "ssrf", "lfi", "rfi"])
                if not (has_cve or has_strong_flag):
                    f.severity = "low"

            filtered.append(f)
        findings = filtered

        findings = self._postprocess_findings(findings, tool=tool, output=output)

        # Merge in deterministic hostscript findings (e.g., smb-vuln-*), avoiding duplicates.
        if hostscript_findings:
            hostscript_findings = self._postprocess_findings(hostscript_findings, tool=tool, output=output)
            existing_keys = {
                (f.title.lower().strip(), (f.evidence or "").lower().strip()) for f in findings
            }
            for hf in hostscript_findings:
                key = (hf.title.lower().strip(), (hf.evidence or "").lower().strip())
                if key in existing_keys:
                    continue
                findings.append(hf)
                existing_keys.add(key)

        findings = self._enrich_findings_standards(findings)

        # If still nothing with evidence, return empty
        if not findings:
            msg = "No evidence-backed findings; output deemed informational."
            self.log_action("AnalysisComplete", msg)
            return {
                "findings": [],
                "summary": msg,
                "reasoning": msg,
                "tool": tool
            }
        
        # Add findings to memory
        for finding in findings:
            self.memory.add_finding(finding)
        
        self.log_action("AnalysisComplete", f"Found {len(findings)} issues from {tool}")
        
        return {
            "findings": findings,
            "summary": result["response"],
            "reasoning": result["reasoning"],
            "tool": tool
        }

    def _condense_nmap_xml(self, xml_text: str) -> str:
        """
        Condense Nmap XML into a smaller, evidence-friendly snippet set:
        - host status + hostnames
        - closed/open counts when present
        - open ports: <port>, <state>, <service>, and <script ...> start tags
        - hostscript: <script ...> start tags (vuln checks live here)

        Keeps verbatim XML tag strings so the model can cite evidence directly.
        """
        try:
            out: list[str] = []
            out.append("NMAP_XML_CONDENSED: true")

            # Host status line
            m = re.search(r"<status[^>]+/>", xml_text)
            if m:
                out.append(m.group(0))

            # Hostnames
            for hn in re.findall(r"<hostname[^>]+/>", xml_text):
                out.append(hn)

            # Extraports summary (closed/filtered counts)
            m = re.search(r"<extraports[^>]+>", xml_text)
            if m:
                out.append(m.group(0))

            # Extract open port blocks and then keep only high-signal tags from within each block.
            # NOTE: use regex word-boundaries like `\b` (not literal backslashes).
            port_blocks = re.findall(r"<port\b[\s\S]*?</port>", xml_text)
            open_blocks = [b for b in port_blocks if re.search(r'<state\b[^>]*state="open"', b)]

            out.append(f"OPEN_PORTS_FOUND: {len(open_blocks)}")

            for block in open_blocks:
                # Port header (includes protocol + portid)
                m = re.search(r"<port\b[^>]+>", block)
                if m:
                    out.append(m.group(0))

                m = re.search(r"<state\b[^>]+/>", block)
                if m:
                    out.append(m.group(0))

                m = re.search(r"<service\b[^>]+>", block)
                if m:
                    out.append(m.group(0))

                # Include script start tags (outputs like http-title, ssl-cert summary, etc.)
                scripts = re.findall(r"<script\b[^>]+>", block)
                # Keep at most a handful per port to prevent bloat.
                for s in scripts[:12]:
                    out.append(s)

                out.append("</port>")

            # Host-level scripts (e.g., smb-vuln-*).
            hostscript_match = re.search(r"<hostscript>([\s\S]*?)</hostscript>", xml_text)
            if hostscript_match:
                host_scripts = re.findall(r"<script\b[^>]+>", hostscript_match.group(1))
                out.append(f"HOSTSCRIPT_SCRIPTS_FOUND: {len(host_scripts)}")
                for s in host_scripts[:20]:
                    out.append(s)

            # Always include run summary if present
            m = re.search(r"<finished\\b[^>]+/>", xml_text)
            if m:
                out.append(m.group(0))

            return "\n".join(out)
        except Exception:
            return xml_text

    def _extract_nmap_hostscript_findings(self, xml_text: str, target: str) -> List[Finding]:
        """
        Extract high-signal vulnerabilities/weaknesses from Nmap <hostscript> output.
        This is deterministic to avoid LLM misses on critical findings.
        """
        findings: List[Finding] = []
        hostscript_match = re.search(r"<hostscript>([\s\S]*?)</hostscript>", xml_text)
        if not hostscript_match:
            return findings

        script_tags = re.findall(r"<script\b[^>]+>", hostscript_match.group(1))
        for tag in script_tags:
            id_match = re.search(r'id="([^"]+)"', tag)
            out_match = re.search(r'output="([^"]*)"', tag)
            if not id_match or not out_match:
                continue

            script_id = id_match.group(1)
            output_raw = html.unescape(out_match.group(1))
            output_text = output_raw.strip()
            if not output_text:
                continue

            lower = output_text.lower()
            if lower in {"false", "true"}:
                continue
            if "nt_status_access_denied" in lower or "access_denied" in lower:
                continue
            if "no reply from server" in lower and "vulnerable" not in lower:
                continue

            title = ""
            severity = ""
            description = ""
            evidence = ""

            if "vulnerable" in lower:
                # Try to extract the first meaningful title line after VULNERABLE:
                lines = [l.strip() for l in output_text.splitlines() if l.strip()]
                if lines and "vulnerable" in lines[0].lower() and len(lines) > 1:
                    title = lines[1]
                elif len(lines) >= 1:
                    title = lines[0]

                if not title:
                    title = f"Nmap hostscript {script_id} reported VULNERABLE"

                if "critical" in lower:
                    severity = "critical"
                else:
                    risk_match = re.search(r"risk factor:\\s*(\\w+)", output_text, re.IGNORECASE)
                    if risk_match:
                        sev = risk_match.group(1).lower()
                        if sev in {"high", "medium", "low"}:
                            severity = sev
                    if not severity:
                        severity = "high"

                description = output_text
                evidence = " | ".join(lines[:2]) if lines else output_text

            elif "message_signing: disabled" in lower:
                title = "SMB signing disabled"
                severity = "medium"
                description = output_text
                evidence = "message_signing: disabled"

            elif "message signing enabled but not required" in lower:
                title = "SMB signing not required (SMB2)"
                severity = "medium"
                description = output_text
                evidence = "Message signing enabled but not required"

            if not title or not severity:
                continue

            finding = Finding(
                id=f"nmap_hostscript_{script_id}_{datetime.now().timestamp()}",
                severity=severity,
                title=title[:200],
                description=description[:2000],
                evidence=evidence[:500],
                tool="nmap",
                target=target,
                timestamp=datetime.now().isoformat(),
            )
            findings.append(finding)

        return findings

    def _smart_filter_zap_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Intelligently filter ZAP alerts to focus on high-value findings.

        Filtering criteria:
        - High/Medium confidence alerts
        - Medium+ risk levels
        - Exclude common false positives (cache headers, info disclosure on static assets)
        - Prioritize alerts with CWE mappings
        - Prioritize alerts with evidence

        Returns filtered list maintaining diversity across vulnerability types.
        """
        if not alerts:
            return []

        scored_alerts = []

        for alert in alerts:
            score = 0
            risk = alert.get("risk", "").lower()
            confidence = alert.get("confidence", "").lower()
            cweid = alert.get("cweid", "")
            evidence = alert.get("evidence", "")
            name = alert.get("name", "").lower()

            # Risk level scoring
            if risk == "high":
                score += 50
            elif risk == "medium":
                score += 30
            elif risk == "low":
                score += 10
            else:  # informational
                score += 2

            # Confidence scoring
            if confidence == "high":
                score += 20
            elif confidence == "medium":
                score += 10

            # Has CWE mapping (more standardized)
            if cweid:
                score += 15

            # Has evidence
            if evidence and len(evidence.strip()) > 5:
                score += 10

            # Penalize common false positives
            if any(fp in name for fp in [
                "cache-control",
                "x-content-type-options",
                "x-frame-options",
                "content-security-policy"
            ]) and risk == "informational":
                score -= 20

            # Boost critical vulnerability types
            if any(vuln in name for vuln in [
                "sql injection",
                "xss",
                "command injection",
                "path traversal",
                "authentication",
                "csrf",
                "xxe"
            ]):
                score += 25

            scored_alerts.append((score, alert))

        # Sort by score descending
        scored_alerts.sort(key=lambda x: x[0], reverse=True)

        # Take top N diverse findings (max 50)
        max_findings = 50
        selected = []
        seen_types = set()

        for score, alert in scored_alerts:
            if score <= 0:  # Skip negatively scored items
                continue

            alert_type = alert.get("name", "unknown")

            # Take first instance of each type, then continue adding high scores
            if alert_type not in seen_types or len(selected) < 20:
                selected.append(alert)
                seen_types.add(alert_type)

            if len(selected) >= max_findings:
                break

        self.logger.info(f"Smart filter: {len(alerts)} ZAP alerts → {len(selected)} selected")
        return selected

    def _condense_nuclei_jsonl(self, text: str) -> str:
        """
        Condense Nuclei JSONL into a smaller, evidence-friendly snippet set:
        - summary counts by severity
        - up to N minimal JSON objects (1 per match), stripping very large fields

        Keeps verbatim JSON (minified) so the model can cite evidence directly.
        """
        text = (text or "").strip()
        if not text:
            return text

        # Nuclei can emit very large JSON fields (e.g., template-encoded, request, response).
        # We keep only high-signal keys needed for triage and evidence.
        drop_keys = {
            "template-encoded",
            "request",
            "response",
            "curl-command",
            "raw-request",
            "raw-response",
            "matcher-status",
        }

        lines = [ln for ln in text.splitlines() if ln.strip()]
        # Some environments may produce a single giant JSON object without newlines.
        if len(lines) == 1 and lines[0].lstrip().startswith("{") and lines[0].rstrip().endswith("}"):
            candidates = [lines[0]]
        else:
            candidates = lines

        items: list[dict[str, Any]] = []
        for ln in candidates:
            if not ln.lstrip().startswith("{"):
                continue
            try:
                obj = json.loads(ln)
            except Exception:
                continue

            minimal: dict[str, Any] = {}
            for k, v in obj.items():
                if k in drop_keys:
                    continue
                minimal[k] = v

            # Keep a stable, compact subset if present.
            info = minimal.get("info") if isinstance(minimal.get("info"), dict) else {}
            slim = {
                "template-id": minimal.get("template-id") or minimal.get("templateID") or minimal.get("template"),
                "name": info.get("name"),
                "severity": (info.get("severity") or "").lower() if isinstance(info.get("severity"), str) else info.get("severity"),
                "type": minimal.get("type"),
                "matched-at": minimal.get("matched-at") or minimal.get("matched") or minimal.get("url"),
                "host": minimal.get("host") or minimal.get("ip"),
                "timestamp": minimal.get("timestamp"),
                "reference": info.get("reference"),
                "tags": info.get("tags"),
            }
            # Remove empty fields
            slim = {k: v for k, v in slim.items() if v not in (None, "", [], {})}
            items.append(slim)

        if not items:
            return text

        by_sev: dict[str, int] = {}
        for it in items:
            sev = it.get("severity") or "unknown"
            if isinstance(sev, str):
                sev = sev.lower()
            by_sev[str(sev)] = by_sev.get(str(sev), 0) + 1

        # Keep the first N for evidence; for larger scans, this prevents prompt bloat.
        max_items = 50
        kept = items[:max_items]

        out: list[str] = []
        out.append("NUCLEI_JSONL_CONDENSED: true")
        out.append(f"NUCLEI_MATCHES: {len(items)}")
        out.append("NUCLEI_BY_SEVERITY: " + json.dumps(by_sev, sort_keys=True))
        out.append("NUCLEI_RESULTS_JSON:")
        for it in kept:
            out.append(json.dumps(it, separators=(",", ":"), ensure_ascii=False))
        if len(items) > max_items:
            out.append(f"... ({len(items) - max_items} more results omitted)")
        return "\n".join(out)

    def _postprocess_findings(self, findings: List[Finding], tool: str, output: str) -> List[Finding]:
        """
        Apply conservative normalization rules so we don't overstate impact from low-signal inputs.
        """
        filtered: List[Finding] = []
        for f in findings:
            ev = (f.evidence or "").lower()
            text = " ".join([f.title or "", f.description or "", f.evidence or ""]).lower()

            if self._is_header_presence_only(text):
                continue
            if self._is_service_unavailable_only(text):
                continue

            # Header-only observations are usually informational without endpoint context.
            if "access-control-allow-origin" in ev and "*" in ev:
                if f.severity in {"critical", "high", "medium"}:
                    f.severity = "low"
                if not f.title:
                    f.title = "Permissive CORS policy"

            if "feature-policy" in ev or "permissions-policy" in ev:
                f.severity = "info"
                if not f.title:
                    f.title = "Browser feature policy header present"

            # "Service exposed" is generally informational unless coupled with auth bypass, CVE, etc.
            if tool in {"nmap", "httpx"} and ("port" in ev or "scheme" in ev) and f.severity in {"critical", "high", "medium"}:
                if not re.search(r"\bCVE-\d{4}-\d+\b", output, re.IGNORECASE):
                    f.severity = "info"

            filtered.append(f)

        return filtered

    def _is_header_presence_only(self, text: str) -> bool:
        if "header" not in text and "headers" not in text:
            return False

        presence_markers = (
            "header present",
            "headers present",
            "header detected",
            "headers detected",
            "header set",
            "headers set",
            "header found",
            "headers found",
        )
        if not any(marker in text for marker in presence_markers):
            return False

        insecure_markers = (
            "missing",
            "absent",
            "not set",
            "not present",
            "misconfig",
            "insecure",
            "unsafe",
            "permissive",
            "wildcard",
            "weak",
            "deprecated",
            "expose",
            "exposed",
            "leak",
            "disclos",
            "allows",
            "allow-all",
            "bypass",
            "vulnerab",
            "cve-",
        )
        return not any(marker in text for marker in insecure_markers)

    def _is_service_unavailable_only(self, text: str) -> bool:
        unavailable_markers = (
            "not running",
            "not reachable",
            "not responding",
            "connection refused",
            "failed to connect",
            "timed out",
            "timeout",
            "no route to host",
            "host down",
            "service unavailable",
            "endpoint not found",
        )
        if any(marker in text for marker in unavailable_markers):
            if self._has_explicit_risk_markers(text):
                return False
            return True

        not_found_markers = ("404", "not found")
        if any(marker in text for marker in not_found_markers):
            if any(term in text for term in ("endpoint", "service", "graphql", "api", "port")):
                return not self._has_explicit_risk_markers(text)

        return False

    def _has_explicit_risk_markers(self, text: str) -> bool:
        risk_markers = (
            "unauth",
            "authentication bypass",
            "authorization bypass",
            "bypass",
            "exposed",
            "misconfig",
            "vulnerab",
            "cve-",
            "exploit",
            "rce",
            "sqli",
            "xss",
            "ssrf",
            "lfi",
            "rfi",
            "csrf",
        )
        return any(marker in text for marker in risk_markers)

    def _enrich_findings_standards(self, findings: List[Finding]) -> List[Finding]:
        """
        Populate CVSS/CWE/OWASP metadata when missing.
        """
        taxonomy = self._get_taxonomy()
        cvss_handler = self._get_cvss_handler()
        confidence_scorer = self._get_confidence_scorer()
        reporting_cfg = (self.config or {}).get("reporting", {}) or {}
        filter_low_confidence = bool(reporting_cfg.get("filter_low_confidence", False))

        for f in findings:
            text = " ".join([f.title or "", f.description or "", f.evidence or ""]).strip()

            # Normalize OWASP labels if provided.
            if f.owasp_categories:
                f.owasp_categories = normalize_owasp_labels(f.owasp_categories)

            # Infer CWE/OWASP when absent.
            if text and (not f.cwe_ids or not f.owasp_categories):
                taxonomy.enrich_finding(f)
                inferred_cwe, inferred_owasp = infer_cwe_owasp(text)
                for cwe in inferred_cwe:
                    if cwe not in f.cwe_ids:
                        f.cwe_ids.append(cwe)
                for cat in inferred_owasp:
                    if cat not in f.owasp_categories:
                        f.owasp_categories.append(cat)

            # Derive CVSS score from vector if present.
            if f.cvss_score is None and f.cvss_vector:
                cvss_score = cvss_handler.calculate_score_from_vector(f.cvss_vector)
                if cvss_score:
                    f.cvss_score = cvss_score.base_score
                    f.cvss_score_source = "calculated"
                    f.cvss_version = cvss_score.version.value

            # Estimate CVSS if still missing.
            if f.cvss_score is None:
                estimated = cvss_handler.estimate_score(f.severity, f.title, f.description)
                f.cvss_score = estimated.base_score
                f.cvss_score_source = "estimated"
                f.cvss_version = estimated.version.value

            if not f.cvss_score_source or f.cvss_score_source == "none":
                f.cvss_score_source = "provided"

            if confidence_scorer:
                confidence_scorer.enrich_finding_with_confidence(f)
                if filter_low_confidence and not confidence_scorer.verbose:
                    level = ConfidenceLevel.from_string(getattr(f, "confidence", "unknown"))
                    if level < confidence_scorer.min_confidence:
                        f.false_positive = True

        return findings

    def _get_taxonomy(self) -> VulnerabilityTaxonomy:
        if self._taxonomy is None:
            self._taxonomy = VulnerabilityTaxonomy(self.config)
        return self._taxonomy

    def _get_cvss_handler(self) -> CVSSHandler:
        if self._cvss_handler is None:
            self._cvss_handler = CVSSHandler(self.config)
        return self._cvss_handler

    def _get_confidence_scorer(self) -> ConfidenceScorer | None:
        reporting_cfg = (self.config or {}).get("reporting", {}) or {}
        if reporting_cfg.get("enable_confidence_scoring", True):
            if self._confidence_scorer is None:
                self._confidence_scorer = ConfidenceScorer(self.config)
            return self._confidence_scorer
        return None
    
    async def correlate_findings(self) -> Dict[str, Any]:
        """
        Correlate findings from multiple tools to build attack chains
        
        Returns:
            Strategic analysis of all findings
        """
        if not self.memory.findings:
            return {
                "correlations": [],
                "attack_chains": [],
                "priority_findings": []
            }
        
        # Format findings for AI
        tool_results = self._format_findings_for_correlation()
        
        prompt = self.prompts["ANALYST_CORRELATION_PROMPT"].format(
            target=self.memory.target,
            tool_results=tool_results
        )

        result = await self.think(prompt, self.prompts["ANALYST_SYSTEM_PROMPT"])
        
        return {
            "analysis": result["response"],
            "reasoning": result["reasoning"],
            "findings_count": len(self.memory.findings)
        }
    
    async def check_false_positive(self, finding: Finding) -> Dict[str, Any]:
        """
        Evaluate if a finding is likely a false positive
        
        Returns:
            Dict with confidence score and recommendation
        """
        # Get context
        context = self.memory.get_context_for_ai()
        
        prompt = self.prompts["ANALYST_FALSE_POSITIVE_PROMPT"].format(
            tool=finding.tool,
            severity=finding.severity,
            description=finding.description,
            evidence=finding.evidence[:500],  # Truncate
            context=context
        )

        result = await self.think(prompt, self.prompts["ANALYST_SYSTEM_PROMPT"])
        
        # Parse confidence from response
        confidence = self._extract_confidence(result["response"])
        
        return {
            "confidence": confidence,
            "analysis": result["response"],
            "reasoning": result["reasoning"],
            "recommendation": self._extract_recommendation(result["response"])
        }
    
    def _parse_findings(self, ai_response: str, tool: str, target: str) -> List[Finding]:
        """Parse findings from AI analysis response"""
        text = (ai_response or "").strip()
        if not text:
            return []

        # Try structured format first (preferred)
        if re.search(r"(?mi)^###\s*FINDING:\s*", text):
            return self._parse_findings_with_markers(text, tool, target)

        # Try fallback format for LLMs that don't follow instructions
        fallback_findings = self._parse_findings_fallback(text, tool, target)
        if fallback_findings:
            return fallback_findings

        # Fall back to legacy format
        return self._parse_findings_legacy(text, tool, target)

    def _new_finding(self, tool: str, target: str, severity: str, title: str) -> Finding:
        sev = (severity or "info").strip().lower()
        if sev not in {"critical", "high", "medium", "low", "info"}:
            sev = "info"

        return Finding(
            id=f"{tool}_{datetime.now().timestamp()}_{len(self.memory.findings)}",
            severity=sev,
            title=(title or f"{sev.title()} finding")[:200],
            description="",
            evidence="",
            tool=tool,
            target=target,
            timestamp=datetime.now().isoformat(),
        )

    def _extract_cvss(self, text: str) -> tuple[Optional[float], Optional[str]]:
        if not text:
            return None, None

        cvss_vector_re = re.compile(
            r"(CVSS:3\.[01]/)?AV:[A-Z]/AC:[A-Z]/PR:[A-Z]/UI:[A-Z]/S:[A-Z]/C:[A-Z]/I:[A-Z]/A:[A-Z]",
            re.IGNORECASE,
        )
        vector_match = cvss_vector_re.search(text)
        vector = vector_match.group(0).strip() if vector_match else None

        score_match = re.search(r"\b(10(?:\.0)?|[0-9](?:\.[0-9])?)\b", text)
        score: Optional[float] = None
        if score_match:
            try:
                candidate = float(score_match.group(1))
                if 0.0 <= candidate <= 10.0:
                    score = candidate
            except ValueError:
                score = None

        return score, vector

    def _parse_findings_with_markers(self, text: str, tool: str, target: str) -> List[Finding]:
        findings: List[Finding] = []

        field_re = re.compile(
            r"(?im)^(SEVERITY|EVIDENCE|DESCRIPTION|IMPACT|RECOMMENDATION|FIX|REMEDIATION|CVSS|CWE|OWASP|CVE|"
            r"EXPLOITABILITY|ATTACK VECTOR|DEFENSE BYPASS|MITRE ATT&CK|PREREQUISITES)\s*:\s*(.*)$"
        )

        def parse_fields(block: str) -> Dict[str, str]:
            matches = list(field_re.finditer(block))
            if not matches:
                return {}

            out: Dict[str, str] = {}
            for idx, match in enumerate(matches):
                raw_key = match.group(1).strip().upper()
                key = re.sub(r"\s+", "_", raw_key)
                end = matches[idx + 1].start() if idx + 1 < len(matches) else len(block)
                tail = block[match.end() : end].strip("\n")
                head = (match.group(2) or "").rstrip()
                value = (head + ("\n" + tail if tail else "")).strip()
                if value:
                    out[key] = value
            return out

        # split() yields a leading preamble segment; ignore it.
        for block in re.split(r"(?mi)^###\s*FINDING:\s*", text)[1:]:
            title_line, _, rest = block.partition("\n")
            title = title_line.strip() or "Finding"
            fields = parse_fields(rest)

            severity_raw = fields.get("SEVERITY", "")
            severity = (severity_raw.split()[0] if severity_raw else "info").strip().lower()
            finding = self._new_finding(tool=tool, target=target, severity=severity, title=title)

            evidence = fields.get("EVIDENCE", "").strip()
            if evidence:
                finding.evidence = evidence

            description = fields.get("DESCRIPTION", "").strip()
            if description:
                finding.description = description

            remediation = (
                fields.get("RECOMMENDATION")
                or fields.get("FIX")
                or fields.get("REMEDIATION")
                or ""
            ).strip()
            if remediation:
                finding.remediation = remediation

            cvss_text = fields.get("CVSS", "")
            cvss_score, cvss_vector = self._extract_cvss(cvss_text or rest)
            if cvss_vector:
                finding.cvss_vector = cvss_vector
            if cvss_score is not None:
                finding.cvss_score = cvss_score
                finding.cvss_score_source = "provided"

            cves = re.findall(r"CVE-\d{4}-\d{4,7}", rest, re.IGNORECASE)
            for cve in cves:
                normalized = cve.upper()
                if normalized not in finding.cve_ids:
                    finding.cve_ids.append(normalized)

            cwes = re.findall(r"CWE-\d{1,5}", rest, re.IGNORECASE)
            for cwe in cwes:
                normalized = cwe.upper()
                if normalized not in finding.cwe_ids:
                    finding.cwe_ids.append(normalized)

            owasp_matches = re.findall(
                r"A\d{2}:2021(?:\s*-\s*[^,;\n]+)?", rest, re.IGNORECASE
            )
            for match in owasp_matches:
                normalized = match.strip()
                if normalized not in finding.owasp_categories:
                    finding.owasp_categories.append(normalized)

            impact = fields.get("IMPACT", "").strip()
            if impact:
                finding.metadata["impact"] = impact
            exploitability = fields.get("EXPLOITABILITY", "").strip()
            if exploitability:
                finding.metadata["exploitability"] = exploitability
            attack_vector = fields.get("ATTACK_VECTOR", "").strip()
            if attack_vector:
                finding.metadata["attack_vector"] = attack_vector
            defense_bypass = fields.get("DEFENSE_BYPASS", "").strip()
            if defense_bypass:
                finding.metadata["defense_bypass"] = defense_bypass
            mitre = fields.get("MITRE_ATT&CK", "").strip()
            if mitre:
                finding.metadata["mitre_attack"] = mitre
            prerequisites = fields.get("PREREQUISITES", "").strip()
            if prerequisites:
                finding.metadata["prerequisites"] = prerequisites

            findings.append(finding)

        return findings

    def _parse_findings_fallback(self, text: str, tool: str, target: str) -> List[Finding]:
        """
        Fallback parser for LLMs that don't follow the structured format.
        Handles formats like:
        ### Critical Vulnerabilities:
        - **Port 22**: SSH service vulnerable to...
        """
        findings: List[Finding] = []

        # Pattern to match severity section headers
        section_re = re.compile(
            r"(?mi)^###\s*(Critical|High|Medium|Low|Info)(?:\s+Severity)?\s*(?:Vulnerabilities?|Findings?|Issues?)?:?\s*$"
        )

        # Pattern to match bullet points with descriptions
        bullet_re = re.compile(
            r"^[-*]\s+\*\*([^*]+)\*\*:\s*(.+)$"
        )

        current_severity = "info"
        lines = text.splitlines()

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Check if this is a severity section header
            section_match = section_re.match(line)
            if section_match:
                current_severity = section_match.group(1).lower()
                continue

            # Check if this is a bullet point finding
            bullet_match = bullet_re.match(line)
            if bullet_match:
                title = bullet_match.group(1).strip()
                description = bullet_match.group(2).strip()

                finding = self._new_finding(
                    tool=tool,
                    target=target,
                    severity=current_severity,
                    title=title
                )
                finding.description = description

                # Try to extract evidence from description
                # Look for quoted strings or specific technical details
                evidence_match = re.search(r'"([^"]+)"', description)
                if evidence_match:
                    finding.evidence = evidence_match.group(1)
                elif "port" in description.lower():
                    # Extract port numbers as evidence
                    port_match = re.search(r"(?:port\s+)?(\d{1,5})", description, re.IGNORECASE)
                    if port_match:
                        finding.evidence = f"Port {port_match.group(1)}"

                # Extract CVEs
                cves = re.findall(r"CVE-\d{4}-\d{4,7}", description, re.IGNORECASE)
                for cve in cves:
                    normalized = cve.upper()
                    if normalized not in finding.cve_ids:
                        finding.cve_ids.append(normalized)

                findings.append(finding)

        return findings

    def _parse_findings_legacy(self, text: str, tool: str, target: str) -> List[Finding]:
        findings: List[Finding] = []
        current: Optional[Finding] = None

        start_re = re.compile(
            r"(?im)^(?:[-*]|\d+[\.\)])\s*\[?(critical|high|medium|low|info)\]?\s*[:\-]?\s*(.+)$|"
            r"^(critical|high|medium|low|info)\s*[:\-]\s*(.+)$"
        )

        lines = [l.rstrip() for l in text.splitlines()]
        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue

            m = start_re.match(line)
            if m:
                sev = (m.group(1) or m.group(3) or "info").strip().lower()
                title = (m.group(2) or m.group(4) or "").strip()
                if current:
                    findings.append(current)
                current = self._new_finding(tool=tool, target=target, severity=sev, title=title)
                continue

            if not current:
                continue

            if re.match(r"(?im)^evidence\s*:", line):
                current.evidence = re.sub(r"(?im)^evidence\s*:\s*", "", line).strip()
                continue

            if re.match(r"(?im)^(recommendation|fix|remediation)\s*:", line):
                current.remediation = re.sub(
                    r"(?im)^(recommendation|fix|remediation)\s*:\s*", "", line
                ).strip()
                continue

            if "cvss" in line.lower():
                cvss_score, cvss_vector = self._extract_cvss(line)
                if cvss_vector:
                    current.cvss_vector = cvss_vector
                if cvss_score is not None:
                    current.cvss_score = cvss_score
                    current.cvss_score_source = "provided"
                continue

            if line.lower().startswith("cwe"):
                for cwe in re.findall(r"CWE-\d{1,5}", line, re.IGNORECASE):
                    normalized = cwe.upper()
                    if normalized not in current.cwe_ids:
                        current.cwe_ids.append(normalized)
                continue

            if line.lower().startswith("owasp"):
                for match in re.findall(r"A\d{2}:2021(?:\s*-\s*[^,;\n]+)?", line, re.IGNORECASE):
                    normalized = match.strip()
                    if normalized not in current.owasp_categories:
                        current.owasp_categories.append(normalized)
                continue

            for cve in re.findall(r"CVE-\d{4}-\d{4,7}", line, re.IGNORECASE):
                normalized = cve.upper()
                if normalized not in current.cve_ids:
                    current.cve_ids.append(normalized)

            current.description += line + "\n"

        if current:
            findings.append(current)

        return findings
    
    def _format_findings_for_correlation(self) -> str:
        """Format findings for correlation analysis"""
        by_tool = {}
        for finding in self.memory.findings:
            if finding.tool not in by_tool:
                by_tool[finding.tool] = []
            by_tool[finding.tool].append(finding)
        
        formatted = []
        for tool, findings in by_tool.items():
            formatted.append(f"\n{tool.upper()}:")
            for f in findings:
                formatted.append(f"  [{f.severity.upper()}] {f.title}")
        
        return "\n".join(formatted)
    
    def _extract_confidence(self, response: str) -> int:
        """Extract confidence percentage from response"""
        if "CONFIDENCE:" in response:
            start = response.find("CONFIDENCE:") + len("CONFIDENCE:")
            end = start + 10
            confidence_str = response[start:end].strip()
            
            # Extract number
            import re
            match = re.search(r'(\d+)', confidence_str)
            if match:
                return int(match.group(1))
        
        return 50  # Default
    
    def _extract_recommendation(self, response: str) -> str:
        """Extract recommendation from response"""
        if "RECOMMENDATION:" in response:
            start = response.find("RECOMMENDATION:") + len("RECOMMENDATION:")
            recommendation = response[start:].strip()
            return recommendation.split('\n')[0]
        
        return "VERIFY_MANUALLY"
