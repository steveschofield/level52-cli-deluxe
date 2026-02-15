"""
Reporter Agent
Generates professional penetration testing reports
"""

from typing import Dict, Any, List
from pathlib import Path
from datetime import datetime
import shlex
import json
import re
import hashlib
from core.agent import BaseAgent
from ai.prompt_templates import (
    REPORTER_SYSTEM_PROMPT,
    REPORTER_EXECUTIVE_SUMMARY_PROMPT,
    REPORTER_TECHNICAL_FINDINGS_PROMPT,
    REPORTER_REMEDIATION_PROMPT,
    REPORTER_AI_TRACE_PROMPT
)
from utils.exploit_cache import ExploitLookup
from utils.finding_deduplicator import FindingDeduplicator
from utils.confidence_scorer import ConfidenceScorer
from utils.osint import OSINTEnricher


class ReporterAgent(BaseAgent):
    """Agent that generates professional penetration testing reports"""

    def __init__(self, config, llm_client, memory):
        super().__init__("Reporter", config, llm_client, memory)
        self.osint_enricher = OSINTEnricher(config, logger=self.logger)

    def _clean_llm_artifacts(self, text: str) -> str:
        """
        Remove common LLM prompt artifacts from generated text.

        Strips:
        - Numbered prompt instructions (e.g., "3. EXPLANATION:", "1. REASONING:")
        - Follow-up questions (e.g., "Would you like me to elaborate?")
        - Meta-commentary about the response
        """
        if not text:
            return text

        # Remove numbered prompt headers like "3. EXPLANATION:", "1. REASONING:", etc.
        text = re.sub(r'^\s*\d+\.\s+(EXPLANATION|REASONING|SUPPORTING FACTS|JUSTIFICATION|'
                     r'ATTACK CHAIN|REFERENCES|REFLECTION|SUPPORTING DETAILS):\s*',
                     '', text, flags=re.MULTILINE | re.IGNORECASE)

        # Remove follow-up questions at the end
        followup_patterns = [
            r'Would you like me to elaborate.*?\?',
            r'Should I (?:explain|clarify|provide more|elaborate).*?\?',
            r'Do you want me to.*?\?',
            r'Let me know if you.*?\?',
            r'Would you like.*?\?'
        ]
        for pattern in followup_patterns:
            text = re.sub(pattern, '', text, flags=re.IGNORECASE)

        # Remove trailing empty lines and whitespace
        text = text.rstrip()

        return text
    
    async def execute(self, format: str = "markdown") -> Dict[str, Any]:
        """
        Generate a complete penetration testing report
        
        Args:
            format: Report format (markdown, html, json)
        
        Returns:
            Dict with report content and metadata
        """
        self.log_action("GeneratingReport", f"Format: {format}")
        sections = await self.generate_sections()
        report_content = await self.assemble_report(format, sections)
        
        return {
            "content": report_content,
            "format": format,
            "session_id": self.memory.session_id,
            "target": self.memory.target,
            "timestamp": datetime.now().isoformat()
        }

    async def generate_sections(self) -> Dict[str, str]:
        """Generate report sections once for reuse across formats."""
        # Reset per-report cache
        self._report_findings_cache = None
        self._report_quality_notes = []

        executive_summary = await self.generate_executive_summary()
        technical_findings = await self.generate_technical_findings()
        remediation = await self.generate_remediation_plan()
        ai_trace = await self.generate_ai_trace()
        zap_summary = await self.generate_zap_summary()

        return {
            "executive_summary": executive_summary,
            "technical_findings": technical_findings,
            "remediation": remediation,
            "ai_trace": ai_trace,
            "zap_summary": zap_summary,
        }

    async def assemble_report(self, format: str, sections: Dict[str, str]) -> str:
        """Assemble report content for the requested format."""
        if format == "markdown":
            return await self._assemble_markdown_report(
                sections["executive_summary"],
                sections["technical_findings"],
                sections["remediation"],
                sections["ai_trace"],
                sections.get("zap_summary", "")
            )
        if format == "html":
            return self._assemble_html_report(
                sections["executive_summary"],
                sections["technical_findings"],
                sections["remediation"],
                sections["ai_trace"],
                sections.get("zap_summary", "")
            )
        if format == "json":
            return self._assemble_json_report(
                sections["executive_summary"],
                sections["technical_findings"],
                sections["remediation"],
                sections["ai_trace"]
            )
        raise ValueError(f"Unknown format: {format}")
    
    async def generate_executive_summary(self) -> str:
        """Generate executive summary for non-technical audience"""
        findings = self._get_report_findings()
        summary = self._summarize_findings(findings)
        
        # Get top critical issues
        critical_findings = [f for f in findings if f.severity.lower() == "critical"]
        high_findings = [f for f in findings if f.severity.lower() == "high"]
        
        top_issues = []
        for f in (critical_findings + high_findings)[:3]:
            top_issues.append(f"- {f.title}")
        
        prompt = REPORTER_EXECUTIVE_SUMMARY_PROMPT.format(
            target=self.memory.target,
            scope="Full penetration test",
            duration=self._calculate_duration(),
            findings_count=len(findings),
            critical_count=summary["critical"],
            high_count=summary["high"],
            medium_count=summary["medium"],
            low_count=summary["low"],
            top_issues="\n".join(top_issues) if top_issues else "No critical issues found"
        )
        
        result = await self.think(prompt, REPORTER_SYSTEM_PROMPT)
        return self._clean_llm_artifacts(result["response"])

    async def generate_technical_findings(self) -> str:
        """Generate detailed technical findings section"""
        # Format findings for AI
        findings_text = self._format_findings_detailed()
        
        prompt = REPORTER_TECHNICAL_FINDINGS_PROMPT.format(
            findings=findings_text
        )
        
        result = await self.think(prompt, REPORTER_SYSTEM_PROMPT)
        technical = self._clean_llm_artifacts(result["response"])
        technical = self._dedupe_markdown_sections(technical)
        issues = self._validate_technical_findings_quality(technical)
        if not issues:
            return technical

        self._add_report_quality_note(
            "Technical findings required quality repair: " + "; ".join(issues)
        )
        self.logger.warning(
            "Technical findings quality validation failed: " + "; ".join(issues)
        )

        repaired = await self._regenerate_technical_findings_with_quality_guard(
            findings_text, issues
        )
        repaired = self._dedupe_markdown_sections(repaired)
        repaired_issues = self._validate_technical_findings_quality(repaired)
        if not repaired_issues:
            self.logger.info("Technical findings quality repaired on retry")
            self._add_report_quality_note(
                "Technical findings were regenerated once to resolve quality issues."
            )
            return repaired

        self.logger.warning(
            "Technical findings retry still failed quality checks; using structured fallback: "
            + "; ".join(repaired_issues)
        )
        self._add_report_quality_note(
            "Technical findings fallback used after retry still failed quality checks: "
            + "; ".join(repaired_issues)
        )
        return self._render_structured_technical_findings_fallback(findings_text)
    
    async def generate_remediation_plan(self) -> str:
        """Generate prioritized remediation recommendations"""
        findings_text = self._format_findings_detailed()
        
        # Get affected systems
        affected = set()
        for f in self.memory.findings:
            affected.add(f.target)
        
        prompt = REPORTER_REMEDIATION_PROMPT.format(
            findings=findings_text,
            affected_systems="\n".join(f"- {s}" for s in affected)
        )
        
        result = await self.think(prompt, REPORTER_SYSTEM_PROMPT)
        return self._clean_llm_artifacts(result["response"])

    async def generate_ai_trace(self) -> str:
        """Generate AI decision trace for transparency"""
        reporting_cfg = (self.config or {}).get("reporting", {}) or {}
        max_entries = reporting_cfg.get("max_ai_trace_entries", 200)
        try:
            max_entries = int(max_entries)
        except (TypeError, ValueError):
            max_entries = 200

        decisions = list(self.memory.ai_decisions)
        truncated = False
        if max_entries > 0 and len(decisions) > max_entries:
            decisions = decisions[-max_entries:]
            truncated = True

        max_decision_chars = reporting_cfg.get("max_ai_trace_decision_chars", 200)
        try:
            max_decision_chars = int(max_decision_chars)
        except (TypeError, ValueError):
            max_decision_chars = 200

        ai_decisions_lines = []
        for d in decisions:
            decision = d.get("decision", "")
            if max_decision_chars > 0 and len(decision) > max_decision_chars:
                decision = decision[:max_decision_chars].rstrip() + "…"
            reasoning = (d.get("reasoning", "") or "")[:100]
            ai_decisions_lines.append(
                f"- [{d['agent']}] {decision} (Reasoning: {reasoning}...)"
            )
        if truncated:
            ai_decisions_lines.insert(
                0, f"- [system] AI trace truncated to last {max_entries} decisions"
            )
        ai_decisions = "\n".join(ai_decisions_lines)

        # Apply max_ai_trace_chars limit to the entire AI trace string
        max_trace_chars = reporting_cfg.get("max_ai_trace_chars", 0)
        try:
            max_trace_chars = int(max_trace_chars)
        except (TypeError, ValueError):
            max_trace_chars = 0

        if max_trace_chars > 0 and len(ai_decisions) > max_trace_chars:
            ai_decisions = ai_decisions[:max_trace_chars].rstrip() + "\n\n[AI trace truncated due to length]"
            self.logger.info(f"AI trace truncated to {max_trace_chars} chars to reduce LLM token usage")

        workflow = f"Phase: {self.memory.current_phase}\nCompleted Actions: {len(self.memory.completed_actions)}"

        prompt = REPORTER_AI_TRACE_PROMPT.format(
            ai_decisions=ai_decisions or "No AI decisions recorded",
            workflow=workflow
        )
        
        result = await self.think(prompt, REPORTER_SYSTEM_PROMPT)
        return self._clean_llm_artifacts(result["response"])

    async def generate_zap_summary(self) -> str:
        """
        Generate ZAP findings summary section with links to detailed reports.
        Returns empty string if no ZAP findings exist.
        """
        # Check if ZAP was executed
        zap_executions = [
            exec for exec in self.memory.tool_executions
            if exec.tool == "zap"
        ]

        if not zap_executions:
            return ""

        # Find ZAP report files
        session_id = self.memory.session_id
        output_dir = Path(self.config.get("output", {}).get("save_path", "./reports"))
        zap_dir = output_dir / session_id / "zap"

        if not zap_dir.exists():
            return ""

        # Load ZAP JSON to get alert counts
        zap_json_files = list(zap_dir.glob("zap_*.json"))
        if not zap_json_files:
            return ""

        zap_json = zap_json_files[0]  # Use most recent
        try:
            with open(zap_json) as f:
                zap_data = json.load(f)
            alerts = zap_data.get("alerts", [])

            # Count by severity
            severity_counts = {}
            for alert in alerts:
                risk = alert.get("risk", "Unknown")
                severity_counts[risk] = severity_counts.get(risk, 0) + 1

            # Build summary text
            summary_parts = [
                "## ZAP Scan Summary",
                "",
                f"OWASP ZAP identified **{len(alerts)} potential security issues** across the target application.",
                "",
                "### Severity Breakdown",
                "",
                "| Severity | Count |",
                "|----------|-------|",
            ]

            for severity in ["High", "Medium", "Low", "Informational"]:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    summary_parts.append(f"| {severity} | {count} |")

            summary_parts.extend([
                "",
                "### Detailed Reports",
                "",
                f"Full ZAP scan results are available in the following files:",
                "",
                f"- **JSON Report**: `zap/{zap_json.name}`",
                f"- **HTML Report**: `zap/{zap_json.stem}.html`",
                f"- **Markdown Report**: `zap/{zap_json.stem}.md`",
                "",
                "The findings below include a curated selection of the most critical ZAP discoveries, "
                "filtered by confidence and exploitability.",
                ""
            ])

            return "\n".join(summary_parts)

        except Exception as e:
            self.logger.warning(f"Failed to load ZAP summary: {e}")
            return ""

    def _format_whitebox_analysis_markdown(self) -> str:
        """Format whitebox analysis section for markdown report"""
        whitebox_metadata = self.memory.metadata.get("whitebox_analysis")
        if not whitebox_metadata:
            return ""

        section = f"""## Whitebox Analysis (Source Code Security)

**Source Path**: `{whitebox_metadata.get('source_path', 'N/A')}`
**Frameworks Detected**: {', '.join(whitebox_metadata.get('frameworks', [])) or 'None'}
**API Endpoints Found**: {whitebox_metadata.get('endpoints_found', 0)}
**Secrets Found**: {whitebox_metadata.get('secrets_found', 0)}

### SAST Findings Summary

The following static analysis tools were executed on the source code:
"""

        # Add Semgrep findings if available
        semgrep_summary = self.memory.metadata.get("sast_results", {}).get("semgrep", {}).get("summary", {})
        if semgrep_summary.get("total", 0) > 0:
            section += f"\n**Semgrep** ({semgrep_summary['total']} issues):\n"
            for severity, count in semgrep_summary.get("by_severity", {}).items():
                section += f"- {severity}: {count}\n"

        # Add Trivy findings if available
        trivy_summary = self.memory.metadata.get("sast_results", {}).get("trivy", {}).get("summary", {})
        if trivy_summary.get("total_vulns", 0) > 0:
            section += f"\n**Trivy** ({trivy_summary['total_vulns']} vulnerabilities):\n"
            critical_cves = trivy_summary.get("critical_cves", [])
            if critical_cves:
                section += f"- CRITICAL CVEs: {', '.join(critical_cves[:5])}\n"

        # Add Gitleaks findings if available
        gitleaks_count = self.memory.metadata.get("sast_results", {}).get("gitleaks", {}).get("count", 0)
        if gitleaks_count > 0:
            section += f"\n**Gitleaks**: {gitleaks_count} secrets detected\n"

        # Add correlation summary if available
        correlation_summary = self.memory.metadata.get("correlation_summary", {})
        if correlation_summary:
            section += f"""
### SAST/DAST Correlation

**Confirmed Vulnerabilities**: {correlation_summary.get('confirmed_vulnerabilities', 0)}
(Findings validated by both static analysis and dynamic exploitation)

**High Confidence Correlations**: {correlation_summary.get('high_confidence', 0)}
**Total Correlations**: {correlation_summary.get('total_correlations', 0)}
"""

        return section

    async def _assemble_markdown_report(
        self,
        exec_summary: str,
        technical: str,
        remediation: str,
        ai_trace: str,
        zap_summary: str = ""
    ) -> str:
        """Assemble Markdown report"""
        findings = self._get_report_findings()
        summary = self._summarize_findings(findings)
        evidence_section = self._format_evidence_markdown()
        quality_notes_section = self._format_report_quality_notes_markdown()

        # Build ZAP section if present
        zap_section = f"\n\n{zap_summary}\n" if zap_summary else ""

        # Build whitebox analysis section if present
        whitebox_section = self._format_whitebox_analysis_markdown()

        # Build SAN section if certificate info available
        cert_info = self.memory.context.get("certificate_info", {})
        san_list = cert_info.get("san", [])
        if san_list and isinstance(san_list, list):
            san_display = "\n".join([f"  - {san}" for san in san_list])
            san_section = f"\n- **Subject Alternative Names (SAN)**:\n{san_display}"
        else:
            san_section = "\n- **Subject Alternative Names (SAN)**: No additional SAN attributes listed"

        report = f"""# Penetration Test Report

## Target Information
- **Target**: {self.memory.target}
- **Session ID**: {self.memory.session_id}
- **Date**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- **Duration**: {self._calculate_duration()}{san_section}

## Executive Summary

{exec_summary}

## Findings Summary

| Severity | Count |
|----------|-------|
| Critical | {summary['critical']} |
| High     | {summary['high']} |
| Medium   | {summary['medium']} |
| Low      | {summary['low']} |
| Info     | {summary['info']} |
| **Total** | **{len(findings)}** |
{quality_notes_section}
{zap_section}
{whitebox_section if whitebox_section else ""}

## Technical Findings

{technical}
{evidence_section}

## Standards Mapping

{self._format_standards_mapping_markdown()}

## Exploitation References

{self._format_exploit_references_markdown()}

## Remediation Plan

{remediation}

## AI Decision Trace

{ai_trace}

## Tool Summary

{self._format_tool_summary_markdown()}

## Tools Executed

{self._format_tool_executions()}

---
*Report generated by Guardian AI Pentest Tool*
"""
        return report
    
    def _assemble_html_report(
        self,
        exec_summary: str,
        technical: str,
        remediation: str,
        ai_trace: str,
        zap_summary: str = ""
    ) -> str:
        """Assemble HTML report"""
        findings = self._get_report_findings()
        summary = self._summarize_findings(findings)
        evidence_section = self._format_evidence_html()
        quality_notes_section = self._format_report_quality_notes_html()
        import html as _html

        # Build SAN section if certificate info available
        cert_info = self.memory.context.get("certificate_info", {})
        san_list = cert_info.get("san", [])
        if san_list and isinstance(san_list, list):
            san_items = "".join(f"<li>{_html.escape(str(san))}</li>" for san in san_list)
            san_section = f"<p><strong>Subject Alternative Names (SAN):</strong></p><ul>{san_items}</ul>"
        else:
            san_section = "<p><strong>Subject Alternative Names (SAN):</strong> No additional SAN attributes listed</p>"
        
        # Convert markdown-style content to HTML
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Penetration Test Report - {self.memory.target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #3498db; color: white; }}
        .critical {{ color: #e74c3c; font-weight: bold; }}
        .high {{ color: #e67e22; font-weight: bold; }}
        .medium {{ color: #f39c12; }}
        .low {{ color: #3498db; }}
        .info {{ color: #95a5a6; }}
        .summary {{ background-color: #ecf0f1; padding: 20px; border-radius: 5px; }}
    </style>
</head>
<body>
    <h1>🔐 Penetration Test Report</h1>
    
    <div class="summary">
        <h3>Target Information</h3>
        <p><strong>Target:</strong> {self.memory.target}</p>
        <p><strong>Session ID:</strong> {self.memory.session_id}</p>
        <p><strong>Date:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        <p><strong>Duration:</strong> {self._calculate_duration()}</p>
        {san_section}
    </div>
    
    <h2>Executive Summary</h2>
    <div>{self._markdown_to_html(exec_summary)}</div>
    
    <h2>Findings Summary</h2>
    <table>
        <tr><th>Severity</th><th>Count</th></tr>
        <tr><td class="critical">Critical</td><td>{summary['critical']}</td></tr>
        <tr><td class="high">High</td><td>{summary['high']}</td></tr>
        <tr><td class="medium">Medium</td><td>{summary['medium']}</td></tr>
        <tr><td class="low">Low</td><td>{summary['low']}</td></tr>
        <tr><td class="info">Info</td><td>{summary['info']}</td></tr>
        <tr><th>Total</th><th>{len(findings)}</th></tr>
    </table>
    {quality_notes_section}

    {"<h2>ZAP Scan Summary</h2><div>" + self._markdown_to_html(zap_summary) + "</div>" if zap_summary else ""}
    
    <h2>Technical Findings</h2>
    <div>{self._markdown_to_html(technical)}</div>
{evidence_section}

    <h2>Standards Mapping</h2>
    {self._format_standards_mapping_html()}

    <h2>Exploitation References</h2>
    {self._format_exploit_references_html()}
    
    <h2>Remediation Plan</h2>
    <div>{self._markdown_to_html(remediation)}</div>
    
    <h2>AI Decision Trace</h2>
    <div>{self._markdown_to_html(ai_trace)}</div>

    <h2>Tool Summary</h2>
    {self._format_tool_summary_html()}

    <h2>Tools Executed</h2>
    <div>{self._markdown_to_html(self._format_tool_executions())}</div>
    
    <footer>
        <hr>
        <p><em>Report generated by Guardian AI Pentest Tool</em></p>
    </footer>
</body>
</html>"""
        return html
    
    def _assemble_json_report(
        self,
        exec_summary: str,
        technical: str,
        remediation: str,
        ai_trace: str
    ) -> str:
        """Assemble JSON report"""
        import json
        from dataclasses import asdict
        
        findings = self._get_report_findings()
        report = {
            "metadata": {
                "target": self.memory.target,
                "session_id": self.memory.session_id,
                "timestamp": datetime.now().isoformat(),
                "duration": self._calculate_duration()
            },
            "executive_summary": exec_summary,
            "findings_summary": self._summarize_findings(findings),
            "findings": [asdict(f) for f in findings],
            "technical_findings": technical,
            "exploit_lookup": self._get_exploit_lookup(),
            "remediation_plan": remediation,
            "ai_trace": ai_trace,
            "tool_executions": [asdict(t) for t in self.memory.tool_executions],
            "tool_summary": self._get_tool_summary(),
        }
        
        return json.dumps(report, indent=2, default=str)
    
    def _calculate_duration(self) -> str:
        """Calculate test duration"""
        start = datetime.fromisoformat(self.memory.start_time)
        end = datetime.now()
        duration = end - start
        
        hours = duration.seconds // 3600
        minutes = (duration.seconds % 3600) // 60
        
        return f"{hours}h {minutes}m"
    
    def _format_findings_detailed(self) -> str:
        """Format findings for AI consumption"""
        formatted = []
        findings = self._get_report_findings()
        exploit_lookup = self._get_exploit_lookup()
        matches = exploit_lookup.get("matches", {}) if isinstance(exploit_lookup, dict) else {}

        # Get OSINT enrichment data
        osint_data = self.osint_enricher.enrich_findings(findings)

        for f in findings:
            cvss = self._format_cvss_display(f)
            cwe = ", ".join(f.cwe_ids) if f.cwe_ids else "Unmapped"
            owasp = ", ".join(f.owasp_categories) if f.owasp_categories else "Unmapped"
            confidence = getattr(f, "confidence", None) or "unknown"

            # Build exploit information section
            exploit_info = []

            # Add CVE IDs if present
            if f.cve_ids:
                exploit_info.append(f"CVE IDs: {', '.join(f.cve_ids)}")

            # OSINT: Check CISA KEV status (CRITICAL PRIORITY)
            enrichment = osint_data.get(f.id, {})
            kev_status = enrichment.get("kev_status", {})
            for cve_id, kev_entry in kev_status.items():
                exploit_info.append(f"🔥 CISA KEV: {cve_id} - ACTIVELY EXPLOITED IN THE WILD")
                if kev_entry.get("ransomware_use"):
                    exploit_info.append(f"   ⚠️ RANSOMWARE ASSOCIATED")
                exploit_info.append(f"   Required Action: {kev_entry.get('required_action')}")
                exploit_info.append(f"   Government Deadline: {kev_entry.get('due_date')}")

            # Track whether local exploit sources produced concrete matches
            has_msf_match = False
            has_edb_match = False

            # Add known exploits from database lookup
            entry = matches.get(f.id)
            if entry:
                metasploit = entry.get("metasploit", [])
                exploitdb = entry.get("exploitdb", [])

                if metasploit:
                    msf_names = [m.get("name") or m.get("module", "") for m in metasploit[:3]]
                    exploit_info.append(f"Known Metasploit Modules: {', '.join(msf_names)}")
                    has_msf_match = True

                if exploitdb:
                    edb_ids = [f"EDB-{e.get('id')}" for e in exploitdb[:3] if e.get('id')]
                    if edb_ids:
                        exploit_info.append(f"Known Exploit-DB: {', '.join(edb_ids)}")
                        has_edb_match = True

            # OSINT: Add GitHub PoCs
            github_pocs = enrichment.get("github_pocs", [])
            if github_pocs:
                exploit_info.append(f"GitHub PoCs ({len(github_pocs)} repositories):")
                for poc in github_pocs[:3]:  # Top 3
                    exploit_info.append(f"  - {poc['name']} ⭐ {poc['stars']} stars - {poc['url']}")

            # Add exploitation attempt status if auto-exploit was used
            if f.metadata.get("exploitation_attempted"):
                if f.metadata.get("exploitation_successful"):
                    exploit_module = f.metadata.get("exploit_module", "Unknown")
                    exploit_info.append(f"⚠️ EXPLOITATION SUCCESSFUL using {exploit_module}")
                elif f.metadata.get("exploitation_error"):
                    exploit_info.append(f"Exploitation attempted but failed: {f.metadata.get('exploitation_error')}")
                else:
                    exploit_info.append("Exploitation attempted but unsuccessful")
            elif f.metadata.get("exploitdb_available"):
                edb_count = len(f.metadata.get("exploitdb_ids", []))
                exploit_info.append(f"{edb_count} Exploit-DB exploit(s) available for manual use")

            # Provide explicit N/A values to reduce LLM placeholder/hallucinated exploit references.
            if not has_msf_match:
                exploit_info.append("Known Metasploit Modules: N/A")
            if not has_edb_match:
                exploit_info.append("Known Exploit-DB IDs: N/A")

            exploit_section = "\n".join(exploit_info) if exploit_info else "No public exploits found"

            formatted.append(f"""
[{f.severity.upper()}] {f.title}
Tool: {f.tool}
Target: {f.target}
CVSS: {cvss}
CWE: {cwe}
OWASP: {owasp}
Confidence: {confidence}
Description: {f.description[:200]}
Evidence: {f.evidence[:200]}
Evidence Source: {self._build_finding_evidence_reference(f)}
Provenance ID: {self._get_finding_provenance_id(f)}
Exploitation Information:
{exploit_section}
""")

        return "\n---\n".join(formatted) if formatted else "No findings"
    
    def _format_tool_executions(self) -> str:
        """Format tool executions for report"""
        if not self.memory.tool_executions:
            return "No tools executed"
        
        formatted = []
        for t in self.memory.tool_executions:
            formatted.append(f"- **{t.tool}**: {t.command} (Duration: {t.duration:.2f}s)")
        
        return "\n".join(formatted)

    def _format_cvss_display(self, finding) -> str:
        if finding.cvss_score is None:
            return "N/A"

        try:
            score = f"{float(finding.cvss_score):.1f}"
        except (TypeError, ValueError):
            score = str(finding.cvss_score)
        suffix = " (est.)" if finding.cvss_score_source == "estimated" else ""
        if finding.cvss_vector:
            return f"{score} ({finding.cvss_vector})"
        return f"{score}{suffix}"

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
            elif execution.success:  # Use tool-specific success determination
                entry["success"] += 1
            else:
                entry["failed"] += 1

        return [summary[t] for t in ordered_tools]

    def _format_tool_summary_markdown(self) -> str:
        summary = self._get_tool_summary()
        if not summary:
            return "No tool executions recorded"

        lines = [
            "| Tool | Runs | Success | Failed | Skipped | Last Exit |",
            "|------|------|---------|--------|---------|-----------|",
        ]
        for item in summary:
            lines.append(
                f"| {item['tool']} | {item['runs']} | {item['success']} | "
                f"{item['failed']} | {item['skipped']} | {item['last_exit_code']} |"
            )
        return "\n".join(lines)

    def _format_tool_summary_html(self) -> str:
        summary = self._get_tool_summary()
        if not summary:
            return "<p>No tool executions recorded.</p>"

        rows = []
        for item in summary:
            rows.append(
                "<tr>"
                f"<td>{item['tool']}</td>"
                f"<td>{item['runs']}</td>"
                f"<td>{item['success']}</td>"
                f"<td>{item['failed']}</td>"
                f"<td>{item['skipped']}</td>"
                f"<td>{item['last_exit_code']}</td>"
                "</tr>"
            )

        return (
            "<table>"
            "<tr><th>Tool</th><th>Runs</th><th>Success</th><th>Failed</th>"
            "<th>Skipped</th><th>Last Exit</th></tr>"
            + "".join(rows)
            + "</table>"
        )

    def _get_exploit_lookup(self) -> Dict[str, Any]:
        cached = getattr(self, "_exploit_lookup", None)
        if isinstance(cached, dict):
            return cached

        lookup = ExploitLookup(self.config, logger=self.logger)
        result = lookup.lookup_findings(self._get_report_findings())
        self._exploit_lookup = result
        return result

    def _format_standards_mapping_markdown(self) -> str:
        findings = self._get_report_findings()
        if not findings:
            return "No findings to map"

        exploit_lookup = self._get_exploit_lookup()
        matches = exploit_lookup.get("matches", {}) if isinstance(exploit_lookup, dict) else {}

        # Get OSINT enrichment data for KEV status
        osint_data = self.osint_enricher.enrich_findings(findings)

        lines = [
            "| Severity | Finding | CVSS | OWASP | CWE | Exploit Status |",
            "|----------|---------|------|-------|-----|----------------|",
        ]
        for f in findings:
            cvss = self._format_cvss_display(f)
            owasp = ", ".join(f.owasp_categories) if f.owasp_categories else "Unmapped"
            cwe = ", ".join(f.cwe_ids) if f.cwe_ids else "Unmapped"

            # Determine exploit status (KEV takes highest priority)
            exploit_status = "N/A"

            # Check CISA KEV status first (highest priority)
            enrichment = osint_data.get(f.id, {})
            if enrichment.get("kev_status"):
                exploit_status = "🔥🔥 CISA KEV - IN THE WILD"
            elif f.metadata.get("exploitation_successful"):
                exploit_status = "🔥 EXPLOITED"
            elif f.metadata.get("exploitation_attempted"):
                exploit_status = "⚠️ Attempted"
            elif matches.get(f.id):
                entry = matches[f.id]
                msf_count = len(entry.get("metasploit", []))
                edb_count = len(entry.get("exploitdb", []))
                if msf_count > 0 or edb_count > 0:
                    exploit_status = f"💣 Available (MSF:{msf_count}, EDB:{edb_count})"

            lines.append(
                f"| {f.severity.upper()} | {f.title} | {cvss} | {owasp} | {cwe} | {exploit_status} |"
            )
        return "\n".join(lines)

    def _format_standards_mapping_html(self) -> str:
        findings = self._get_report_findings()
        if not findings:
            return "<p>No findings to map.</p>"

        import html as _html

        exploit_lookup = self._get_exploit_lookup()
        matches = exploit_lookup.get("matches", {}) if isinstance(exploit_lookup, dict) else {}

        # Get OSINT enrichment data for KEV status
        osint_data = self.osint_enricher.enrich_findings(findings)

        rows = []
        for f in findings:
            cvss = self._format_cvss_display(f)
            owasp = ", ".join(f.owasp_categories) if f.owasp_categories else "Unmapped"
            cwe = ", ".join(f.cwe_ids) if f.cwe_ids else "Unmapped"

            # Determine exploit status (KEV takes highest priority)
            exploit_status = "N/A"

            # Check CISA KEV status first
            enrichment = osint_data.get(f.id, {})
            if enrichment.get("kev_status"):
                exploit_status = "🔥🔥 CISA KEV - IN THE WILD"
            elif f.metadata.get("exploitation_successful"):
                exploit_status = "🔥 EXPLOITED"
            elif f.metadata.get("exploitation_attempted"):
                exploit_status = "⚠️ Attempted"
            elif matches.get(f.id):
                entry = matches[f.id]
                msf_count = len(entry.get("metasploit", []))
                edb_count = len(entry.get("exploitdb", []))
                if msf_count > 0 or edb_count > 0:
                    exploit_status = f"💣 Available (MSF:{msf_count}, EDB:{edb_count})"

            rows.append(
                "<tr>"
                f"<td>{_html.escape(f.severity.upper())}</td>"
                f"<td>{_html.escape(f.title)}</td>"
                f"<td>{_html.escape(cvss)}</td>"
                f"<td>{_html.escape(owasp)}</td>"
                f"<td>{_html.escape(cwe)}</td>"
                f"<td>{_html.escape(exploit_status)}</td>"
                "</tr>"
            )

        return (
            "<table>"
            "<tr><th>Severity</th><th>Finding</th><th>CVSS</th><th>OWASP</th><th>CWE</th><th>Exploit Status</th></tr>"
            + "".join(rows)
            + "</table>"
        )

    def _format_exploit_references_markdown(self) -> str:
        lookup = self._get_exploit_lookup()
        matches = lookup.get("matches", {}) if isinstance(lookup, dict) else {}
        status = lookup.get("status", {}) if isinstance(lookup, dict) else {}

        if not matches:
            return self._format_exploit_status_markdown(status) or "No matching public exploit references found"

        lines = [
            "| Severity | Finding | CVEs | Metasploit | Exploit-DB |",
            "|----------|---------|------|------------|------------|",
        ]

        findings = self._get_report_findings()
        for f in findings:
            entry = matches.get(f.id)
            if not entry:
                continue
            cves = ", ".join(entry.get("cves", [])) or "None"
            metasploit = _format_metasploit_refs(entry.get("metasploit", []))
            exploitdb = _format_exploitdb_refs(entry.get("exploitdb", []))
            lines.append(
                f"| {f.severity.upper()} | {f.title} | {cves} | {metasploit} | {exploitdb} |"
            )

        note = self._format_exploit_status_markdown(status)
        if note:
            lines.append("")
            lines.append(note)

        return "\n".join(lines)

    def _format_exploit_references_html(self) -> str:
        lookup = self._get_exploit_lookup()
        matches = lookup.get("matches", {}) if isinstance(lookup, dict) else {}
        status = lookup.get("status", {}) if isinstance(lookup, dict) else {}

        if not matches:
            note = self._format_exploit_status_html(status)
            return note or "<p>No matching public exploit references found.</p>"

        import html as _html

        rows = []
        findings = self._get_report_findings()
        for f in findings:
            entry = matches.get(f.id)
            if not entry:
                continue
            cves = ", ".join(entry.get("cves", [])) or "None"
            metasploit = _format_metasploit_refs(entry.get("metasploit", []), html=True)
            exploitdb = _format_exploitdb_refs(entry.get("exploitdb", []), html=True)
            rows.append(
                "<tr>"
                f"<td>{_html.escape(f.severity.upper())}</td>"
                f"<td>{_html.escape(f.title)}</td>"
                f"<td>{_html.escape(cves)}</td>"
                f"<td>{metasploit}</td>"
                f"<td>{exploitdb}</td>"
                "</tr>"
            )

        table = (
            "<table>"
            "<tr><th>Severity</th><th>Finding</th><th>CVEs</th><th>Metasploit</th><th>Exploit-DB</th></tr>"
            + "".join(rows)
            + "</table>"
        )

        note = self._format_exploit_status_html(status)
        return table + (note or "")

    def _format_exploit_status_markdown(self, status: Dict[str, Any]) -> str:
        bits = []
        for name in ("exploitdb", "metasploit"):
            entry = status.get(name, {})
            if not entry:
                continue
            state = entry.get("state", "unknown")
            count = entry.get("count")
            source = entry.get("source")
            detail = f"{name}: {state}"
            if count is not None:
                detail += f" ({count})"
            if source:
                detail += f" from {source}"
            bits.append(detail)
        if not bits:
            return ""
        return "Exploit lookup status: " + "; ".join(bits)

    def _format_exploit_status_html(self, status: Dict[str, Any]) -> str:
        msg = self._format_exploit_status_markdown(status)
        if not msg:
            return ""
        import html as _html
        return f"<p><em>{_html.escape(msg)}</em></p>"

    def _dedupe_markdown_sections(self, text: str) -> str:
        if not text:
            return text
        lines = text.splitlines()
        preamble: list[str] = []
        sections: list[list[str]] = []
        current: list[str] | None = None

        for line in lines:
            if line.startswith("### "):
                if current is not None:
                    sections.append(current)
                current = [line]
            else:
                if current is None:
                    preamble.append(line)
                else:
                    current.append(line)

        if current is not None:
            sections.append(current)

        def _section_key(block: list[str]) -> str:
            text = "\n".join(block)
            cves = {
                cve.upper()
                for cve in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, flags=re.I)
            }
            if cves:
                return "cve:" + ",".join(sorted(cves))
            heading = block[0].strip()
            heading = re.sub(
                r"\s*\((?:low|medium|high|critical)\s+risk\)\s*$",
                "",
                heading,
                flags=re.I,
            )
            heading = re.sub(r"^###\s*\[[^\]]+\]\s*", "### ", heading, flags=re.I)
            heading = re.sub(r"\s+", " ", heading).lower()
            return heading

        seen: set[str] = set()
        deduped: list[str] = []
        for section in sections:
            if not section:
                continue
            key = _section_key(section)
            if key in seen:
                continue
            seen.add(key)
            deduped.append("\n".join(section).rstrip())

        parts: list[str] = []
        preamble_text = "\n".join(preamble).rstrip()
        if preamble_text:
            parts.append(preamble_text)
        parts.extend(deduped)
        return "\n\n".join(p for p in parts if p)

    async def _regenerate_technical_findings_with_quality_guard(
        self,
        findings_text: str,
        issues: List[str],
    ) -> str:
        summary = self._summarize_findings(self._get_report_findings())
        issue_lines = "\n".join(f"- {issue}" for issue in issues)
        prompt = (
            "Regenerate the technical findings section from source findings.\n\n"
            "Quality violations to fix:\n"
            f"{issue_lines}\n\n"
            "Severity counts from source findings (must not be contradicted):\n"
            f"- Critical: {summary['critical']}\n"
            f"- High: {summary['high']}\n"
            f"- Medium: {summary['medium']}\n"
            f"- Low: {summary['low']}\n"
            f"- Info: {summary['info']}\n\n"
            "Hard requirements:\n"
            "- Do not use placeholders like EDB-XXXXX.\n"
            "- Do not include truncation markers like '... (rest of the findings)'.\n"
            "- Do not invent exploit IDs, CVEs, modules, or PoC links not present in the provided data.\n"
            "- If exploit information is not present in the data, use N/A.\n"
            "- Do not classify tool execution/configuration errors as vulnerabilities.\n"
            "- Do not label a finding as CRITICAL when source critical count is 0.\n\n"
            "FINDINGS:\n"
            f"{findings_text}\n"
        )
        result = await self.think(prompt, REPORTER_SYSTEM_PROMPT)
        return result["response"]

    def _render_structured_technical_findings_fallback(self, findings_text: str) -> str:
        return (
            "**Technical Findings Section**\n\n"
            "Structured fallback generated from normalized finding data after quality validation failed.\n\n"
            f"{findings_text}"
        )

    def _add_report_quality_note(self, note: str) -> None:
        if not note:
            return
        notes = getattr(self, "_report_quality_notes", None)
        if not isinstance(notes, list):
            notes = []
            self._report_quality_notes = notes
        if note not in notes:
            notes.append(note)

    def _format_report_quality_notes_markdown(self) -> str:
        notes = getattr(self, "_report_quality_notes", None) or []
        if not notes:
            return ""
        lines = ["", "## Report Quality Notes", ""]
        for note in notes:
            lines.append(f"- {note}")
        lines.append("")
        return "\n".join(lines)

    def _format_report_quality_notes_html(self) -> str:
        notes = getattr(self, "_report_quality_notes", None) or []
        if not notes:
            return ""
        import html as _html
        items = "".join(f"<li>{_html.escape(str(note))}</li>" for note in notes)
        return (
            "<h2>Report Quality Notes</h2>"
            "<div class=\"summary\"><p>Soft quality markers for reviewer awareness.</p>"
            f"<ul>{items}</ul></div>"
        )

    def _validate_technical_findings_quality(self, text: str) -> List[str]:
        issues: List[str] = []
        if not text:
            return ["empty technical findings output"]

        checks = [
            (r"\bEDB-X{2,}\b", "contains Exploit-DB placeholder"),
            (r"\.\.\.\s*\(rest of the findings\)", "contains truncation marker"),
        ]
        for pattern, message in checks:
            if re.search(pattern, text, flags=re.I):
                issues.append(message)

        summary = self._summarize_findings(self._get_report_findings())
        if summary.get("critical", 0) == 0 and re.search(r"\[CRITICAL\]", text, flags=re.I):
            issues.append("contains CRITICAL technical findings but source critical count is 0")
        if summary.get("high", 0) == 0 and re.search(r"\[HIGH\]", text, flags=re.I):
            issues.append("contains HIGH technical findings but source high count is 0")

        tool_error_pattern = re.compile(
            r"\[(?:MEDIUM|HIGH|CRITICAL)\][^\n]*(?:panic:|unrecognized arguments|required arguments were not provided)",
            flags=re.I,
        )
        if tool_error_pattern.search(text):
            issues.append("promotes tool execution/configuration errors as security findings")

        return issues

    def _collect_evidence_entries(self) -> List[Dict[str, str]]:
        trace_index = self._build_evidence_trace_index()
        entries: List[Dict[str, str]] = []
        for f in self._get_report_findings():
            evidence = (f.evidence or "").strip()
            if not evidence:
                continue
            trace = trace_index.get(f.tool, {})
            files = trace.get("files", []) or []
            runs = trace.get("runs", []) or []
            if not files and not runs:
                # Enforce traceability: skip claims that cannot be tied to an artifact/location.
                continue
            compact = " ".join(evidence.split())
            entries.append({
                "title": f.title,
                "severity": f.severity.upper(),
                "tool": f.tool,
                "target": f.target,
                "evidence": compact[:500],
                "evidence_files": ", ".join(files[:3]) if files else "",
                "evidence_locations": "; ".join(runs[:3]) if runs else "",
                "provenance_id": self._get_finding_provenance_id(f),
            })
        return entries

    def _format_evidence_markdown(self) -> str:
        entries = self._collect_evidence_entries()
        if not entries:
            return ""
        lines = ["", "## Evidence", ""]
        for e in entries:
            file_part = f" Evidence file: {e['evidence_files']}" if e.get("evidence_files") else ""
            location_part = (
                f" Evidence location: {e['evidence_locations']}"
                if e.get("evidence_locations")
                else ""
            )
            provenance_part = (
                f" Provenance ID: {e['provenance_id']}"
                if e.get("provenance_id")
                else ""
            )
            lines.append(
                f"- **[{e['severity']}] {e['title']}** (Tool: {e['tool']}, Target: {e['target']}) "
                f"Evidence: {e['evidence']}{file_part}{location_part}{provenance_part}"
            )
        return "\n".join(lines)

    def _format_evidence_html(self) -> str:
        entries = self._collect_evidence_entries()
        if not entries:
            return ""
        import html as _html
        items = []
        for e in entries:
            file_part = f" Evidence file: {_html.escape(e['evidence_files'])}" if e.get("evidence_files") else ""
            location_part = (
                f" Evidence location: {_html.escape(e['evidence_locations'])}"
                if e.get("evidence_locations")
                else ""
            )
            provenance_part = (
                f" Provenance ID: {_html.escape(e['provenance_id'])}"
                if e.get("provenance_id")
                else ""
            )
            item = (
                f"<li><strong>[{_html.escape(e['severity'])}] {_html.escape(e['title'])}</strong> "
                f"(Tool: {_html.escape(e['tool'])}, Target: {_html.escape(e['target'])}) "
                f"Evidence: {_html.escape(e['evidence'])}{file_part}{location_part}{provenance_part}</li>"
            )
            items.append(item)
        return "\n    <h2>Evidence</h2>\n    <ul>\n        " + "\n        ".join(items) + "\n    </ul>\n"

    def _extract_evidence_files(self) -> Dict[str, List[str]]:
        evidence: Dict[str, List[str]] = {}
        for execution in self.memory.tool_executions:
            tool = execution.tool
            cmd = execution.command or ""
            try:
                tokens = shlex.split(cmd)
            except Exception:
                tokens = cmd.split()

            files: List[str] = []
            # Nuclei JSONL output file.
            for i, tok in enumerate(tokens):
                if tok == "-o" and i + 1 < len(tokens):
                    files.append(tokens[i + 1])
                if tok in ("-oX", "-oJ", "-oN", "-oG", "-oA") and i + 1 < len(tokens):
                    files.append(tokens[i + 1])
                if tok.startswith("-o") and len(tok) > 2:
                    suffix = tok[2:]
                    if suffix and suffix not in ("X", "J", "N", "G", "A"):
                        files.append(suffix)
                if tok == "--report-path" and i + 1 < len(tokens):
                    files.append(tokens[i + 1])

            if files:
                existing = evidence.setdefault(tool, [])
                for f in files:
                    if self._is_usable_evidence_file_path(f) and f not in existing:
                        existing.append(f)
        return evidence

    def _is_usable_evidence_file_path(self, path_value: str) -> bool:
        if not path_value:
            return False
        candidate = path_value.strip().strip("'\"")
        if not candidate:
            return False
        lowered = candidate.lower()
        if lowered in {"/dev/null", "null", "none", "cli"}:
            return False
        if len(candidate) <= 1:
            return False
        if candidate.startswith("-"):
            return False
        # Filter parser artifacts like single-letter format tokens (e.g., J).
        if re.fullmatch(r"[A-Za-z]", candidate):
            return False
        return True

    def _build_evidence_trace_index(self) -> Dict[str, Dict[str, List[str]]]:
        cached = getattr(self, "_evidence_trace_index_cache", None)
        if isinstance(cached, dict):
            return cached

        evidence_files = self._extract_evidence_files()
        output_dir = Path((self.config or {}).get("output", {}).get("save_path", "./reports"))
        session_file = str(output_dir / f"session_{self.memory.session_id}.json")
        index: Dict[str, Dict[str, List[str]]] = {}

        for execution in self.memory.tool_executions:
            tool = execution.tool
            if tool not in index:
                tool_files = list(evidence_files.get(tool, []))
                if session_file not in tool_files:
                    # Baseline artifact for every tool execution (contains tool_executions with timestamps/commands/output).
                    tool_files.append(session_file)
                index[tool] = {
                    "files": tool_files,
                    "runs": [],
                }
            command_hash = hashlib.sha1((execution.command or "").encode("utf-8", errors="ignore")).hexdigest()[:10]
            run_ref = (
                f"{session_file}#tool={tool},timestamp={execution.timestamp},cmd_sha1={command_hash}"
            )
            if run_ref not in index[tool]["runs"]:
                index[tool]["runs"].append(run_ref)

        self._evidence_trace_index_cache = index
        return index

    def _build_finding_evidence_reference(self, finding) -> str:
        trace_index = self._build_evidence_trace_index()
        trace = trace_index.get(finding.tool, {})
        files = trace.get("files", []) or []
        runs = trace.get("runs", []) or []
        parts: List[str] = []
        if files:
            parts.append("artifact=" + ", ".join(files[:3]))
        if runs:
            parts.append("location=" + "; ".join(runs[:2]))
        if not parts:
            return "N/A"
        return " | ".join(parts)
    
    def _markdown_to_html(self, markdown: str) -> str:
        """Simple markdown to HTML conversion"""
        # Basic conversion - in production, use a proper library
        html = markdown.replace('\n\n', '</p><p>')
        html = f'<p>{html}</p>'
        html = html.replace('**', '<strong>').replace('**', '</strong>')
        html = html.replace('*', '<em>').replace('*', '</em>')
        return html

    def _get_report_findings(self):
        cached = getattr(self, "_report_findings_cache", None)
        if cached is not None:
            return cached

        findings = [f for f in self.memory.findings if not f.false_positive]

        deduper = FindingDeduplicator(self.config)
        findings = deduper.deduplicate(findings)

        reporting_cfg = (self.config or {}).get("reporting", {}) or {}
        if reporting_cfg.get("enable_confidence_scoring", True):
            scorer = ConfidenceScorer(self.config)
            for f in findings:
                if not getattr(f, "confidence", None):
                    scorer.enrich_finding_with_confidence(f)
            if reporting_cfg.get("filter_low_confidence", False) and not scorer.verbose:
                findings = scorer.filter_findings_by_confidence(findings)

        findings = self._enforce_report_consistency(findings)
        if reporting_cfg.get("require_evidence_traceability", True):
            findings = self._filter_findings_without_traceability(findings)
        findings = self._attach_finding_provenance(findings)

        self._report_findings_cache = findings
        return findings

    def _enforce_report_consistency(self, findings: List) -> List:
        """Enforce severity/CVSS/CWE consistency before rendering."""
        severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        cvss_to_severity = [
            (9.0, "critical"),
            (7.0, "high"),
            (4.0, "medium"),
            (0.1, "low"),
            (0.0, "info"),
        ]
        changes = 0

        for f in findings:
            # Normalize severity token.
            sev = (f.severity or "info").strip().lower()
            if sev not in severity_rank:
                sev = "info"

            # Normalize CVSS range.
            score = None
            if f.cvss_score is not None:
                try:
                    score = float(f.cvss_score)
                except (TypeError, ValueError):
                    score = None
                if score is not None:
                    score = max(0.0, min(10.0, score))
                    f.cvss_score = score

            # Derive severity from CVSS when available.
            if score is not None:
                derived = "info"
                for threshold, label in cvss_to_severity:
                    if score >= threshold:
                        derived = label
                        break
                if severity_rank.get(derived, 0) != severity_rank.get(sev, 0):
                    f.severity = derived
                    sev = derived
                    changes += 1
            else:
                f.severity = sev

            # Validate/normalize CWE identifiers.
            normalized_cwe: List[str] = []
            for cwe in getattr(f, "cwe_ids", []) or []:
                raw = str(cwe).strip().upper()
                m = re.search(r"CWE[-_: ]?(\d+)", raw)
                if not m:
                    continue
                token = f"CWE-{m.group(1)}"
                if token not in normalized_cwe:
                    normalized_cwe.append(token)
            if normalized_cwe != (getattr(f, "cwe_ids", []) or []):
                f.cwe_ids = normalized_cwe
                changes += 1

            # Prevent high/critical claims with weak taxonomy/evidence signal.
            text = " ".join([f.title or "", f.description or "", f.evidence or ""]).lower()
            has_strong_signal = bool(
                getattr(f, "cve_ids", [])
                or getattr(f, "cwe_ids", [])
                or re.search(r"\bcve-\d{4}-\d+\b", text, flags=re.I)
                or any(k in text for k in ["rce", "remote code execution", "sqli", "sql injection", "xss", "ssrf"])
            )
            if sev in {"critical", "high"} and not has_strong_signal:
                f.severity = "medium"
                changes += 1

        if changes:
            self.logger.info(f"Report consistency normalization applied to {changes} finding fields")
            self._add_report_quality_note(
                f"Consistency normalization adjusted {changes} finding field(s) (severity/CVSS/CWE alignment)."
            )
        return findings

    def _filter_findings_without_traceability(self, findings: List) -> List:
        trace_index = self._build_evidence_trace_index()
        kept = []
        dropped = 0
        for f in findings:
            trace = trace_index.get(f.tool, {})
            files = trace.get("files", []) or []
            runs = trace.get("runs", []) or []
            if files and runs:
                kept.append(f)
            else:
                dropped += 1
        if dropped:
            self.logger.warning(
                f"Dropped {dropped} finding(s) from report due to missing evidence traceability (artifact + location)"
            )
            self._add_report_quality_note(
                f"{dropped} finding(s) excluded due to missing evidence traceability (artifact + location)."
            )
        return kept

    def _attach_finding_provenance(self, findings: List) -> List:
        """
        Attach finding-level provenance metadata:
        - snippet hash (SHA-256, short form)
        - primary source artifact
        - source location reference
        - byte offset in tool output when resolvable
        - deterministic provenance id
        """
        trace_index = self._build_evidence_trace_index()
        for finding in findings:
            evidence = (finding.evidence or "").strip()
            if not evidence:
                continue

            trace = trace_index.get(finding.tool, {})
            files = trace.get("files", []) or []
            runs = trace.get("runs", []) or []
            artifact = files[0] if files else "N/A"
            location = runs[0] if runs else "N/A"
            snippet_hash = self._hash_evidence_snippet(evidence)
            offset = self._find_evidence_offset_for_tool(finding.tool, evidence)

            prov_seed = f"{finding.id}|{snippet_hash}|{artifact}|{location}|{offset if offset is not None else 'na'}"
            provenance_id = "prov-" + hashlib.sha1(prov_seed.encode("utf-8", errors="ignore")).hexdigest()[:12]

            metadata = getattr(finding, "metadata", None)
            if not isinstance(metadata, dict):
                metadata = {}
                finding.metadata = metadata
            metadata["provenance"] = {
                "id": provenance_id,
                "snippet_hash_sha256_12": snippet_hash,
                "source_artifact": artifact,
                "source_location": location,
                "evidence_offset_bytes": offset,
            }
        return findings

    def _hash_evidence_snippet(self, evidence: str) -> str:
        normalized = " ".join((evidence or "").split())
        return hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()[:12]

    def _find_evidence_offset_for_tool(self, tool: str, evidence: str) -> int | None:
        candidates = [
            evidence,
            evidence.strip("`"),
            evidence.strip("\"'"),
            evidence.strip("`\"'"),
            " ".join(evidence.split()),
        ]
        candidates = [c for c in candidates if c]
        for execution in self.memory.tool_executions:
            if execution.tool != tool:
                continue
            output = execution.output or ""
            for candidate in candidates:
                pos = output.find(candidate)
                if pos >= 0:
                    return pos
        return None

    def _get_finding_provenance_id(self, finding) -> str:
        metadata = getattr(finding, "metadata", None)
        if not isinstance(metadata, dict):
            return "N/A"
        provenance = metadata.get("provenance")
        if not isinstance(provenance, dict):
            return "N/A"
        return str(provenance.get("id") or "N/A")

    def _summarize_findings(self, findings: List) -> Dict[str, int]:
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            severity = (finding.severity or "").lower()
            if severity in summary:
                summary[severity] += 1
        return summary


def _format_metasploit_refs(items: List[Dict[str, Any]], html: bool = False) -> str:
    if not items:
        return "None"

    parts: List[str] = []
    for item in items:
        label = item.get("name") or item.get("module") or "Metasploit module"
        url = item.get("url")
        if html and url:
            import html as _html
            parts.append(f'<a href="{_html.escape(url)}">{_html.escape(label)}</a>')
        elif url:
            parts.append(f"[{label}]({url})")
        else:
            parts.append(label)
    sep = "<br>" if html else "<br>"
    return sep.join(parts)


def _format_exploitdb_refs(items: List[Dict[str, Any]], html: bool = False) -> str:
    if not items:
        return "None"

    parts: List[str] = []
    for item in items:
        exploit_id = item.get("id")
        label = f"EDB-{exploit_id}" if exploit_id else (item.get("description") or "Exploit-DB")
        url = item.get("url")
        if html and url:
            import html as _html
            parts.append(f'<a href="{_html.escape(url)}">{_html.escape(label)}</a>')
        elif url:
            parts.append(f"[{label}]({url})")
        else:
            parts.append(label)
    sep = "<br>" if html else "<br>"
    return sep.join(parts)
