"""
CORS Scanner tool wrapper for detecting CORS misconfigurations.
"""

import json
import os
import re
import shutil
import sys
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class CORSScannerTool(BaseTool):
    """Detect CORS misconfigurations that allow unauthorized cross-origin access."""

    def __init__(self, config):
        self._script_path = None
        super().__init__(config)
        self.tool_name = "cors-scanner"

    def _check_installation(self) -> bool:
        # Check vendored CORScanner first
        vendor_script = os.path.join(
            os.path.dirname(__file__), "vendor", "CORScanner", "cors_scan.py"
        )
        if os.path.isfile(vendor_script):
            self._script_path = vendor_script
            return True
        # Check PATH - try multiple possible names
        return (
            shutil.which("cors_scan") is not None or
            shutil.which("cors_scan.py") is not None or
            shutil.which("corscanner") is not None
        )

    def get_command(self, target: str, **kwargs) -> List[str]:
        cfg = (self.config or {}).get("tools", {}).get("cors_scanner", {}) or {}
        threads = kwargs.get("threads", cfg.get("threads", 10))
        timeout = kwargs.get("timeout", cfg.get("timeout", 10))

        if self._script_path:
            command = [sys.executable, self._script_path]
        elif shutil.which("corscanner"):
            command = ["corscanner"]
        else:
            command = ["cors_scan"]

        command.extend(["-u", target])
        command.extend(["-t", str(threads)])
        command.extend(["-T", str(timeout)])
        command.append("-j")  # JSON output

        return command

    def is_success_exit_code(self, exit_code: int) -> bool:
        return exit_code in (0, 1)

    def parse_output(self, output: str) -> Dict[str, Any]:
        results = {
            "vulnerable": False,
            "misconfigurations": [],
            "findings": [],
        }

        # Severity mapping for CORS issue types
        severity_map = {
            "reflect_origin": "critical",
            "prefix_match": "high",
            "suffix_match": "high",
            "not_escape_dot": "high",
            "null_origin": "critical",
            "third_party": "medium",
            "subdomain": "medium",
            "http_trust": "high",
            "wildcard": "medium",
        }

        description_map = {
            "reflect_origin": "Server reflects arbitrary Origin header in Access-Control-Allow-Origin. Any website can make authenticated cross-origin requests.",
            "prefix_match": "Server uses prefix matching for Origin validation. Attacker can register a domain starting with the trusted domain name to bypass CORS.",
            "suffix_match": "Server uses suffix matching for Origin validation. Attacker can register a domain ending with the trusted domain to bypass CORS.",
            "not_escape_dot": "Server does not escape dots in origin validation regex. Attacker can register lookalike domains (e.g., exampleXcom.attacker.com).",
            "null_origin": "Server accepts 'null' as a valid Origin. Sandboxed iframes and redirects send null origin, enabling attacks.",
            "third_party": "Server trusts third-party domains in Access-Control-Allow-Origin. Compromised third-party domains can access resources.",
            "subdomain": "Server trusts all subdomains. A vulnerable subdomain can be used for cross-origin attacks.",
            "http_trust": "Server trusts HTTP origins for an HTTPS resource. MitM attackers on HTTP can make cross-origin requests.",
            "wildcard": "Server uses wildcard (*) for Access-Control-Allow-Origin. While less severe if credentials are not allowed, it exposes resources to any origin.",
        }

        remediation_map = {
            "reflect_origin": "Implement a strict whitelist of allowed origins. Never reflect the Origin header directly.",
            "prefix_match": "Use exact string comparison for origin validation instead of prefix matching.",
            "suffix_match": "Use exact string comparison for origin validation instead of suffix matching.",
            "not_escape_dot": "Properly escape dots in regex-based origin validation patterns.",
            "null_origin": "Never accept 'null' as a valid origin in CORS responses.",
            "third_party": "Remove third-party domains from CORS allowlists unless absolutely necessary. Audit trusted domains regularly.",
            "subdomain": "Restrict CORS to specific trusted subdomains rather than all subdomains.",
            "http_trust": "Only allow HTTPS origins in CORS configuration. Never trust HTTP origins for HTTPS resources.",
            "wildcard": "Replace wildcard with specific allowed origins. If wildcard is needed, ensure Access-Control-Allow-Credentials is false.",
        }

        # Try JSON parsing first
        try:
            for line in output.strip().splitlines():
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                data = json.loads(line)
                issue_type = data.get("type", "unknown")
                url = data.get("url", "")
                results["vulnerable"] = True
                severity = severity_map.get(issue_type, "medium")
                results["misconfigurations"].append({
                    "url": url,
                    "type": issue_type,
                    "severity": severity,
                    "description": description_map.get(issue_type, f"CORS misconfiguration: {issue_type}"),
                })
                results["findings"].append({
                    "title": f"CORS Misconfiguration: {issue_type.replace('_', ' ').title()}",
                    "severity": severity,
                    "type": "cors_misconfiguration",
                    "url": url,
                    "issue_type": issue_type,
                    "description": description_map.get(issue_type, f"CORS misconfiguration detected: {issue_type}"),
                    "remediation": remediation_map.get(issue_type, "Review and restrict CORS configuration."),
                })
        except (json.JSONDecodeError, ValueError):
            pass

        # Fallback: text parsing
        if not results["misconfigurations"]:
            vuln_patterns = [
                (r"vulnerable.*?origin.*?reflect", "reflect_origin"),
                (r"null.*?origin.*?accept", "null_origin"),
                (r"wildcard", "wildcard"),
                (r"http.*?trust", "http_trust"),
                (r"subdomain", "subdomain"),
            ]
            for pattern, issue_type in vuln_patterns:
                if re.search(pattern, output, re.IGNORECASE):
                    results["vulnerable"] = True
                    severity = severity_map.get(issue_type, "medium")
                    results["misconfigurations"].append({
                        "url": "",
                        "type": issue_type,
                        "severity": severity,
                        "description": description_map.get(issue_type, f"CORS misconfiguration: {issue_type}"),
                    })
                    results["findings"].append({
                        "title": f"CORS Misconfiguration: {issue_type.replace('_', ' ').title()}",
                        "severity": severity,
                        "type": "cors_misconfiguration",
                        "url": "",
                        "issue_type": issue_type,
                        "description": description_map.get(issue_type, f"CORS misconfiguration detected: {issue_type}"),
                        "remediation": remediation_map.get(issue_type, "Review and restrict CORS configuration."),
                    })

        return results
