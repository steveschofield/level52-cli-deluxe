"""
HTTP security headers check (curl-based).
"""

from __future__ import annotations

import re
import shutil
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class HeadersTool(BaseTool):
    """HTTP security headers checker."""

    # Header severity, descriptions, and remediation
    HEADER_INFO = {
        "strict-transport-security": {
            "severity": "high",
            "description": "HSTS header missing. Without HSTS, the site is vulnerable to SSL stripping attacks (e.g., sslstrip) where a MitM attacker downgrades HTTPS to HTTP.",
            "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        },
        "content-security-policy": {
            "severity": "medium",
            "description": "CSP header missing. Without CSP, the browser cannot restrict resource loading, making XSS attacks significantly easier to exploit.",
            "remediation": "Add a Content-Security-Policy header. Start with: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'self'",
        },
        "x-frame-options": {
            "severity": "medium",
            "description": "X-Frame-Options header missing. The site can be embedded in iframes, enabling clickjacking attacks.",
            "remediation": "Add header: X-Frame-Options: DENY (or SAMEORIGIN if framing by same origin is needed). Also set frame-ancestors in CSP.",
        },
        "x-content-type-options": {
            "severity": "medium",
            "description": "X-Content-Type-Options header missing. Browsers may MIME-sniff responses, potentially treating non-executable content as executable.",
            "remediation": "Add header: X-Content-Type-Options: nosniff",
        },
        "referrer-policy": {
            "severity": "low",
            "description": "Referrer-Policy header missing. The browser may leak the full URL (including query parameters with sensitive data) in the Referer header when navigating to external sites.",
            "remediation": "Add header: Referrer-Policy: strict-origin-when-cross-origin (or no-referrer for maximum privacy)",
        },
        "permissions-policy": {
            "severity": "low",
            "description": "Permissions-Policy header missing. Browser features like camera, microphone, and geolocation are not restricted.",
            "remediation": "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()",
        },
        "cross-origin-opener-policy": {
            "severity": "low",
            "description": "Cross-Origin-Opener-Policy header missing. Other origins may retain a reference to the window object, potentially enabling cross-origin attacks.",
            "remediation": "Add header: Cross-Origin-Opener-Policy: same-origin",
        },
        "cross-origin-embedder-policy": {
            "severity": "low",
            "description": "Cross-Origin-Embedder-Policy header missing. Required for cross-origin isolation (SharedArrayBuffer, high-resolution timers).",
            "remediation": "Add header: Cross-Origin-Embedder-Policy: require-corp",
        },
        "cross-origin-resource-policy": {
            "severity": "low",
            "description": "Cross-Origin-Resource-Policy header missing. Resources may be loaded by cross-origin pages.",
            "remediation": "Add header: Cross-Origin-Resource-Policy: same-origin (or same-site if CDN cross-origin is needed)",
        },
    }

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "headers"

    def _check_installation(self) -> bool:
        return shutil.which("curl") is not None

    def is_success_exit_code(self, exit_code: int) -> bool:
        return exit_code in (0, 60)

    def get_command(self, target: str, **kwargs) -> List[str]:
        timeout = int(kwargs.get("timeout", 10))
        follow = bool(kwargs.get("follow_redirects", True))
        user_agent = kwargs.get("user_agent", "Guardian-Header-Check/1.0")
        insecure = bool(kwargs.get("insecure", True))

        command = [
            "curl",
            "-sS",
            "-D",
            "-",
            "-o",
            "/dev/null",
            "--max-time",
            str(timeout),
            "--connect-timeout",
            str(min(5, timeout)),
            "-A",
            user_agent,
        ]
        if follow:
            command.append("-L")
        if insecure:
            command.append("-k")
        command.append(target)
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        blocks = []
        if output:
            normalized = output.replace("\r\n", "\n")
            blocks = [b.strip() for b in normalized.split("\n\n") if b.strip()]

        last_block = blocks[-1] if blocks else ""
        status_line = ""
        headers: Dict[str, str] = {}
        raw_lines: List[str] = []

        for i, line in enumerate(last_block.splitlines()):
            raw_lines.append(line)
            if i == 0 and line.upper().startswith("HTTP/"):
                status_line = line.strip()
                continue
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()

        security_headers = [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
            "cross-origin-opener-policy",
            "cross-origin-embedder-policy",
            "cross-origin-resource-policy",
        ]
        deprecated_headers = ["x-xss-protection"]

        present = [h for h in security_headers if h in headers]
        missing = [h for h in security_headers if h not in headers]
        deprecated_present = [h for h in deprecated_headers if h in headers]

        # Generate structured findings for missing headers
        findings: List[Dict[str, Any]] = []

        for header_name in missing:
            info = self.HEADER_INFO.get(header_name, {})
            findings.append({
                "title": f"Missing Security Header: {header_name}",
                "severity": info.get("severity", "low"),
                "type": "missing_security_header",
                "header": header_name,
                "description": info.get("description", f"Security header '{header_name}' is not set."),
                "remediation": info.get("remediation", f"Add the {header_name} header to HTTP responses."),
            })

        # Check for weak CSP
        csp_value = headers.get("content-security-policy", "")
        if csp_value:
            csp_issues = []
            if "unsafe-inline" in csp_value:
                csp_issues.append("'unsafe-inline' allows inline script execution, weakening XSS protection")
            if "unsafe-eval" in csp_value:
                csp_issues.append("'unsafe-eval' allows eval() and similar functions, enabling code injection")
            if "data:" in csp_value and ("script-src" in csp_value.split("data:")[0] or "default-src" in csp_value.split("data:")[0]):
                csp_issues.append("'data:' URI in script sources can be used to bypass CSP via data: URIs")
            if "*" in csp_value:
                csp_issues.append("Wildcard (*) source allows loading resources from any origin")

            if csp_issues:
                findings.append({
                    "title": "Weak Content Security Policy",
                    "severity": "medium",
                    "type": "weak_csp",
                    "header": "content-security-policy",
                    "description": "Content Security Policy contains directives that weaken its effectiveness: " + "; ".join(csp_issues),
                    "remediation": "Remove 'unsafe-inline' and use nonces or hashes for inline scripts. "
                                  "Remove 'unsafe-eval' and refactor code to avoid eval(). "
                                  "Replace wildcard (*) with specific trusted origins. "
                                  "Remove 'data:' from script-src.",
                })

        # Check for deprecated X-XSS-Protection
        if deprecated_present:
            findings.append({
                "title": "Deprecated X-XSS-Protection Header Present",
                "severity": "low",
                "type": "deprecated_header",
                "header": "x-xss-protection",
                "description": "The X-XSS-Protection header is deprecated and removed from modern browsers. "
                              "It can introduce vulnerabilities in older browsers (e.g., selective content blocking attacks).",
                "remediation": "Remove the X-XSS-Protection header. Use Content-Security-Policy instead for XSS protection.",
            })

        return {
            "status_line": status_line,
            "headers": headers,
            "security_headers_present": present,
            "security_headers_missing": missing,
            "deprecated_headers_present": deprecated_present,
            "raw_headers": raw_lines,
            "findings": findings,
        }
