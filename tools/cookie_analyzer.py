"""
Cookie Analyzer tool for checking cookie security flags.
"""

import re
import shutil
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class CookieAnalyzerTool(BaseTool):
    """Analyze cookie security flags (HttpOnly, Secure, SameSite)."""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "cookie-analyzer"

    def _check_installation(self) -> bool:
        return shutil.which("curl") is not None

    def is_success_exit_code(self, exit_code: int) -> bool:
        return exit_code in (0, 60)

    def get_command(self, target: str, **kwargs) -> List[str]:
        cfg = (self.config or {}).get("tools", {}).get("cookie_analyzer", {}) or {}
        timeout = kwargs.get("timeout", cfg.get("timeout", 10))
        insecure = kwargs.get("insecure", cfg.get("insecure", True))

        command = [
            "curl",
            "-sS",
            "-D", "-",
            "-o", "/dev/null",
            "--max-time", str(timeout),
            "--connect-timeout", str(min(5, int(timeout))),
            "-A", "Guardian-Cookie-Analyzer/1.0",
            "-L",  # follow redirects
        ]
        if insecure:
            command.append("-k")
        command.append(target)
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        results = {
            "cookies": [],
            "issues": [],
            "findings": [],
        }

        session_cookie_patterns = [
            "session", "sess", "sid", "jsessionid", "phpsessid",
            "asp.net_sessionid", "aspsessionid", "connect.sid",
            "token", "auth", "login", "jwt",
        ]

        # Parse all Set-Cookie headers across redirect blocks
        for line in output.splitlines():
            if not re.match(r"(?i)^set-cookie:", line):
                continue

            header_value = line.split(":", 1)[1].strip()
            parts = [p.strip() for p in header_value.split(";")]
            if not parts:
                continue

            # First part is name=value
            name_value = parts[0]
            name = name_value.split("=", 1)[0].strip() if "=" in name_value else name_value

            flags_lower = [p.lower() for p in parts[1:]]
            httponly = any("httponly" in f for f in flags_lower)
            secure = any("secure" in f for f in flags_lower)
            samesite = None
            for f in flags_lower:
                if f.startswith("samesite"):
                    samesite = f.split("=", 1)[1].strip() if "=" in f else "unset"

            cookie_info = {
                "name": name,
                "httponly": httponly,
                "secure": secure,
                "samesite": samesite,
            }
            results["cookies"].append(cookie_info)

            is_session = any(p in name.lower() for p in session_cookie_patterns)
            label = "Session cookie" if is_session else "Cookie"

            # Check missing HttpOnly
            if not httponly:
                severity = "high" if is_session else "medium"
                issue = {
                    "type": "missing_httponly",
                    "severity": severity,
                    "cookie": name,
                    "description": f"{label} '{name}' missing HttpOnly flag. Cookie accessible via JavaScript, enabling theft through XSS.",
                }
                results["issues"].append(issue)
                results["findings"].append({
                    "title": f"Missing HttpOnly Flag on {label}: {name}",
                    "severity": severity,
                    "type": "cookie_security",
                    "cookie": name,
                    "description": issue["description"],
                    "remediation": f"Set the HttpOnly flag on the '{name}' cookie to prevent client-side JavaScript access.",
                })

            # Check missing Secure
            if not secure:
                severity = "high" if is_session else "medium"
                issue = {
                    "type": "missing_secure",
                    "severity": severity,
                    "cookie": name,
                    "description": f"{label} '{name}' missing Secure flag. Cookie may be sent over unencrypted HTTP connections.",
                }
                results["issues"].append(issue)
                results["findings"].append({
                    "title": f"Missing Secure Flag on {label}: {name}",
                    "severity": severity,
                    "type": "cookie_security",
                    "cookie": name,
                    "description": issue["description"],
                    "remediation": f"Set the Secure flag on the '{name}' cookie to ensure it is only sent over HTTPS.",
                })

            # Check missing SameSite
            if samesite is None:
                issue = {
                    "type": "missing_samesite",
                    "severity": "low",
                    "cookie": name,
                    "description": f"{label} '{name}' missing SameSite attribute. Browser defaults may vary, potentially allowing CSRF.",
                }
                results["issues"].append(issue)
                results["findings"].append({
                    "title": f"Missing SameSite Attribute on {label}: {name}",
                    "severity": "low",
                    "type": "cookie_security",
                    "cookie": name,
                    "description": issue["description"],
                    "remediation": f"Set SameSite=Lax or SameSite=Strict on the '{name}' cookie to mitigate CSRF attacks.",
                })

            # Check SameSite=None without Secure
            if samesite and samesite.lower() == "none" and not secure:
                issue = {
                    "type": "samesite_none_no_secure",
                    "severity": "high",
                    "cookie": name,
                    "description": f"{label} '{name}' has SameSite=None without Secure flag. Modern browsers will reject this cookie.",
                }
                results["issues"].append(issue)
                results["findings"].append({
                    "title": f"SameSite=None Without Secure on {label}: {name}",
                    "severity": "high",
                    "type": "cookie_security",
                    "cookie": name,
                    "description": issue["description"],
                    "remediation": f"Add the Secure flag to the '{name}' cookie when using SameSite=None.",
                })

        return results
