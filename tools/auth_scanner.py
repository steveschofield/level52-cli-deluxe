"""
Authentication Testing tool.

Tests for common authentication bypass vulnerabilities including
default credentials, authentication logic flaws, and session management issues.
"""

import re
import shutil
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class AuthScannerTool(BaseTool):
    """Detect authentication bypass and session management vulnerabilities."""

    # Common authentication bypass paths
    AUTH_BYPASS_PATHS = [
        # Admin panels
        "/admin", "/administrator", "/admin/login",
        "/wp-admin", "/wp-login.php",
        "/manager/html", "/console",
        "/phpmyadmin", "/pma",
        "/admin/dashboard", "/dashboard",
        # API endpoints without auth
        "/api", "/api/v1", "/api/v2",
        "/graphql", "/swagger", "/api-docs",
        "/swagger.json", "/openapi.json",
        # Debug/development endpoints
        "/debug", "/trace", "/actuator",
        "/actuator/health", "/actuator/env",
        "/actuator/beans", "/actuator/mappings",
        "/.env", "/config", "/settings",
        # Registration / password reset
        "/register", "/signup", "/forgot-password",
        "/reset-password", "/change-password",
    ]

    # Headers that indicate authentication issues
    AUTH_ISSUE_PATTERNS = {
        "missing_auth_header": {
            "pattern": r"(?i)^(?!.*(?:authorization|www-authenticate|x-auth|x-api-key)).*$",
            "severity": "medium",
            "description": "Endpoint accessible without authentication headers.",
        },
        "bearer_token_exposed": {
            "pattern": r"(?i)(?:bearer|token|jwt|api[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9_.\-]{20,}",
            "severity": "high",
            "description": "Authentication token or API key exposed in response.",
        },
        "session_fixation": {
            "pattern": r"(?i)set-cookie:.*?(?:session|sess|sid|token).*?(?:;\s*path=/[^;]*)?(?!.*(?:httponly|secure))",
            "severity": "high",
            "description": "Session cookie set without adequate security flags, potential session fixation.",
        },
    }

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "auth-scanner"

    def _check_installation(self) -> bool:
        return shutil.which("curl") is not None

    def is_success_exit_code(self, exit_code: int) -> bool:
        return exit_code in (0, 22, 28, 35, 52, 56, 60)

    def get_command(self, target: str, **kwargs) -> List[str]:
        """
        Test authentication on the target. Sends requests to common admin/auth
        endpoints and checks for authentication bypass indicators.
        """
        timeout = kwargs.get("timeout", 10)
        # First request: test main target with verbose headers
        command = [
            "curl", "-sS",
            "-D", "-",
            "-o", "/dev/null",
            "--max-time", str(timeout),
            "--connect-timeout", "5",
            "-A", "Guardian-Auth-Scanner/1.0",
            "-L", "-k",
            # Test common auth bypass headers
            "-H", "X-Forwarded-For: 127.0.0.1",
            "-H", "X-Original-URL: /admin",
            "-H", "X-Rewrite-URL: /admin",
            target,
        ]
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Analyze response for authentication issues."""
        results = {
            "auth_issues": [],
            "exposed_endpoints": [],
            "findings": [],
        }

        if not output or not output.strip():
            return results

        # Check for exposed tokens/keys in response
        token_patterns = [
            (r'(?i)["\']((?:access|refresh|auth|bearer|session)[-_]?token)["\']:\s*["\'][A-Za-z0-9_.\-]{20,}["\']', "Authentication Token Exposure"),
            (r'(?i)["\'](api[-_]?key|apikey|secret[-_]?key|private[-_]?key)["\']:\s*["\'][A-Za-z0-9_.\-]{16,}["\']', "API Key Exposure"),
            (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']', "Password Exposure in Response"),
        ]

        for pattern, title in token_patterns:
            matches = re.findall(pattern, output)
            if matches:
                results["findings"].append({
                    "title": title,
                    "severity": "critical",
                    "type": "authentication_flaw",
                    "description": f"{title} detected in server response. Sensitive authentication data is being leaked to clients.",
                    "remediation": "Never include authentication tokens, API keys, or passwords in HTTP responses. "
                                  "Use secure token storage (HttpOnly cookies) and ensure debug endpoints are disabled in production.",
                    "evidence": [m[:50] + "..." if len(m) > 50 else m for m in matches[:3]],
                })

        # Check for authentication bypass indicators
        # Look at status line for 200 on admin paths
        status_match = re.search(r"HTTP/[\d.]+ (\d+)", output)
        status_code = status_match.group(1) if status_match else ""

        if status_code == "200":
            # Check if response contains admin panel indicators
            admin_patterns = [
                (r"(?i)<title>.*?(?:admin|dashboard|control panel|management).*?</title>", "Admin Panel Accessible Without Authentication"),
                (r"(?i)(?:spring boot actuator|actuator endpoint)", "Spring Boot Actuator Exposed"),
                (r"(?i)(?:swagger|openapi).*?(?:ui|spec|doc)", "API Documentation Exposed"),
            ]
            for pattern, title in admin_patterns:
                if re.search(pattern, output):
                    results["findings"].append({
                        "title": title,
                        "severity": "high",
                        "type": "authentication_bypass",
                        "description": f"{title}. Sensitive administrative or API endpoints are accessible without proper authentication.",
                        "remediation": "Implement proper authentication on all administrative endpoints. "
                                      "Use role-based access control. Disable debug/actuator endpoints in production. "
                                      "Restrict access to API documentation to authenticated users.",
                    })

        # Check for header-based auth bypass
        if status_code in ("200", "302", "301"):
            header_bypass_patterns = [
                (r"(?i)x-forwarded-for", "Header-Based Authentication Bypass Possible"),
                (r"(?i)x-original-url", "URL Rewrite Authentication Bypass"),
            ]
            for pattern, title in header_bypass_patterns:
                # Only flag if the response indicates access was granted
                if re.search(pattern, output) and status_code == "200":
                    # This needs more context to be actionable
                    results["auth_issues"].append({
                        "type": "header_bypass_surface",
                        "description": f"Endpoint responds to requests with {pattern} header manipulation",
                    })

        # Check for weak session configuration
        set_cookie_lines = re.findall(r"(?i)^set-cookie:.*$", output, re.MULTILINE)
        for cookie_line in set_cookie_lines:
            cookie_lower = cookie_line.lower()
            session_names = ["session", "sess", "sid", "token", "auth", "jwt"]
            is_session = any(name in cookie_lower for name in session_names)

            if is_session:
                issues = []
                if "httponly" not in cookie_lower:
                    issues.append("HttpOnly")
                if "secure" not in cookie_lower:
                    issues.append("Secure")
                if "samesite" not in cookie_lower:
                    issues.append("SameSite")

                if issues:
                    results["findings"].append({
                        "title": f"Weak Session Cookie Configuration (Missing: {', '.join(issues)})",
                        "severity": "high",
                        "type": "session_management",
                        "description": f"Session cookie is missing security flags: {', '.join(issues)}. "
                                      "This weakens protection against XSS-based session theft, "
                                      "session fixation, and CSRF attacks.",
                        "remediation": f"Add the following flags to session cookies: {', '.join(issues)}. "
                                      "Example: Set-Cookie: session=value; HttpOnly; Secure; SameSite=Strict",
                    })

        return results
