"""
SSRF (Server-Side Request Forgery) Detection tool.

Tests for SSRF vulnerabilities by injecting payloads into URL parameters
and monitoring for callbacks or behavioral differences.
"""

import json
import re
import shutil
from typing import Dict, Any, List
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

from tools.base_tool import BaseTool


class SSRFScannerTool(BaseTool):
    """Detect Server-Side Request Forgery vulnerabilities."""

    # SSRF test payloads targeting internal services
    SSRF_PAYLOADS = [
        # Localhost variants
        "http://127.0.0.1",
        "http://localhost",
        "http://0.0.0.0",
        "http://[::1]",
        "http://0177.0.0.1",        # Octal
        "http://2130706433",          # Decimal
        "http://0x7f000001",          # Hex
        # Cloud metadata endpoints
        "http://169.254.169.254/latest/meta-data/",          # AWS
        "http://metadata.google.internal/computeMetadata/v1/", # GCP
        "http://169.254.169.254/metadata/instance",           # Azure
        # Internal services
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",
        "http://127.0.0.1:6379",
        # Protocol smuggling
        "file:///etc/passwd",
        "dict://127.0.0.1:11211/info",
        "gopher://127.0.0.1:25/_EHLO",
    ]

    # Parameters commonly vulnerable to SSRF
    SSRF_PARAMS = [
        "url", "uri", "path", "dest", "redirect", "target",
        "rurl", "domain", "feed", "host", "site", "to",
        "out", "view", "dir", "show", "navigation", "open",
        "file", "val", "validate", "link", "img", "image",
        "return", "next", "data", "reference", "src", "source",
        "callback", "page", "fetch", "proxy", "request",
    ]

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "ssrf-scanner"

    def _check_installation(self) -> bool:
        return shutil.which("curl") is not None

    def is_success_exit_code(self, exit_code: int) -> bool:
        return exit_code in (0, 22, 28, 35, 47, 52, 56, 60)

    def get_command(self, target: str, **kwargs) -> List[str]:
        """
        Fetch the target to analyze its response as a baseline.
        The actual SSRF testing logic is in execute() which runs multiple requests.
        """
        command = [
            "curl", "-sS",
            "-o", "/dev/null",
            "-w", "%{http_code}|%{size_download}|%{time_total}",
            "--max-time", "10",
            "--connect-timeout", "5",
            "-A", "Guardian-SSRF-Scanner/1.0",
            "-L", "-k",
            target,
        ]
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse curl output for SSRF indicators."""
        results = {
            "vulnerable": False,
            "tested_params": [],
            "findings": [],
        }

        if not output:
            return results

        # The main SSRF detection happens in the behavioral analysis
        # This parser handles the baseline response analysis
        # Look for signs the app fetches URLs (common SSRF surface)
        ssrf_surface_patterns = [
            (r"(?i)<(?:img|iframe|script|link|embed|object)\s+[^>]*(?:src|href|data|action)\s*=\s*['\"]?(?:https?://|//)", "URL-loading HTML elements detected"),
            (r"(?i)(?:fetch|request|redirect|proxy|forward|load|include|import|require)\s*\(", "URL-fetching function calls detected"),
            (r"(?i)(?:url|uri|path|redirect|callback|return|next)\s*=\s*https?://", "URL parameters in response"),
        ]

        for pattern, desc in ssrf_surface_patterns:
            if re.search(pattern, output):
                results["tested_params"].append(desc)

        return results

    def analyze_for_ssrf(self, url: str, param_name: str, baseline_code: str,
                          baseline_size: int, response_code: str, response_size: int,
                          response_time: float, payload: str) -> Dict[str, Any] | None:
        """
        Analyze a response for SSRF indicators by comparing against baseline.
        Returns a finding dict if SSRF is likely, None otherwise.
        """
        finding = None

        # Significant size difference may indicate server-side content fetch
        size_diff = abs(response_size - baseline_size)
        size_ratio = size_diff / max(baseline_size, 1)

        # Time-based detection: internal requests often return faster than external
        # or cloud metadata returns very differently

        # Response code differences
        code_changed = response_code != baseline_code

        # Heuristics for SSRF detection
        is_suspicious = False
        evidence = []

        if code_changed and response_code in ("200", "301", "302"):
            is_suspicious = True
            evidence.append(f"Status code changed from {baseline_code} to {response_code} with payload")

        if size_ratio > 0.5 and size_diff > 100:
            is_suspicious = True
            evidence.append(f"Response size changed significantly ({baseline_size} -> {response_size} bytes)")

        if is_suspicious:
            severity = "critical" if "169.254.169.254" in payload or "metadata" in payload else "high"
            finding = {
                "title": f"Potential SSRF in Parameter '{param_name}'",
                "severity": severity,
                "type": "ssrf",
                "parameter": param_name,
                "payload": payload,
                "evidence": evidence,
                "description": f"Server-Side Request Forgery (SSRF) detected in parameter '{param_name}'. "
                              f"The server appears to make requests to attacker-controlled URLs, potentially "
                              f"allowing access to internal services, cloud metadata, or other restricted resources.",
                "remediation": "Validate and sanitize all user-supplied URLs. Implement allowlists for "
                              "permitted domains/IPs. Block requests to internal/private IP ranges and "
                              "cloud metadata endpoints. Use network-level controls to restrict outbound "
                              "requests from the application server.",
            }

        return finding
