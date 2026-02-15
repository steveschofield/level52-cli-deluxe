"""
Authorization Testing (IDOR) tool.

Tests for Insecure Direct Object Reference (IDOR) and privilege
escalation vulnerabilities by manipulating resource identifiers.
"""

import re
import shutil
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from tools.base_tool import BaseTool


class IDORScannerTool(BaseTool):
    """Detect IDOR and authorization bypass vulnerabilities."""

    # Parameters commonly vulnerable to IDOR
    IDOR_PARAMS = [
        "id", "uid", "user_id", "userid", "account_id", "accountid",
        "profile_id", "profileid", "order_id", "orderid",
        "doc_id", "docid", "document_id", "file_id", "fileid",
        "report_id", "reportid", "invoice_id", "invoiceid",
        "msg_id", "message_id", "thread_id",
        "project_id", "projectid", "org_id", "orgid",
        "record", "ref", "reference", "num", "number",
    ]

    # Numeric IDOR test values (relative to original)
    NUMERIC_OFFSETS = [1, -1, 0, 2, -2, 100, 999999]

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "idor-scanner"

    def _check_installation(self) -> bool:
        return shutil.which("curl") is not None

    def is_success_exit_code(self, exit_code: int) -> bool:
        return exit_code in (0, 22, 28, 35, 52, 56, 60)

    def get_command(self, target: str, **kwargs) -> List[str]:
        """
        Fetch the target URL to establish a baseline response.
        The IDOR testing compares responses when manipulating identifiers.
        """
        timeout = kwargs.get("timeout", 10)
        command = [
            "curl", "-sS",
            "-D", "-",
            "-w", "\n---GUARDIAN-META---\n%{http_code}|%{size_download}",
            "--max-time", str(timeout),
            "--connect-timeout", "5",
            "-A", "Guardian-IDOR-Scanner/1.0",
            "-L", "-k",
            target,
        ]
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Analyze response for IDOR indicators."""
        results = {
            "idor_surface": [],
            "findings": [],
        }

        if not output or not output.strip():
            return results

        # Detect IDOR surface in the response
        # Look for numeric IDs in URLs, JSON responses, and HTML
        id_patterns = [
            # JSON object IDs
            (r'"(?:id|user_id|account_id|order_id|doc_id)":\s*(\d+)', "Numeric ID in JSON response"),
            # URL path-based IDs
            (r'/(?:users?|accounts?|orders?|profiles?|documents?|files?|reports?)/(\d+)', "Numeric ID in URL path"),
            # UUID-based IDs (less vulnerable but worth noting)
            (r'"(?:id|uuid|guid)":\s*"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"', "UUID in response"),
            # HTML form hidden fields with IDs
            (r'<input[^>]*?name=["\'](?:id|user_id|account_id)["\'][^>]*?value=["\'](\d+)["\']', "Numeric ID in hidden form field"),
            # Sequential patterns suggesting enumerable resources
            (r'href=["\'][^"\']*?[?&](?:id|uid|account)=(\d+)', "Enumerable ID in link"),
        ]

        for pattern, desc in id_patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            if matches:
                results["idor_surface"].append({
                    "type": desc,
                    "values": list(set(matches[:5])),
                    "count": len(matches),
                })

        # Check for authorization-related information in response
        authz_patterns = [
            (r'(?i)"(?:role|permission|privilege|access_level)":\s*"([^"]+)"', "Role/Permission Information Exposed"),
            (r'(?i)"(?:is_admin|isAdmin|admin)":\s*(true|false|\d)', "Admin Status Exposed in API Response"),
            (r'(?i)"(?:email|phone|ssn|address)":\s*"[^"]+"', "PII Exposed in API Response"),
        ]

        for pattern, title in authz_patterns:
            matches = re.findall(pattern, output)
            if matches:
                results["findings"].append({
                    "title": title,
                    "severity": "medium",
                    "type": "authorization_flaw",
                    "description": f"{title}. This information could aid in authorization bypass or "
                                  "indicate missing access controls on user data.",
                    "remediation": "Implement proper authorization checks on all API endpoints. "
                                  "Verify the authenticated user has permission to access the requested resource. "
                                  "Use indirect references (mapping tables) instead of direct database IDs. "
                                  "Minimize data exposure in API responses.",
                    "evidence": [str(m)[:50] for m in matches[:3]],
                })

        # Check for missing authorization indicators
        status_match = re.search(r"HTTP/[\d.]+ (\d+)", output)
        status_code = status_match.group(1) if status_match else ""

        # If response is 200 and contains user data patterns, flag IDOR surface
        if status_code == "200" and results["idor_surface"]:
            numeric_surfaces = [s for s in results["idor_surface"] if "Numeric ID" in s["type"]]
            if numeric_surfaces:
                results["findings"].append({
                    "title": "IDOR Attack Surface Detected",
                    "severity": "medium",
                    "type": "idor_surface",
                    "description": "Sequential numeric identifiers detected in API responses. "
                                  "These are commonly vulnerable to IDOR attacks where an attacker "
                                  "modifies the ID value to access other users' resources.",
                    "remediation": "Replace sequential numeric IDs with UUIDs. "
                                  "Implement server-side authorization checks that verify the "
                                  "authenticated user owns or has permission to access the requested resource. "
                                  "Use object-level authorization (e.g., policy-based access control).",
                })

        # Look for data that should require different authorization levels
        sensitive_data_patterns = [
            (r'(?i)"(?:credit_card|card_number|cvv|ssn|social_security)"', "Highly Sensitive Data Without Adequate Authorization"),
            (r'(?i)"(?:salary|compensation|bank_account|routing_number)"', "Financial Data Exposure"),
            (r'(?i)"(?:medical|diagnosis|prescription|health)"', "Medical/Health Data Exposure"),
        ]

        for pattern, title in sensitive_data_patterns:
            if re.search(pattern, output):
                results["findings"].append({
                    "title": title,
                    "severity": "critical",
                    "type": "sensitive_data_exposure",
                    "description": f"{title}. Highly sensitive information is accessible and may lack "
                                  "proper authorization controls.",
                    "remediation": "Implement strict authorization checks for sensitive data endpoints. "
                                  "Apply data masking/redaction for sensitive fields. "
                                  "Use column-level security in the database. "
                                  "Implement audit logging for all access to sensitive data.",
                })

        return results
