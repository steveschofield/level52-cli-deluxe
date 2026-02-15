from typing import List, Dict, Any
from tools.base_tool import BaseTool
import json
import os

class SemgrepTool(BaseTool):
    """Wrapper for Semgrep - Static Application Security Testing (SAST)"""

    def get_command(self, target: str, **kwargs) -> List[str]:
        """
        Generate Semgrep command for source code analysis

        Args:
            target: Path to source code directory
            **kwargs: Additional options
                - rulesets: List of rulesets (default: ["auto"])
                - severity: List of severities to include (default: all)
        """
        cmd = ["semgrep", "scan"]

        # Rulesets configuration
        rulesets = kwargs.get("rulesets", ["auto"])
        for ruleset in rulesets:
            cmd.extend(["--config", ruleset])

        # Severity filter
        severity = kwargs.get("severity")
        if severity:
            if isinstance(severity, list):
                for level in severity:
                    if level:
                        cmd.extend(["--severity", str(level)])
            else:
                cmd.extend(["--severity", str(severity)])

        # Output format
        cmd.append("--json")

        # Disable metrics collection for privacy unless using auto config (requires metrics)
        if "auto" not in rulesets:
            cmd.append("--metrics=off")

        # Target directory
        cmd.append(target)

        # Output file
        self.output_file = f"semgrep_{self._get_timestamp()}.json"
        cmd.extend(["-o", self.output_file])

        return cmd

    def parse_output(self, output: str) -> Dict[str, Any]:
        """
        Parse Semgrep JSON output

        Returns structured findings with:
        - Vulnerability type categorization
        - Severity levels
        - File locations and line numbers
        - CWE mappings
        - Vulnerable parameters/endpoints
        """
        result = {
            "findings": [],
            "summary": {
                "total": 0,
                "by_severity": {},
                "by_category": {},
            },
            "vulnerable_endpoints": [],
            "vulnerable_params": [],
            "raw_output": output
        }

        if not os.path.exists(self.output_file):
            self.logger.warning(f"Semgrep output file not found: {self.output_file}")
            return result

        try:
            with open(self.output_file, 'r') as f:
                data = json.load(f)

            # Parse results
            results = data.get("results", [])

            for finding in results:
                parsed_finding = self._parse_finding(finding)
                result["findings"].append(parsed_finding)

                # Update summary
                result["summary"]["total"] += 1

                # Count by severity
                severity = parsed_finding.get("severity", "UNKNOWN")
                result["summary"]["by_severity"][severity] = \
                    result["summary"]["by_severity"].get(severity, 0) + 1

                # Count by category
                category = parsed_finding.get("category", "UNKNOWN")
                result["summary"]["by_category"][category] = \
                    result["summary"]["by_category"].get(category, 0) + 1

                # Extract vulnerable endpoints/params
                if parsed_finding.get("endpoint"):
                    result["vulnerable_endpoints"].append({
                        "endpoint": parsed_finding["endpoint"],
                        "vuln_type": category,
                        "severity": severity,
                        "file": parsed_finding["file"],
                        "line": parsed_finding["line"]
                    })

                if parsed_finding.get("parameter"):
                    result["vulnerable_params"].append({
                        "parameter": parsed_finding["parameter"],
                        "vuln_type": category,
                        "severity": severity,
                        "file": parsed_finding["file"],
                        "line": parsed_finding["line"]
                    })

            # Cleanup output file
            os.remove(self.output_file)

        except Exception as e:
            self.logger.error(f"Error parsing Semgrep output: {e}")

        return result

    def _parse_finding(self, finding: Dict) -> Dict[str, Any]:
        """Parse individual Semgrep finding"""

        # Extract basic info
        parsed = {
            "rule_id": finding.get("check_id", ""),
            "message": finding.get("extra", {}).get("message", ""),
            "severity": finding.get("extra", {}).get("severity", "INFO").upper(),
            "file": finding.get("path", ""),
            "line": finding.get("start", {}).get("line", 0),
            "end_line": finding.get("end", {}).get("line", 0),
            "code_snippet": finding.get("extra", {}).get("lines", ""),
        }

        # Categorize vulnerability type
        parsed["category"] = self._categorize_vulnerability(parsed["rule_id"], parsed["message"])

        # Extract CWE if available
        metadata = finding.get("extra", {}).get("metadata", {})
        parsed["cwe"] = metadata.get("cwe", [])
        parsed["owasp"] = metadata.get("owasp", [])
        parsed["confidence"] = metadata.get("confidence", "MEDIUM")

        # Try to extract endpoint/parameter info from code
        parsed["endpoint"] = self._extract_endpoint(finding)
        parsed["parameter"] = self._extract_parameter(finding)

        return parsed

    def _categorize_vulnerability(self, rule_id: str, message: str) -> str:
        """Categorize vulnerability type from rule ID and message"""

        rule_lower = rule_id.lower()
        message_lower = message.lower()

        # SQL Injection
        if "sql" in rule_lower or "sql-injection" in rule_lower:
            return "sqli"

        # XSS
        if "xss" in rule_lower or "cross-site" in message_lower:
            return "xss"

        # Command Injection
        if "command-injection" in rule_lower or "code-injection" in rule_lower:
            return "command_injection"

        # Authentication/Authorization
        if "auth" in rule_lower or "jwt" in rule_lower or "session" in rule_lower:
            return "auth"

        # Cryptography
        if "crypto" in rule_lower or "hash" in rule_lower or "encryption" in rule_lower:
            return "crypto"

        # Path Traversal
        if "path-traversal" in rule_lower or "directory-traversal" in rule_lower:
            return "path_traversal"

        # SSRF
        if "ssrf" in rule_lower or "server-side-request" in message_lower:
            return "ssrf"

        # Deserialization
        if "deserial" in rule_lower or "pickle" in rule_lower:
            return "deserialization"

        # File Upload
        if "upload" in rule_lower or "file-upload" in message_lower:
            return "file_upload"

        # XXE
        if "xxe" in rule_lower or "xml-external" in message_lower:
            return "xxe"

        return "other"

    def _extract_endpoint(self, finding: Dict) -> str:
        """Try to extract endpoint/route from code snippet"""

        code = finding.get("extra", {}).get("lines", "")

        # Look for common routing patterns
        patterns = [
            r'@app\.route\(["\']([^"\']+)["\']',  # Flask
            r'@router\.(get|post|put|delete)\(["\']([^"\']+)["\']',  # FastAPI
            r'path\(["\']([^"\']+)["\']',  # Django
            r'app\.(get|post|put|delete)\(["\']([^"\']+)["\']',  # Express
            r'@RequestMapping\(["\']([^"\']+)["\']',  # Spring
        ]

        import re
        for pattern in patterns:
            match = re.search(pattern, code)
            if match:
                # Return the path group (usually last group)
                return match.group(match.lastindex)

        return ""

    def _extract_parameter(self, finding: Dict) -> str:
        """Try to extract vulnerable parameter name from code"""

        code = finding.get("extra", {}).get("lines", "")

        # Look for parameter patterns in vulnerable code
        patterns = [
            r'request\.(args|form|json)\[[\'"]([\w_]+)[\'"]\]',  # Flask
            r'request\.(GET|POST)\[[\'"]([\w_]+)[\'"]\]',  # Django
            r'req\.(query|body|params)\.([\w_]+)',  # Express
            r'params\.([\w_]+)',  # FastAPI
        ]

        import re
        for pattern in patterns:
            match = re.search(pattern, code)
            if match:
                # Return the parameter name (usually last group)
                return match.group(match.lastindex)

        return ""

    def _get_timestamp(self) -> int:
        """Get current timestamp for unique filenames"""
        import time
        return int(time.time())
