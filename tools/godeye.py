"""
God-eye tool wrapper for comprehensive subdomain reconnaissance and security assessment
"""

import json
from typing import Dict, Any, List
from urllib.parse import urlparse

from tools.base_tool import BaseTool


class GodEyeTool(BaseTool):
    """God's Eye comprehensive reconnaissance and security assessment wrapper"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "godeye"  # Binary name without hyphen

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build god-eye command"""
        config = self.config.get("tools", {}).get("godeye", {})

        # Normalize domain input (strip scheme/port)
        parsed = urlparse(target)
        domain = parsed.hostname or target

        command = ["godeye", "-d", domain]

        # Output format
        command.append("--json")

        # Concurrency settings
        concurrency = kwargs.get("concurrency", config.get("concurrency", 500))
        command.extend(["-c", str(concurrency)])

        # Timeout
        timeout = kwargs.get("timeout", config.get("timeout", 10))
        command.extend(["-t", str(timeout)])

        # Ports to scan
        ports = kwargs.get("ports", config.get("ports"))
        if ports:
            if isinstance(ports, list):
                ports = ",".join(str(p) for p in ports)
            command.extend(["-p", str(ports)])

        # Custom resolvers
        resolvers = kwargs.get("resolvers", config.get("resolvers"))
        if resolvers:
            if isinstance(resolvers, list):
                resolvers = ",".join(resolvers)
            command.extend(["-r", str(resolvers)])

        # Custom wordlist for brute-forcing
        wordlist = kwargs.get("wordlist", config.get("wordlist"))
        if wordlist:
            command.extend(["-w", wordlist])

        # Disable flags (for targeted scanning)
        if kwargs.get("no_brute", config.get("no_brute", False)):
            command.append("--no-brute")

        if kwargs.get("no_probe", config.get("no_probe", False)):
            command.append("--no-probe")

        if kwargs.get("no_ports", config.get("no_ports", False)):
            command.append("--no-ports")

        if kwargs.get("no_takeover", config.get("no_takeover", False)):
            command.append("--no-takeover")

        # Active-only responses (HTTP 2xx/3xx)
        if kwargs.get("active_only", config.get("active_only", False)):
            command.append("--active")

        # AI integration
        enable_ai = kwargs.get("enable_ai", config.get("enable_ai", False))
        if enable_ai:
            command.append("--enable-ai")

            # AI URL (Ollama endpoint)
            ai_url = kwargs.get("ai_url", config.get("ai_url", "http://localhost:11434"))
            command.extend(["--ai-url", ai_url])

            # AI models
            fast_model = kwargs.get("fast_model", config.get("fast_model"))
            if fast_model:
                command.extend(["--ai-fast-model", fast_model])

            deep_model = kwargs.get("deep_model", config.get("deep_model"))
            if deep_model:
                command.extend(["--ai-deep-model", deep_model])

            # AI cascade (default: true)
            if not kwargs.get("ai_cascade", config.get("ai_cascade", True)):
                command.append("--ai-cascade=false")

            # Deep AI analysis
            if kwargs.get("ai_deep", config.get("ai_deep", False)):
                command.append("--ai-deep")

            # Multi-agent mode (8 specialized agents)
            if kwargs.get("multi_agent", config.get("multi_agent", False)):
                command.append("--multi-agent")

        # Verbose mode
        if kwargs.get("verbose", config.get("verbose", False)):
            command.append("-v")

        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse god-eye JSON output"""
        results = {
            "subdomains": [],
            "count": 0,
            "active_count": 0,
            "vulnerabilities": [],
            "vulnerability_count": 0,
            "findings": {
                "critical": [],
                "high": [],
                "medium": [],
                "low": [],
                "info": []
            },
            "ai_findings": [],
            "wildcard_detected": False,
            "stats": {},
            "technologies": {},
            "cloud_providers": {},
            "security_issues": []
        }

        # Try to parse as JSON
        try:
            data = json.loads(output.strip())

            # Extract metadata
            if "meta" in data:
                results["meta"] = data["meta"]

            # Extract statistics
            if "stats" in data:
                results["stats"] = data["stats"]
                results["count"] = data["stats"].get("total_subdomains", 0)
                results["active_count"] = data["stats"].get("active_subdomains", 0)
                results["vulnerability_count"] = data["stats"].get("vulnerabilities", 0)

            # Wildcard detection
            if "wildcard" in data:
                results["wildcard_detected"] = data["wildcard"].get("detected", False)
                results["wildcard_confidence"] = data["wildcard"].get("confidence", 0)

            # Extract findings by severity
            if "findings" in data:
                for severity in ["critical", "high", "medium", "low", "info"]:
                    if severity in data["findings"]:
                        results["findings"][severity] = data["findings"][severity]
                        results["vulnerabilities"].extend(data["findings"][severity])

            # Extract subdomain details
            if "subdomains" in data:
                for subdomain_data in data["subdomains"]:
                    subdomain = subdomain_data.get("subdomain", "")

                    if subdomain:
                        # Add to subdomain list
                        results["subdomains"].append({
                            "subdomain": subdomain,
                            "ips": subdomain_data.get("ips", []),
                            "status_code": subdomain_data.get("status_code"),
                            "title": subdomain_data.get("title", ""),
                            "technologies": subdomain_data.get("technologies", []),
                            "cloud_provider": subdomain_data.get("cloud_provider"),
                            "security_headers": subdomain_data.get("security_headers", []),
                            "ai_findings": subdomain_data.get("ai_findings", [])
                        })

                        # Aggregate technologies
                        for tech in subdomain_data.get("technologies", []):
                            results["technologies"][tech] = results["technologies"].get(tech, 0) + 1

                        # Track cloud providers
                        cloud = subdomain_data.get("cloud_provider")
                        if cloud:
                            results["cloud_providers"][cloud] = results["cloud_providers"].get(cloud, 0) + 1

                        # Collect AI findings
                        if subdomain_data.get("ai_findings"):
                            for finding in subdomain_data["ai_findings"]:
                                results["ai_findings"].append({
                                    "subdomain": subdomain,
                                    "finding": finding
                                })

                        # Check for security issues
                        if subdomain_data.get("takeover_risk"):
                            results["security_issues"].append({
                                "type": "subdomain_takeover",
                                "subdomain": subdomain,
                                "severity": "high",
                                "details": subdomain_data.get("takeover_details", {})
                            })

                        if subdomain_data.get("exposed_files"):
                            results["security_issues"].append({
                                "type": "exposed_files",
                                "subdomain": subdomain,
                                "severity": "medium",
                                "files": subdomain_data.get("exposed_files", [])
                            })

            # Update counts based on parsed data
            if not results["count"]:
                results["count"] = len(results["subdomains"])

            if not results["active_count"]:
                results["active_count"] = sum(
                    1 for s in results["subdomains"]
                    if s.get("status_code") and 200 <= s["status_code"] < 400
                )

        except json.JSONDecodeError:
            # Fallback: try to parse as line-delimited plain text
            lines = [line.strip() for line in output.strip().split('\n') if line.strip()]
            results["subdomains"] = [{"subdomain": line} for line in lines]
            results["count"] = len(lines)

        return results

    def is_success_exit_code(self, exit_code: int) -> bool:
        """
        God-eye may return non-zero exit codes even on successful scans
        (e.g., when some features fail but core functionality works)
        """
        # Accept 0 (success) and 1 (partial success)
        return exit_code in [0, 1]
