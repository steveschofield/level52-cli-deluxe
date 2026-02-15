"""
Correlation Engine - SAST/DAST Intelligence Bridge

Maps static analysis findings to dynamic testing targets for enhanced
penetration testing with code-level context.
"""

from typing import Dict, List, Any, Optional, Tuple
import re
from urllib.parse import urlparse, urljoin


class CorrelationEngine:
    """Correlates SAST findings with DAST results for intelligent testing"""

    def __init__(self, sast_findings: Dict, config: Dict, logger, ai_client=None):
        """
        Initialize correlation engine

        Args:
            sast_findings: Results from source code analysis
            config: Configuration dictionary
            logger: Logger instance
            ai_client: Optional AI client for intelligent correlation
        """
        self.sast_findings = sast_findings
        self.config = config
        self.logger = logger
        self.ai_client = ai_client

        self.correlations = []
        self.test_plan = {
            "high_priority": [],
            "medium_priority": [],
            "low_priority": []
        }

    def prioritize_targets(self, discovered_urls: List[str], base_url: str) -> List[Dict]:
        """
        Prioritize discovered URLs based on SAST findings

        Args:
            discovered_urls: List of URLs discovered during reconnaissance
            base_url: Base target URL

        Returns:
            List of prioritized targets with scores and reasons
        """
        self.logger.info(f"Prioritizing {len(discovered_urls)} URLs based on SAST findings")

        priority_targets = []

        for url in discovered_urls:
            score, reasons = self._calculate_priority_score(url, base_url)

            if score > 0:
                priority_targets.append({
                    "url": url,
                    "priority_score": score,
                    "reasons": reasons,
                    "sast_context": self._get_sast_context_for_url(url)
                })

        # Sort by priority score (highest first)
        priority_targets.sort(key=lambda x: x["priority_score"], reverse=True)

        # Log top priorities
        self.logger.info(f"Top 5 priority targets:")
        for target in priority_targets[:5]:
            self.logger.info(f"  [{target['priority_score']}] {target['url']} - {', '.join(target['reasons'])}")

        return priority_targets

    def generate_test_plan(self, target_url: str) -> Dict[str, List[Dict]]:
        """
        Generate targeted test plan based on SAST findings

        Args:
            target_url: Base target URL

        Returns:
            Dictionary with categorized tests (sqli, xss, nuclei, etc.)
        """
        plan = {
            "sqli_tests": [],
            "xss_tests": [],
            "command_injection_tests": [],
            "path_traversal_tests": [],
            "nuclei_templates": [],
            "authenticated_scans": [],
            "api_fuzzing": []
        }

        # Map Semgrep findings to specific tests
        semgrep_findings = self.sast_findings.get("sast_results", {}).get("semgrep", {}).get("findings", [])
        for finding in semgrep_findings:
            category = finding.get("category", "")
            severity = finding.get("severity", "")

            # SQL Injection tests
            if category == "sqli":
                endpoint = self._construct_endpoint(target_url, finding)
                plan["sqli_tests"].append({
                    "endpoint": endpoint,
                    "parameter": finding.get("parameter", ""),
                    "confidence": "high",
                    "severity": severity,
                    "source_file": finding.get("file", ""),
                    "source_line": finding.get("line", 0),
                    "evidence": finding.get("message", "")
                })

            # XSS tests
            elif category == "xss":
                endpoint = self._construct_endpoint(target_url, finding)
                plan["xss_tests"].append({
                    "endpoint": endpoint,
                    "parameter": finding.get("parameter", ""),
                    "confidence": "high",
                    "severity": severity,
                    "source_file": finding.get("file", ""),
                    "source_line": finding.get("line", 0)
                })

            # Command Injection tests
            elif category == "command_injection":
                endpoint = self._construct_endpoint(target_url, finding)
                plan["command_injection_tests"].append({
                    "endpoint": endpoint,
                    "parameter": finding.get("parameter", ""),
                    "severity": severity,
                    "source_file": finding.get("file", ""),
                    "source_line": finding.get("line", 0)
                })

            # Path Traversal tests
            elif category == "path_traversal":
                endpoint = self._construct_endpoint(target_url, finding)
                plan["path_traversal_tests"].append({
                    "endpoint": endpoint,
                    "parameter": finding.get("parameter", ""),
                    "severity": severity,
                    "source_file": finding.get("file", ""),
                    "source_line": finding.get("line", 0)
                })

        # Map Trivy CVEs to Nuclei templates
        trivy_findings = self.sast_findings.get("sast_results", {}).get("trivy", {})
        nuclei_templates = trivy_findings.get("nuclei_templates", [])
        for template in nuclei_templates:
            plan["nuclei_templates"].append({
                "template": template,
                "target": target_url,
                "source": "trivy_cve_mapping"
            })

        # Add CVE-specific Nuclei tests
        for vuln in trivy_findings.get("vulnerabilities", []):
            if vuln.get("severity") in ["CRITICAL", "HIGH"]:
                plan["nuclei_templates"].append({
                    "template": self._map_cve_to_nuclei(vuln.get("cve_id", "")),
                    "cve_id": vuln.get("cve_id", ""),
                    "package": vuln.get("package_name", ""),
                    "severity": vuln.get("severity", ""),
                    "target": target_url
                })

        # Authenticated scans using discovered secrets
        secrets = self.sast_findings.get("attack_surface", {}).get("secrets", [])
        for secret in secrets:
            if self._is_api_key_or_token(secret):
                plan["authenticated_scans"].append({
                    "credential_type": secret.get("type", ""),
                    "credential_source": f"{secret.get('file', '')}:{secret.get('line', '')}",
                    "secret_value": secret.get("secret", ""),
                    "target": target_url
                })

        # API fuzzing based on extracted endpoints
        endpoints = self.sast_findings.get("attack_surface", {}).get("endpoints", [])
        for endpoint in endpoints:
            if endpoint.get("endpoint"):
                full_url = urljoin(target_url, endpoint.get("endpoint", ""))
                plan["api_fuzzing"].append({
                    "endpoint": full_url,
                    "methods": endpoint.get("methods", ["GET"]),
                    "framework": endpoint.get("framework", ""),
                    "source_file": endpoint.get("file", "")
                })

        # Log test plan summary
        self.logger.info(f"Generated test plan:")
        self.logger.info(f"  SQLi tests: {len(plan['sqli_tests'])}")
        self.logger.info(f"  XSS tests: {len(plan['xss_tests'])}")
        self.logger.info(f"  Command injection tests: {len(plan['command_injection_tests'])}")
        self.logger.info(f"  Nuclei templates: {len(plan['nuclei_templates'])}")
        self.logger.info(f"  Authenticated scans: {len(plan['authenticated_scans'])}")
        self.logger.info(f"  API endpoints for fuzzing: {len(plan['api_fuzzing'])}")

        return plan

    def correlate_results(self, sast_finding: Dict, dast_result: Dict) -> Dict[str, Any]:
        """
        Correlate SAST finding with DAST exploitation result

        Args:
            sast_finding: Finding from static analysis
            dast_result: Result from dynamic testing

        Returns:
            Correlation metadata with confidence level
        """
        correlation = {
            "confirmed": False,
            "confidence": "low",
            "sast_source": None,
            "dast_proof": None,
            "severity": "UNKNOWN",
            "impact": ""
        }

        # Check if findings match
        if self._findings_match(sast_finding, dast_result):
            correlation["confirmed"] = True
            correlation["confidence"] = self._calculate_correlation_confidence(sast_finding, dast_result)
            correlation["sast_source"] = f"{sast_finding.get('file', '')}:{sast_finding.get('line', '')}"
            correlation["dast_proof"] = dast_result.get("evidence", "")
            correlation["severity"] = max(
                sast_finding.get("severity", "LOW"),
                dast_result.get("severity", "LOW"),
                key=lambda x: ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(x) if x in ["LOW", "MEDIUM", "HIGH", "CRITICAL"] else 0
            )
            correlation["impact"] = self._assess_impact(sast_finding, dast_result)

        self.correlations.append(correlation)
        return correlation

    def get_correlation_summary(self) -> Dict[str, Any]:
        """Get summary of SAST/DAST correlations"""
        confirmed = [c for c in self.correlations if c["confirmed"]]
        high_confidence = [c for c in confirmed if c["confidence"] == "high"]

        return {
            "total_correlations": len(self.correlations),
            "confirmed_vulnerabilities": len(confirmed),
            "high_confidence": len(high_confidence),
            "critical_findings": len([c for c in confirmed if c["severity"] == "CRITICAL"]),
            "correlations": self.correlations
        }

    def _calculate_priority_score(self, url: str, base_url: str) -> Tuple[int, List[str]]:
        """Calculate priority score for a URL based on SAST context"""
        score = 0
        reasons = []

        # Extract path from URL
        parsed_url = urlparse(url)
        path = parsed_url.path

        # Check if URL matches vulnerable endpoint from source code
        endpoints = self.sast_findings.get("attack_surface", {}).get("endpoints", [])
        for endpoint_info in endpoints:
            endpoint = endpoint_info.get("endpoint", "")
            if self._path_matches(path, endpoint):
                vuln_type = endpoint_info.get("vuln_type", "")
                if vuln_type:
                    score += 10
                    reasons.append(f"Matches {vuln_type} vulnerable endpoint in source")
                else:
                    score += 5
                    reasons.append("Matches endpoint defined in source code")

        # Check if URL has vulnerable parameters from SAST
        vulnerable_params = self.sast_findings.get("attack_surface", {}).get("vulnerable_params", [])
        for param_info in vulnerable_params:
            param_name = param_info.get("parameter", "")
            if param_name and param_name in parsed_url.query:
                score += 8
                vuln_type = param_info.get("vuln_type", "unknown")
                reasons.append(f"Contains vulnerable parameter '{param_name}' ({vuln_type})")

        # Check if we have credentials for authenticated testing
        if self._has_credentials_for_domain(parsed_url.netloc):
            score += 5
            reasons.append("Found credentials for authenticated testing")

        # Check if endpoint matches Trivy CVE findings
        trivy_vulns = self.sast_findings.get("sast_results", {}).get("trivy", {}).get("vulnerabilities", [])
        critical_cves = [v for v in trivy_vulns if v.get("severity") == "CRITICAL"]
        if critical_cves:
            score += 7
            reasons.append(f"Target has {len(critical_cves)} critical CVEs")

        return score, reasons

    def _get_sast_context_for_url(self, url: str) -> Dict[str, Any]:
        """Get SAST context for a specific URL"""
        context = {
            "vulnerable_endpoints": [],
            "vulnerable_params": [],
            "related_cves": [],
            "secrets": []
        }

        parsed_url = urlparse(url)
        path = parsed_url.path

        # Find matching endpoints
        endpoints = self.sast_findings.get("attack_surface", {}).get("endpoints", [])
        for endpoint_info in endpoints:
            if self._path_matches(path, endpoint_info.get("endpoint", "")):
                context["vulnerable_endpoints"].append(endpoint_info)

        # Find matching parameters
        vulnerable_params = self.sast_findings.get("attack_surface", {}).get("vulnerable_params", [])
        for param_info in vulnerable_params:
            param_name = param_info.get("parameter", "")
            if param_name and param_name in parsed_url.query:
                context["vulnerable_params"].append(param_info)

        return context

    def _construct_endpoint(self, base_url: str, finding: Dict) -> str:
        """Construct full endpoint URL from SAST finding"""
        endpoint = finding.get("endpoint", "")
        if not endpoint:
            return base_url

        # Ensure endpoint starts with /
        if not endpoint.startswith("/"):
            endpoint = "/" + endpoint

        return urljoin(base_url, endpoint)

    def _map_cve_to_nuclei(self, cve_id: str) -> str:
        """Map CVE ID to Nuclei template path"""
        if not cve_id or not cve_id.startswith("CVE-"):
            return ""

        parts = cve_id.split("-")
        if len(parts) >= 2:
            year = parts[1]
            template_id = cve_id.lower()
            return f"cves/{year}/{template_id}.yaml"

        return ""

    def _is_api_key_or_token(self, secret: Dict) -> bool:
        """Check if secret is an API key or token"""
        secret_type = secret.get("type", "").lower()
        api_indicators = [
            "api", "token", "key", "secret", "bearer",
            "jwt", "oauth", "credential", "password"
        ]
        return any(indicator in secret_type for indicator in api_indicators)

    def _has_credentials_for_domain(self, domain: str) -> bool:
        """Check if we have credentials for a specific domain"""
        secrets = self.sast_findings.get("attack_surface", {}).get("secrets", [])
        return len(secrets) > 0

    def _path_matches(self, discovered_path: str, code_path: str) -> bool:
        """Check if discovered path matches code-defined path"""
        if not code_path:
            return False

        # Exact match
        if discovered_path == code_path:
            return True

        # Normalize paths
        discovered_path = discovered_path.rstrip("/")
        code_path = code_path.rstrip("/")

        # Handle path parameters like /users/{id} or /users/:id
        code_path_pattern = re.sub(r'\{[^}]+\}', r'[^/]+', code_path)
        code_path_pattern = re.sub(r':[^/]+', r'[^/]+', code_path_pattern)
        code_path_pattern = f"^{code_path_pattern}$"

        return bool(re.match(code_path_pattern, discovered_path))

    def _findings_match(self, sast_finding: Dict, dast_result: Dict) -> bool:
        """Check if SAST and DAST findings refer to the same vulnerability"""

        # Match by vulnerability type
        sast_category = sast_finding.get("category", "")
        dast_type = dast_result.get("type", "").lower()

        type_matches = {
            "sqli": ["sql", "injection", "sqli"],
            "xss": ["xss", "cross-site", "script"],
            "command_injection": ["command", "injection", "rce"],
            "path_traversal": ["path", "traversal", "directory"],
            "ssrf": ["ssrf", "server-side"],
        }

        if sast_category in type_matches:
            for keyword in type_matches[sast_category]:
                if keyword in dast_type:
                    return True

        # Match by endpoint/URL
        sast_endpoint = sast_finding.get("endpoint", "")
        dast_url = dast_result.get("url", "")

        if sast_endpoint and dast_url:
            if self._path_matches(urlparse(dast_url).path, sast_endpoint):
                return True

        # Match by parameter name
        sast_param = sast_finding.get("parameter", "")
        dast_param = dast_result.get("parameter", "")

        if sast_param and dast_param and sast_param == dast_param:
            return True

        return False

    def _calculate_correlation_confidence(self, sast_finding: Dict, dast_result: Dict) -> str:
        """Calculate confidence level of SAST/DAST correlation"""

        # High confidence: Type match + Endpoint match + Parameter match
        if (self._type_matches(sast_finding, dast_result) and
            self._endpoint_matches(sast_finding, dast_result) and
            self._parameter_matches(sast_finding, dast_result)):
            return "high"

        # Medium confidence: Type match + (Endpoint OR Parameter match)
        if (self._type_matches(sast_finding, dast_result) and
            (self._endpoint_matches(sast_finding, dast_result) or
             self._parameter_matches(sast_finding, dast_result))):
            return "medium"

        # Low confidence: Only type match
        if self._type_matches(sast_finding, dast_result):
            return "low"

        return "unknown"

    def _type_matches(self, sast_finding: Dict, dast_result: Dict) -> bool:
        """Check if vulnerability types match"""
        return self._findings_match(sast_finding, dast_result)

    def _endpoint_matches(self, sast_finding: Dict, dast_result: Dict) -> bool:
        """Check if endpoints match"""
        sast_endpoint = sast_finding.get("endpoint", "")
        dast_url = dast_result.get("url", "")

        if not sast_endpoint or not dast_url:
            return False

        return self._path_matches(urlparse(dast_url).path, sast_endpoint)

    def _parameter_matches(self, sast_finding: Dict, dast_result: Dict) -> bool:
        """Check if parameters match"""
        sast_param = sast_finding.get("parameter", "")
        dast_param = dast_result.get("parameter", "")

        return sast_param and dast_param and sast_param == dast_param

    def _assess_impact(self, sast_finding: Dict, dast_result: Dict) -> str:
        """Assess impact of confirmed vulnerability"""

        category = sast_finding.get("category", "")

        impact_descriptions = {
            "sqli": "Full database access, data exfiltration, potential remote code execution",
            "xss": "Session hijacking, credential theft, phishing attacks, malware distribution",
            "command_injection": "Remote code execution, system compromise, data exfiltration",
            "path_traversal": "Unauthorized file access, information disclosure, potential code execution",
            "ssrf": "Internal network access, cloud metadata access, port scanning",
            "auth": "Authentication bypass, privilege escalation, unauthorized access",
            "deserialization": "Remote code execution, denial of service",
        }

        return impact_descriptions.get(category, "Security vulnerability confirmed by both static and dynamic analysis")
