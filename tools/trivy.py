from typing import List, Dict, Any
from tools.base_tool import BaseTool
import json
import os

class TrivyTool(BaseTool):
    """Wrapper for Trivy - Comprehensive vulnerability scanner for containers, filesystems, and IaC"""

    def get_command(self, target: str, **kwargs) -> List[str]:
        """
        Generate Trivy command for vulnerability scanning

        Args:
            target: Path to source code, container image, or config directory
            **kwargs: Additional options
                - scan_type: Type of scan (fs, config, image) - default: fs
                - scanners: List of scanners to run (vuln, config, secret) - default: all
                - severity: List of severities (CRITICAL, HIGH, MEDIUM, LOW) - default: all
        """
        # Determine scan type
        scan_type = kwargs.get("scan_type", "fs")

        cmd = ["trivy", scan_type]

        # Output format
        cmd.extend(["--format", "json"])

        # Scanners to run
        scanners = kwargs.get("scanners", ["vuln", "config", "secret"])
        if scanners:
            scanners_str = ",".join(scanners)
            cmd.extend(["--scanners", scanners_str])

        # Severity filter
        severity = kwargs.get("severity", ["CRITICAL", "HIGH", "MEDIUM"])
        if severity:
            if isinstance(severity, list):
                severity_str = ",".join(severity)
            else:
                severity_str = severity
            cmd.extend(["--severity", severity_str])

        # Skip files that fail to scan
        cmd.append("--skip-files")
        cmd.append("**/*.{min.js,bundle.js}")

        # Disable progress bar for cleaner output
        cmd.append("--quiet")

        # Output file
        self.output_file = f"trivy_{self._get_timestamp()}.json"
        cmd.extend(["-o", self.output_file])

        # Target
        cmd.append(target)

        return cmd

    def parse_output(self, output: str) -> Dict[str, Any]:
        """
        Parse Trivy JSON output

        Returns structured findings with:
        - CVE vulnerabilities with severity
        - Misconfigurations
        - Exposed secrets
        - Package information
        - Nuclei template mappings
        """
        result = {
            "vulnerabilities": [],
            "misconfigurations": [],
            "secrets": [],
            "summary": {
                "total_vulns": 0,
                "total_misconfigs": 0,
                "total_secrets": 0,
                "by_severity": {},
                "critical_cves": [],
            },
            "nuclei_templates": [],  # CVE IDs that can be tested with Nuclei
            "raw_output": output
        }

        if not os.path.exists(self.output_file):
            self.logger.warning(f"Trivy output file not found: {self.output_file}")
            return result

        try:
            with open(self.output_file, 'r') as f:
                data = json.load(f)

            # Trivy outputs results per target
            for target_result in data.get("Results", []):
                # Process vulnerabilities
                vulns = target_result.get("Vulnerabilities", [])
                for vuln in vulns:
                    parsed_vuln = self._parse_vulnerability(vuln, target_result)
                    result["vulnerabilities"].append(parsed_vuln)

                    # Update summary
                    result["summary"]["total_vulns"] += 1

                    severity = parsed_vuln["severity"]
                    result["summary"]["by_severity"][severity] = \
                        result["summary"]["by_severity"].get(severity, 0) + 1

                    # Track critical CVEs
                    if severity == "CRITICAL":
                        result["summary"]["critical_cves"].append(parsed_vuln["cve_id"])

                    # Map to Nuclei template if possible
                    nuclei_template = self._map_cve_to_nuclei_template(parsed_vuln["cve_id"])
                    if nuclei_template:
                        result["nuclei_templates"].append(nuclei_template)

                # Process misconfigurations
                misconfigs = target_result.get("Misconfigurations", [])
                for misconfig in misconfigs:
                    parsed_misconfig = self._parse_misconfiguration(misconfig, target_result)
                    result["misconfigurations"].append(parsed_misconfig)
                    result["summary"]["total_misconfigs"] += 1

                # Process secrets
                secrets = target_result.get("Secrets", [])
                for secret in secrets:
                    parsed_secret = self._parse_secret(secret, target_result)
                    result["secrets"].append(parsed_secret)
                    result["summary"]["total_secrets"] += 1

            # Cleanup output file
            os.remove(self.output_file)

        except Exception as e:
            self.logger.error(f"Error parsing Trivy output: {e}")

        return result

    def _parse_vulnerability(self, vuln: Dict, target_result: Dict) -> Dict[str, Any]:
        """Parse individual vulnerability finding"""

        return {
            "cve_id": vuln.get("VulnerabilityID", ""),
            "package_name": vuln.get("PkgName", ""),
            "installed_version": vuln.get("InstalledVersion", ""),
            "fixed_version": vuln.get("FixedVersion", ""),
            "severity": vuln.get("Severity", "UNKNOWN"),
            "title": vuln.get("Title", ""),
            "description": vuln.get("Description", ""),
            "references": vuln.get("References", []),
            "published_date": vuln.get("PublishedDate", ""),
            "last_modified_date": vuln.get("LastModifiedDate", ""),
            "cvss_score": self._extract_cvss_score(vuln),
            "target": target_result.get("Target", ""),
            "type": target_result.get("Type", ""),
        }

    def _parse_misconfiguration(self, misconfig: Dict, target_result: Dict) -> Dict[str, Any]:
        """Parse infrastructure-as-code misconfiguration"""

        return {
            "id": misconfig.get("ID", ""),
            "title": misconfig.get("Title", ""),
            "description": misconfig.get("Description", ""),
            "severity": misconfig.get("Severity", "UNKNOWN"),
            "message": misconfig.get("Message", ""),
            "resolution": misconfig.get("Resolution", ""),
            "references": misconfig.get("References", []),
            "file": misconfig.get("CauseMetadata", {}).get("Resource", ""),
            "line": misconfig.get("CauseMetadata", {}).get("StartLine", 0),
            "target": target_result.get("Target", ""),
        }

    def _parse_secret(self, secret: Dict, target_result: Dict) -> Dict[str, Any]:
        """Parse exposed secret finding"""

        return {
            "rule_id": secret.get("RuleID", ""),
            "category": secret.get("Category", ""),
            "title": secret.get("Title", ""),
            "severity": secret.get("Severity", "HIGH"),
            "file": secret.get("StartLine", 0),
            "line": secret.get("StartLine", 0),
            "end_line": secret.get("EndLine", 0),
            "code": secret.get("Code", {}).get("Lines", []),
            "match": secret.get("Match", ""),
            "target": target_result.get("Target", ""),
        }

    def _extract_cvss_score(self, vuln: Dict) -> float:
        """Extract CVSS score from vulnerability data"""

        # Try CVSS v3 first
        cvss_v3 = vuln.get("CVSS", {})
        if cvss_v3:
            for vendor, data in cvss_v3.items():
                if isinstance(data, dict) and "V3Score" in data:
                    return data["V3Score"]

        # Fallback to CVSS v2
        cvss_v2 = vuln.get("CVSS", {})
        if cvss_v2:
            for vendor, data in cvss_v2.items():
                if isinstance(data, dict) and "V2Score" in data:
                    return data["V2Score"]

        return 0.0

    def _map_cve_to_nuclei_template(self, cve_id: str) -> str:
        """
        Map CVE ID to Nuclei template path

        Nuclei templates follow pattern: cves/YEAR/CVE-YEAR-XXXXX.yaml
        """
        if not cve_id or not cve_id.startswith("CVE-"):
            return ""

        # Extract year from CVE-YYYY-XXXXX
        parts = cve_id.split("-")
        if len(parts) >= 2:
            year = parts[1]
            template_id = cve_id.lower()

            # Nuclei template path
            return f"cves/{year}/{template_id}.yaml"

        return ""

    def _get_timestamp(self) -> int:
        """Get current timestamp for unique filenames"""
        import time
        return int(time.time())
