"""
OSV (Open Source Vulnerabilities) Client

Queries the OSV database for open source package vulnerabilities.
"""

import requests
from typing import Dict, List, Optional
from utils.osint.base import OSINTClient


class OSVClient(OSINTClient):
    """
    Query OSV for open source package vulnerabilities

    OSV is a distributed vulnerability database for open source,
    aggregating data from:
    - GitHub Security Advisories
    - Python PyPI advisories
    - Go vulndb
    - RustSec
    - And many more ecosystems

    API: https://api.osv.dev/v1/
    No authentication required, free to use
    """

    API_URL = "https://api.osv.dev/v1"

    def __init__(self, config: Dict, logger=None):
        super().__init__(config, logger)
        osv_config = config.get("osint", {}).get("sources", {}).get("osv", {})
        self.timeout = osv_config.get("timeout", 10)
        self.include_aliases = osv_config.get("include_aliases", True)

    def _get_enabled_status(self) -> bool:
        """Check if OSV is enabled"""
        return self.config.get("osint", {}).get("sources", {}).get("osv", {}).get("enabled", True)

    def query_by_cve(self, cve_id: str) -> Optional[Dict]:
        """
        Query OSV by CVE ID

        Args:
            cve_id: CVE identifier

        Returns:
            Vulnerability data dict or None if not found
        """
        if not self.enabled:
            return None

        headers = {
            "Accept": "application/json",
            "User-Agent": "Guardian-OSINT/1.0"
        }

        try:
            # OSV uses vulnerability ID endpoint
            response = requests.get(
                f"{self.API_URL}/vulns/{cve_id}",
                headers=headers,
                timeout=self.timeout
            )

            if response.status_code == 404:
                self.log_debug(f"No OSV data for {cve_id}")
                return None

            response.raise_for_status()
            data = response.json()

            # Extract relevant information
            result = {
                "id": data.get("id"),
                "summary": data.get("summary", ""),
                "details": data.get("details", ""),
                "aliases": data.get("aliases", []),
                "modified": data.get("modified"),
                "published": data.get("published"),
                "database_specific": data.get("database_specific", {}),
                "url": f"https://osv.dev/vulnerability/{data.get('id')}",
            }

            # Extract affected packages and ecosystems
            affected = []
            for pkg in data.get("affected", []):
                package = pkg.get("package", {})
                affected.append({
                    "ecosystem": package.get("ecosystem"),
                    "name": package.get("name"),
                    "purl": package.get("purl"),
                })

            result["affected_packages"] = affected

            # Extract severity if available
            severity_list = data.get("severity", [])
            if severity_list:
                result["severity"] = severity_list[0].get("score")  # CVSS score
                result["severity_type"] = severity_list[0].get("type")

            # Extract references
            references = []
            for ref in data.get("references", []):
                references.append({
                    "url": ref.get("url"),
                    "type": ref.get("type"),
                })
            result["references"] = references

            self.log_info(f"Found OSV data for {cve_id}")
            return result

        except requests.exceptions.HTTPError as e:
            if e.response.status_code != 404:
                self.log_error(f"OSV API HTTP error for {cve_id}: {e}")
            return None

        except requests.exceptions.Timeout:
            self.log_warning(f"OSV API timeout for {cve_id}")
            return None

        except Exception as e:
            self.log_error(f"OSV query failed for {cve_id}: {e}")
            return None

    def query_by_package(self, ecosystem: str, package: str, version: Optional[str] = None) -> List[Dict]:
        """
        Query OSV by package name and version

        Args:
            ecosystem: Package ecosystem (e.g., "PyPI", "npm", "Go")
            package: Package name
            version: Specific version (optional)

        Returns:
            List of vulnerability dicts
        """
        if not self.enabled:
            return []

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "Guardian-OSINT/1.0"
        }

        payload = {
            "package": {
                "ecosystem": ecosystem,
                "name": package,
            }
        }

        if version:
            payload["version"] = version

        try:
            response = requests.post(
                f"{self.API_URL}/query",
                json=payload,
                headers=headers,
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()

            vulns = data.get("vulns", [])

            self.log_info(f"Found {len(vulns)} OSV vulnerabilities for {ecosystem}/{package}")
            return vulns

        except requests.exceptions.HTTPError as e:
            self.log_error(f"OSV API HTTP error for {package}: {e}")
            return []

        except requests.exceptions.Timeout:
            self.log_warning(f"OSV API timeout for {package}")
            return []

        except Exception as e:
            self.log_error(f"OSV query failed for {package}: {e}")
            return []

    def batch_query(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """
        Query multiple CVEs from OSV

        Args:
            cve_ids: List of CVE identifiers

        Returns:
            Dict mapping CVE ID to vulnerability data
        """
        results = {}

        for cve_id in cve_ids:
            vuln_data = self.query_by_cve(cve_id)
            if vuln_data:
                results[cve_id] = vuln_data

        return results

    def get_affected_ecosystems(self, cve_id: str) -> List[str]:
        """
        Get list of affected package ecosystems for a CVE

        Args:
            cve_id: CVE identifier

        Returns:
            List of ecosystem names
        """
        vuln_data = self.query_by_cve(cve_id)
        if not vuln_data:
            return []

        ecosystems = set()
        for pkg in vuln_data.get("affected_packages", []):
            ecosystem = pkg.get("ecosystem")
            if ecosystem:
                ecosystems.add(ecosystem)

        return list(ecosystems)
