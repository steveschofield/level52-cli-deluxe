"""
OSINT Enricher - Main orchestrator for vulnerability intelligence gathering
"""

from typing import Dict, List, Any
from core.memory import Finding
from utils.osint.cisa_kev import CISAKEVClient
from utils.osint.github_pocs import GitHubPoCSearch
from utils.osint.epss import EPSSClient
from utils.osint.osv import OSVClient


class OSINTEnricher:
    """
    Orchestrates multiple OSINT sources to enrich vulnerability findings

    Integrates:
    - CISA KEV: Known exploited vulnerabilities
    - GitHub: Community exploit PoCs
    - EPSS: Exploitation probability predictions
    - OSV: Open source package vulnerabilities
    """

    def __init__(self, config: Dict[str, Any], logger=None):
        self.config = config
        self.logger = logger
        self.enabled = config.get("osint", {}).get("enabled", True)

        if not self.enabled:
            if logger:
                logger.info("OSINT enrichment disabled")
            return

        # Initialize OSINT clients
        self.cisa_kev = CISAKEVClient(config, logger)
        self.github = GitHubPoCSearch(config, logger)
        self.epss = EPSSClient(config, logger)
        self.osv = OSVClient(config, logger)

        if logger:
            enabled_sources = []
            if self.cisa_kev.enabled:
                enabled_sources.append("CISA KEV")
            if self.github.enabled:
                enabled_sources.append("GitHub")
            if self.epss.enabled:
                enabled_sources.append("EPSS")
            if self.osv.enabled:
                enabled_sources.append("OSV")

            if enabled_sources:
                logger.info(f"OSINT enrichment enabled: {', '.join(enabled_sources)}")
            else:
                logger.warning("OSINT enabled but no sources configured")

    def enrich_findings(self, findings: List[Finding]) -> Dict[str, Any]:
        """
        Enrich multiple findings with OSINT intelligence

        Args:
            findings: List of Finding objects

        Returns:
            Dict with enrichment data keyed by finding ID
        """
        if not self.enabled:
            return {}

        enrichment_data = {}

        # Collect all unique CVEs from findings
        all_cves = set()
        for finding in findings:
            if finding.cve_ids:
                all_cves.update(finding.cve_ids)

        if not all_cves:
            if self.logger:
                self.logger.debug("No CVEs found in findings for OSINT enrichment")
            return {}

        if self.logger:
            self.logger.info(f"Enriching {len(findings)} findings with {len(all_cves)} unique CVEs")

        # Process each finding
        for finding in findings:
            if not finding.cve_ids:
                continue

            finding_enrichment = {
                "cve_data": {},
                "kev_status": {},
                "github_pocs": [],
                "epss_scores": {},
                "osv_data": {},
            }

            # Enrich each CVE in the finding
            for cve_id in finding.cve_ids:
                # CISA KEV lookup (critical priority indicator)
                if self.cisa_kev.enabled:
                    kev_entry = self.cisa_kev.lookup(cve_id)
                    if kev_entry:
                        finding_enrichment["kev_status"][cve_id] = kev_entry

                # OSV lookup
                if self.osv.enabled:
                    osv_data = self.osv.query_by_cve(cve_id)
                    if osv_data:
                        finding_enrichment["osv_data"][cve_id] = osv_data

            # GitHub PoC search (search across all CVEs in finding)
            if self.github.enabled and finding.cve_ids:
                # Search for the first CVE (most relevant)
                primary_cve = finding.cve_ids[0]
                pocs = self.github.search_exploits(primary_cve)
                if pocs:
                    finding_enrichment["github_pocs"] = pocs

            # EPSS scores (batch lookup for all CVEs)
            if self.epss.enabled and finding.cve_ids:
                epss_scores = self.epss.get_scores(finding.cve_ids)
                if epss_scores:
                    finding_enrichment["epss_scores"] = epss_scores

            # Only add enrichment if we found something
            if any([
                finding_enrichment["kev_status"],
                finding_enrichment["github_pocs"],
                finding_enrichment["epss_scores"],
                finding_enrichment["osv_data"]
            ]):
                enrichment_data[finding.id] = finding_enrichment

        if self.logger:
            enriched_count = len(enrichment_data)
            self.logger.info(f"Enriched {enriched_count}/{len(findings)} findings with OSINT data")

        return enrichment_data

    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary statistics about OSINT sources

        Returns:
            Dict with summary info from each source
        """
        summary = {
            "enabled": self.enabled,
            "sources": {}
        }

        if not self.enabled:
            return summary

        # CISA KEV summary
        if self.cisa_kev.enabled:
            summary["sources"]["cisa_kev"] = self.cisa_kev.get_summary()

        # GitHub rate limit info
        if self.github.enabled:
            rate_limit = self.github.get_rate_limit_info()
            if rate_limit:
                summary["sources"]["github"] = {
                    "rate_limit_remaining": rate_limit.get("remaining"),
                    "rate_limit_total": rate_limit.get("limit"),
                }

        # EPSS status
        if self.epss.enabled:
            summary["sources"]["epss"] = {
                "enabled": True
            }

        # OSV status
        if self.osv.enabled:
            summary["sources"]["osv"] = {
                "enabled": True
            }

        return summary

    def check_cve_kev_status(self, cve_ids: List[str]) -> Dict[str, bool]:
        """
        Quick check if CVEs are in CISA KEV catalog

        Args:
            cve_ids: List of CVE identifiers

        Returns:
            Dict mapping CVE ID to KEV status (True/False)
        """
        if not self.enabled or not self.cisa_kev.enabled:
            return {cve_id: False for cve_id in cve_ids}

        return {cve_id: self.cisa_kev.is_kev(cve_id) for cve_id in cve_ids}
