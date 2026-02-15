"""
EPSS (Exploit Prediction Scoring System) Client

Provides exploitation probability predictions from FIRST.org EPSS API.
"""

import requests
from typing import Dict, List, Optional
from utils.osint.base import OSINTClient


class EPSSClient(OSINTClient):
    """
    Query EPSS for exploitation probability scores

    EPSS provides daily probability scores (0-1) that a CVE will be exploited
    in the next 30 days, along with percentile rankings.

    API: https://api.first.org/data/v1/epss
    No authentication required, free to use
    """

    API_URL = "https://api.first.org/data/v1/epss"

    def __init__(self, config: Dict, logger=None):
        super().__init__(config, logger)
        epss_config = config.get("osint", {}).get("sources", {}).get("epss", {})
        self.timeout = epss_config.get("timeout", 10)
        self.high_risk_threshold = epss_config.get("high_risk_threshold", 0.7)

    def _get_enabled_status(self) -> bool:
        """Check if EPSS is enabled"""
        return self.config.get("osint", {}).get("sources", {}).get("epss", {}).get("enabled", True)

    def get_scores(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """
        Get EPSS scores for CVE IDs

        Args:
            cve_ids: List of CVE identifiers

        Returns:
            Dict mapping CVE ID to EPSS data with keys:
                - epss: probability score (0-1)
                - percentile: percentile ranking (0-1)
                - date: date of score calculation
                - risk_level: "critical", "high", "medium", "low"
        """
        if not self.enabled or not cve_ids:
            return {}

        # EPSS API accepts comma-separated CVE IDs
        cve_param = ",".join(cve_ids)

        params = {
            "cve": cve_param
        }

        headers = {
            "Accept": "application/json",
            "User-Agent": "Guardian-OSINT/1.0"
        }

        try:
            response = requests.get(
                self.API_URL,
                params=params,
                headers=headers,
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()

            results = {}
            for item in data.get("data", []):
                cve_id = item.get("cve", "").upper()
                epss_score = float(item.get("epss", 0))
                percentile = float(item.get("percentile", 0))

                # Determine risk level based on EPSS score
                if epss_score >= 0.7:
                    risk_level = "critical"
                elif epss_score >= 0.4:
                    risk_level = "high"
                elif epss_score >= 0.1:
                    risk_level = "medium"
                else:
                    risk_level = "low"

                results[cve_id] = {
                    "epss": epss_score,
                    "percentile": percentile,
                    "date": item.get("date"),
                    "risk_level": risk_level,
                    "epss_percentage": f"{epss_score * 100:.2f}%",
                    "percentile_rank": f"{percentile * 100:.1f}th"
                }

            if results:
                self.log_info(f"Retrieved EPSS scores for {len(results)} CVEs")

            return results

        except requests.exceptions.HTTPError as e:
            self.log_error(f"EPSS API HTTP error: {e}")
            return {}

        except requests.exceptions.Timeout:
            self.log_warning("EPSS API timeout")
            return {}

        except Exception as e:
            self.log_error(f"EPSS query failed: {e}")
            return {}

    def get_score(self, cve_id: str) -> Optional[Dict]:
        """
        Get EPSS score for a single CVE

        Args:
            cve_id: CVE identifier

        Returns:
            EPSS data dict or None if not found
        """
        results = self.get_scores([cve_id])
        return results.get(cve_id.upper())

    def get_high_risk_cves(self, cve_ids: List[str]) -> List[str]:
        """
        Filter CVEs to those with high exploitation probability

        Args:
            cve_ids: List of CVE identifiers

        Returns:
            List of high-risk CVE IDs (EPSS >= threshold)
        """
        scores = self.get_scores(cve_ids)
        high_risk = []

        for cve_id, data in scores.items():
            if data.get("epss", 0) >= self.high_risk_threshold:
                high_risk.append(cve_id)

        return high_risk
