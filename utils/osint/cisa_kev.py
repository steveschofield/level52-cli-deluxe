"""
CISA Known Exploited Vulnerabilities (KEV) Catalog Client

Checks if CVEs are actively exploited in the wild according to CISA.
"""

import json
import requests
from pathlib import Path
from typing import Dict, Optional, List
from datetime import datetime, timedelta
from utils.osint.base import OSINTClient


class CISAKEVClient(OSINTClient):
    """
    Client for CISA Known Exploited Vulnerabilities Catalog

    Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
    """

    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    CACHE_FILE = Path.home() / ".guardian" / "cache" / "cisa_kev.json"
    DEFAULT_CACHE_TTL_HOURS = 24

    def __init__(self, config: Dict, logger=None):
        super().__init__(config, logger)
        self.cache_ttl_hours = config.get("osint", {}).get("sources", {}).get("cisa_kev", {}).get("cache_ttl_hours", self.DEFAULT_CACHE_TTL_HOURS)
        self.kev_data = None

        if self.enabled:
            self._load_kev_data()

    def _get_enabled_status(self) -> bool:
        """Check if CISA KEV is enabled"""
        return self.config.get("osint", {}).get("sources", {}).get("cisa_kev", {}).get("enabled", True)

    def _load_kev_data(self):
        """Load KEV data from cache or fetch fresh"""
        # Check cache first
        if self.CACHE_FILE.exists():
            cache_age = datetime.now() - datetime.fromtimestamp(self.CACHE_FILE.stat().st_mtime)
            if cache_age < timedelta(hours=self.cache_ttl_hours):
                try:
                    with open(self.CACHE_FILE, 'r', encoding='utf-8') as f:
                        self.kev_data = json.load(f)
                    vuln_count = len(self.kev_data.get('vulnerabilities', []))
                    self.log_info(f"Loaded CISA KEV from cache ({vuln_count} entries)")
                    return
                except Exception as e:
                    self.log_warning(f"Failed to load KEV cache: {e}")

        # Fetch fresh data
        try:
            self.log_info("Fetching CISA KEV catalog...")
            response = requests.get(self.KEV_URL, timeout=30)
            response.raise_for_status()
            self.kev_data = response.json()

            # Save to cache
            self.CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(self.CACHE_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.kev_data, f, indent=2)

            vuln_count = len(self.kev_data.get("vulnerabilities", []))
            catalog_version = self.kev_data.get("catalogVersion", "Unknown")
            self.log_info(f"Fetched CISA KEV catalog v{catalog_version} ({vuln_count} entries)")

        except requests.exceptions.RequestException as e:
            self.log_error(f"Failed to fetch CISA KEV: {e}")
            self.kev_data = {"vulnerabilities": []}
        except Exception as e:
            self.log_error(f"Unexpected error loading CISA KEV: {e}")
            self.kev_data = {"vulnerabilities": []}

    def lookup(self, cve_id: str) -> Optional[Dict]:
        """
        Check if CVE is in CISA KEV catalog

        Args:
            cve_id: CVE identifier (e.g., "CVE-2017-0143")

        Returns:
            KEV entry dict if found, None otherwise
        """
        if not self.enabled or not self.kev_data:
            return None

        cve_upper = cve_id.upper()
        for vuln in self.kev_data.get("vulnerabilities", []):
            if vuln.get("cveID", "").upper() == cve_upper:
                return {
                    "cve_id": vuln.get("cveID"),
                    "vendor": vuln.get("vendorProject"),
                    "product": vuln.get("product"),
                    "name": vuln.get("vulnerabilityName"),
                    "description": vuln.get("shortDescription"),
                    "date_added": vuln.get("dateAdded"),
                    "due_date": vuln.get("dueDate"),
                    "required_action": vuln.get("requiredAction"),
                    "ransomware_use": vuln.get("knownRansomwareCampaignUse") == "Known",
                    "notes": vuln.get("notes"),
                }

        return None

    def is_kev(self, cve_id: str) -> bool:
        """Quick check if CVE is in KEV catalog"""
        return self.lookup(cve_id) is not None

    def get_summary(self) -> Dict:
        """Get KEV catalog statistics"""
        if not self.kev_data:
            return {"total": 0, "catalog_version": None, "ransomware_associated": 0}

        vulnerabilities = self.kev_data.get("vulnerabilities", [])
        ransomware_count = sum(1 for v in vulnerabilities if v.get("knownRansomwareCampaignUse") == "Known")

        return {
            "total": len(vulnerabilities),
            "catalog_version": self.kev_data.get("catalogVersion"),
            "date_released": self.kev_data.get("dateReleased"),
            "ransomware_associated": ransomware_count,
        }

    def get_all_cves(self) -> List[str]:
        """Get list of all CVE IDs in KEV catalog"""
        if not self.kev_data:
            return []
        return [v.get("cveID") for v in self.kev_data.get("vulnerabilities", []) if v.get("cveID")]
