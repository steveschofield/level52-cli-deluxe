"""
GitHub Exploit PoC Search Client

Searches GitHub for exploit proof-of-concept repositories.
"""

import requests
from typing import List, Dict, Optional
from time import sleep
from utils.osint.base import OSINTClient


class GitHubPoCSearch(OSINTClient):
    """
    Search GitHub for exploit PoCs

    Requires: GitHub personal access token (optional but recommended)
    Rate limits: 60/hour (no auth), 5000/hour (with token)
    """

    API_URL = "https://api.github.com/search/repositories"

    def __init__(self, config: Dict, logger=None):
        super().__init__(config, logger)
        gh_config = config.get("osint", {}).get("sources", {}).get("github", {})
        self.token = gh_config.get("token", None)
        self.min_stars = gh_config.get("min_stars", 10)
        self.max_results = gh_config.get("max_results", 5)
        self.timeout = gh_config.get("timeout", 10)

    def _get_enabled_status(self) -> bool:
        """Check if GitHub PoC search is enabled"""
        return self.config.get("osint", {}).get("sources", {}).get("github", {}).get("enabled", True)

    def search_exploits(self, cve_id: str) -> List[Dict]:
        """
        Search GitHub for exploit PoCs for a CVE

        Args:
            cve_id: CVE identifier (e.g., "CVE-2017-0143")

        Returns:
            List of GitHub repository dicts with name, url, stars, etc.
        """
        if not self.enabled:
            return []

        # Build search query
        query = f'"{cve_id}" (exploit OR poc OR vulnerability) language:python OR language:ruby OR language:go OR language:c'

        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Guardian-OSINT/1.0"
        }
        if self.token:
            headers["Authorization"] = f"token {self.token}"

        params = {
            "q": query,
            "sort": "stars",
            "order": "desc",
            "per_page": min(self.max_results * 2, 30),  # Get extra in case we filter some
        }

        try:
            response = requests.get(
                self.API_URL,
                headers=headers,
                params=params,
                timeout=self.timeout
            )

            # Check rate limit
            if response.status_code == 403:
                rate_limit_remaining = response.headers.get("X-RateLimit-Remaining", "0")
                if rate_limit_remaining == "0":
                    self.log_warning(f"GitHub API rate limit exceeded for {cve_id}")
                    return []

            response.raise_for_status()
            data = response.json()

            pocs = []
            for repo in data.get("items", []):
                # Filter by minimum stars
                stars = repo.get("stargazers_count", 0)
                if stars < self.min_stars:
                    continue

                pocs.append({
                    "name": repo.get("full_name"),
                    "url": repo.get("html_url"),
                    "description": repo.get("description", "")[:200],  # Limit description length
                    "stars": stars,
                    "language": repo.get("language"),
                    "updated_at": repo.get("updated_at"),
                    "created_at": repo.get("created_at"),
                })

                if len(pocs) >= self.max_results:
                    break

            if pocs:
                self.log_info(f"Found {len(pocs)} GitHub PoCs for {cve_id}")

            return pocs

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                self.log_warning(f"GitHub API rate limit hit for {cve_id}")
            elif e.response.status_code == 422:
                self.log_debug(f"GitHub API query error for {cve_id} (query too complex)")
            else:
                self.log_error(f"GitHub API HTTP error for {cve_id}: {e}")
            return []

        except requests.exceptions.Timeout:
            self.log_warning(f"GitHub API timeout for {cve_id}")
            return []

        except Exception as e:
            self.log_error(f"GitHub PoC search failed for {cve_id}: {e}")
            return []

    def search_multiple(self, cve_ids: List[str], delay: float = 1.0) -> Dict[str, List[Dict]]:
        """
        Search for multiple CVEs with rate limiting

        Args:
            cve_ids: List of CVE identifiers
            delay: Delay between requests in seconds

        Returns:
            Dict mapping CVE ID to list of PoCs
        """
        results = {}
        for i, cve_id in enumerate(cve_ids):
            results[cve_id] = self.search_exploits(cve_id)

            # Add delay between requests to respect rate limits
            if i < len(cve_ids) - 1 and results[cve_id]:  # Only delay if we got results
                sleep(delay)

        return results

    def get_rate_limit_info(self) -> Optional[Dict]:
        """
        Get current GitHub API rate limit status

        Returns:
            Dict with rate limit info or None if unavailable
        """
        if not self.enabled:
            return None

        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Guardian-OSINT/1.0"
        }
        if self.token:
            headers["Authorization"] = f"token {self.token}"

        try:
            response = requests.get(
                "https://api.github.com/rate_limit",
                headers=headers,
                timeout=5
            )
            response.raise_for_status()
            data = response.json()

            search_limit = data.get("resources", {}).get("search", {})
            return {
                "limit": search_limit.get("limit"),
                "remaining": search_limit.get("remaining"),
                "reset": search_limit.get("reset"),
            }

        except Exception as e:
            self.log_debug(f"Failed to get GitHub rate limit info: {e}")
            return None
