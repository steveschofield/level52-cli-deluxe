"""
CVSS handling utilities for validation and scoring.
"""

from dataclasses import dataclass
from enum import Enum
import re
from typing import Optional, Dict, Tuple

from utils.logger import get_logger


class CVSSVersion(Enum):
    """CVSS version."""
    V2 = "2.0"
    V3_0 = "3.0"
    V3_1 = "3.1"
    UNKNOWN = "unknown"


@dataclass
class CVSSScore:
    """CVSS score with metadata."""
    base_score: float
    vector: Optional[str]
    version: CVSSVersion
    source: str
    temporal_score: Optional[float] = None
    environmental_score: Optional[float] = None

    def __str__(self) -> str:
        suffix = " (est.)" if self.source == "estimated" else ""
        version_str = f"v{self.version.value}" if self.version != CVSSVersion.UNKNOWN else ""
        if self.vector:
            return f"{self.base_score:.1f}{suffix} {version_str} ({self.vector})"
        return f"{self.base_score:.1f}{suffix} {version_str}"

    def to_dict(self) -> Dict:
        return {
            "base_score": self.base_score,
            "vector": self.vector,
            "version": self.version.value,
            "source": self.source,
            "temporal_score": self.temporal_score,
            "environmental_score": self.environmental_score,
        }


class CVSSHandler:
    """CVSS validation and scoring helper."""

    CVSS_V3_PATTERN = re.compile(
        r"^(CVSS:3\.[01]/)?AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]$",
        re.IGNORECASE,
    )
    CVSS_V2_PATTERN = re.compile(
        r"\bAV:[LAN]/AC:[HML]/Au:[MSN]/C:[NPC]/I:[NPC]/A:[NPC]\b",
        re.IGNORECASE,
    )

    SEVERITY_RATINGS_V3 = {
        (0.0, 0.0): "None",
        (0.1, 3.9): "Low",
        (4.0, 6.9): "Medium",
        (7.0, 8.9): "High",
        (9.0, 10.0): "Critical",
    }
    SEVERITY_RATINGS_V2 = {
        (0.0, 3.9): "Low",
        (4.0, 6.9): "Medium",
        (7.0, 10.0): "High",
    }

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.logger = get_logger(self.config)

    def validate_vector(self, vector: str) -> Tuple[bool, Optional[CVSSVersion], Optional[str]]:
        if not vector:
            return False, None, "Empty vector string"

        vector = vector.strip()
        if self.CVSS_V3_PATTERN.match(vector):
            if vector.startswith("CVSS:3.0/"):
                return True, CVSSVersion.V3_0, None
            if vector.startswith("CVSS:3.1/"):
                return True, CVSSVersion.V3_1, None
            return True, CVSSVersion.V3_1, None

        if self.CVSS_V2_PATTERN.search(vector):
            return True, CVSSVersion.V2, None

        return False, CVSSVersion.UNKNOWN, "Unknown CVSS version or invalid format"

    def calculate_score_from_vector(self, vector: str) -> Optional[CVSSScore]:
        is_valid, version, error = self.validate_vector(vector)
        if not is_valid:
            self.logger.warning(f"Invalid CVSS vector: {error}")
            return None

        try:
            if version in (CVSSVersion.V3_0, CVSSVersion.V3_1):
                score = self._calculate_v3_score(vector)
            elif version == CVSSVersion.V2:
                score = self._calculate_v2_score(vector)
            else:
                return None

            return CVSSScore(
                base_score=score,
                vector=vector,
                version=version,
                source="calculated",
            )
        except Exception as exc:
            self.logger.error(f"Error calculating CVSS score: {exc}")
            return None

    def _calculate_v3_score(self, vector: str) -> float:
        text = vector.strip()
        if text.startswith("CVSS:3.0/"):
            text = text[len("CVSS:3.0/"):]
        elif text.startswith("CVSS:3.1/"):
            text = text[len("CVSS:3.1/"):]

        components: Dict[str, str] = {}
        for part in text.split("/"):
            if ":" not in part:
                continue
            key, value = part.split(":", 1)
            components[key] = value

        impact_base = 1 - (
            (1 - self._get_impact_value("C", components["C"]))
            * (1 - self._get_impact_value("I", components["I"]))
            * (1 - self._get_impact_value("A", components["A"]))
        )

        if components["S"] == "U":
            impact = 6.42 * impact_base
        else:
            impact = 7.52 * (impact_base - 0.029) - 3.25 * pow(impact_base - 0.02, 15)

        exploitability = (
            8.22
            * self._get_exploit_value("AV", components["AV"])
            * self._get_exploit_value("AC", components["AC"])
            * self._get_exploit_value("PR", components["PR"], components["S"])
            * self._get_exploit_value("UI", components["UI"])
        )

        if impact <= 0:
            return 0.0

        if components["S"] == "U":
            base_score = min(impact + exploitability, 10.0)
        else:
            base_score = min(1.08 * (impact + exploitability), 10.0)

        return round(base_score * 10) / 10

    def _calculate_v2_score(self, vector: str) -> float:
        match = self.CVSS_V2_PATTERN.search(vector)
        if not match:
            raise ValueError("Invalid CVSS v2 vector")

        vector_str = match.group(0)
        components: Dict[str, str] = {}
        for part in vector_str.split("/"):
            key, value = part.split(":", 1)
            components[key] = value

        impact = 10.41 * (
            1
            - (1 - self._get_v2_impact("C", components["C"]))
            * (1 - self._get_v2_impact("I", components["I"]))
            * (1 - self._get_v2_impact("A", components["A"]))
        )

        exploitability = (
            20
            * self._get_v2_exploit("AV", components["AV"])
            * self._get_v2_exploit("AC", components["AC"])
            * self._get_v2_exploit("Au", components["Au"])
        )

        f_impact = 0 if impact == 0 else 1.176
        base_score = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact
        return round(base_score * 10) / 10

    def _get_impact_value(self, metric: str, value: str) -> float:
        values = {
            "C": {"N": 0.0, "L": 0.22, "H": 0.56},
            "I": {"N": 0.0, "L": 0.22, "H": 0.56},
            "A": {"N": 0.0, "L": 0.22, "H": 0.56},
        }
        return values.get(metric, {}).get(value, 0.0)

    def _get_exploit_value(self, metric: str, value: str, scope: str = "U") -> float:
        values = {
            "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
            "AC": {"L": 0.77, "H": 0.44},
            "PR": {
                "U": {"N": 0.85, "L": 0.62, "H": 0.27},
                "C": {"N": 0.85, "L": 0.68, "H": 0.5},
            },
            "UI": {"N": 0.85, "R": 0.62},
        }
        if metric == "PR":
            return values["PR"].get(scope, {}).get(value, 0.0)
        return values.get(metric, {}).get(value, 0.0)

    def _get_v2_impact(self, metric: str, value: str) -> float:
        values = {
            "C": {"N": 0.0, "P": 0.275, "C": 0.660},
            "I": {"N": 0.0, "P": 0.275, "C": 0.660},
            "A": {"N": 0.0, "P": 0.275, "C": 0.660},
        }
        return values.get(metric, {}).get(value, 0.0)

    def _get_v2_exploit(self, metric: str, value: str) -> float:
        values = {
            "AV": {"L": 0.395, "A": 0.646, "N": 1.0},
            "AC": {"H": 0.35, "M": 0.61, "L": 0.71},
            "Au": {"M": 0.45, "S": 0.56, "N": 0.704},
        }
        return values.get(metric, {}).get(value, 0.0)

    def get_severity_rating(self, score: float, version: CVSSVersion = CVSSVersion.V3_1) -> str:
        ratings = self.SEVERITY_RATINGS_V3 if version != CVSSVersion.V2 else self.SEVERITY_RATINGS_V2
        for (low, high), rating in ratings.items():
            if low <= score <= high:
                return rating
        return "Unknown"

    def estimate_score(self, severity: str, title: str = "", description: str = "") -> CVSSScore:
        severity_estimates = {
            "critical": 9.5,
            "high": 7.5,
            "medium": 5.5,
            "low": 3.5,
            "info": 0.0,
            "informational": 0.0,
        }
        base_score = severity_estimates.get((severity or "").lower(), 5.0)

        title_lower = (title or "").lower()
        if "rce" in title_lower or "remote code execution" in title_lower:
            base_score = max(base_score, 9.8)
        elif "sql injection" in title_lower:
            base_score = max(base_score, 9.0)
        elif "xss" in title_lower or "cross-site scripting" in title_lower:
            base_score = max(base_score, 7.5)
        elif "information disclosure" in title_lower:
            base_score = min(base_score, 5.0)

        return CVSSScore(
            base_score=base_score,
            vector=None,
            version=CVSSVersion.V3_1,
            source="estimated",
        )
