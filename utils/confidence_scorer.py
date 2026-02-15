"""
Finding confidence scoring utilities.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional
import re

from utils.logger import get_logger


class ConfidenceLevel(Enum):
    """Confidence level enumeration."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"

    @classmethod
    def from_string(cls, value: Optional[str]):
        try:
            return cls((value or "").lower())
        except (ValueError, AttributeError):
            return cls.UNKNOWN

    def __lt__(self, other):
        order = [self.UNKNOWN, self.LOW, self.MEDIUM, self.HIGH]
        return order.index(self) < order.index(other)

    def __le__(self, other):
        return self < other or self == other

    def __gt__(self, other):
        order = [self.UNKNOWN, self.LOW, self.MEDIUM, self.HIGH]
        return order.index(self) > order.index(other)

    def __ge__(self, other):
        return self > other or self == other


@dataclass
class ConfidenceScore:
    """Confidence score with reasoning."""
    level: ConfidenceLevel
    score: float
    factors: Dict[str, float]
    reasoning: str


class ConfidenceScorer:
    """Assigns confidence scores to findings based on multiple factors."""

    HIGH_THRESHOLD = 0.7
    MEDIUM_THRESHOLD = 0.4

    FACTOR_WEIGHTS = {
        "evidence_quality": 0.30,
        "tool_reliability": 0.25,
        "verification_status": 0.20,
        "context_relevance": 0.15,
        "false_positive_indicators": 0.10,
    }

    RELIABLE_TOOLS = {
        "nmap": 0.9,
        "nuclei": 0.85,
        "sqlmap": 0.90,
        "nikto": 0.75,
        "metasploit": 0.95,
        "zap": 0.80,
    }

    FALSE_POSITIVE_KEYWORDS = [
        "possible",
        "potential",
        "might be",
        "could be",
        "suspected",
        "unconfirmed",
        "informational",
    ]

    HIGH_CONFIDENCE_KEYWORDS = [
        "confirmed",
        "exploitable",
        "verified",
        "successful",
        "authenticated",
        "validated",
    ]

    def __init__(self, config: Dict | None = None):
        self.config = config or {}
        reporting_cfg = self.config.get("reporting", {}) if isinstance(self.config, dict) else {}
        self.min_confidence = ConfidenceLevel.from_string(
            reporting_cfg.get("min_confidence", "medium")
        )
        self.verbose = bool(reporting_cfg.get("verbose_reporting", False))
        self.logger = get_logger(self.config)

    def calculate_confidence(self, finding) -> ConfidenceScore:
        factors: Dict[str, float] = {}
        factors["evidence_quality"] = self._score_evidence_quality(finding)
        factors["tool_reliability"] = self._score_tool_reliability(finding)
        factors["verification_status"] = self._score_verification_status(finding)
        factors["context_relevance"] = self._score_context_relevance(finding)
        factors["false_positive_indicators"] = self._score_false_positive_indicators(finding)

        total_score = sum(factors[factor] * self.FACTOR_WEIGHTS[factor] for factor in factors)

        if total_score >= self.HIGH_THRESHOLD:
            level = ConfidenceLevel.HIGH
        elif total_score >= self.MEDIUM_THRESHOLD:
            level = ConfidenceLevel.MEDIUM
        else:
            level = ConfidenceLevel.LOW

        reasoning = self._generate_reasoning(factors, total_score)

        return ConfidenceScore(level=level, score=total_score, factors=factors, reasoning=reasoning)

    def _score_evidence_quality(self, finding) -> float:
        evidence = getattr(finding, "evidence", "") or ""
        if not evidence:
            return 0.2

        score = 0.5
        if len(evidence) > 200:
            score += 0.2
        elif len(evidence) > 100:
            score += 0.1

        technical_indicators = [
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
            r":\d{1,5}",
            r"http[s]?://",
            r"<script>",
            r"SELECT.*FROM",
            r"200 OK|404|500",
        ]
        for pattern in technical_indicators:
            if re.search(pattern, evidence, re.IGNORECASE):
                score += 0.05

        return min(score, 1.0)

    def _score_tool_reliability(self, finding) -> float:
        source = getattr(finding, "tool", "unknown").lower()
        for tool, reliability in self.RELIABLE_TOOLS.items():
            if tool in source:
                return reliability
        return 0.6

    def _score_verification_status(self, finding) -> float:
        if getattr(finding, "verified", False):
            return 1.0

        metadata = getattr(finding, "metadata", None)
        if isinstance(metadata, dict):
            if metadata.get("manually_verified"):
                return 1.0
            if metadata.get("auto_verified"):
                return 0.8

        title = (getattr(finding, "title", "") or "").lower()
        description = (getattr(finding, "description", "") or "").lower()
        for keyword in self.HIGH_CONFIDENCE_KEYWORDS:
            if keyword in title or keyword in description:
                return 0.8

        return 0.4

    def _score_context_relevance(self, finding) -> float:
        severity = (getattr(finding, "severity", "") or "").lower()
        if severity in ["critical", "high"]:
            score = 0.8
        elif severity == "medium":
            score = 0.6
        else:
            score = 0.4

        if getattr(finding, "cwe_ids", None) or getattr(finding, "cve_ids", None):
            score += 0.2

        return min(score, 1.0)

    def _score_false_positive_indicators(self, finding) -> float:
        title = (getattr(finding, "title", "") or "").lower()
        description = (getattr(finding, "description", "") or "").lower()
        evidence = (getattr(finding, "evidence", "") or "").lower()
        text = f"{title} {description} {evidence}"

        fp_count = 0
        for keyword in self.FALSE_POSITIVE_KEYWORDS:
            if keyword in text:
                fp_count += 1

        if fp_count >= 3:
            return 0.2
        if fp_count >= 2:
            return 0.4
        if fp_count >= 1:
            return 0.6

        severity = (getattr(finding, "severity", "") or "").lower()
        if severity in ["info", "informational"]:
            return 0.5

        return 0.8

    def _generate_reasoning(self, factors: Dict[str, float], total_score: float) -> str:
        reasons: List[str] = []
        strong_factors = [k for k, v in factors.items() if v >= 0.7]
        if strong_factors:
            reasons.append(f"Strong: {', '.join(strong_factors)}")

        weak_factors = [k for k, v in factors.items() if v < 0.4]
        if weak_factors:
            reasons.append(f"Weak: {', '.join(weak_factors)}")

        if total_score >= self.HIGH_THRESHOLD:
            reasons.append("High overall confidence")
        elif total_score >= self.MEDIUM_THRESHOLD:
            reasons.append("Medium confidence, may need verification")
        else:
            reasons.append("Low confidence, likely needs manual review")

        return "; ".join(reasons)

    def enrich_finding_with_confidence(self, finding) -> object:
        confidence_score = self.calculate_confidence(finding)
        finding.confidence = confidence_score.level.value
        finding.confidence_score = confidence_score.score

        metadata = getattr(finding, "metadata", None)
        if isinstance(metadata, dict):
            metadata["confidence_factors"] = confidence_score.factors
            metadata["confidence_reasoning"] = confidence_score.reasoning

        return finding

    def filter_findings_by_confidence(self, findings: List) -> List:
        if self.verbose:
            return findings

        return [
            f
            for f in findings
            if ConfidenceLevel.from_string(getattr(f, "confidence", "unknown"))
            >= self.min_confidence
        ]
