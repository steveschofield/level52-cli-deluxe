"""
Finding deduplication and evidence merging utilities.
"""

from dataclasses import dataclass
from collections import defaultdict
from typing import Dict, List, Optional, Iterable

from utils.logger import get_logger


@dataclass(frozen=True)
class FindingKey:
    """Unique identifier for a finding."""
    title_normalized: str
    target: str
    severity: str


class FindingDeduplicator:
    """Deduplicates findings and merges evidence."""

    def __init__(self, config: Dict | None = None):
        self.config = config or {}
        reporting_cfg = self.config.get("reporting", {}) if isinstance(self.config, dict) else {}
        self.enabled = bool(reporting_cfg.get("deduplicate_findings", True))
        self.merge_evidence = bool(reporting_cfg.get("merge_duplicate_evidence", True))
        self.merge_cve_findings = bool(reporting_cfg.get("merge_cve_findings", True))
        self.logger = get_logger(self.config)

    def deduplicate(self, findings: List) -> List:
        """Remove duplicate findings and merge evidence."""
        if not self.enabled:
            return findings

        groups: Dict[FindingKey, List] = defaultdict(list)
        for finding in findings:
            key = self._create_key(finding)
            groups[key].append(finding)

        deduplicated: List = []
        for key, group in groups.items():
            if len(group) == 1:
                deduplicated.append(group[0])
                continue
            deduplicated.append(self._merge_findings(group))
            self.logger.debug(f"Merged {len(group)} duplicate findings for: {key.title_normalized}")

        if self.merge_cve_findings:
            deduplicated = self._merge_by_cve_overlap(deduplicated)

        return deduplicated

    def _merge_by_cve_overlap(self, findings: List) -> List:
        if not findings:
            return findings

        by_target: Dict[str, List] = defaultdict(list)
        for finding in findings:
            target = self._normalize_text(getattr(finding, "target", ""))
            by_target[target].append(finding)

        merged: List = []
        for target, group in by_target.items():
            if len(group) <= 1:
                merged.extend(group)
                continue

            cve_map: Dict[str, List[int]] = defaultdict(list)
            for idx, finding in enumerate(group):
                for cve in getattr(finding, "cve_ids", []) or []:
                    cve_map[cve.upper()].append(idx)

            if not cve_map:
                merged.extend(group)
                continue

            parent = list(range(len(group)))

            def find(i: int) -> int:
                while parent[i] != i:
                    parent[i] = parent[parent[i]]
                    i = parent[i]
                return i

            def union(a: int, b: int) -> None:
                ra = find(a)
                rb = find(b)
                if ra != rb:
                    parent[rb] = ra

            for indices in cve_map.values():
                if len(indices) < 2:
                    continue
                first = indices[0]
                for idx in indices[1:]:
                    union(first, idx)

            components: Dict[int, List] = defaultdict(list)
            for idx, finding in enumerate(group):
                components[find(idx)].append(finding)

            for component in components.values():
                if len(component) == 1:
                    merged.append(component[0])
                    continue
                merged.append(self._merge_findings(component))
                self.logger.debug(
                    f"Merged {len(component)} findings by CVE overlap for target: {target}"
                )

        return merged

    def _create_key(self, finding) -> FindingKey:
        title = self._normalize_text(getattr(finding, "title", ""))
        target = self._normalize_text(getattr(finding, "target", ""))
        severity = getattr(finding, "severity", "unknown").lower()
        return FindingKey(title_normalized=title, target=target, severity=severity)

    def _normalize_text(self, text: str) -> str:
        if not text:
            return ""

        text = text.lower()
        replacements = {
            "vulnerability": "vuln",
            "injection": "inj",
            "cross-site": "xss",
            "cross site": "xss",
        }
        for old, new in replacements.items():
            text = text.replace(old, new)

        text = "".join(c if c.isalnum() or c.isspace() else " " for c in text)
        return " ".join(text.split())

    def _merge_findings(self, findings: List) -> object:
        if not findings:
            return None

        merged = findings[0]
        if not self.merge_evidence or len(findings) == 1:
            return merged

        evidence_entries = self._collect_evidence_entries(findings)
        all_sources = self._collect_sources(findings)
        all_cves = self._collect_ids(findings, "cve_ids")
        all_cwes = self._collect_ids(findings, "cwe_ids")
        all_owasp = self._collect_ids(findings, "owasp_categories")

        severity_order = ["critical", "high", "medium", "low", "info", "informational"]
        worst_idx = severity_order.index(merged.severity.lower()) if merged.severity.lower() in severity_order else 999

        for finding in findings[1:]:
            sev = getattr(finding, "severity", "").lower()
            if sev in severity_order:
                idx = severity_order.index(sev)
                if idx < worst_idx:
                    worst_idx = idx
                    merged.severity = getattr(finding, "severity", merged.severity)

        merged.evidence = self._format_merged_evidence(evidence_entries)
        if all_cves:
            merged.cve_ids = sorted(all_cves)
        if all_cwes:
            merged.cwe_ids = sorted(all_cwes)
        if all_owasp:
            merged.owasp_categories = sorted(all_owasp)

        metadata = getattr(merged, "metadata", None)
        if isinstance(metadata, dict):
            metadata.setdefault("merged_from_sources", all_sources)
            metadata.setdefault("duplicate_count", len(findings))

        return merged

    def _collect_sources(self, findings: Iterable) -> List[str]:
        sources: List[str] = []
        for finding in findings:
            source = getattr(finding, "tool", "unknown") or "unknown"
            if source not in sources:
                sources.append(source)
        return sources

    def _collect_ids(self, findings: Iterable, attr: str) -> List[str]:
        ids: List[str] = []
        for finding in findings:
            values = getattr(finding, attr, None)
            if not values:
                continue
            for value in values:
                if value and value not in ids:
                    ids.append(value)
        return ids

    def _collect_evidence_entries(self, findings: Iterable) -> List[tuple[str, str]]:
        entries: List[tuple[str, str]] = []
        for finding in findings:
            evidence = getattr(finding, "evidence", "") or ""
            evidence = evidence.strip()
            if not evidence:
                continue
            source = getattr(finding, "tool", "unknown") or "unknown"
            entry = (evidence, source)
            if entry not in entries:
                entries.append(entry)
        return entries

    def _format_merged_evidence(self, entries: List[tuple[str, str]]) -> str:
        if not entries:
            return ""
        if len(entries) == 1:
            return entries[0][0]

        parts: List[str] = []
        for evidence, source in entries:
            parts.append(f"Evidence from {source}:\n{evidence}")
        return "\n\n---\n\n".join(parts)
