import sys
import types

import pytest

# ReporterAgent imports OSINT clients which import requests at module import time.
# Tests here do not perform network calls, so provide a lightweight stub when requests
# is unavailable in the test environment.
if "requests" not in sys.modules:
    sys.modules["requests"] = types.ModuleType("requests")

from core.memory import Finding, PentestMemory, ToolExecution
from core.reporter_agent import ReporterAgent


class DummyLLM:
    async def generate_with_reasoning(self, prompt: str, system_prompt: str):
        return {"reasoning": "test", "response": "test"}


def _make_config(tmp_path, require_traceability=True):
    return {
        "output": {
            "save_path": str(tmp_path),
            "format": "markdown",
        },
        "reporting": {
            "deduplicate_findings": False,
            "enable_confidence_scoring": False,
            "require_evidence_traceability": require_traceability,
        },
        "osint": {"enabled": False},
        "exploits": {"enabled": False},
    }


def _make_finding(
    *,
    finding_id: str,
    tool: str,
    evidence: str,
    severity: str = "low",
    cvss_score=None,
    cwe_ids=None,
):
    return Finding(
        id=finding_id,
        severity=severity,
        title=f"Finding {finding_id}",
        description="Test finding",
        evidence=evidence,
        tool=tool,
        target="127.0.0.1",
        timestamp="2026-02-06T00:00:00",
        cvss_score=cvss_score,
        cwe_ids=cwe_ids or [],
    )


def _make_execution(tool: str, output: str):
    return ToolExecution(
        tool=tool,
        command=f"{tool} --example -o sample.out",
        target="127.0.0.1",
        timestamp="2026-02-06T00:01:00",
        exit_code=0,
        output=output,
        duration=1.0,
    )


def test_finding_provenance_attached_with_offset(tmp_path):
    memory = PentestMemory(target="127.0.0.1", session_id="20260206_000000")
    finding = _make_finding(
        finding_id="f-1",
        tool="nmap",
        evidence="VULNERABLE: test-service",
        severity="high",
        cwe_ids=["CWE-79"],
    )
    memory.add_finding(finding)
    memory.add_tool_execution(
        _make_execution(
            "nmap",
            "scan start\nVULNERABLE: test-service\nscan end",
        )
    )

    agent = ReporterAgent(_make_config(tmp_path), DummyLLM(), memory)
    findings = agent._get_report_findings()
    assert len(findings) == 1

    provenance = findings[0].metadata.get("provenance")
    assert provenance
    assert provenance["id"].startswith("prov-")
    assert len(provenance["snippet_hash_sha256_12"]) == 12
    assert provenance["evidence_offset_bytes"] is not None
    assert provenance["evidence_offset_bytes"] >= 0
    assert provenance["source_artifact"] in {"sample.out", str(tmp_path / "session_20260206_000000.json")}
    assert "tool=nmap" in provenance["source_location"]


def test_consistency_normalizes_severity_cvss_and_cwe(tmp_path):
    memory = PentestMemory(target="127.0.0.1", session_id="20260206_000001")
    finding = _make_finding(
        finding_id="f-2",
        tool="nmap",
        evidence="Detected CVE-2025-0001 with remote code execution",
        severity="low",
        cvss_score=9.8,
        cwe_ids=["foo", "cwe_79", "CWE-79"],
    )
    finding.cve_ids = ["CVE-2025-0001"]
    memory.add_finding(finding)
    memory.add_tool_execution(
        _make_execution("nmap", "Detected CVE-2025-0001 with remote code execution")
    )

    agent = ReporterAgent(_make_config(tmp_path), DummyLLM(), memory)
    findings = agent._get_report_findings()
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "critical"
    assert f.cvss_score == 9.8
    assert f.cwe_ids == ["CWE-79"]


def test_traceability_filter_excludes_untraceable_findings(tmp_path):
    memory = PentestMemory(target="127.0.0.1", session_id="20260206_000002")
    memory.add_finding(
        _make_finding(
            finding_id="f-3",
            tool="nmap",
            evidence="Untraceable evidence line",
            severity="medium",
            cwe_ids=["CWE-79"],
        )
    )
    # Intentionally no matching tool execution, so this should be excluded.

    agent = ReporterAgent(_make_config(tmp_path, require_traceability=True), DummyLLM(), memory)
    findings = agent._get_report_findings()
    assert findings == []
    notes = getattr(agent, "_report_quality_notes", [])
    assert any("excluded due to missing evidence traceability" in n for n in notes)


def test_technical_quality_validator_detects_known_bad_patterns(tmp_path):
    memory = PentestMemory(target="127.0.0.1", session_id="20260206_000003")
    agent = ReporterAgent(_make_config(tmp_path), DummyLLM(), memory)

    bad = """
### [CRITICAL] Placeholder Issue
Exploit-DB ID: EDB-XXXXX
... (rest of the findings)
"""
    issues = agent._validate_technical_findings_quality(bad)
    assert any("placeholder" in i for i in issues)
    assert any("truncation marker" in i for i in issues)
