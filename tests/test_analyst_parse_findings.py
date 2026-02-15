import pytest

from core.analyst_agent import AnalystAgent
from core.memory import PentestMemory


class DummyLLM:
    async def generate_with_reasoning(self, prompt: str, system_prompt: str):
        raise RuntimeError("Not used in these tests")


@pytest.fixture()
def agent():
    memory = PentestMemory(target="example.com")
    return AnalystAgent(config={}, llm_client=DummyLLM(), memory=memory)


def test_parse_findings_with_markers_multiple(agent):
    ai_response = """
Intro text that should be ignored.

### FINDING: SQL Injection in login
SEVERITY: High
EVIDENCE: "Error: mysql_fetch_array() expects parameter 1 to be resource"
DESCRIPTION: The error indicates unsanitized input reaches a database query.
IMPACT: Data theft and potential authentication bypass
RECOMMENDATION: Use parameterized queries and input validation
CVSS: 8.6 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L)
CWE: CWE-89
OWASP: A03:2021 - Injection

### FINDING: Missing HSTS Header
SEVERITY: Low
EVIDENCE: "Strict-Transport-Security header is not present"
DESCRIPTION: HSTS is not enforced for the site.
IMPACT: Increased risk of SSL stripping on first visit
RECOMMENDATION: Add Strict-Transport-Security with appropriate max-age
"""
    findings = agent._parse_findings(ai_response, tool="httpx", target="example.com")
    assert len(findings) == 2

    f1, f2 = findings
    assert f1.severity == "high"
    assert "SQL Injection" in f1.title
    assert "mysql_fetch_array" in f1.evidence
    assert f1.cvss_score == 8.6
    assert f1.cvss_vector and "AV:N" in f1.cvss_vector
    assert "CWE-89" in f1.cwe_ids
    assert any(x.startswith("A03:2021") for x in f1.owasp_categories)
    assert f1.remediation and "parameterized" in f1.remediation.lower()
    assert f1.metadata.get("impact")

    assert f2.severity == "low"
    assert "HSTS" in f2.title
    assert "Strict-Transport-Security" in f2.evidence


def test_parse_findings_with_markers_missing_optional_fields(agent):
    ai_response = """
### FINDING: Anonymous FTP enabled
SEVERITY: Medium
EVIDENCE: "230 Login successful."
RECOMMENDATION: Disable anonymous access
"""
    findings = agent._parse_findings(ai_response, tool="nmap", target="example.com")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "medium"
    assert "FTP" in f.title
    assert f.evidence
    assert f.remediation


def test_parse_findings_legacy_bullets_multiple(agent):
    ai_response = """
FINDINGS:
- [HIGH] SQL Injection in login
  Evidence: "Error: mysql_fetch_array() expects parameter 1 to be resource"
  CVSS v3.1: 8.6 (Vector: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L)
  CWE: CWE-89
  OWASP: A03:2021 - Injection
- [LOW] Missing HSTS Header
  Evidence: "Strict-Transport-Security header is not present"
SUMMARY: Issues identified.
"""
    findings = agent._parse_findings(ai_response, tool="httpx", target="example.com")
    assert len(findings) == 2
    assert findings[0].severity == "high"
    assert findings[1].severity == "low"


def test_parse_findings_no_false_splits_on_infix_severity_words(agent):
    ai_response = """
This output has high impact in general, but there are no concrete findings.
Summary: No security findings in this output.
"""
    findings = agent._parse_findings(ai_response, tool="httpx", target="example.com")
    assert findings == []

