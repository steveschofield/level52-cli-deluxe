"""
Industry standard mappings and scoring helpers (CVSS, CWE, OWASP).
"""

from __future__ import annotations

import math
import re
from typing import Dict, List, Optional, Tuple


OWASP_2021 = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery (SSRF)",
}

CVSS_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
CVSS_AC = {"L": 0.77, "H": 0.44}
CVSS_UI = {"N": 0.85, "R": 0.62}
CVSS_S = {"U", "C"}
CVSS_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
CVSS_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
CVSS_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}


def parse_cvss_vector(vector: str) -> Optional[Dict[str, str]]:
    if not vector:
        return None

    text = vector.strip()
    text = text.replace("CVSS:3.1/", "").replace("CVSS:3.0/", "")
    parts = [p.strip() for p in text.split("/") if ":" in p]

    metrics: Dict[str, str] = {}
    for part in parts:
        key, value = part.split(":", 1)
        key = key.strip().upper()
        value = value.strip().upper()
        metrics[key] = value

    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if not required.issubset(metrics.keys()):
        return None

    # Basic validation on allowed values.
    if metrics["AV"] not in CVSS_AV:
        return None
    if metrics["AC"] not in CVSS_AC:
        return None
    if metrics["UI"] not in CVSS_UI:
        return None
    if metrics["S"] not in CVSS_S:
        return None
    for k in ("C", "I", "A"):
        if metrics[k] not in CVSS_CIA:
            return None
    if metrics["PR"] not in CVSS_PR_U:
        return None

    return metrics


def calculate_cvss_base_score(vector: str) -> Optional[float]:
    metrics = parse_cvss_vector(vector)
    if not metrics:
        return None

    scope = metrics["S"]
    pr_map = CVSS_PR_C if scope == "C" else CVSS_PR_U

    av = CVSS_AV[metrics["AV"]]
    ac = CVSS_AC[metrics["AC"]]
    pr = pr_map[metrics["PR"]]
    ui = CVSS_UI[metrics["UI"]]

    c = CVSS_CIA[metrics["C"]]
    i = CVSS_CIA[metrics["I"]]
    a = CVSS_CIA[metrics["A"]]

    iss = 1 - (1 - c) * (1 - i) * (1 - a)

    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0

    if scope == "U":
        score = min(impact + exploitability, 10)
    else:
        score = min(1.08 * (impact + exploitability), 10)

    return _round_up_1_decimal(score)


def estimate_cvss_from_severity(severity: str) -> float:
    severity = (severity or "").lower()
    mapping = {
        "critical": 9.5,
        "high": 8.0,
        "medium": 5.5,
        "low": 2.0,
        "info": 0.0,
    }
    return mapping.get(severity, 0.0)


def infer_cwe_owasp(text: str) -> Tuple[List[str], List[str]]:
    if not text:
        return [], []

    text = text.lower()

    rules = [
        {
            "patterns": [r"\bsql injection\b", r"\bsqli\b"],
            "cwe": ["CWE-89"],
            "owasp": [_owasp_label("A03:2021")],
        },
        {
            "patterns": [r"\bcross[- ]site scripting\b", r"\bxss\b"],
            "cwe": ["CWE-79"],
            "owasp": [_owasp_label("A03:2021")],
        },
        {
            "patterns": [r"\bcommand injection\b", r"\bos command injection\b"],
            "cwe": ["CWE-78"],
            "owasp": [_owasp_label("A03:2021")],
        },
        {
            "patterns": [r"\bremote code execution\b", r"\brce\b", r"\bcode injection\b"],
            "cwe": ["CWE-94"],
            "owasp": [_owasp_label("A03:2021")],
        },
        {
            "patterns": [r"\bssrf\b", r"\bserver[- ]side request forgery\b"],
            "cwe": ["CWE-918"],
            "owasp": [_owasp_label("A10:2021")],
        },
        {
            "patterns": [r"\bpath traversal\b", r"\blfi\b", r"\blocal file inclusion\b"],
            "cwe": ["CWE-22"],
            "owasp": [_owasp_label("A01:2021")],
        },
        {
            "patterns": [r"\brfi\b", r"\bremote file inclusion\b"],
            "cwe": ["CWE-98"],
            "owasp": [_owasp_label("A01:2021")],
        },
        {
            "patterns": [r"\bcsrf\b", r"\bcross[- ]site request forgery\b"],
            "cwe": ["CWE-352"],
            "owasp": [_owasp_label("A01:2021")],
        },
        {
            "patterns": [r"\bidor\b", r"\binsecure direct object reference\b"],
            "cwe": ["CWE-639"],
            "owasp": [_owasp_label("A01:2021")],
        },
        {
            "patterns": [r"\bauthentication bypass\b", r"\bunauthenticated\b", r"\bweak authentication\b"],
            "cwe": ["CWE-287"],
            "owasp": [_owasp_label("A07:2021")],
        },
        {
            "patterns": [r"\bdeserialization\b", r"\binsecure deserialization\b"],
            "cwe": ["CWE-502"],
            "owasp": [_owasp_label("A08:2021")],
        },
        {
            "patterns": [r"\bcleartext\b", r"\bplaintext\b", r"\bunencrypted\b", r"\bweak tls\b", r"\binsecure tls\b", r"\binsecure ssl\b"],
            "cwe": ["CWE-319"],
            "owasp": [_owasp_label("A02:2021")],
        },
        {
            "patterns": [r"\boutdated component\b", r"\bunsupported component\b", r"\bvulnerable component\b"],
            "cwe": ["CWE-1104"],
            "owasp": [_owasp_label("A06:2021")],
        },
    ]

    cwe_ids: List[str] = []
    owasp: List[str] = []

    for rule in rules:
        if any(re.search(pat, text) for pat in rule["patterns"]):
            for cwe in rule["cwe"]:
                if cwe not in cwe_ids:
                    cwe_ids.append(cwe)
            for cat in rule["owasp"]:
                if cat and cat not in owasp:
                    owasp.append(cat)

    return cwe_ids, owasp


def normalize_owasp_labels(labels: List[str]) -> List[str]:
    normalized: List[str] = []
    for label in labels:
        if not label:
            continue
        code_match = re.search(r"A\d{2}:2021", label)
        if code_match:
            code = code_match.group(0)
            normalized_label = _owasp_label(code)
        else:
            normalized_label = label.strip()
        if normalized_label and normalized_label not in normalized:
            normalized.append(normalized_label)
    return normalized


def _round_up_1_decimal(value: float) -> float:
    return math.ceil(value * 10.0) / 10.0


def _owasp_label(code: str) -> str:
    name = OWASP_2021.get(code, "")
    return f"{code} - {name}" if name else code
