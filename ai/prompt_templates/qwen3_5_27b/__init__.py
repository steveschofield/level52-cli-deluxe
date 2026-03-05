"""
Qwen 3.5 27B optimized prompt templates

Large-model optimizations:
- Explicit reasoning chains (leverages native thinking/CoT capability)
- Stricter JSON output enforcement for Planner decisions
- Richer evidence and correlation instructions for Analyst
- Full-detail technical reporting with CISA KEV and CVSS fidelity

Suitable for remote hosting via:
- Ollama (remote): provider: ollama, base_url: http://<host>:11434
- OpenRouter: provider: openrouter, model: qwen/qwen3-235b-a22b:free (or similar)
"""

from .analyst import (
    ANALYST_SYSTEM_PROMPT,
    ANALYST_INTERPRET_PROMPT,
    ANALYST_CORRELATION_PROMPT,
    ANALYST_FALSE_POSITIVE_PROMPT,
)

from .planner import (
    PLANNER_SYSTEM_PROMPT,
    PLANNER_DECISION_PROMPT,
    PLANNER_ANALYSIS_PROMPT,
)

from .reporter import (
    REPORTER_SYSTEM_PROMPT,
    REPORTER_EXECUTIVE_SUMMARY_PROMPT,
    REPORTER_TECHNICAL_FINDINGS_PROMPT,
    REPORTER_REMEDIATION_PROMPT,
    REPORTER_AI_TRACE_PROMPT,
)

__all__ = [
    # Analyst
    "ANALYST_SYSTEM_PROMPT",
    "ANALYST_INTERPRET_PROMPT",
    "ANALYST_CORRELATION_PROMPT",
    "ANALYST_FALSE_POSITIVE_PROMPT",
    # Planner
    "PLANNER_SYSTEM_PROMPT",
    "PLANNER_DECISION_PROMPT",
    "PLANNER_ANALYSIS_PROMPT",
    # Reporter
    "REPORTER_SYSTEM_PROMPT",
    "REPORTER_EXECUTIVE_SUMMARY_PROMPT",
    "REPORTER_TECHNICAL_FINDINGS_PROMPT",
    "REPORTER_REMEDIATION_PROMPT",
    "REPORTER_AI_TRACE_PROMPT",
]
