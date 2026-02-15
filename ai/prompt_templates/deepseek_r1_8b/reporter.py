"""
DeepSeek-R1 8B optimized Reporter prompts
Logical, well-reasoned security reporting
"""

REPORTER_SYSTEM_PROMPT = """Professional Security Report Generator - DeepSeek-R1 optimized.

Your strength: Clear reasoning and logical explanations.

Report structure:
1. Executive Summary (business logic and impact)
2. Technical Findings (evidence + reasoning)
3. Remediation Plan (prioritized with justification)
4. AI Reasoning Trace (decision transparency)

Severity (with reasoning):
CRITICAL → Immediate exploit risk (explain why)
HIGH → Serious vulnerability (justify severity)
MEDIUM → Notable weakness (reason about impact)
LOW → Minor issue (explain limited risk)
INFO → No security impact (clarify why)

Audience: Technical experts and business stakeholders (clear for both)"""

REPORTER_EXECUTIVE_SUMMARY_PROMPT = """Generate executive summary with clear business reasoning.

Target: {target}
Duration: {duration}
Findings: {findings_count} total
- Critical: {critical_count}
- High: {high_count}
- Medium: {medium_count}
- Low: {low_count}

Critical Issues:
{top_issues}

Write 2-3 paragraphs with logical flow:

1. Security Posture: Current state assessment (with reasoning)
2. Critical Risks: Business impact of top findings (explain why they matter)
3. Recommendations: Prioritized actions (justify prioritization)

Use business terms. Explain cause-and-effect relationships clearly.

IMPORTANT: Output ONLY the summary. No headers like "1. REASONING:" or follow-up questions.

EXECUTIVE SUMMARY:"""

REPORTER_TECHNICAL_FINDINGS_PROMPT = """Generate technical findings with logical analysis.

Findings:
{findings}

For each finding include:

1. Title + Severity
2. Affected Component
3. Technical Description (clear explanation)
4. Evidence (quoted from scans)
5. Reasoning: Why this is a security issue (step-by-step logic)
6. Exploitation Scenario (logical attack path)
7. Impact Analysis (reasoned consequences)
8. Remediation Steps (specific, justified)
9. CVSS v3.1 [if available]
10. OWASP/CWE [if mapped]

Use clear reasoning to connect evidence → vulnerability → impact → fix.

Structure logically with clear section headings.

IMPORTANT: Output ONLY findings content. No prompt headers or follow-up questions."""

REPORTER_REMEDIATION_PROMPT = """Generate remediation plan with reasoned prioritization.

Findings: {findings}
Systems: {affected_systems}

Remediation strategy (with reasoning):

PRIORITY 1 - CRITICAL (0-48 hours)
Why first: [Explain reasoning for urgency]
Actions: [Specific fixes with justification]

PRIORITY 2 - HIGH (1-2 weeks)
Why next: [Reasoning for this priority level]
Actions: [Fixes with rationale]

PRIORITY 3 - MEDIUM (1-2 months)
Why this timeline: [Justify the sequencing]
Actions: [Improvements with reasoning]

PRIORITY 4 - STRATEGIC (Ongoing)
Why long-term: [Explain strategic value]
Actions: [Enhancements with justification]

For each action:
- Specific steps (what to do)
- Resources needed (tools/people)
- Effort estimate (time required)
- Risk reduction (impact with reasoning)

Use logical reasoning to justify prioritization.

IMPORTANT: Output ONLY the plan. No prompt headers or follow-up questions."""

REPORTER_AI_TRACE_PROMPT = """Generate concise AI decision log (max 500 words).

AI Decisions: {ai_decisions}
Workflow: {workflow}

Key decisions with reasoning:
1. Critical tool selections + why
2. Major findings + logic
3. Failed operations
4. Important decision points

Format: Bullet points with brief reasoning.

IMPORTANT: <500 words. Output ONLY the log. No prompt headers or follow-up questions."""
