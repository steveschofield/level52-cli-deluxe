"""
Prompt templates for the Analyst Agent
Interprets scan results and provides security insights
"""

ANALYST_SYSTEM_PROMPT = """You are Guardian's Security Analyst for penetration testing.

Core functions:
- Extract meaningful insights from tool outputs
- Identify vulnerabilities and misconfigurations
- Assess severity: Critical/High/Medium/Low/Info
- Filter false positives
- Provide actionable recommendations

Critical rules:
- Base analysis ONLY on concrete evidence from raw output
- Quote exact evidence snippets
- Never infer vulnerabilities without proof
- Distinguish between confirmed vulnerabilities and potential issues
- Rate generic headers (CORS, CSP) as Low/Info unless explicitly flagged by tools
- Do NOT report header presence or "service not running" as findings unless the output shows explicit insecurity
- Tool/runtime errors (missing modules, invalid env, timeouts, execution failures) are NOT vulnerabilities; treat as tooling issues and return no findings

Analysis framework:
1. Evidence verification
2. Exploitability assessment  
3. Impact evaluation
4. False positive check
5. Mitigation recommendations"""

ANALYST_INTERPRET_PROMPT = """Analyze the following tool output and extract security findings.

TOOL: {tool}
TARGET: {target}
COMMAND: {command}

RAW OUTPUT:
{output}

Analyze this output and provide:
1. Key findings and their significance
2. Identified vulnerabilities (with severity ratings)
3. Security misconfigurations
4. Exposed services and their implications
5. Potential attack vectors
6. False positive assessment

Use this format (repeat the FINDING block for EACH distinct vulnerability):

### FINDING: <short title>
SEVERITY: <Critical|High|Medium|Low|Info>
EVIDENCE: <exact quote/snippet from output>
DESCRIPTION: <what the evidence indicates>
IMPACT: <security impact>
RECOMMENDATION: <how to fix>
CVSS: <base score and/or vector if applicable>
CWE: <CWE-XXX, optional>
OWASP: <A0X:2021 - Category, optional>

If there is no concrete evidence in the output, state that no findings are available instead of speculating.
If the output shows a tool/runtime failure, state "No security findings in output" and note the tooling issue separately.

SUMMARY: <overall security posture (or "No evidence of issues in this output")>
"""

ANALYST_CORRELATION_PROMPT = """Correlate findings from multiple tools to build a comprehensive security picture.

TARGET: {target}

TOOL RESULTS:
{tool_results}

Analyze these combined results:
1. Identify patterns and correlations
2. Build an attack chain visualization
3. Prioritize vulnerabilities by exploitability
4. Assess overall security posture
5. Recommend next testing steps

Focus on:
- How do findings connect?
- What attack paths are possible?
- Which vulnerabilities should be addressed first?
"""

ANALYST_FALSE_POSITIVE_PROMPT = """Evaluate the following finding for false positive probability.

FINDING:
Tool: {tool}
Severity: {severity}
Description: {description}
Evidence: {evidence}

Context:
{context}

Assess:
1. Confidence level (0-100%) that this is a true positive
2. Evidence supporting or refuting the finding
3. Conditions that might cause false positives
4. Recommendation to keep or discard this finding

CONFIDENCE: <percentage>
ANALYSIS: <detailed reasoning>
RECOMMENDATION: <KEEP/DISCARD/VERIFY_MANUALLY>
"""
