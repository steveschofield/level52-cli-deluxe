"""
Prompt templates for the Reporter Agent  
Generates structured penetration testing reports
"""

REPORTER_SYSTEM_PROMPT = """You are Guardian's Report Generator for penetration testing.

Core functions:
- Generate professional pentest reports
- Structure findings by severity and impact
- Provide actionable remediation guidance
- Include AI reasoning for transparency

Report framework:
1. Executive Summary (business-focused)
2. Scope & Methodology
3. Key Findings (severity-prioritized)
4. Technical Details
5. Remediation Plan
6. AI Decision Trace
7. Appendix

Severity scale:
- CRITICAL: Immediate threat, high impact
- HIGH: Serious, likely exploitable
- MEDIUM: Notable weakness, moderate impact
- LOW: Minor issue, low impact
- INFO: No direct security impact

Writing principles:
- Clear for technical and executive audiences
- Evidence-based findings
- Specific, actionable recommendations
- Professional tone
- Accurate without exaggeration"""

REPORTER_EXECUTIVE_SUMMARY_PROMPT = """Generate an executive summary for this penetration test.

TARGET: {target}
SCOPE: {scope}
DURATION: {duration}
FINDINGS COUNT: {findings_count}

CRITICAL FINDINGS: {critical_count}
HIGH FINDINGS: {high_count}
MEDIUM FINDINGS: {medium_count}
LOW FINDINGS: {low_count}

TOP 3 CRITICAL ISSUES:
{top_issues}

Create a concise executive summary (2-3 paragraphs) that:
1. Explains the security posture in business terms
2. Highlights the most critical risks
3. Provides high-level recommendations
4. Uses non-technical language suitable for executives

IMPORTANT OUTPUT REQUIREMENTS:
- Output ONLY the executive summary content
- Do NOT include prompt headers like "1. REASONING:" or "3. EXPLANATION:"
- Do NOT ask follow-up questions like "Would you like me to elaborate?"
- Write as a final, polished report section ready for executives

EXECUTIVE SUMMARY:
"""

REPORTER_TECHNICAL_FINDINGS_PROMPT = """Generate detailed technical findings section.

FINDINGS:
{findings}

For each finding, provide:
1. Title and severity
2. Affected component/service
3. Technical description
4. Evidence and proof of concept
5. Impact analysis
6. **Exploitation Information** - IMPORTANT: If CVE IDs, known exploits, or exploitation attempts are mentioned in the finding data:
   - **PRIORITY: CISA KEV Status** - If finding mentions "CISA KEV: ACTIVELY EXPLOITED IN THE WILD", prominently display:
     * ⚠️ **CRITICAL WARNING: This vulnerability is actively exploited in the wild (CISA KEV)**
     * Ransomware association if mentioned
     * Government-mandated remediation deadline
     * Required action
   - List all CVE identifiers
   - Specify available Metasploit modules by name
   - Specify available Exploit-DB references using real IDs from input data (e.g., EDB-42315)
   - Include GitHub PoC repositories if mentioned (with star counts)
   - If exploitation was attempted, clearly state the outcome (successful/failed) and which module was used
   - If Exploit-DB exploits are available for manual use, note this
7. Detailed remediation steps
8. CVSS v3.1 score/vector if applicable
9. OWASP Top 10 (2021) and CWE mapping if provided

**CRITICAL**: For each finding, include a dedicated "Exploitation Information" subsection that summarizes:
- **CISA KEV status (if applicable)** - Highest priority indicator
- CVE identifiers
- Known public exploits (Metasploit modules, Exploit-DB IDs, GitHub PoCs)
- Exploitation attempt status if auto-exploit was used
- Whether successful exploitation was achieved

Strict data integrity rules:
- Use only exploit references present in the provided finding data.
- Do not invent Metasploit modules, Exploit-DB IDs, or GitHub PoC links.
- If an exploit source is not present in the finding data, write `N/A` for that source.

Format as a professional technical report section with clear headings and structure.

IMPORTANT OUTPUT REQUIREMENTS:
- Output ONLY the technical findings content
- Do NOT include prompt headers like "1. REASONING:" or "3. SUPPORTING FACTS:"
- Do NOT ask follow-up questions
- Write as a final, polished report section
"""

REPORTER_REMEDIATION_PROMPT = """Generate prioritized remediation recommendations.

FINDINGS:
{findings}

AFFECTED SYSTEMS:
{affected_systems}

Create an actionable remediation plan:
1. Quick Wins (easy fixes with high impact)
2. Critical Priorities (must fix immediately)
3. Medium-term Improvements
4. Long-term Security Enhancements

For each recommendation:
- Specific action steps
- Required resources/tools
- Estimated effort
- Security impact

Format as a prioritized action plan.

IMPORTANT OUTPUT REQUIREMENTS:
- Output ONLY the remediation plan content
- Do NOT include prompt headers or meta-commentary
- Do NOT ask follow-up questions
- Write as a final, polished report section
"""

REPORTER_AI_TRACE_PROMPT = """Generate concise AI decision log (max 500 words).

AI DECISIONS:
{ai_decisions}

WORKFLOW:
{workflow}

List only key decisions in bullet points:
1. Critical tool selections and rationale
2. Major vulnerability findings
3. Failed operations (if any)
4. Important decision points

Format: Bullet points for technical audience.

IMPORTANT OUTPUT REQUIREMENTS:
- Keep response under 500 words
- Output ONLY the decision log content
- Do NOT include prompt headers or numbered instructions
- Do NOT ask follow-up questions
- Write as a final, polished report section
"""
