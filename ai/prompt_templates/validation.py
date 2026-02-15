"""
Prompt templates for the Validation Agent
Reduces false positives and validates security findings
"""

VALIDATION_SYSTEM_PROMPT = """You are Guardian's Validation Specialist for penetration testing.

Core responsibilities:
- Validate security findings for accuracy
- Eliminate false positives
- Verify exploitability claims
- Cross-reference findings across tools
- Assess finding confidence levels
- Provide verification steps for uncertain findings

Validation principles:
- Evidence-based assessment (require concrete proof)
- Multi-source confirmation (prefer findings from 2+ tools)
- Context-aware analysis (understand target environment)
- Conservative rating (downgrade uncertain findings)
- Actionable output (clear accept/reject/verify decisions)

False positive categories:
1. Tool artifacts (scanning side effects, tool bugs)
2. Misinterpretations (normal behavior flagged as vulnerability)
3. Out-of-scope findings (informational items marked as vulns)
4. Duplicate findings (same issue reported by multiple tools)
5. Environmental issues (network timeouts, DNS failures)

Validation workflow:
1. Evidence collection (raw tool output analysis)
2. Cross-tool correlation (multiple sources confirm?)
3. Exploitability verification (can this be exploited?)
4. Impact assessment (what's the actual risk?)
5. Confidence rating (0-100% confidence)
6. Decision: CONFIRMED / FALSE_POSITIVE / NEEDS_MANUAL_VERIFICATION"""

VALIDATION_FINDING_ASSESSMENT_PROMPT = """Validate security finding for false positive probability.

FINDING DETAILS:
Title: {title}
Severity: {severity}
Tool: {tool}
Target: {target}
Description: {description}
Evidence: {evidence}

CONTEXT:
Related Findings: {related_findings}
Target Type: {target_type}
Scan Configuration: {scan_config}

VALIDATION CHECKLIST:

1. EVIDENCE QUALITY
   ✓/✗ Concrete evidence provided (not generic warning)
   ✓/✗ Evidence matches vulnerability description
   ✓/✗ Evidence is reproducible
   ✓/✗ Timestamps and versions included

2. CROSS-TOOL CONFIRMATION
   ✓/✗ Multiple tools detected this issue
   ✓/✗ Tools agree on severity
   ✓/✗ No conflicting evidence from other tools

3. EXPLOITABILITY VERIFICATION
   ✓/✗ Exploit path clearly defined
   ✓/✗ Prerequisites are met
   ✓/✗ Known CVE or public exploit exists
   ✓/✗ Successfully demonstrated (if applicable)

4. FALSE POSITIVE INDICATORS
   ✓/✗ Generic security header warning
   ✓/✗ Tool error message misinterpreted as vulnerability
   ✓/✗ Network timeout/connection issue
   ✓/✗ Out-of-scope informational finding
   ✓/✗ Known tool false positive pattern

5. SEVERITY VALIDATION
   ✓/✗ Severity matches CVSS scoring guidelines
   ✓/✗ Impact is accurately described
   ✓/✗ Exploitability is realistically assessed

VALIDATION DECISION:

Confidence Level: <0-100>%
Status: CONFIRMED / FALSE_POSITIVE / NEEDS_VERIFICATION

Reasoning:
<Detailed analysis of evidence quality, cross-tool confirmation, and false positive indicators>

Recommended Action:
- CONFIRMED: Include in final report with [confidence]% certainty
- FALSE_POSITIVE: Discard finding, reason: <explanation>
- NEEDS_VERIFICATION: Manual testing required, steps: <verification steps>

Adjusted Severity (if changed): <CRITICAL/HIGH/MEDIUM/LOW/INFO>
Justification for severity change: <reasoning>"""

VALIDATION_CROSS_TOOL_CORRELATION_PROMPT = """Cross-reference findings from multiple security tools.

FINDINGS TO CORRELATE:
{findings_list}

TARGET: {target}

CORRELATION MATRIX:

For each unique vulnerability:
1. Identify all tools that detected it
2. Compare severity ratings across tools
3. Analyze evidence consistency
4. Determine consensus or conflicts

OUTPUT FORMAT:

Vulnerability: <vulnerability name>
Detected By: [<tool1>, <tool2>, <tool3>]
Consensus: YES / PARTIAL / NO

Evidence Comparison:
- Tool1: "<evidence snippet>"
- Tool2: "<evidence snippet>"
- Tool3: "<evidence snippet>"

Severity Ratings:
- Tool1: <severity>
- Tool2: <severity>
- Tool3: <severity>
- Consensus Severity: <final severity>

Confidence Assessment:
- Single tool: 40-60% confidence
- Two tools agree: 70-85% confidence
- Three+ tools agree: 90-100% confidence

Conflicts/Anomalies:
<List any disagreements between tools and analysis>

FINAL VALIDATION:

1. HIGHLY CONFIDENT (3+ tools, consistent evidence)
   - <list confirmed vulnerabilities>

2. MODERATE CONFIDENCE (2 tools, mostly consistent)
   - <list likely vulnerabilities>

3. LOW CONFIDENCE (1 tool, or conflicting evidence)
   - <list uncertain findings>
   - Recommended manual verification steps

4. FALSE POSITIVES (contradictory evidence)
   - <list rejected findings>
   - Reasoning for rejection

DUPLICATE DETECTION:
Merged findings (same vulnerability, different tool names):
- Finding A + Finding B = <consolidated finding>

Total Findings After Deduplication: <count>"""

VALIDATION_SEVERITY_ASSESSMENT_PROMPT = """Validate and potentially re-rate finding severity.

FINDING:
Title: {title}
Tool-Reported Severity: {reported_severity}
Description: {description}
Evidence: {evidence}
Target: {target}

CVSS v3.1 SCORING FRAMEWORK:

Attack Vector (AV):
- Network (N): Exploitable remotely
- Adjacent (A): Same network segment
- Local (L): Local access required
- Physical (P): Physical access required

Attack Complexity (AC):
- Low (L): No special conditions
- High (H): Requires specific conditions

Privileges Required (PR):
- None (N): No authentication needed
- Low (L): Basic user privileges
- High (H): Admin/elevated privileges

User Interaction (UI):
- None (N): Fully automatic
- Required (R): User must interact

Scope (S):
- Unchanged (U): Impacts only vulnerable component
- Changed (C): Impacts beyond vulnerable component

Confidentiality Impact (C): None/Low/High
Integrity Impact (I): None/Low/High
Availability Impact (A): None/Low/High

SEVERITY CALCULATION:

Based on evidence, assign CVSS metrics:
AV:{value} / AC:{value} / PR:{value} / UI:{value} / S:{value} / C:{value} / I:{value} / A:{value}

CVSS Base Score: <0.0-10.0>

Severity Mapping:
- 9.0-10.0: CRITICAL
- 7.0-8.9: HIGH
- 4.0-6.9: MEDIUM
- 0.1-3.9: LOW
- 0.0: INFO

COMMON SEVERITY ISSUES:

Generic Header Warnings:
- Missing HSTS/CSP/X-Frame-Options: Usually LOW or INFO
- Only CRITICAL/HIGH if directly exploitable

Information Disclosure:
- Version numbers: INFO (unless vulnerable version)
- Directory listings: LOW-MEDIUM (depends on contents)
- Error messages: LOW (unless leak credentials)

Authentication Issues:
- Bypass: CRITICAL
- Weak passwords: HIGH
- No rate limiting: MEDIUM

SEVERITY VALIDATION:

Tool Rating: {reported_severity}
Validated Rating: <CRITICAL/HIGH/MEDIUM/LOW/INFO>
Rating Changed: YES/NO

Justification:
<Explain why severity was confirmed or adjusted>

Evidence Supporting This Rating:
<Specific evidence that supports the severity level>

Real-World Impact:
<Practical exploitation scenario and business impact>"""

VALIDATION_TOOL_OUTPUT_ANALYSIS_PROMPT = """Analyze raw tool output to distinguish vulnerabilities from errors.

TOOL: {tool}
TARGET: {target}
RAW OUTPUT:
{raw_output}

ANALYSIS CATEGORIES:

1. LEGITIMATE VULNERABILITIES
   Indicators:
   - Specific CVE numbers
   - Version-matched exploits
   - Concrete proof of misconfiguration
   - Actual sensitive data exposure

2. TOOL ERRORS (NOT VULNERABILITIES)
   Indicators:
   - "Module not found"
   - "Connection timeout"
   - "Permission denied"
   - "Invalid configuration"
   - "Dependencies missing"
   - Python/Ruby/system errors

3. INFORMATIONAL OUTPUT (NOT VULNERABILITIES)
   Indicators:
   - Banner grabbing results
   - Service identification
   - Technology detection
   - Generic recommendations

4. FALSE POSITIVE PATTERNS
   Indicators:
   - Generic security header warnings
   - Theoretical vulnerabilities without proof
   - "Possible" or "Potential" findings without evidence
   - Normal behavior flagged as suspicious

OUTPUT CLASSIFICATION:

VULNERABILITIES FOUND: <count>
1. <vulnerability description>
   Evidence: "<exact quote from output>"
   Severity: <level>
   Line numbers: <reference>

TOOL ERRORS DETECTED: <count>
1. <error description>
   Error type: <category>
   Line numbers: <reference>
   Impact: No security finding

INFORMATIONAL DATA: <count>
1. <information type>
   Value: <extracted data>
   Security relevance: <explanation>

FALSE POSITIVES FILTERED: <count>
1. <false positive description>
   Reason for rejection: <explanation>

SUMMARY:
Actual Vulnerabilities: <count>
Tool/Environment Issues: <count>
Informational Only: <count>
False Positives: <count>

CONFIDENCE LEVEL: <HIGH/MEDIUM/LOW>
Reasoning: <explanation of confidence rating>"""

VALIDATION_EXPLOITABILITY_VERIFICATION_PROMPT = """Verify whether a reported vulnerability is actually exploitable.

VULNERABILITY CLAIM:
Title: {title}
Severity: {severity}
Description: {description}
Evidence: {evidence}
CVE: {cve}

EXPLOITABILITY CHECKLIST:

1. VULNERABILITY EXISTS
   ✓/✗ Concrete evidence of vulnerability
   ✓/✗ Version number confirms vulnerable software
   ✓/✗ Configuration confirms exploitable state

2. EXPLOIT AVAILABILITY
   ✓/✗ Public exploit exists (Metasploit, Exploit-DB)
   ✓/✗ PoC code available
   ✓/✗ Detailed exploitation steps documented

3. PREREQUISITES MET
   ✓/✗ Network access to vulnerable service
   ✓/✗ Required authentication (if any) obtainable
   ✓/✗ Exploitation dependencies available
   ✓/✗ Target OS/architecture matches exploit

4. IMPACT VERIFICATION
   ✓/✗ Claimed impact is achievable
   ✓/✗ Exploitation is reliable (not race condition)
   ✓/✗ No significant mitigations in place

5. EXPLOIT COMPLEXITY
   Complexity Rating: EASY / MODERATE / HARD / VERY_HARD

   EASY: Single-step exploitation, public tool
   MODERATE: Multi-step, requires some customization
   HARD: Requires significant effort, custom development
   VERY_HARD: Theoretical or requires rare conditions

EXPLOITABILITY ASSESSMENT:

Verdict: EXPLOITABLE / POTENTIALLY_EXPLOITABLE / NOT_EXPLOITABLE / UNKNOWN

Confidence: <0-100>%

Exploitation Path:
Step 1: <action>
Step 2: <action>
Step 3: <action>
Expected Outcome: <result>

Required Resources:
- Tools: <list>
- Knowledge: <required expertise level>
- Time: <estimated exploitation time>
- Special Conditions: <any prerequisites>

Mitigating Factors:
- <factors that hinder exploitation>

Risk Rating (Severity × Exploitability):
- CRITICAL + EXPLOITABLE = CRITICAL RISK
- HIGH + NOT_EXPLOITABLE = MEDIUM RISK
- Adjusted Risk: <final risk rating>

RECOMMENDATION:
- Include in report: YES/NO
- Manual verification required: YES/NO
- Verification steps: <specific testing steps>"""

VALIDATION_BATCH_PROCESSING_PROMPT = """Process multiple findings for false positive filtering.

FINDINGS BATCH ({count} findings):
{findings}

BATCH VALIDATION WORKFLOW:

1. CATEGORIZE FINDINGS
   Group by similarity:
   - Port scan results
   - Web vulnerabilities
   - SSL/TLS issues
   - Information disclosure
   - Misconfigurations
   - Code vulnerabilities

2. APPLY CATEGORY-SPECIFIC RULES

   Port Scan Findings:
   - Open ports are informational, not vulnerabilities
   - Only flag if running vulnerable service version

   Web Vulnerabilities:
   - Require proof of exploitation, not just presence
   - Missing headers: Usually LOW/INFO unless PoC provided

   SSL/TLS Issues:
   - Expired certificates: HIGH
   - Weak ciphers: MEDIUM (unless actively exploited)
   - Missing HSTS: LOW/INFO

   Information Disclosure:
   - Version numbers: INFO (note for correlation)
   - Error messages: LOW (unless credential leak)
   - Directory listings: MEDIUM (context-dependent)

3. DEDUPLICATION
   Merge duplicate findings:
   - Same vulnerability, different tools
   - Same issue, different ports/endpoints

4. BULK FALSE POSITIVE PATTERNS
   Auto-reject common false positives:
   - "Server: nginx" header → Not a vulnerability
   - "Missing X-Content-Type-Options" → INFO (unless XSS exists)
   - "HTTP 404 errors" → Not a vulnerability
   - "DNS resolution successful" → Not a vulnerability

VALIDATION RESULTS:

CONFIRMED VULNERABILITIES: <count>
Critical: <count>
High: <count>
Medium: <count>
Low: <count>

REJECTED (False Positives): <count>
- <brief summary of rejection reasons>

NEEDS VERIFICATION: <count>
- <list findings requiring manual review>

INFORMATIONAL FINDINGS: <count>
- <findings downgraded to informational>

DUPLICATES MERGED: <count>
- Before: <original count>
- After: <deduplicated count>

EFFICIENCY METRICS:
- False positive rate: <percentage>%
- Findings requiring manual review: <percentage>%
- High-confidence findings: <percentage>%

FINAL REPORT READY:
Total actionable findings: <count>
Estimated false positive removal: <count> findings filtered"""
