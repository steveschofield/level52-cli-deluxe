# Findings Extraction Fix - Analysis & Solution

## Problem Discovery

Analysis of report `20260214_093721` for target `192.168.1.244` (Metasploitable2) revealed:

**Expected**: Multiple critical vulnerabilities (vsftpd 2.3.4 backdoor, SSH vulnerabilities, exposed services)
**Actual**: Zero findings in final report despite comprehensive scanning

### Root Cause Analysis

The issue occurred in the **Analyst Agent → Findings Parser** pipeline:

1. **LLM Generated Analysis**: The DeepHat-V1-7B model correctly identified vulnerabilities
2. **Wrong Format**: LLM didn't follow the structured output format specified in prompts
3. **Parser Failure**: The `_parse_findings()` method couldn't extract findings from the unstructured response

#### Evidence from Logs

```log
2026-02-14 09:40:28,773 - guardian - INFO - [Analyst] LLM response: 2061 chars
2026-02-14 09:40:28,794 - guardian - INFO - AI Decision [Analyst]:
### Critical Vulnerabilities:
- **Port 22**: SSH service vulnerable to brute force attacks...
- **Port 3632**: Potential RCE in custom application...
- **Port 8009**: Apache Tomcat exposed without authentication...

2026-02-14 09:40:28,808 - guardian - INFO - [Analyst] AnalysisComplete: No evidence-backed findings; output deemed informational.
2026-02-14 09:40:28,810 - guardian - INFO - Found 0 findings from masscan
```

The LLM used format:
```
### Critical Vulnerabilities:
- **Port 22**: Description...
```

Expected format:
```
### FINDING: Port 22
SEVERITY: Critical
EVIDENCE: "exact quote"
DESCRIPTION: ...
```

## Solution Implemented

### 1. Enhanced Prompt (ai/prompt_templates/deephat_v1_7b/analyst.py)

**Changes:**
- Added explicit "CRITICAL INSTRUCTION" header
- Added concrete examples with exact format
- Emphasized format rules with "MUST" and "EXACT"
- Added negative examples (what NOT to do)
- Added second example showing the preferred format

**Impact:** Increases likelihood of LLM following format correctly

### 2. Fallback Parser (core/analyst_agent.py)

**New Method:** `_parse_findings_fallback()`

Handles the format that LLMs actually produce when they don't follow instructions:

```python
# Recognizes patterns like:
### Critical Vulnerabilities:
- **Title**: Description
- **Another Title**: Description

### High Severity Issues:
- **Title**: Description
```

**Features:**
- Extracts severity from section headers (`### Critical Vulnerabilities:`)
- Parses bullet points with bold titles (`- **Port 22**: Description`)
- Extracts evidence from quoted strings in descriptions
- Extracts port numbers as evidence when mentioned
- Extracts CVE IDs from descriptions
- Maintains proper Finding object structure

**Integration:**
```python
def _parse_findings(self, ai_response: str, tool: str, target: str) -> List[Finding]:
    # 1. Try structured format first (preferred)
    if re.search(r"(?mi)^###\s*FINDING:\s*", text):
        return self._parse_findings_with_markers(text, tool, target)

    # 2. Try fallback format for non-compliant LLMs
    fallback_findings = self._parse_findings_fallback(text, tool, target)
    if fallback_findings:
        return fallback_findings

    # 3. Legacy format (last resort)
    return self._parse_findings_legacy(text, tool, target)
```

### 3. Validation Testing

Created and ran standalone test with actual failing LLM output:

```
✓ Parsed 5 findings

1. [CRITICAL] Port 22
2. [CRITICAL] Port 3632
3. [CRITICAL] Port 8009
4. [HIGH] Port 5432 (PostgreSQL)
5. [HIGH] Port 1099 (RMI Registry)

VALIDATION: ✓ PASS
```

## Files Modified

1. `ai/prompt_templates/deephat_v1_7b/analyst.py` - Enhanced prompts
2. `core/analyst_agent.py` - Added fallback parser

## Impact & Benefits

### Immediate Fixes
- ✅ Findings now extracted from non-compliant LLM responses
- ✅ Zero findings bug resolved for DeepHat-V1-7B model
- ✅ Reports will now properly reflect discovered vulnerabilities

### Long-term Benefits
- **Robustness**: System handles multiple LLM output formats
- **Model Flexibility**: Can use different LLMs without parser changes
- **Graceful Degradation**: Falls back through multiple parsers
- **Better Reports**: Findings properly captured and reported

## Testing Recommendations

1. **Re-run failed scan**: Test against same Metasploitable2 target to verify findings are captured
2. **Cross-model testing**: Test with other LLM providers (Gemini, Claude, GPT-4) to ensure compatibility
3. **Regression testing**: Run against existing passing test cases to ensure no breakage

## Future Improvements

1. **Structured Output APIs**: When available, use JSON schema constraints for LLM output
2. **Parser Metrics**: Log which parser succeeded for monitoring/debugging
3. **LLM Validation**: Add pre-commit hooks to validate LLM responses against expected schemas
4. **Confidence Scoring**: Downweight findings from fallback parser vs. structured parser

## Related Issues

This fix addresses the broader pattern of:
- LLM instruction-following failures
- Format compliance issues across different models
- Robustness in agentic systems with unreliable LLM outputs
