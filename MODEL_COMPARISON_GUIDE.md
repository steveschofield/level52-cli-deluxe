# Model Size Comparison Guide - 7B vs 3B

## Testing Setup

When comparing **DeepHat-V1-7B (7B parameters)** vs **Llama 3.2 3B (3B parameters)**, watch for these key differences:

## What to Compare

### 1. **Format Compliance**
- Does the 3B model follow the `### FINDING:` structure?
- Count findings that fail to parse vs. total findings
- Check if fallback parser is needed more often

### 2. **Reasoning Quality**
Look at the AI Decision logs for:
- **Evidence selection**: Does it quote relevant parts?
- **Severity accuracy**: Is Critical/High/Medium/Low appropriate?
- **False positives**: Does it identify non-issues as vulnerabilities?
- **CVE hallucination**: Does it make up CVE IDs not in the output?

### 3. **Findings Accuracy**

**Expected from Metasploitable2 (192.168.1.244):**
- ✅ vsftpd 2.3.4 backdoor (CVE-2011-2523) - CRITICAL
- ✅ Old OpenSSH with CVEs - HIGH/MEDIUM
- ✅ PostgreSQL exposed (port 5432) - CRITICAL
- ✅ MySQL exposed (port 3306) - HIGH
- ✅ Telnet (port 23) - HIGH
- ✅ Old Apache 2.2.8 - MEDIUM/LOW
- ✅ PHP 5.2.4 - MEDIUM/LOW

**Common 3B Weaknesses to Watch For:**
- Missing context from condensed nmap XML
- Confusing port open = vulnerability
- Not recognizing when tools fail vs. when they find nothing
- Mixing up severity levels
- Generating CVEs that don't exist

### 4. **Performance Metrics**

Track in console logs:
```bash
grep "LLM response:" console_*.log
# Look for response times - 3B should be faster
# But watch for quality drops
```

Count findings:
```bash
jq '.findings | length' session_*.json
```

### 5. **Attack Chain Reasoning**

Compare the "Attack Chain Summary" sections:
- **7B**: Should understand privilege escalation paths
- **3B**: May miss connections between findings

## How to Test

### Run against Metasploitable2:
```bash
# Update config to use llama3_2_3b
# Set in config: ai.model_name = "llama3.2:3b"

guardian scan 192.168.1.244 --workflow recon
```

### Compare Reports:
```bash
# 7B results
cat reports/20260214_150033-*/report_*.md

# 3B results
cat reports/TIMESTAMP-*/report_*.md
```

## Decision Criteria

### **Stick with 7B if:**
- 3B misses >20% of critical findings
- 3B has >30% false positives
- 3B frequently hallucinates CVEs
- 3B can't follow structured format consistently

### **Consider 3B if:**
- Findings quality is >80% as good
- Speed improvement is significant (>2x faster)
- You need lower memory/GPU requirements
- Cost is a major concern (for API-based models)

### **Hybrid Approach:**
- Use 3B for initial recon/port scanning
- Use 7B for vuln analysis and correlation
- Use 7B+ for exploitation planning

## Expected Tradeoffs

### 7B Advantages:
- ✅ Better context understanding
- ✅ More accurate severity classification
- ✅ Fewer hallucinations
- ✅ Better attack chain reasoning
- ✅ More consistent format following

### 3B Advantages:
- ✅ Faster inference (2-3x)
- ✅ Lower memory requirements
- ✅ Can run on smaller GPUs
- ✅ Lower API costs
- ✅ Still adequate for basic vulnerability detection

## Known Issues with Small Models (<7B)

1. **Context Length**: May struggle with long nmap XML outputs
2. **Instruction Following**: More likely to ignore format requirements (hence the fallback parser)
3. **False Positives**: More aggressive flagging without proper evidence
4. **CVE Fabrication**: More likely to make up CVE IDs
5. **Severity Confusion**: May mark info findings as high/critical

## Evaluation Checklist

Run this after each test:

- [ ] Check findings count: `jq '.findings | length' session_*.json`
- [ ] Verify format compliance: `grep "### FINDING:" console_*.log | wc -l`
- [ ] Check for CVE hallucinations: Compare CVEs in findings vs. tool output
- [ ] Review severity distribution: Are most findings Info/Low or Critical/High?
- [ ] Test fallback parser usage: `grep "fallback" console_*.log`
- [ ] Compare inference times: `grep "LLM response" console_*.log`
- [ ] Check for parsing failures: `grep "No evidence-backed findings" console_*.log`

## Recommendations

**For Production:**
- Use **7B minimum** for security testing
- Consider **13B+** for complex engagements
- Use **3B** only for speed-critical scanning where false positives are acceptable

**For Development/Testing:**
- **3B** is fine for testing the framework
- Good for validating prompt changes quickly
- Useful for CI/CD where speed matters more than precision

**For Enterprise:**
- **Gemini 1.5 Pro** or **Claude 3.5 Sonnet** for best quality
- **GPT-4** for complex reasoning
- **7B-13B local models** for sensitive data that can't leave premises
