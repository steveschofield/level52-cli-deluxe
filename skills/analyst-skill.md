# Analyst Agent - Tool Output Interpretation

## enum4linux Output Interpretation
**Success indicators:**
- "Got domain/workgroup name: [NAME]"
- "User/Share enumeration: [data]"

**Failure patterns (NOT vulnerabilities):**
- "session setup failed: NT_STATUS_LOGON_FAILURE" = Expected for null session, continue analysis
- "Connection refused" = Service not running
- Empty output = No SMB service or blocked

**Real findings:**
- Shares with Everyone/Guest access = High severity
- User enumeration succeeding = Medium (info disclosure)
- Null session enabled = Low (expected in test environments)

## nmap Output Patterns
**Vulnerable patterns:**
- "VULNERABLE:" in script output = Confirmed vuln
- Open management ports (3389, 5900, 22) with weak auth = High
- Outdated service versions with known CVEs = Critical/High

**False positives:**
- "filtered" ports = Not a finding
- Generic HTTP headers = Info only unless specific weakness
- Service detection guesses = Verify before reporting

## Tool Error vs Security Finding
**These are NOT vulnerabilities:**
- "Module not found" = Installation issue
- "Permission denied" = Runtime config problem
- "Timeout" = Network/tool issue
- "Invalid syntax" = Command construction error
- Empty/blank output with 0 exit code = Tool ran, found nothing

**These ARE potential findings:**
- Tool completes successfully + flags specific issue
- Output contains "vulnerable", "exposed", "weak"
- Evidence of misconfigurations or exploitable conditions
