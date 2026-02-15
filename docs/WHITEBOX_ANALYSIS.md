# Whitebox Analysis - Source Code Security Testing

## Overview

Guardian Enterprise now supports **whitebox security analysis**, combining Static Application Security Testing (SAST) with dynamic penetration testing to provide comprehensive security assessment. This hybrid approach validates code-level vulnerabilities with runtime exploitation, delivering high-confidence findings.

## What is Whitebox Analysis?

Whitebox analysis (also called **SAST** or **source code analysis**) examines application source code to identify security vulnerabilities, misconfigurations, and secrets **before** deploying or testing the application. When combined with Guardian's dynamic testing (DAST), you get:

- **Code-level Context**: Know exactly where vulnerabilities exist in your codebase
- **Intelligent Testing**: Dynamic tests prioritize SAST-identified weak points
- **Confirmed Exploitability**: Correlate static findings with runtime exploitation
- **Reduced False Positives**: SAST + DAST confirmation = high confidence

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  PHASE 1: WHITEBOX ANALYSIS (SAST)                          │
├─────────────────────────────────────────────────────────────┤
│  ✓ Semgrep: Code vulnerability detection                    │
│  ✓ Trivy: Dependency CVEs, IaC misconfigurations           │
│  ✓ Gitleaks: Secret detection in code/git history          │
│  ✓ TruffleHog: Advanced secret scanning                    │
│                                                              │
│  AI EXTRACTS:                                               │
│  • API endpoints from routing code                          │
│  • Vulnerable parameters (SQLi, XSS, etc.)                  │
│  • Authentication mechanisms                                │
│  • Discovered secrets/credentials                           │
│  • CVE mappings to Nuclei templates                        │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  PHASE 2: DYNAMIC TESTING (Enhanced with SAST Context)      │
├─────────────────────────────────────────────────────────────┤
│  ✓ Reconnaissance (prioritizes SAST-identified endpoints)  │
│  ✓ Targeted SQLMap (focuses on SAST SQLi findings)         │
│  ✓ XSStrike/Dalfox (tests SAST XSS-vulnerable params)      │
│  ✓ Nuclei (matches CVE templates from Trivy)               │
│  ✓ Authenticated Scans (uses discovered secrets)           │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  PHASE 3: CORRELATION & REPORTING                           │
├─────────────────────────────────────────────────────────────┤
│  ✓ SAST ✓ DAST Confirmed Vulnerabilities                   │
│  ✓ Source Code Location → Exploitation Proof               │
│  ✓ High-Confidence Findings Report                         │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

Install SAST tools (one-time setup):

```bash
# Semgrep - SAST scanner
pip install semgrep

# Trivy - Dependency/CVE scanner
# macOS
brew install trivy
# Linux
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install trivy

# Gitleaks - Secret scanner (already in Guardian)
# TruffleHog - Secret scanner (already in Guardian)
```

### Basic Usage

#### Web Application Testing with Source Code

```bash
python -m cli.main workflow run --name web \
  --target https://api.example.com \
  --source /path/to/source/code
```

#### Autonomous Testing with Source Code

```bash
python -m cli.main workflow run --name autonomous \
  --target https://example.com \
  --source /path/to/source/code \
  --auto-exploit
```

#### SAST Only (No Dynamic Testing)

If you only have source code and no running application:

```bash
# Coming soon: dedicated source-only workflow
# For now, whitebox requires --target for dynamic testing
```

## Supported Workflows

| Workflow | Whitebox Support | Best For |
|----------|------------------|----------|
| **web** | ✅ **Recommended** | Web applications, APIs |
| **autonomous** | ✅ **Recommended** | AI-driven comprehensive testing |
| recon | ⚠️ Limited benefit | Network reconnaissance |
| network | ⚠️ Limited benefit | Infrastructure testing |

## SAST Tools

### 1. Semgrep

**Detects**: Code-level vulnerabilities (SQLi, XSS, auth bypass, crypto flaws, injection)

**Configuration** (`config/guardian.yaml`):

```yaml
whitebox:
  tools:
    semgrep:
      enabled: true
      rulesets:
        - "auto"                # Curated high-signal rules
        - "p/owasp-top-ten"     # OWASP Top 10 coverage
      severity: ["ERROR", "WARNING"]
```

**Output Examples**:
- SQL Injection in `api/users.py:42` - Unsanitized user input in query
- XSS in `views/profile.py:67` - Unescaped template variable
- JWT verification bypass in `auth/middleware.py:123`

### 2. Trivy

**Detects**: CVEs in dependencies, container vulnerabilities, IaC misconfigurations

**Configuration**:

```yaml
whitebox:
  tools:
    trivy:
      enabled: true
      scanners: ["vuln", "config", "secret"]
      severity: ["CRITICAL", "HIGH", "MEDIUM"]
```

**Output Examples**:
- CVE-2021-44228 (Log4Shell) in `log4j:2.14.1`
- CVE-2022-12345 in `Flask:1.1.2`
- Kubernetes misconfiguration: `allowPrivilegeEscalation: true`

**Nuclei Integration**: Trivy CVEs are automatically mapped to Nuclei templates for runtime verification.

### 3. Gitleaks

**Detects**: Secrets, API keys, credentials in source code and git history

**Configuration**:

```yaml
whitebox:
  tools:
    gitleaks:
      enabled: true
```

**Output Examples**:
- AWS_SECRET_KEY in `config/settings.py` (committed 6 months ago)
- GitHub Personal Access Token in `.env.example`
- Database password in `docker-compose.yml`

### 4. TruffleHog

**Detects**: High-entropy secrets, verified credentials

**Configuration**:

```yaml
whitebox:
  tools:
    trufflehog:
      enabled: true
```

## Correlation Engine

The correlation engine intelligently maps SAST findings to dynamic testing:

### Endpoint Prioritization

URLs discovered during reconnaissance are scored based on SAST context:

```
Priority Score Calculation:
+10 points: Matches SAST-identified vulnerable endpoint
+8 points:  Contains vulnerable parameter from SAST
+7 points:  Application has critical CVEs (Trivy)
+5 points:  Credentials available for authenticated testing
+5 points:  Endpoint defined in source code
```

### Test Plan Generation

```python
# Example: SAST finding triggers targeted dynamic test

# Semgrep finds SQLi in source code:
File: api/users.py:42
Code: cursor.execute(f"SELECT * FROM users WHERE id={user_id}")
Parameter: user_id

# Correlation engine generates:
{
  "endpoint": "https://api.example.com/api/users",
  "parameter": "id",
  "test_tool": "sqlmap",
  "confidence": "high",
  "source_line": "api/users.py:42"
}

# SQLMap executes targeted test:
sqlmap -u "https://api.example.com/api/users?id=1" -p id --batch
```

### Vulnerability Correlation

Findings are correlated by:
- **Type Match**: SQLi (SAST) ↔ SQL injection (DAST)
- **Endpoint Match**: `/api/users` (source code) ↔ `https://api.example.com/api/users` (runtime)
- **Parameter Match**: `user_id` (code) ↔ `id` (URL parameter)

**Confidence Levels**:
- **High**: Type + Endpoint + Parameter match
- **Medium**: Type + (Endpoint OR Parameter) match
- **Low**: Type match only

## Example Workflows

### Example 1: Python Flask API

```bash
# Source code structure:
/home/user/myapp/
  ├── app.py
  ├── api/
  │   ├── users.py      # Contains SQLi vulnerability
  │   └── orders.py
  ├── requirements.txt  # Has Flask 1.1.2 (CVE-2022-12345)
  └── config.py         # Contains AWS_SECRET_KEY

# Run whitebox + dynamic test:
python -m cli.main workflow run --name web \
  --target https://api.myapp.com \
  --source /home/user/myapp

# Results:
# [SAST] Semgrep: SQLi in api/users.py:42
# [DAST] SQLMap: Confirmed SQLi at /api/users?id=1
# [CORRELATION] ✓ CONFIRMED (High confidence)
#   Source: api/users.py:42
#   Exploit: Successfully extracted database schema
```

### Example 2: Node.js Express Application

```bash
# Run autonomous test with source code:
python -m cli.main workflow run --name autonomous \
  --target https://example.com \
  --source /home/user/express-app \
  --auto-exploit

# AI receives SAST context:
# - Framework: Express.js
# - 12 API endpoints extracted from routes/
# - 3 XSS vulnerabilities (Semgrep)
# - 1 CRITICAL CVE (Trivy): CVE-2021-23383
# - 2 leaked API keys (Gitleaks)

# AI prioritizes:
# 1. Test XSS-vulnerable endpoints with Dalfox
# 2. Run Nuclei CVE template for CVE-2021-23383
# 3. Use leaked API keys for authenticated scanning
```

### Example 3: Java Spring Boot Application

```bash
python -m cli.main workflow run --name web \
  --target https://springapp.example.com \
  --source /home/user/spring-project

# Trivy finds:
# - CVE-2021-44228 (Log4Shell) in log4j:2.14.1

# Nuclei automatically tests:
# - Template: cves/2021/CVE-2021-44228.yaml
# - Result: VULNERABLE

# Report shows:
# ✓ CONFIRMED Log4Shell Exploitation
#   SAST Source: pom.xml (log4j 2.14.1)
#   DAST Proof: RCE via ${jndi:ldap://...}
```

## Configuration

### Full Configuration (`config/guardian.yaml`)

```yaml
whitebox:
  enabled: true

  tools:
    semgrep:
      enabled: true
      rulesets:
        - "auto"
        - "p/owasp-top-ten"
        - "p/security-audit"
      severity: ["ERROR", "WARNING"]

    trivy:
      enabled: true
      scanners: ["vuln", "config", "secret"]
      severity: ["CRITICAL", "HIGH", "MEDIUM"]

    gitleaks:
      enabled: true

    trufflehog:
      enabled: true

  correlation:
    enabled: true
    prioritize_sast_findings: true
    auto_extract_endpoints: true
    use_found_credentials: true
    confidence_threshold: 0.7
```

### Disable Specific Tools

```yaml
whitebox:
  enabled: true
  tools:
    semgrep:
      enabled: true
    trivy:
      enabled: false  # Skip dependency scanning
    gitleaks:
      enabled: true
    trufflehog:
      enabled: false  # Skip TruffleHog
```

## Report Output

Whitebox findings appear in the final report with clear SAST/DAST correlation:

```markdown
## Whitebox Analysis (Source Code Security)

**Source Path**: `/home/user/myapp`
**Frameworks Detected**: Flask, SQLAlchemy
**API Endpoints Found**: 15
**Secrets Found**: 3

### SAST Findings Summary

**Semgrep** (12 issues):
- ERROR: 5
- WARNING: 7

**Trivy** (8 vulnerabilities):
- CRITICAL CVEs: CVE-2021-44228, CVE-2022-12345

**Gitleaks**: 3 secrets detected

### SAST/DAST Correlation

**Confirmed Vulnerabilities**: 5
(Findings validated by both static analysis and dynamic exploitation)

**High Confidence Correlations**: 3
**Total Correlations**: 8

---

## Technical Findings

### 1. SQL Injection in /api/users [CRITICAL] ✓ CONFIRMED

**SAST Source**: `api/users.py:42`
```python
cursor.execute(f"SELECT * FROM users WHERE id={user_id}")
```

**DAST Validation**: SQLMap successfully exploited `/api/users?id=1`
- Extracted database schema
- Retrieved 10,000 user records

**Confidence**: HIGH (Type + Endpoint + Parameter match)
**Impact**: Full database access, data exfiltration possible
```

## Benefits

### 1. Reduced False Positives

**SAST Only**:
- Semgrep flags 50 potential issues
- Many may not be exploitable in runtime context

**SAST + DAST Correlation**:
- 5 confirmed vulnerabilities (exploited in runtime)
- 10× reduction in noise

### 2. Faster Exploitation

**Without Source Code**:
- Blind fuzzing: Test 10,000 parameters
- Time: 2-4 hours

**With Source Code**:
- Targeted testing: 3 parameters (from SAST)
- Time: 5-10 minutes

### 3. Better Prioritization

**Traditional Severity**:
- All SQLi findings marked "CRITICAL"
- No context on exploitability

**Whitebox Context**:
- Severity + Confirmation + Source location
- Clear remediation path (fix line 42 in api/users.py)

### 4. Credential Reuse

**Discovered Secrets**:
- AWS_SECRET_KEY in source code
- Used for authenticated S3 bucket enumeration
- Reveals additional attack surface

## Troubleshooting

### Issue: Semgrep Not Found

```bash
# Install Semgrep
pip install semgrep

# Verify installation
semgrep --version
```

### Issue: Trivy Not Found

```bash
# Install Trivy (Linux)
sudo apt-get install trivy

# Install Trivy (macOS)
brew install trivy

# Verify installation
trivy --version
```

### Issue: Whitebox Analysis Skipped

Check that:
1. `--source` path exists and is a directory
2. Workflow supports whitebox (`web` or `autonomous`)
3. `whitebox.enabled: true` in `config/guardian.yaml`

### Issue: No Endpoints Extracted

Ensure your source code contains routing definitions:
- Flask: `@app.route('/api/users')`
- FastAPI: `@app.get('/api/users')`
- Express: `app.get('/api/users', ...)`
- Django: `path('api/users/', ...)`
- Spring: `@RequestMapping('/api/users')`

### Issue: Secrets Not Found

Gitleaks scans:
- Current source files
- Git commit history (if `.git/` exists)

Ensure:
- Path includes `.git/` folder for historical secret detection
- Secrets are not in `.gitignore` files (won't be scanned)

## Performance Considerations

### SAST Tool Execution Times

| Tool | Small Codebase | Medium Codebase | Large Codebase |
|------|----------------|-----------------|----------------|
| Semgrep | 10-30s | 1-3 min | 5-10 min |
| Trivy | 5-15s | 30s-2 min | 2-5 min |
| Gitleaks | 5-10s | 30s-1 min | 1-3 min |
| TruffleHog | 10-20s | 1-2 min | 3-5 min |

**Total SAST Phase**: ~30 seconds to 10 minutes (runs in parallel)

### Optimization Tips

1. **Reduce Semgrep Rulesets**:
   ```yaml
   rulesets: ["auto"]  # Faster than p/owasp-top-ten
   ```

2. **Filter Trivy Severity**:
   ```yaml
   severity: ["CRITICAL", "HIGH"]  # Skip MEDIUM/LOW
   ```

3. **Disable Unused Tools**:
   ```yaml
   trufflehog:
     enabled: false  # Skip if Gitleaks is sufficient
   ```

## Roadmap

- [ ] **Source-Only Mode**: Run SAST without requiring a live target
- [ ] **IDE Integration**: Real-time SAST feedback in VS Code/PyCharm
- [ ] **Custom Semgrep Rules**: Project-specific vulnerability patterns
- [ ] **Code Fix Suggestions**: AI-generated remediation code
- [ ] **Diff-Based Scanning**: Only scan changed files (CI/CD optimization)
- [ ] **SAST Dashboard**: Visual correlation mapping UI

## FAQ

**Q: Can I run whitebox analysis without a live application?**
A: Not yet. Current implementation requires `--target` for dynamic testing. Source-only mode is planned.

**Q: Does whitebox analysis slow down my scans?**
A: SAST adds ~1-10 minutes depending on codebase size, but dramatically speeds up dynamic testing through prioritization.

**Q: What languages are supported?**
A: Semgrep supports 30+ languages. Trivy scans dependencies for all major languages. Framework detection works for Python, Node.js, Java, Ruby, PHP, Go.

**Q: Can I use whitebox in CI/CD pipelines?**
A: Yes! Run Guardian with `--source .` in your CI pipeline for shift-left security testing.

**Q: How accurate is the correlation?**
A: High-confidence correlations (type + endpoint + parameter match) have >90% accuracy. Medium confidence ~70%. Low confidence requires manual review.

## Support

For issues, questions, or feature requests:
- GitHub Issues: https://github.com/steveschofield/guardian-cli-deluxe/issues
- Documentation: `docs/TOOLS_DEVELOPMENT_GUIDE.md`

---

**Guardian Enterprise** - Intelligent Whitebox + Blackbox Security Testing
