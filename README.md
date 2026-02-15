# 🔐 Guardian Enterprise

### AI-Powered Penetration Testing Automation Platform

**Guardian Enterprise** is an AI-powered penetration testing automation framework designed for internal security teams. It combines modern LLM providers with industry-standard security tools to deliver intelligent, automated security assessments.

---

## 🚀 Quick Start (5 Minutes)

### Prerequisites

- **Kali Linux**
- **Python 3.11+**
- **Git**
- **Container Runtime**: Docker for ZAP scans

### Installation# 1. Clone and setup

```bash
git clone https://github.com/steveschofield/guardian-cli-deluxe
cd guardian-cli-deluxe
python3 -m venv venv
source venv/bin/activate

# 1. Install security tools (Kali Linux).
#    + installs Guardian into the active venv.
./setup.sh 2>&1 | tee setup.log

# 2. Initialize Guardian
python -m cli.main init

# 3. Test installation
source venv/bin/activate (need this before)
python -m cli.main workflow run --name recon --target <approved-test-target>
```

---

## 🔧 Enterprise Configuration

### AI Provider Setup

Configure an AI provider in your `config/guardian.yaml`:

```yaml
# config/guardian.yaml
ai:
  provider: ollama
  model: "llama3.1:8b"
  base_url: "http://127.0.0.1:11434"
```

### Security & Compliance

- **Audit Logging**: All AI decisions and tool executions logged
- **Scope Validation**: Automatic blacklisting prevents unauthorized scanning
- **Safe Mode**: Destructive actions disabled by default
- **Session Tracking**: Complete audit trail for compliance

### Tool Installation

Run the automated setup script:

```bash
./setup.sh 2>&1 | tee setup-tools.log
```

Missing tools will be logged with installation commands.

---

## 📊 Usage Workflows

### Network Assessment

```bash
python -m cli.main workflow run --name network --target <target-ip-or-range>
```

### Web Application Testing

```bash
python -m cli.main workflow run --name web --target https://<target-domain>
```

### Reconnaissance Only

```bash
python -m cli.main workflow run --name recon --target <target>
python -m cli.main workflow run --name recon_quick --target <target>
python -m cli.main workflow run --name quick_vuln_scan --target https://<target-domain>
python -m cli.main workflow run --name wordpress_audit --target https://<target-domain>
```

### AI-Driven Autonomous Testing

```bash
python -m cli.main workflow run --name autonomous --target <target>
```

### Automatic Exploitation

Guardian can automatically attempt exploitation when vulnerabilities are discovered. This feature is **disabled by default** for safety.

**⚠️ WARNING**: Only use auto-exploit in authorized testing environments with explicit permission.

#### Enable via Configuration

Edit `config/guardian.yaml`:

```yaml
exploits:
  enabled: true
  auto_exploit: true  # Enable automatic exploitation
  auto_exploit_require_confirmation: true  # Prompt before each exploit
  auto_exploit_min_severity: "critical"  # Only exploit critical findings
  auto_exploit_max_attempts: 5  # Max exploits per session
```

#### Enable via CLI Flags

```bash
# With confirmation prompts (recommended)
python -m cli.main workflow run --name web --target <target> --auto-exploit

# Without confirmation (dangerous - use with caution)
python -m cli.main workflow run --name web --target <target> --auto-exploit --auto-exploit-no-confirm

# Works with all workflow commands
python -m cli.main recon --domain <target> --auto-exploit
```

#### How It Works

1. **Finding Detection**: When a vulnerability is found (e.g., CVE-2021-12345)
2. **Severity Filter**: Only findings meeting the minimum severity are considered
3. **Exploit Matching**: Guardian searches local Metasploit and Exploit-DB for matching exploits
4. **Confirmation** (if enabled): User is prompted before each exploit attempt
5. **Execution**: Metasploit module is executed against the target
6. **Logging**: Exploitation attempts and results are recorded in findings

#### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `auto_exploit` | `false` | Enable/disable automatic exploitation |
| `auto_exploit_require_confirmation` | `true` | Require user approval before each exploit |
| `auto_exploit_min_severity` | `"critical"` | Minimum severity to exploit (`critical`, `high`, `medium`, `low`) |
| `auto_exploit_max_attempts` | `5` | Maximum exploitation attempts per session |
| `exploitdb_path` | `/usr/share/exploitdb` | Path to local Exploit-DB repository |
| `metasploit_path` | `/usr/share/metasploit-framework` | Path to Metasploit installation |

#### Safety Features

- **Disabled by default**: Must be explicitly enabled
- **Confirmation prompts**: User must approve each exploit (unless disabled)
- **Severity filtering**: Only exploit findings above configured severity
- **Attempt limits**: Maximum number of exploits per session
- **Full logging**: All exploitation attempts recorded in session logs
- **Safe mode respect**: Works with existing `pentest.safe_mode` settings

---

## 📋 Reports & Outputs

Each scan generates:

- **HTML Report**: `reports/report_<session>.html`
- **Markdown Report**: `reports/report_<session>.md`
- **Tool Commands**: `reports/payloads_<session>.txt` (for manual verification)
- **Discovered URLs**: `reports/urls_<session>.txt` (for proxy/ZAP import)
- **Session Data**: `reports/session_<session>.json` (full audit trail)

---

## 🛠️ Tool Arsenal

For the full list of tools and how they are used, see the workflow files in `workflows/`.

**Core Tools (Always Available):**

- **[nmap](https://nmap.org/)** - Port scanning and service detection (vuln profile runs `--script vuln,vulners` by default; configurable)
- **[nuclei](https://github.com/projectdiscovery/nuclei)** - Vulnerability scanning (15min timeout)
- **[subfinder](https://github.com/projectdiscovery/subfinder)** - Subdomain enumeration
- **[ffuf](https://github.com/ffuf/ffuf)** - Directory/file brute forcing
- **[testssl](https://github.com/drwetter/testssl.sh)** - SSL/TLS analysis
- **[gitleaks](https://github.com/zricethezav/gitleaks)** - Secret detection
- **[arjun](https://github.com/s0md3v/Arjun)** - Parameter discovery
- **[xsstrike](https://github.com/s0md3v/XSStrike)** - XSS testing
- **[dnsrecon](https://github.com/darkoperator/dnsrecon)** - DNS enumeration
- **[godeye](https://github.com/Vyntral/god-eye)** - Subdomain reconnaissance with AI analysis

**Additional Tools** (installed via setup.sh):

- **[httpx](https://github.com/projectdiscovery/httpx)** - HTTP probing
- **[katana](https://github.com/projectdiscovery/katana)** - Advanced web crawling
- **[nikto](https://github.com/sullo/nikto)** - Web vulnerability scanner
- **[sqlmap](https://github.com/sqlmapproject/sqlmap)** - SQL injection testing
- **[wpscan](https://github.com/wpscanteam/wpscan)** - WordPress security scanner
- **[sslyze](https://github.com/nabla-c0d3/sslyze)** - SSL/TLS configuration analysis
- **[dnsx](https://github.com/projectdiscovery/dnsx)** - Fast DNS toolkit
- **[shuffledns](https://github.com/projectdiscovery/shuffledns)** - DNS permutation enumeration
- **[puredns](https://github.com/d3mondev/puredns)** - High-confidence DNS resolver
- **[wafw00f](https://github.com/EnableSecurity/wafw00f)** - WAF detection
- **[whatweb](https://github.com/urbanadventurer/WhatWeb)** - Web technology identification
- **[metasploit](https://github.com/rapid7/metasploit-framework)** - Exploitation framework
- **[zap](https://github.com/zaproxy/zaproxy)** - OWASP ZAP (Docker-based)

**Application Security Tools:**

- **[dalfox](https://github.com/hahwul/dalfox)** - Advanced XSS scanner and parameter analysis
- **[commix](https://github.com/commixproject/commix)** - Command injection testing framework
- **[feroxbuster](https://github.com/epi052/feroxbuster)** - Fast API endpoint and content discovery
- **[trufflehog](https://github.com/trufflesecurity/trufflehog)** - Secret scanning

**Platform Notes:**

- **Kali Linux**: All tools supported

---

## 🔍 Troubleshooting

### Common Issues

**"Unable to locate credentials"**

Ensure your chosen provider credentials are set in the environment (see `docs/CONFIGURATION.md`).

**Enterprise Authentication**

- **SSO Users**: Authenticate via your identity provider before running Guardian
- **Helper Script**: Use `./scripts/auth-check.sh` to verify authentication status

**Missing Tools**

```bash
# Check what's available
python -m cli.main workflow list
# Install missing tools
./setup.sh
```

**masscan permission denied**

`masscan` needs raw socket access. `./setup.sh` attempts to set capabilities; if it still fails, run:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v masscan)"
```

**Kali Linux Compatibility**

- Ensure required tools are installed via `./setup.sh` before running workflows.

---

## 📞 Internal Support

- **Issues**: Create ticket in internal issue tracker
- **Documentation**: See `docs/` directory
- **Tool Development**: See `docs/TOOLS_DEVELOPMENT_GUIDE.md`
- **Setup Issues**: See `STREAMLINING.md` for modern tool stack and fixes

---

## 🔒 Security Notes

- **Authorized Use Only**: Ensure proper authorization before scanning
- **Network Policies**: Verify firewall/proxy compatibility
- **Data Handling**: All scan data stored locally in `reports/`
- **Audit Trail**: Complete logging enabled by default

---

**Guardian Enterprise** - Intelligent Security Assessment for Internal Teams
