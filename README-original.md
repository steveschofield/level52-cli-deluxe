<div align="center">

<img src="docs/logo.svg" alt="Guardian Logo" width="200" />

# 🔐 Guardian

### AI-Powered Penetration Testing Automation Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**Guardian** is an enterprise-grade AI-powered penetration testing automation framework that combines the strategic reasoning of modern LLMs (Gemini or local models via Ollama/OpenAI-compatible) with battle-tested security tools to deliver intelligent, adaptive security assessments.

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Contributing](#-contributing)

</div>

---

## ⚠️ Legal Disclaimer

**Guardian is designed exclusively for authorized security testing and educational purposes.**

- ✅ **Legal Use**: Authorized penetration testing, security research, educational environments
- ❌ **Illegal Use**: Unauthorized access, malicious activities, any form of cyber attack

**You are fully responsible for ensuring you have explicit written permission before testing any system.** Unauthorized access to computer systems is illegal under laws including the Computer Fraud and Abuse Act (CFAA), GDPR, and equivalent international legislation.

**By using Guardian, you agree to use it only on systems you own or have explicit authorization to test.**

⚠️ My Disclaimer
This tool is intended for EDUCATIONAL and AUTHORIZED security testing purposes ONLY.

Do NOT use against systems without explicit written permission
The authors are NOT responsible for misuse of this extension
Use ONLY on systems you own or have authorization to test
Recommended for local testing against vulnerable apps like OWASP Juice Shop or DVWA
USE AT YOUR OWN RISK - NO WARRANTY PROVIDED

---

## ✨ Features

### 🤖 AI-Powered Intelligence

- **Multi-Agent Architecture**: Specialized AI agents (Planner, Tool Selector, Analyst, Reporter) collaborate for comprehensive security assessments
- **Flexible LLM Backends**: Use Google Gemini (API key or Vertex/ADC), OpenRouter, or a local LLM (e.g., Ollama) via config
- **Strategic Decision Making**: LLM analyzes findings and determines optimal next steps
- **Adaptive Testing**: AI adjusts tactics based on discovered vulnerabilities and system responses
- **False Positive Filtering**: Intelligent analysis reduces noise and focuses on real vulnerabilities

### 🛠️ Extensive Tool Arsenal

**20+ Integrated Security Tools:**

- **Network**: Nmap (comprehensive port scanning; vuln profile runs `--script vuln,vulners`), Masscan (ultra-fast scanning), Naabu (fast TCP/UDP)
- **Web Reconnaissance**: httpx (HTTP probing), WhatWeb (technology fingerprinting), Wafw00f (WAF detection)
- **Subdomain/ASN Discovery**: Subfinder (passive enum), Amass (active/passive mapping), ASNmap (AS intel), dnsx/shuffledns/puredns/altdns
- **URL/Content Discovery**: Katana (crawler), Gospider, Hakrawler, Waybackurls, Subjs, Dirsearch/Gobuster/FFuf
- **JS/API Analysis**: LinkFinder/xnLinkFinder (JS endpoint discovery), ParamSpider/Arjun (parameter discovery), Schemathesis (OpenAPI fuzzing)
- **Vulnerability Scanning**: Nuclei (templates), Nikto (web vulns), SQLMap (SQLi), WPScan (WordPress)
- **Web App Scanning**: OWASP ZAP (headless baseline/full scans via Docker)
- **Secrets/Leak Detection**: Gitleaks, TruffleHog
- **SSL/TLS Testing**: TestSSL (cipher analysis), SSLyze (advanced configuration analysis)

### 🔒 Security & Compliance

- **Scope Validation**: Automatic blacklisting of private networks and unauthorized targets
- **Audit Logging**: Complete transparency with detailed logs of all AI decisions and actions
- **Human-in-the-Loop**: Configurable confirmation prompts for sensitive operations
- **Safe Mode**: Prevents destructive actions by default

### 📊 Professional Reporting

- **Multiple Formats**: Markdown, HTML, and JSON reports
- **Manual Testing Helpers**: Each session exports `urls_<session>.txt` and `payloads_<session>.txt` under `reports/` for quick import into proxy/ZAP or other tools
- **Executive Summaries**: Non-technical overviews for stakeholders
- **Technical Deep-Dives**: Detailed findings with evidence and remediation steps
- **AI Decision Traces**: Full transparency into AI reasoning process

### ⚡ Performance & Efficiency

- **Asynchronous Execution**: Parallel tool execution for faster assessments
- **Workflow Automation**: Predefined workflows (Recon, Web, Network, Autonomous)
- **Customizable**: Create custom tools and workflows via simple YAML/Python

---

## 📋 Prerequisites

### Required

- **Python 3.11 or higher** ([Download](https://www.python.org/downloads/))
- **Git** (for cloning repository)
- **One LLM backend**:
  - Google Gemini API Key ([Get API Key](https://makersuite.google.com/app/apikey)), _or_
  - Local LLM endpoint (e.g., Ollama at `http://127.0.0.1:11434`)

### Optional Tools (for full functionality)

Guardian will use these automatically if present:

| Tool                                                      | Purpose                    | Installation                                                                                                             |
| --------------------------------------------------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| **nmap**                                            | Port scanning              | `apt install nmap` / `brew install nmap`                                                                             |
| **naabu**                                           | Fast TCP/UDP scan          | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest`                                                     |
| **httpx**                                           | HTTP probing               | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest`                                                        |
| **subfinder**                                       | Subdomain enum             | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`                                             |
| **asnmap**                                          | ASN intel                  | `go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest`                                                      |
| **nuclei**                                          | Vuln scanning              | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`                                                   |
| **whatweb**                                         | Tech fingerprint           | `apt install whatweb` / `gem install whatweb`                                                                        |
| **wafw00f**                                         | WAF detection              | `pip install wafw00f`                                                                                                  |
| **nikto**                                           | Web vuln scan              | `apt install nikto`                                                                                                    |
| **sqlmap**                                          | SQL injection              | `pip install sqlmap` / `apt install sqlmap`                                                                          |
| **wpscan**                                          | WordPress scan             | `gem install wpscan`                                                                                                   |
| **testssl**                                         | SSL/TLS testing            | `git clone https://github.com/drwetter/testssl.sh`                                                                     |
| **sslyze**                                          | SSL/TLS analysis           | `pip install sslyze`                                                                                                   |
| **ffuf / dirsearch**                                | Content brute force        | `go install github.com/ffuf/ffuf/v2@latest` / `pip install dirsearch`                                                 |
| **katana**                                          | Crawling & URL harvest     | `go install github.com/projectdiscovery/katana/cmd/katana@latest`                                                     |
| **waybackurls / subjs**                             | Historical/JS URL harvest  | `go install tomnomnom/waybackurls@latest` / `go install github.com/lc/subjs@latest`                                  |
| **linkfinder / xnLinkFinder**                       | JS endpoint discovery      | `pip install "linkfinder @ git+https://github.com/GerbenJavado/LinkFinder.git"` / `pip install xnlinkfinder`         |
| **arjun / paramspider**                             | Parameter discovery        | `pip install arjun` / `pip install "paramspider @ git+https://github.com/devanshbatham/ParamSpider.git"`             |
| **schemathesis**                                    | OpenAPI fuzzing            | `pip install schemathesis`                                                                                             |
| **gitleaks / trufflehog**                           | Secret scanning            | `go install github.com/zricethezav/gitleaks/v8@latest` / `pip install trufflehog`                                    |
| **dnsrecon / dnsx / shuffledns / puredns / altdns** | DNS enumeration/resolution | `pip install dnsrecon` / `go install ...` / `pip install py-altdns @ git+https://github.com/infosec-au/altdns.git` |
| **cmseek / xsstrike**                               | CMS/XSS utilities          | `pip install cmseek` / `pip install xsstrike`                                                                        |
| **metasploit**                                      | Exploitation framework     | `apt install metasploit-framework` or nightly installer                                                                |

> **Note**: Guardian works without external tools but with limited scanning capabilities. The AI will adapt based on available tools.

---

## 🚀 Installation

### Quick Setup (5 Minutes)

**For first-time users - minimal setup to get started:**

```bash
# 1. Clone and setup
git clone https://github.com/steveschofield/guardian-cli-deluxe.git
cd guardian-cli-deluxe
python3 -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
pip install -e .

# 2. Initialize config
python -m cli.main init

# 3. Test with basic tools (nmap should work out of box)
python -m cli.main workflow run --name recon --target scanme.nmap.org
```

**That's it!** Guardian will use available tools and skip missing ones.

---

### Option 1: Docker (Recommended - All Tools Included) 🐳

**Easiest and fastest way to get started with the core security tools pre-installed!**

```bash
# Clone repository original framework
git clone https://github.com/zakirkun/guardian-cli.git
cd guardian-cli

# Clone repository updated framework by Steve Schofield
git clone https://github.com/steveschofield/guardian-cli-deluxe.git
cd guardian-cli-deluxe

# Optional: .env if using Gemini
echo "GOOGLE_API_KEY=your_api_key_here" > .env

# Build Docker image (one-time, ~5 minutes)
docker-compose build

# Run Guardian
docker-compose run --rm guardian recon --domain example.com
```

**Benefits:**

- ✅ Core tools pre-installed (nmap, httpx, nuclei, sqlmap, etc.)
- ✅ No manual tool installation required
- ✅ Consistent environment across all systems
- ✅ Isolated and secure

**See [Docker Guide](docs/DOCKER.md) for advanced usage.**

---

### Option 2: Local Installation (Customizable)

#### Step 1: Clone Repository

```bash
git clone https://github.com/zakirkun/guardian-cli.git
cd guardian-cli
```

#### Step 2: Set Up Python Environment

**Linux/macOS:**

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

**Windows:**

```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -e .
```

Optional (Linux/macOS): run the setup helper to install additional tools, and keep a log of the output:

```bash
./setup.sh 2>&1 | tee setup.log
```

#### Step 3: Initialize Configuration

```bash
# Linux/macOS
python -m cli.main init

# Windows
python -m cli.main init
# or use the batch launcher
.\guardian.bat init
```

During initialization, you can provide a Gemini API key (optional if using a local model). Alternatively, create a `.env` file:

```bash
echo "GOOGLE_API_KEY=your_api_key_here" > .env  # only if using Gemini
```

To use Gemini via Vertex AI / ADC (recommended for higher limits, no API key):

```bash
pip install -U google-genai
gcloud auth application-default login

# In config/guardian.yaml (or your copied ~/.guardian/guardian.yaml)
ai:
  provider: gemini
  model: "gemini-2.5-flash"
  vertexai: true
  project: "your-gcp-project-id-or-number"
  location: "us-central1"
```

To use OpenRouter (hosted models via OpenAI-compatible API):

```bash
echo "OPENROUTER_API_KEY=your_key_here" > .env

# In config/guardian.yaml (or your copied ~/.guardian/guardian.yaml)
ai:
  provider: openrouter
  model: "openai/gpt-4o-mini"   # pick any OpenRouter model slug
  base_url: "https://openrouter.ai/api/v1"
```

To use Hugging Face Serverless Inference API (routed via `router.huggingface.co`):

```bash
echo "HF_TOKEN=your_huggingface_token_here" > .env

# In config/guardian.yaml (or your copied ~/.guardian/guardian.yaml)
ai:
  provider: huggingface
  model: "meta-llama/Meta-Llama-3-8B-Instruct"   # any public HF model repo id you can access
  base_url: "https://router.huggingface.co/hf-inference/models"
```

To use Hugging Face Router (OpenAI-compatible API):

```bash
echo "HF_TOKEN=your_huggingface_token_here" > .env

ai:
  provider: huggingface
  model: "openai/gpt-oss-120b"
  base_url: "https://router.huggingface.co/v1"
```

To use a local LLM (e.g., Ollama Llama 3.x):

```bash
# In config/guardian.yaml (or your copied ~/.guardian/guardian.yaml)
ai:
  provider: ollama
  model: "llama3.1:8b"
  base_url: "http://127.0.0.1:11434"  # adjust if remote host
```

To enable OWASP ZAP scans (headless via Docker):

```bash
docker pull ghcr.io/zaproxy/zaproxy:stable

# In config/guardian.yaml
tools:
  zap:
    enabled: true
    mode: docker
    scan: baseline   # full requires pentest.safe_mode: false
    docker_image: ghcr.io/zaproxy/zaproxy:stable   # or :bare / :weekly / :nightly
```

To log full LLM request/response payloads (enabled by default in config):

```bash
# Logging is now enabled by default in config/guardian.yaml
# Files written to reports/llm_io_<session>_<timestamp>.jsonl
# Includes tool executions, AI decisions, and workflow progress
```

The file contains JSONL events per LLM call (`request`, `response`, `error`) correlated by `call_id`.

Prompt size controls:

- `ai.max_tool_output_chars`: caps raw tool output included in prompts (Analyst).
- `ai.max_input_chars`: caps total characters sent to the LLM (best-effort across providers).
- `ai.context_window`: (Ollama only) sets `num_ctx` via `ChatOllama(options=...)`.

TODO (future optimization): Condense other noisy tool outputs (e.g., `httpx` JSONL, `nuclei` JSONL, `testssl`/`sslyze`, crawlers) before sending to the LLM, while keeping raw outputs in session logs for audit.
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## 🎯 Quick Start

### Basic Commands

```bash
# List available workflows
python -m cli.main workflow list

# Dry run (see execution plan without running)
python -m cli.main recon --domain example.com --dry-run
```

### Example Usage Scenarios

#### 1. Quick Web Application Scan

```bash
# Fast security check of a web application
python -m cli.main workflow run --name web --target https://example.com
```

> The web and recon workflows now include a **Nikto baseline scan** after HTTP discovery. Make sure `nikto` is installed (e.g., `apt install nikto`) so the step runs.

#### 2. Comprehensive Network Assessment

```bash
# Full network penetration test
python -m cli.main workflow run --name network --target 192.168.1.0/24
```

#### 3. Subdomain Reconnaissance

```bash
# Discover and analyze subdomains
python -m cli.main recon --domain example.com
```

#### 4. Autonomous AI-Driven Test

```bash
# Let AI decide each step dynamically
python -m cli.main workflow run --name autonomous --target example.com
```

#### 5. Generate Professional Report

```bash
# Create HTML report from previous scan
python -m cli.main report --session 20251222_120000 --format html
```

Reports are saved to `./reports` with helper exports (`urls_<session>.txt`, `payloads_<session>.txt`) you can load into proxy tools or ZAP.

#### 6. Explain AI Decisions

```bash
# View AI decision-making process
python -m cli.main ai --last
```

> **Windows Users**: Use `python -m cli.main` or `.\guardian.bat` instead of `guardian`

---

## 📖 Documentation

### User Guides

- **[Quick Start Guide](QUICKSTART.md)** - Get up and running in 5 minutes
- **[Docker Deployment Guide](docs/DOCKER.md)** - Run Guardian with Docker (recommended)
- **[Command Reference](docs/USAGE.md)** - CLI command reference
- **[Configuration Guide](docs/CONFIGURATION.md)** - How config loading works + key settings

### Developer Guides

- **[Creating Custom Tools](docs/TOOLS_DEVELOPMENT_GUIDE.md)** - Build your own tool integrations
- **[Workflow Development](docs/WORKFLOW_GUIDE.md)** - Create custom testing workflows
- **[Available Tools](tools/README.md)** - Overview of integrated tools

### Architecture

- **Multi-Agent System**: Planner → Tool Selector → Analyst → Reporter
- **AI-Driven**: Google Gemini for strategic decision-making
- **Modular**: Easy to extend with new tools and workflows

---

## 🏗️ Project Structure

```
guardian-cli/
├── ai/                    # AI integration (Gemini client, prompts)
├── cli/                   # Command-line interface
│   └── commands/         # CLI commands (init, scan, recon, etc.)
├── core/                  # Core agent system
│   ├── agent.py          # Base agent
│   ├── planner.py        # Planner agent
│   ├── tool_agent.py     # Tool selection agent
│   ├── analyst_agent.py  # Analysis agent
│   ├── reporter_agent.py # Reporting agent
│   ├── memory.py         # State management
│   └── workflow.py       # Workflow orchestration
├── tools/                 # Pentesting tool wrappers (20+)
│   ├── nmap.py, naabu.py
│   ├── httpx.py, nuclei.py, nikto.py, sqlmap.py, wpscan.py
│   ├── subfinder.py, asnmap.py, dnsx.py, shuffledns.py, puredns.py, altdns.py
│   ├── katana.py, waybackurls.py, subjs.py
│   ├── dirsearch.py, ffuf.py
│   ├── linkfinder.py, xnlinkfinder.py, paramspider.py, arjun.py, schemathesis.py
│   ├── gitleaks.py, trufflehog.py, cmseek.py
│   ├── testssl.py, sslyze.py, wafw00f.py, whatweb.py, metasploit.py
│   └── ...               # See tools/README.md and config/guardian.yaml for defaults
├── workflows/             # Workflow definitions (YAML)
├── utils/                 # Utilities (logging, validation)
├── config/                # Configuration files
├── docs/                  # Documentation
└── reports/               # Generated reports
```

---

## 🔧 Configuration

Edit `config/guardian.yaml` to customize (repo default). When running outside the repo, `guardian init` creates `~/.guardian/guardian.yaml` and Guardian will use it if `config/guardian.yaml` is not present.

```yaml
ai:
  provider: gemini   # or ollama / openrouter / huggingface
  model: gemini-1.5-pro
  temperature: 0.2

pentest:
  safe_mode: true              # Prevent destructive actions
  require_confirmation: true   # Confirm before each step
  max_parallel_tools: 3        # Concurrent tool execution

scope:
  blacklist:                   # Never scan these
    - 127.0.0.0/8
    - 10.0.0.0/8
```

---

## 🤝 Contributing

We welcome contributions! Here's how:

### Setting Up Development Environment

```bash
# Fork and clone
git clone https://github.com/zakirkun/guardian-cli.git
cd guardian-cli

# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Format code
black .
```

### Contribution Guidelines

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Areas for Contribution

- 🛠️ **New Tool Integrations** - Add more security tools
- 🔄 **Custom Workflows** - Share your workflow templates
- 🐛 **Bug Fixes** - Report and fix issues
- 📚 **Documentation** - Improve guides and examples
- 🧪 **Testing** - Expand test coverage

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

## 📊 Roadmap

- [ ] Web Dashboard for visualization
- [ ] PostgreSQL backend for multi-session tracking
- [ ] MITRE ATT&CK mapping for findings
- [ ] Plugin system for custom modules
- [ ] Integration with CI/CD pipelines
- [ ] Additional AI models support (Claude, GPT-4)
- [ ] Mobile app for on-the-go assessments

---

## 🐛 Troubleshooting

### Common Issues

**Import Errors**

```bash
# Reinstall dependencies
pip install -e . --force-reinstall
```

**API Rate Limits**

- Provider limits vary by backend/model; switch tiers/models if you hit rate limits.
- If you see timeouts, increase `ai.timeout` / `ai.llm_timeout_seconds` in your config.

**Tool Not Found**

```bash
# Check tool availability
which nmap
which httpx

# Install missing tools (see Prerequisites)
```

**macOS Compatibility**

- Ensure httpx and katana are installed on PATH before running web workflows.
- Run `./setup.sh` to install compatible tools via `go install`

**Windows Command Not Found**

```powershell
# Use full command
python -m cli.main --help

# Or use batch launcher
.\guardian.bat --help
```

For more help, [open an issue](https://github.com/zakirkun/guardian-cli/issues).

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 Guardian Project

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
```

---

## 🙏 Acknowledgments

- **Google Gemini** - AI capabilities
- **LangChain** - AI orchestration framework
- **ProjectDiscovery** - Open-source security tools (httpx, subfinder, nuclei)
- **Nmap** - Network exploration and security auditing
- **The Security Community** - Tool developers and researchers

---

## 📞 Support & Contact

- **GitHub Issues**: [Report bugs or request features](https://github.com/zakirkun/guardian-cli/issues)
- **Discussions**: [Join community discussions](https://github.com/zakirkun/guardian-cli/discussions)
- **Documentation**: [Read the docs](docs/)
- **Security**: Report vulnerabilities privately to security@example.com

---

## ⭐ Star History

If you find Guardian useful, please consider giving it a star! ⭐

---

<div align="center">

**Guardian** - Intelligent, Ethical, Automated Penetration Testing

Made with ❤️ by the Security Community

[⬆ Back to Top](#-guardian)

</div>
