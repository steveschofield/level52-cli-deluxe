# Guardian CLI Deluxe - Docker Container Guide

## Overview

Guardian CLI Deluxe is now available as a fully-featured Kali Linux Docker container with **complete parity** to the native `setup.sh` installation.

Version 3.0 includes all tools, dependencies, and enhancements from the native setup.

---

## Quick Start

### Build the Container

```bash
docker build -f Dockerfile.kali -t guardian-cli-deluxe:latest .
```

### Run the Container

```bash
docker run -it --rm \
  -e ANTHROPIC_API_KEY="your-key-here" \
  -v $(pwd)/reports:/guardian/reports \
  guardian-cli-deluxe:latest
```

### Using Docker Compose

```bash
# Edit docker-compose.yml to add your API keys
docker-compose up -d
docker-compose exec guardian-kali bash
```

---

## Native Kali vs Docker Container

### Recommendation: **Native Kali + setup.sh (Preferred)**

The native installation is the recommended approach for the following reasons:

| Feature | Native Kali + setup.sh | Docker Container |
|---------|------------------------|------------------|
| **Tool Coverage** | ✅ 100% (all tools) | ✅ 100% (complete parity) |
| **Performance** | ✅ Native speed | ⚠️ Docker overhead |
| **Network Access** | ✅ Direct access | ⚠️ Requires `--net=host` for some tools |
| **Privilege Escalation** | ✅ Easy with sudo | ⚠️ Requires `--privileged` or caps |
| **GPU Access** | ✅ Direct access | ⚠️ Complex GPU passthrough |
| **Installation Time** | ⚠️ 10-20 minutes | ⚠️ 30-60 minutes (build) |
| **Disk Space** | ✅ ~5-10 GB | ❌ ~15-20 GB (image size) |
| **Idempotency** | ✅ Re-run safe | ⚠️ Requires rebuild |
| **Updates** | ✅ Just re-run setup.sh | ⚠️ Rebuild entire image |
| **Customization** | ✅ Easy modifications | ⚠️ Requires Dockerfile edits |
| **Tool Binaries** | ✅ GitHub releases first | ✅ Same strategy |
| **Dependency Isolation** | ✅ Python venv | ⚠️ System-wide pip |
| **Portability** | ❌ Kali-only | ✅ Runs anywhere |

---

## When to Use Docker

Docker is ideal for:

1. **Isolated Testing Environments** - Don't want to modify your main system
2. **CI/CD Pipelines** - Automated security scanning in Jenkins/GitLab/GitHub Actions
3. **Multi-tenant Environments** - Multiple isolated Guardian instances
4. **Non-Kali Systems** - Want Guardian on Ubuntu/macOS/Windows
5. **Reproducible Builds** - Exact same environment every time
6. **Quick Demos** - Spin up/tear down quickly

---

## When to Use Native Kali

Native installation is better for:

1. **Primary Pentest Workstation** - Maximum performance and flexibility
2. **Hardware Access** - GPU cracking, wireless adapters, USB devices
3. **Network Testing** - Raw packet manipulation, masscan, nmap SYN scans
4. **Long-term Development** - Actively modifying Guardian code
5. **Resource Constraints** - Limited disk space or RAM
6. **Tool Updates** - Frequently updating individual tools

---

## Tool Coverage Comparison

### ✅ Complete Parity Achieved (v3.0)

Both Docker and native setups now include:

#### SAST/Whitebox Analysis Tools
- ✅ **Semgrep** - Code vulnerability scanner (SQLi, XSS, SSTI, etc.)
- ✅ **Trivy** - Dependency CVE scanner + IaC misconfigurations
- ✅ **TruffleHog** - Advanced secret detection (v3 binary)
- ✅ **Gitleaks** - Secret scanning (regex patterns)

#### ProjectDiscovery Suite
- ✅ httpx, nuclei, subfinder, dnsx, katana, naabu, shuffledns, asnmap, interactsh-client

#### Go Tools
- ✅ ffuf, waybackurls, gau, dalfox, gitleaks, puredns, subjs, webanalyze, god-eye

#### Rust Tools
- ✅ feroxbuster (compiled from source)

#### Python Security Tools
- ✅ arjun, dirsearch, schemathesis, wafw00f, sqlmap, sslyze, dnsrecon
- ✅ xnlinkfinder, dnsgen, sstimap (replaces tplmap)

#### Git-Cloned Tools
- ✅ testssl.sh, XSStrike, CMSeeK, WhatWeb, commix
- ✅ graphql-cop, jwt_tool, SSTImap, CORScanner, LinkFinder, ParamSpider

#### npm Tools
- ✅ retire.js (JavaScript library vulnerability scanner)

#### Wordlists
- ✅ SecLists (comprehensive wordlist collection)
- ✅ Kiterunner API routes wordlist

#### LangChain Ecosystem
- ✅ langchain, langchain-core, langchain-community
- ✅ **langchain-ollama** (was missing in v2.0)
- ✅ **langsmith** (was missing in v2.0)

#### Fixed Dependencies
- ✅ requests >= 2.32.0
- ✅ urllib3 >= 2.0.0
- ✅ charset-normalizer >= 3.0.0
- ✅ attrs >= 22.2.0

#### Guardian Enhancements
- ✅ ZAP hybrid mode (Docker + native detection)
- ✅ Smart port scanner (masscan → nmap pipeline)
- ✅ Comprehensive verification checks

---

## Installation Instructions

### Option 1: Native Kali (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/guardian-cli-deluxe.git
cd guardian-cli-deluxe

# Create and activate Python virtual environment
python3.12 -m venv venv
source venv/bin/activate

# Run setup script
./setup.sh
```

**Advantages:**
- Faster execution
- Direct hardware access
- Easier to update individual tools
- Less disk space

### Option 2: Docker Container

```bash
# Clone the repository
git clone https://github.com/yourusername/guardian-cli-deluxe.git
cd guardian-cli-deluxe

# Build the Docker image (takes 30-60 minutes)
docker build -f Dockerfile.kali -t guardian-cli-deluxe:latest .

# Run with API keys
docker run -it --rm \
  -e ANTHROPIC_API_KEY="sk-ant-..." \
  -v $(pwd)/reports:/guardian/reports \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  guardian-cli-deluxe:latest
```

**Advantages:**
- Portable across systems
- Isolated environment
- Consistent builds
- Easy CI/CD integration

---

## Docker Usage Examples

### Basic Interactive Shell

```bash
docker run -it --rm guardian-cli-deluxe:latest
```

### Run a Workflow

```bash
docker run -it --rm \
  -e ANTHROPIC_API_KEY="sk-ant-..." \
  -v $(pwd)/reports:/guardian/reports \
  guardian-cli-deluxe:latest \
  python -m cli.main workflow run --name web --target https://example.com
```

### Whitebox Analysis (SAST + DAST)

```bash
docker run -it --rm \
  -e ANTHROPIC_API_KEY="sk-ant-..." \
  -v $(pwd)/reports:/guardian/reports \
  -v $(pwd)/source-code:/guardian/source \
  guardian-cli-deluxe:latest \
  python -m cli.main workflow run \
    --name web \
    --target https://example.com \
    --source /guardian/source
```

### Network Scanning (Requires Privileged Mode)

```bash
docker run -it --rm \
  --privileged \
  --net=host \
  -e ANTHROPIC_API_KEY="sk-ant-..." \
  guardian-cli-deluxe:latest \
  nmap -sS -sV 192.168.1.0/24
```

### Using Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  guardian-kali:
    build:
      context: .
      dockerfile: Dockerfile.kali
    image: guardian-cli-deluxe:latest
    container_name: guardian-kali
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
    volumes:
      - ./reports:/guardian/reports
      - ./logs:/guardian/logs
      - ./data:/guardian/data
    cap_add:
      - NET_ADMIN
      - NET_RAW
    stdin_open: true
    tty: true
    restart: unless-stopped
```

```bash
# Start container
docker-compose up -d

# Exec into container
docker-compose exec guardian-kali bash

# Stop container
docker-compose down
```

---

## Docker Container Features

### System Tools (via apt)
- nmap, masscan, rustscan
- nikto, whatweb, wpscan
- enum4linux, enum4linux-ng
- hydra, medusa
- sqlmap, nuclei
- metasploit-framework
- amass, sublist3r
- smbclient, smbmap
- ldap-utils, snmp tools
- john, hashcat
- crackmapexec, impacket-scripts

### Verification on Build

The Dockerfile includes comprehensive verification:

```dockerfile
# Verify SAST tools
which semgrep && semgrep --version
which trivy && trivy --version
which trufflehog && trufflehog --version
which gitleaks && gitleaks version

# Verify ProjectDiscovery tools
which httpx && httpx -version
which nuclei && nuclei -version
which subfinder && subfinder -version

# Verify Python packages
python3 -c "from langchain_ollama import ChatOllama"
python3 -c "import requests; assert requests.__version__ >= '2.32.0'"
```

If any critical tool is missing, the Docker build will **fail**.

---

## Environment Variables

### Required
- `ANTHROPIC_API_KEY` - Claude API key for AI-powered analysis

### Optional
- `OPENAI_API_KEY` - OpenAI API key (if using GPT models)
- `GOOGLE_API_KEY` - Google API key (if using Gemini)
- `GUARDIAN_CONFIG` - Custom config file path (default: `/guardian/config/guardian.yaml`)

---

## Volume Mounts

### Recommended Mounts

```bash
docker run -it --rm \
  -v $(pwd)/reports:/guardian/reports \      # Scan reports
  -v $(pwd)/logs:/guardian/logs \            # Application logs
  -v $(pwd)/data:/guardian/data \            # Persistent data
  -v $(pwd)/config:/guardian/config \        # Custom configs
  -v $(pwd)/source:/guardian/source \        # Source code for SAST
  guardian-cli-deluxe:latest
```

---

## Networking Considerations

### Default Bridge Mode

Works for most HTTP-based testing:

```bash
docker run -it --rm guardian-cli-deluxe:latest
```

### Host Network Mode

Required for raw packet manipulation, SYN scans, masscan:

```bash
docker run -it --rm \
  --net=host \
  guardian-cli-deluxe:latest
```

### Port Forwarding

For running services inside the container:

```bash
docker run -it --rm \
  -p 8080:8080 \
  -p 8443:8443 \
  guardian-cli-deluxe:latest
```

---

## Security Capabilities

### Minimum Required Capabilities

For network scanning tools like nmap, masscan:

```bash
docker run -it --rm \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  guardian-cli-deluxe:latest
```

### Privileged Mode (Use with Caution)

For full access (required for some advanced attacks):

```bash
docker run -it --rm \
  --privileged \
  guardian-cli-deluxe:latest
```

⚠️ **Warning:** Only use `--privileged` in isolated/trusted environments.

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Security Scan

on:
  push:
    branches: [ main ]

jobs:
  guardian-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Build Guardian Docker Image
        run: docker build -f Dockerfile.kali -t guardian-cli-deluxe:latest .

      - name: Run Security Scan
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          docker run --rm \
            -e ANTHROPIC_API_KEY \
            -v $PWD/reports:/guardian/reports \
            guardian-cli-deluxe:latest \
            python -m cli.main workflow run \
              --name web \
              --target https://staging.example.com \
              --source .

      - name: Upload Reports
        uses: actions/upload-artifact@v2
        with:
          name: security-reports
          path: reports/
```

### GitLab CI Example

```yaml
guardian-security-scan:
  image: guardian-cli-deluxe:latest
  script:
    - python -m cli.main workflow run --name web --target $TARGET_URL --source .
  artifacts:
    paths:
      - reports/
  only:
    - main
```

---

## Troubleshooting

### Image Build Fails

```bash
# Clean build (no cache)
docker build --no-cache -f Dockerfile.kali -t guardian-cli-deluxe:latest .

# Check specific stage failure
docker build --target STAGE_NAME -f Dockerfile.kali -t guardian-test .
```

### Tool Not Found in PATH

```bash
# Check if tool is installed
docker run -it --rm guardian-cli-deluxe:latest which nuclei

# Verify Go tools are in PATH
docker run -it --rm guardian-cli-deluxe:latest echo $PATH
```

### Python Import Errors

```bash
# Verify Python packages
docker run -it --rm guardian-cli-deluxe:latest \
  python3 -c "import langchain_ollama; print('OK')"

# Check pip packages
docker run -it --rm guardian-cli-deluxe:latest pip list
```

### Network Scanning Not Working

```bash
# Use host network mode
docker run -it --rm --net=host guardian-cli-deluxe:latest nmap -sS 192.168.1.1

# Add network capabilities
docker run -it --rm \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  guardian-cli-deluxe:latest masscan 192.168.1.0/24 -p80
```

---

## Differences from Native Setup

### Advantages of Docker
1. ✅ Portable - runs on any system with Docker
2. ✅ Isolated - doesn't affect host system
3. ✅ Reproducible - exact same environment
4. ✅ CI/CD friendly - easy automation

### Limitations of Docker
1. ❌ Larger disk footprint (~15-20 GB vs ~5-10 GB)
2. ❌ Slower builds (30-60 min vs 10-20 min)
3. ❌ Network limitations (requires `--net=host` for some tools)
4. ❌ No venv isolation (system-wide pip install)
5. ❌ Harder to update individual tools (requires rebuild)

### What's Identical
- ✅ All tools installed (100% parity)
- ✅ All dependencies fixed (requests>=2.32.0, etc.)
- ✅ LangChain ecosystem complete
- ✅ SAST tools (Semgrep, Trivy, TruffleHog, Gitleaks)
- ✅ Wordlists (SecLists, Kiterunner)
- ✅ Smart wrappers (guardian-portscan, guardian-zap)
- ✅ Verification checks

---

## Maintenance

### Update Tools in Docker

Since Docker doesn't have the idempotent retry logic from `setup.sh`, updates require rebuilding:

```bash
# Rebuild image with latest tools
docker build --no-cache -f Dockerfile.kali -t guardian-cli-deluxe:latest .

# Tag with version
docker tag guardian-cli-deluxe:latest guardian-cli-deluxe:v3.0
```

### Update Tools in Native Kali

Native setup is easier to update:

```bash
# Just re-run setup.sh (idempotent)
source venv/bin/activate
./setup.sh
```

---

## Size Comparison

| Component | Native Kali | Docker |
|-----------|-------------|--------|
| Base OS | 0 GB (already installed) | ~2 GB (Kali base image) |
| System packages | ~2 GB | ~4 GB |
| Go tools | ~500 MB | ~500 MB |
| Python tools | ~1 GB | ~2 GB (no venv) |
| Git repos | ~1 GB | ~1 GB |
| Wordlists | ~2 GB | ~2 GB |
| Rust tools | ~500 MB | ~500 MB |
| Docker overhead | 0 GB | ~3 GB (layers) |
| **Total** | **~7 GB** | **~15 GB** |

---

## Performance Comparison

| Operation | Native Kali | Docker | Difference |
|-----------|-------------|--------|------------|
| Setup time | 10-20 min | 30-60 min | **2-3x slower** |
| Tool execution | 1.0x baseline | 0.95x | ~5% overhead |
| Network scanning | Full speed | Requires `--net=host` | Depends on mode |
| File I/O | Native FS | Volume mount overhead | ~10-20% slower |
| Memory usage | ~2 GB | ~2.5 GB | +500 MB overhead |

---

## Recommendations

### Use Native Kali If:
- ✅ You're on Kali Linux already
- ✅ You need maximum performance
- ✅ You frequently update tools
- ✅ You need raw network access
- ✅ You're doing active pentesting

### Use Docker If:
- ✅ You're on non-Kali systems (Ubuntu, macOS, Windows)
- ✅ You want isolated environments
- ✅ You're running in CI/CD
- ✅ You want reproducible builds
- ✅ You're doing demos or training

---

## Support

For issues or questions:
- GitHub Issues: https://github.com/yourusername/guardian-cli-deluxe/issues
- Documentation: See README.md and setup.sh comments

---

## Version History

### v3.0 (Current) - Full Parity Release
- ✅ Added all missing SAST tools (Semgrep, Trivy)
- ✅ Added all ProjectDiscovery tools
- ✅ Added all Go tools (gau, waybackurls, gitleaks, etc.)
- ✅ Added all Python security tools (arjun, dirsearch, dnsgen, etc.)
- ✅ Added all git-cloned tools (cmseek, jwt_tool, graphql-cop, etc.)
- ✅ Fixed LangChain dependencies (langchain-ollama, langsmith)
- ✅ Fixed Python dependency versions (requests>=2.32.0, urllib3>=2.0.0)
- ✅ Added wordlists (SecLists, Kiterunner)
- ✅ Added smart wrappers (guardian-portscan, guardian-zap)
- ✅ Added comprehensive verification checks
- ✅ **Achieved 100% parity with native setup.sh**

### v2.0 - Initial Docker Release
- ❌ Missing SAST tools
- ❌ Missing many Go tools
- ❌ Missing LangChain dependencies
- ❌ Incomplete verification

---

## Conclusion

Both Docker and native Kali installations are now **fully equivalent** in terms of tool coverage.

**Native Kali + setup.sh remains the recommended approach** for most pentesters due to:
- Better performance
- Easier updates
- Less disk space
- Direct hardware/network access

**Docker is perfect for**:
- CI/CD automation
- Non-Kali systems
- Isolated testing
- Reproducible builds

Choose based on your specific needs!
