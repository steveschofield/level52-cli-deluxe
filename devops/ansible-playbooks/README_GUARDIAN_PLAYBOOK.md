# Guardian CLI - Master Playbook

## 🎯 One Playbook to Rule Them All

**`remote_playbook_guardian.yml`** - The unified Guardian CLI deployment playbook

This is the **ONLY** playbook you need to run for complete Guardian CLI setup with all security tools.

## ✅ What It Includes

### Original Features (Your Custom Work)
- ✅ Python 3.13 installation via pyenv
- ✅ Go 1.22.0 installation
- ✅ Guardian CLI setup and configuration
- ✅ Lab assessment scripts (`guardian-lab-assess`)
- ✅ Network targets: 192.168.1.232, 192.168.1.244
- ✅ Web targets: juice-shop, dvwa, webgoat, vampi, etc.
- ✅ Systemd services for scheduled scans
- ✅ Bash aliases and auto-activation
- ✅ Metasploit Framework
- ✅ Exploit-DB / searchsploit

### NEW: All Missing Security Tools
- ✅ testssl - SSL/TLS testing suite
- ✅ kiterunner (kr) - API endpoint discovery
- ✅ jwt_tool - JWT security testing
- ✅ graphqlcop - GraphQL security auditor
- ✅ arjun - HTTP parameter discovery
- ✅ xsstrike - Advanced XSS scanner
- ✅ cmseek - CMS detection & exploitation
- ✅ retire - JavaScript library vulnerability scanner
- ✅ linkfinder - Endpoint discovery in JavaScript
- ✅ xnlinkfinder - Advanced link finder
- ✅ paramspider - Parameter mining
- ✅ schemathesis - API testing
- ✅ feroxbuster - Fast content discovery
- ✅ godeye (god-eye) - Subdomain recon with AI
- ✅ corsscanner - CORS misconfiguration scanner
- ✅ trivy - Vulnerability/secret scanner
- ✅ bloodhound - Active Directory analysis (Docker)

### Python Packages (via pip)
- ✅ dirsearch, wafw00f, sslyze, dnsrecon, dnsgen, linkfinder-py

## 🚀 Usage

### Quick Start

```bash
cd /Users/ss/code/guardian-cli-deluxe/devops/ansible-playbooks

# Run the master playbook
ansible-playbook -i inventory/hosts.ini remote_playbook_guardian.yml
```

**Duration**: ~30-45 minutes

### Update Existing Server (Already Has Guardian)

If you already ran the playbook before and just want to add the missing tools:

```bash
# The playbook is idempotent - safe to re-run
ansible-playbook -i inventory/hosts.ini remote_playbook_guardian.yml

# Or use the standalone tool installer (faster - 15 mins)
ansible-playbook -i inventory/hosts.ini install_missing_tools.yml
```

### Test Connection First

```bash
ansible -i inventory/hosts.ini guardian_workers -m ping
```

### Verbose Mode (For Debugging)

```bash
ansible-playbook -i inventory/hosts.ini remote_playbook_guardian.yml -vv
```

## 📊 What Gets Installed Where

| Tool | Location | Type |
|------|----------|------|
| testssl | /usr/local/bin/testssl | Wrapper → /opt/guardian-tools/testssl.sh |
| kr | /usr/local/bin/kr | Binary |
| jwt_tool | /usr/local/bin/jwt_tool | Wrapper → /opt/guardian-tools/jwt_tool |
| graphqlcop | /usr/local/bin/graphqlcop | Wrapper → /opt/guardian-tools/graphql-cop |
| xsstrike | /usr/local/bin/xsstrike | Wrapper → /opt/guardian-tools/XSStrike |
| cmseek | /usr/local/bin/cmseek | Wrapper → /opt/guardian-tools/CMSeeK |
| linkfinder | /usr/local/bin/linkfinder | Wrapper → /opt/guardian-tools/LinkFinder |
| xnlinkfinder | /usr/local/bin/xnlinkfinder | Wrapper → /opt/guardian-tools/xnLinkFinder |
| paramspider | /usr/local/bin/paramspider | Wrapper → /opt/guardian-tools/ParamSpider |
| corsscanner | /usr/local/bin/corsscanner | Wrapper → /opt/guardian-tools/CORScanner |
| feroxbuster | /usr/local/bin/feroxbuster | Binary |
| godeye | /usr/local/bin/godeye | Symlink → $GOPATH/bin/god-eye |
| trivy | /usr/local/bin/trivy | Binary |
| arjun, schemathesis, etc. | System Python | pip install |
| retire | npm global | npm install -g |

## 🔍 Verification

After the playbook completes:

```bash
# SSH into your server
ssh 52pickup@192.168.1.148

# Check all tools are installed
which testssl kr jwt_tool graphqlcop xsstrike cmseek linkfinder \
      xnlinkfinder paramspider feroxbuster godeye corsscanner trivy

# Check Python tools
pip3 list | grep -E "arjun|schemathesis|dirsearch"

# Check npm tools
retire --version

# Test Guardian - Should show NO warnings!
cd ~/guardian-cli-deluxe
source venv/bin/activate
python -m cli.main workflow run --name recon --target 192.168.1.232
```

**Expected output**: NO warnings about missing tools! ✨

## 📁 Directory Structure

```
/home/52pickup/
├── guardian-cli-deluxe/          # Main Guardian installation
│   ├── venv/                     # Python virtual environment
│   ├── reports/                  # Scan reports
│   ├── logs/                     # Application logs
│   └── setup.sh                  # Setup script (run by playbook)
│
└── .local/
    └── go/                       # Go toolchain (1.22.0)

/opt/
├── guardian-tools/               # Security tools (git clones)
│   ├── testssl.sh/
│   ├── jwt_tool/
│   ├── graphql-cop/
│   ├── XSStrike/
│   ├── CMSeeK/
│   ├── LinkFinder/
│   ├── xnLinkFinder/
│   ├── ParamSpider/
│   └── CORScanner/
│
└── exploitdb/                    # Exploit database

/usr/local/bin/                   # All tool wrappers and binaries
├── testssl -> /opt/guardian-tools/testssl.sh/testssl.sh
├── kr
├── jwt_tool
├── graphqlcop
├── xsstrike
├── cmseek
├── linkfinder
├── xnlinkfinder
├── paramspider
├── feroxbuster
├── godeye -> /home/52pickup/go/bin/god-eye
├── corsscanner
├── trivy
└── searchsploit -> /opt/exploitdb/searchsploit
```

## 🛠️ Customization

### Change Network Targets

Edit the playbook variables section (lines 17-19):

```yaml
vars:
  network_targets:
    - "192.168.1.232"
    - "192.168.1.244"
    - "10.0.0.0/24"  # Add your targets
```

### Change Python or Go Version

```yaml
vars:
  guardian_python_version: "3.13.0"  # Change version
  go_version: "1.22.0"               # Change version
```

### Add More Web Targets

```yaml
vars:
  web_targets:
    - name: "my-app"
      url: "http://localhost:9000"
      description: "My Custom App"
```

## 🔧 Troubleshooting

### Playbook fails partway through

```bash
# Re-run (playbook is idempotent)
ansible-playbook -i inventory/hosts.ini remote_playbook_guardian.yml
```

### Tools not found after installation

```bash
# SSH into server
ssh 52pickup@192.168.1.148

# Reload shell
source ~/.bashrc
source ~/.profile
```

### Go tools not installing

```bash
# Verify Go environment
source ~/.profile
echo $GOROOT  # Should be /home/52pickup/.local/go
echo $GOPATH  # Should be /home/52pickup/go
go version    # Should be go1.22.0
```

## 📂 Other Playbooks

- `install_missing_tools.yml` - Standalone tool installer (faster if Guardian already installed)
- `remote_playbook_base.yml` - Base system configuration
- `remote_playbook_docker.yml` - Docker installation
- `remote_playbook_vulnapps.yml` - Vulnerable application deployment

## 🎯 Recommended Workflow

### First-Time Setup

```bash
# 1. Base system
ansible-playbook -i inventory/hosts.ini remote_playbook_base.yml

# 2. Docker (if needed)
ansible-playbook -i inventory/hosts.ini remote_playbook_docker.yml

# 3. Guardian CLI (includes ALL tools now!)
ansible-playbook -i inventory/hosts.ini remote_playbook_guardian.yml

# 4. Vulnerable apps (optional)
ansible-playbook -i inventory/hosts.ini remote_playbook_vulnapps.yml
```

### Update Existing Installation

```bash
# Just re-run Guardian playbook
ansible-playbook -i inventory/hosts.ini remote_playbook_guardian.yml
```

## 📝 What Changed

**Before**: `remote_playbook_guardian.yml` was 831 lines, missing 17 tools

**After**: `remote_playbook_guardian.yml` is 1100 lines, includes ALL tools

**Deleted**: `remote_playbook_guardian_enhanced.yml` (merged into main)

**Result**: ONE master playbook with everything! 🎉

## ✅ Ready to Deploy

```bash
cd /Users/ss/code/guardian-cli-deluxe/devops/ansible-playbooks
ansible-playbook -i inventory/hosts.ini remote_playbook_guardian.yml
```

---

**Questions?** Check the [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md) for detailed documentation.
