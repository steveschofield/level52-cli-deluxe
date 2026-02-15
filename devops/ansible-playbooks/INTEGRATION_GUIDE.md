# Guardian CLI - Complete Integration Guide

## 🎯 Goal

Install all missing security tools that were showing warnings when you ran Guardian:
```
WARNING  Tool testssl is not installed or not in PATH
WARNING  Tool kiterunner is not installed or not in PATH
WARNING  Tool jwt is not installed or not in PATH
... (and 14 more)
```

## 🚀 Quick Start - Interactive Integration

The easiest way to integrate the missing tools:

```bash
cd /Users/ss/code/level52-cli-deluxe/devops/ansible-playbooks
./integrate.sh
```

This interactive script will let you choose:
1. Install on your local machine
2. Install on remote server (192.168.1.148)
3. Install on both
4. Check what's missing

## 📋 Available Playbooks

### 1. `install_missing_tools.yml` (RECOMMENDED)

**Purpose**: Install ONLY the missing tools without changing existing Guardian setup

**Use when**: You want to add missing tools to an existing working Guardian installation

**Run on remote server**:
```bash
ansible-playbook -i inventory/hosts.ini install_missing_tools.yml
```

**Duration**: ~15-20 minutes

**What it does**:
- ✅ Installs testssl, kiterunner, jwt_tool, graphqlcop
- ✅ Installs arjun, xsstrike, cmseek, retire
- ✅ Installs linkfinder, xnlinkfinder, paramspider
- ✅ Installs schemathesis, feroxbuster, godeye
- ✅ Installs corsscanner, trivy
- ✅ Creates wrapper scripts in /usr/local/bin/
- ✅ Leaves existing Guardian configuration untouched

### 2. `remote_playbook_guardian_enhanced.yml`

**Purpose**: Complete from-scratch Guardian installation with all tools

**Use when**: Setting up Guardian on a brand new server

**Run**:
```bash
ansible-playbook -i inventory/hosts.ini remote_playbook_guardian_enhanced.yml
```

**Duration**: ~30-45 minutes

**What it does**:
- Everything from `install_missing_tools.yml` PLUS:
- Installs Python via pyenv
- Creates Guardian virtual environment
- Runs Guardian setup.sh
- Configures Docker images (ZAP, BloodHound)

### 3. `remote_playbook_guardian.yml` (Original)

**Purpose**: Your existing working playbook with lab assessment scripts

**Use when**: Full Guardian setup with lab automation features

**Run**:
```bash
ansible-playbook -i inventory/hosts.ini remote_playbook_guardian.yml
```

**Note**: This is your original playbook. It works but is missing the 17 tools. Combine it with `install_missing_tools.yml` for complete coverage.

## 🎓 Integration Workflows

### Workflow 1: Update Existing Remote Server (FASTEST)

```bash
cd /Users/ss/code/level52-cli-deluxe/devops/ansible-playbooks

# Install only what's missing
ansible-playbook -i inventory/hosts.ini install_missing_tools.yml

# Verify
ssh 52pickup@192.168.1.148
which testssl kr jwt_tool graphqlcop xsstrike feroxbuster trivy
```

**Time**: ~15 minutes
**Impact**: Minimal - only adds tools
**Risk**: Very low

### Workflow 2: Update Both Local and Remote

```bash
cd /Users/ss/code/level52-cli-deluxe/devops/ansible-playbooks

# Interactive menu
./integrate.sh

# Choose option 3: Install on BOTH local and remote
```

**Time**: ~30 minutes total
**Impact**: Updates all environments
**Risk**: Low

### Workflow 3: Merge Enhanced Tools into Original Playbook

If you want to keep your original `remote_playbook_guardian.yml` with all its features:

```bash
cd /Users/ss/code/level52-cli-deluxe/devops/ansible-playbooks

# 1. Backup original
cp remote_playbook_guardian.yml remote_playbook_guardian.yml.backup

# 2. Add missing tools section at end of remote_playbook_guardian.yml
# Copy the tasks from install_missing_tools.yml into remote_playbook_guardian.yml
# (before the final "Display Guardian installation message" task)

# 3. Run the merged playbook
ansible-playbook -i inventory/hosts.ini remote_playbook_guardian.yml
```

## 🔍 Verification

### On Remote Server

```bash
# SSH in
ssh 52pickup@192.168.1.148

# Check all tools
which testssl        # /usr/local/bin/testssl
which kr             # /usr/local/bin/kr
which jwt_tool       # /usr/local/bin/jwt_tool
which graphqlcop     # /usr/local/bin/graphqlcop
which xsstrike       # /usr/local/bin/xsstrike
which cmseek         # /usr/local/bin/cmseek
which linkfinder     # /usr/local/bin/linkfinder
which xnlinkfinder   # /usr/local/bin/xnlinkfinder
which paramspider    # /usr/local/bin/paramspider
which feroxbuster    # /usr/local/bin/feroxbuster
which godeye         # /usr/local/bin/godeye
which corsscanner    # /usr/local/bin/corsscanner
which trivy          # /usr/local/bin/trivy

# Check Python tools
pip3 list | grep -E "arjun|schemathesis|dirsearch"

# Check npm tools
retire --version

# Test Guardian (should show NO warnings!)
cd ~/level52-cli-deluxe
source venv/bin/activate
python -m cli.main workflow run --name recon --target 192.168.1.232
```

### Expected Output (NO WARNINGS!)

```
[INFO] Starting recon workflow...
[INFO] Target: 192.168.1.232
[INFO] Using testssl for SSL/TLS analysis...
[INFO] Using kiterunner for API discovery...
[INFO] Using jwt_tool for JWT analysis...
... (all tools detected and working!)
```

## 📊 What Gets Installed Where

| Tool | Type | Location | Wrapper Script |
|------|------|----------|----------------|
| testssl | Git clone | /opt/guardian-tools/testssl.sh | /usr/local/bin/testssl |
| kiterunner (kr) | Binary | /usr/local/bin/kr | - |
| jwt_tool | Git clone | /opt/guardian-tools/jwt_tool | /usr/local/bin/jwt_tool |
| graphqlcop | Git clone | /opt/guardian-tools/graphql-cop | /usr/local/bin/graphqlcop |
| arjun | pip | System Python | - |
| xsstrike | Git clone | /opt/guardian-tools/XSStrike | /usr/local/bin/xsstrike |
| cmseek | Git clone | /opt/guardian-tools/CMSeeK | /usr/local/bin/cmseek |
| retire | npm global | Node modules | /usr/local/bin/retire |
| linkfinder | Git clone | /opt/guardian-tools/LinkFinder | /usr/local/bin/linkfinder |
| xnlinkfinder | Git clone + pip | /opt/guardian-tools/xnLinkFinder | /usr/local/bin/xnlinkfinder |
| paramspider | Git clone | /opt/guardian-tools/ParamSpider | /usr/local/bin/paramspider |
| schemathesis | pip | System Python | - |
| feroxbuster | Binary | /usr/local/bin/feroxbuster | - |
| godeye | Go install | $GOPATH/bin/god-eye | /usr/local/bin/godeye |
| corsscanner | Git clone | /opt/guardian-tools/CORScanner | /usr/local/bin/corsscanner |
| trivy | Binary | /usr/local/bin/trivy | - |

## 🛠️ Troubleshooting

### Tools installed but not found

```bash
# Reload shell environment
source ~/.bashrc
source ~/.profile

# Or logout/login
exit
ssh 52pickup@192.168.1.148
```

### Permission errors

```bash
# Ensure you're running with sudo (playbook handles this)
ansible-playbook -i inventory/hosts.ini install_missing_tools.yml --ask-become-pass
```

### Go tools not installing

```bash
# SSH into server
ssh 52pickup@192.168.1.148

# Check Go environment
source ~/.profile
echo $GOROOT  # Should show /home/52pickup/.local/go
echo $GOPATH  # Should show /home/52pickup/go
go version    # Should show Go 1.22.0

# Manually install godeye if needed
export GOROOT="$HOME/.local/go"
export GOPATH="$HOME/go"
export PATH="$GOROOT/bin:$GOPATH/bin:$PATH"
go install github.com/Vyntral/god-eye@latest
sudo ln -s $GOPATH/bin/god-eye /usr/local/bin/godeye
```

### Ansible connectivity issues

```bash
# Test connection
ansible -i inventory/hosts.ini guardian_workers -m ping

# Check SSH key
ssh 52pickup@192.168.1.148

# Verify inventory
cat inventory/hosts.ini
```

## 📂 File Organization

```
/Users/ss/code/level52-cli-deluxe/devops/ansible-playbooks/
├── inventory/
│   └── hosts.ini                              # Ansible inventory
├── install_missing_tools.yml                  # Quick fix playbook (NEW)
├── remote_playbook_guardian.yml               # Original working playbook
├── remote_playbook_guardian_enhanced.yml      # Full enhanced playbook (NEW)
├── remote_playbook_base.yml                   # Base system setup
├── remote_playbook_docker.yml                 # Docker setup
├── remote_playbook_vulnapps.yml               # Vulnerable apps
├── integrate.sh                               # Interactive integration script (NEW)
├── run_guardian_enhanced.sh                   # Run enhanced playbook (NEW)
├── INTEGRATION_GUIDE.md                       # This file (NEW)
├── UPGRADE_INSTRUCTIONS.md                    # Detailed upgrade guide (NEW)
└── README.md                                  # General documentation
```

## 🎯 Recommended Approach

**For your immediate needs (fixing missing tools on existing server):**

```bash
cd /Users/ss/code/level52-cli-deluxe/devops/ansible-playbooks
ansible-playbook -i inventory/hosts.ini install_missing_tools.yml
```

This will:
- ✅ Keep your existing Guardian setup intact
- ✅ Add only the missing tools
- ✅ Take ~15-20 minutes
- ✅ Be ready to test immediately

**After it completes:**

```bash
ssh 52pickup@192.168.1.148
cd ~/level52-cli-deluxe
source venv/bin/activate
python -m cli.main workflow run --name recon --target 192.168.1.232
```

You should see **zero warnings** about missing tools! 🎉

## 📞 Need Help?

- Check logs: `tail -f ~/level52-cli-deluxe/setup.log`
- Run playbook with verbose output: `ansible-playbook -i inventory/hosts.ini install_missing_tools.yml -vv`
- Test individual tools: `ssh 52pickup@192.168.1.148 "which testssl"`

---

**Quick Commands Reference:**

```bash
# Install missing tools on remote
ansible-playbook -i inventory/hosts.ini install_missing_tools.yml

# Interactive integration
./integrate.sh

# Test connection
ansible -i inventory/hosts.ini guardian_workers -m ping

# Verify tools
ssh 52pickup@192.168.1.148 "which testssl kr jwt_tool graphqlcop"

# Test Guardian
ssh 52pickup@192.168.1.148 "cd ~/level52-cli-deluxe && source venv/bin/activate && python -m cli.main workflow run --name recon --target 192.168.1.232"
```
