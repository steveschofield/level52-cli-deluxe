# Guardian CLI - Quick Setup Guide

## 🎯 What You Need

Based on your error message, these tools were missing:
```
testssl, kiterunner, jwt, graphqlcop, arjun, xsstrike, cmseek,
retire, linkfinder, xnlinkfinder, paramspider, schemathesis,
feroxbuster, godeye, corsscanner, trivy, bloodhound
```

## ✅ Solution: Enhanced Ansible Playbook

I've created `remote_playbook_guardian_enhanced.yml` which installs **ALL** missing tools plus the complete Guardian CLI setup.

## 🚀 Quick Fix for Your Hyper-V VM

Since you mentioned you have a working Hyper-V setup at `/Users/ss/code/guardian-cli-deluxe/devops/vagrant-ubuntu-hyperv-guardian-kali/`, here's how to update it:

### Option 1: Update Existing Remote Playbook

```bash
# 1. Copy the enhanced playbook to your devops folder
cp ansible-playbooks/remote_playbook_guardian_enhanced.yml \
   /Users/ss/code/guardian-cli-deluxe/devops/ansible-playbooks/

# 2. SSH into your VM
ssh 52pickup@<your-vm-ip>

# 3. On the VM, run the enhanced playbook
cd /vagrant  # or wherever your playbooks are synced
sudo ansible-playbook remote_playbook_guardian_enhanced.yml
```

### Option 2: Run from This Repository

```bash
# 1. Navigate to this repo
cd /Users/ss/.claude-worktrees/guardian-cli-deluxe/strange-khorana/ansible-playbooks

# 2. Create inventory for your remote VM
cat > inventory/hosts.ini <<EOF
[guardian_workers]
kali-vm ansible_host=<your-vm-ip> ansible_user=52pickup

[guardian_workers:vars]
ansible_python_interpreter=/usr/bin/python3
ansible_become_password=example123!
EOF

# 3. Run the enhanced playbook
ansible-playbook -i inventory/hosts.ini -K remote_playbook_guardian_enhanced.yml
```

## 📦 What Gets Fixed

The enhanced playbook adds these installations:

### Git-Cloned Tools (with wrappers)
- `testssl` → /usr/local/bin/testssl
- `jwt_tool` → /usr/local/bin/jwt_tool
- `graphqlcop` → /usr/local/bin/graphqlcop
- `xsstrike` → /usr/local/bin/xsstrike
- `cmseek` → /usr/local/bin/cmseek
- `linkfinder` → /usr/local/bin/linkfinder
- `xnlinkfinder` → /usr/local/bin/xnlinkfinder
- `paramspider` → /usr/local/bin/paramspider
- `corsscanner` → /usr/local/bin/corsscanner

### Binary Downloads
- `kiterunner` (kr) → /usr/local/bin/kr
- `feroxbuster` → /usr/local/bin/feroxbuster
- `trivy` → /usr/local/bin/trivy

### Go-based Tools
- `godeye` (god-eye) → via go install → /usr/local/bin/godeye

### NPM Tools
- `retire` → via npm install -g

### Python Tools (pip)
- `arjun`
- `schemathesis`
- `dirsearch`
- `wafw00f`
- `sslyze`
- `dnsrecon`
- `xnlinkfinder`
- `dnsgen`
- `linkfinder-py`

### Docker Images
- `bloodhound` → ghcr.io/fuzzinglabs/bloodhound-mcp:latest

## 🔍 Verify Installation

After running the playbook, SSH into your VM and check:

```bash
# SSH into VM
ssh 52pickup@<your-vm-ip>

# Check all tools are in PATH
which testssl        # Should return /usr/local/bin/testssl
which kr             # Should return /usr/local/bin/kr
which jwt_tool       # Should return /usr/local/bin/jwt_tool
which graphqlcop     # Should return /usr/local/bin/graphqlcop
which xsstrike       # Should return /usr/local/bin/xsstrike
which cmseek         # Should return /usr/local/bin/cmseek
which linkfinder     # Should return /usr/local/bin/linkfinder
which xnlinkfinder   # Should return /usr/local/bin/xnlinkfinder
which paramspider    # Should return /usr/local/bin/paramspider
which feroxbuster    # Should return /usr/local/bin/feroxbuster
which godeye         # Should return /usr/local/bin/godeye
which corsscanner    # Should return /usr/local/bin/corsscanner
which trivy          # Should return /usr/local/bin/trivy
retire --version     # Should show version

# Check Python tools
pip3 list | grep arjun
pip3 list | grep schemathesis

# Test Guardian
cd ~/guardian-cli-deluxe
source venv/bin/activate
python -m cli.main workflow run --name recon --target 192.168.1.232
```

## 🎯 Key Differences from Original Playbook

The enhanced playbook adds:

1. **Tools Directory**: Creates `/opt/guardian-tools` for git-cloned tools
2. **Wrapper Scripts**: Creates executable wrappers in `/usr/local/bin/`
3. **Binary Downloads**: Uses GitHub releases for faster installation
4. **Python Packages**: Installs all missing pip packages
5. **Go Tools**: Properly sets up GOPATH and installs god-eye
6. **NPM Tools**: Installs retire.js globally
7. **Error Handling**: More robust with `ignore_errors` where appropriate

## 🔧 Troubleshooting

### If tools still not found after playbook:

```bash
# Reload shell environment
source ~/.bashrc
source ~/.profile

# Or logout and login again
exit
ssh 52pickup@<your-vm-ip>
```

### If Go tools aren't working:

```bash
# Add to ~/.bashrc or ~/.profile
export GOROOT="$HOME/.local/go"
export GOPATH="$HOME/go"
export PATH="$GOROOT/bin:$GOPATH/bin:$PATH"

source ~/.bashrc
```

### If Python tools have import errors:

```bash
cd ~/guardian-cli-deluxe
source venv/bin/activate
pip install -r requirements.txt
```

## 📊 Comparison

| Component | Original Playbook | Enhanced Playbook |
|-----------|-------------------|-------------------|
| testssl | ❌ Missing | ✅ Installed |
| kiterunner | ❌ Missing | ✅ Installed |
| jwt_tool | ❌ Missing | ✅ Installed |
| graphqlcop | ❌ Missing | ✅ Installed |
| arjun | ❌ Missing | ✅ Installed |
| xsstrike | ❌ Missing | ✅ Installed |
| cmseek | ❌ Missing | ✅ Installed |
| retire.js | ❌ Missing | ✅ Installed |
| linkfinder | ❌ Missing | ✅ Installed |
| xnlinkfinder | ❌ Missing | ✅ Installed |
| paramspider | ❌ Missing | ✅ Installed |
| schemathesis | ❌ Missing | ✅ Installed |
| feroxbuster | ❌ Missing | ✅ Installed |
| godeye | ❌ Missing | ✅ Installed |
| corsscanner | ❌ Missing | ✅ Installed |
| trivy | ❌ Missing | ✅ Installed |
| bloodhound | ⚠️ Partial | ✅ Docker image |

## 🎓 Next Steps

After installation completes successfully:

1. **Test Basic Workflow**:
   ```bash
   cd ~/guardian-cli-deluxe
   source venv/bin/activate
   python -m cli.main workflow run --name recon --target 192.168.1.232
   ```

2. **Verify All Tools Load**:
   Check that you don't see WARNING messages about missing tools

3. **Run Full Workflow**:
   ```bash
   python -m cli.main workflow run --name network --target 192.168.1.232
   ```

4. **Check Reports**:
   ```bash
   ls -lh ~/guardian-cli-deluxe/reports/
   ```

---

**Need More Help?**

- See full documentation: [README.md](README.md)
- Check playbook source: [remote_playbook_guardian_enhanced.yml](remote_playbook_guardian_enhanced.yml)
- Original working playbook: `/Users/ss/code/guardian-cli-deluxe/devops/ansible-playbooks/remote_playbook_guardian.yml`
