# Level52 CLI Deluxe - Ansible Playbooks

This directory contains Ansible playbooks and Vagrant configuration for automated deployment of Guardian CLI on Kali Linux systems.

## 📁 Directory Structure

```
ansible-playbooks/
├── local_playbook_kali.yml           # Local playbook for Kali Linux setup
├── remote_playbook_guardian_enhanced.yml  # Enhanced remote playbook with all tools
├── Vagrantfile                       # Vagrant configuration for VM setup
├── inventory/                        # Ansible inventory files (for remote hosts)
├── roles/                           # Ansible roles (if needed)
└── README.md                        # This file
```

## 🚀 Quick Start

### Option 1: Local Setup on Existing Kali Linux

If you're already running Kali Linux and want to install Guardian CLI locally:

```bash
# 1. Install Ansible
sudo apt update
sudo apt install -y ansible

# 2. Clone this repository
git clone https://github.com/steveschofield/level52-cli-deluxe.git
cd level52-cli-deluxe/ansible-playbooks

# 3. Run the local playbook
ansible-playbook -K local_playbook_kali.yml
```

The `-K` flag will prompt for your sudo password.

### Option 2: Vagrant VM Setup

If you want to create a new Kali Linux VM with Guardian CLI pre-installed:

```bash
# 1. Install Vagrant and VirtualBox (or Hyper-V on Windows)
# See: https://www.vagrantup.com/downloads

# 2. Clone this repository
git clone https://github.com/steveschofield/level52-cli-deluxe.git
cd level52-cli-deluxe/ansible-playbooks

# 3. Start the VM (VirtualBox)
vagrant up

# Or for Hyper-V on Windows (run PowerShell as Administrator)
vagrant up --provider=hyperv

# 4. SSH into the VM
vagrant ssh

# 5. Activate Guardian environment
cd /home/vagrant/level52-cli-deluxe
source venv/bin/activate

# 6. Run a test scan
python -m cli.main workflow run --name recon --target scanme.nmap.org
```

### Option 3: Remote Server Setup

For setting up Guardian CLI on remote servers:

```bash
# 1. Create inventory file
cat > inventory/hosts.ini <<EOF
[guardian_workers]
kali-server-1 ansible_host=192.168.1.100 ansible_user=kali
kali-server-2 ansible_host=192.168.1.101 ansible_user=kali

[guardian_workers:vars]
ansible_python_interpreter=/usr/bin/python3
EOF

# 2. Test connectivity
ansible -i inventory/hosts.ini guardian_workers -m ping

# 3. Run the enhanced playbook
ansible-playbook -i inventory/hosts.ini remote_playbook_guardian_enhanced.yml
```

## 📦 What Gets Installed

### System Packages (via apt)

- **Core Tools**: git, curl, wget, build-essential, python3, go, nodejs, npm, cargo
- **Network Scanning**: nmap, masscan, nikto, hydra
- **Web Testing**: sqlmap, dirb, gobuster, whatweb
- **Enumeration**: enum4linux, amass, smbclient, snmp tools
- **Framework**: metasploit-framework
- **Container**: docker.io, docker-compose

### Security Tools Installed

#### Go-based Tools

- ✅ **httpx** - HTTP toolkit (ProjectDiscovery)
- ✅ **nuclei** - Vulnerability scanner (ProjectDiscovery)
- ✅ **subfinder** - Subdomain discovery (ProjectDiscovery)
- ✅ **dnsx** - DNS toolkit (ProjectDiscovery)
- ✅ **naabu** - Port scanner (ProjectDiscovery)
- ✅ **ffuf** - Web fuzzer
- ✅ **waybackurls** - Wayback machine URL fetcher
- ✅ **gau** - Get All URLs
- ✅ **dalfox** - XSS scanner
- ✅ **gitleaks** - Secret scanner
- ✅ **puredns** - DNS resolver
- ✅ **godeye** - Subdomain recon with AI

#### Python-based Tools

- ✅ **arjun** - HTTP parameter discovery
- ✅ **xsstrike** - Advanced XSS detection
- ✅ **cmseek** - CMS detection & exploitation
- ✅ **dirsearch** - Web path scanner
- ✅ **schemathesis** - API testing
- ✅ **wafw00f** - WAF detection
- ✅ **sqlmap** - SQL injection tool
- ✅ **sslyze** - SSL/TLS scanner
- ✅ **dnsrecon** - DNS enumeration
- ✅ **xnlinkfinder** - Link finder
- ✅ **paramspider** - Parameter miner
- ✅ **dnsgen** - DNS wordlist generator
- ✅ **linkfinder** - Endpoint discovery
- ✅ **corsscanner** - CORS misconfiguration scanner
- ✅ **graphqlcop** - GraphQL security auditor

#### Git-cloned Tools

- ✅ **testssl.sh** - SSL/TLS testing suite
- ✅ **jwt_tool** - JWT security testing
- ✅ **LinkFinder** - JavaScript endpoint discovery

#### Rust-based Tools

- ✅ **feroxbuster** - Content discovery

#### npm Tools

- ✅ **retire.js** - JavaScript library vulnerability scanner

#### SAST (Static Analysis) Tools

- ✅ **trivy** - Vulnerability/secret scanner
- ✅ **semgrep** - Code security scanner (installed via setup.sh)

#### Frameworks & Databases

- ✅ **Metasploit Framework** - Exploitation framework
- ✅ **BloodHound** - Active Directory analysis (Docker)
- ✅ **ZAP** - OWASP ZAP proxy (Docker)

#### Exploit Database

- ✅ **Exploit-DB** - Local copy of exploit database
- ✅ **searchsploit** - Exploit search tool

## 🔧 Playbook Descriptions

### `local_playbook_kali.yml`

**Purpose**: Install all Guardian CLI security tools on a local Kali Linux machine.

**Features**:

- Installs all missing security tools from your error list
- Creates wrapper scripts for Python-based tools
- Configures PATH and environment variables
- Idempotent (safe to run multiple times)

**Usage**:

```bash
ansible-playbook -K local_playbook_kali.yml
```

**Duration**: ~20-30 minutes (depending on network speed)

### `remote_playbook_guardian_enhanced.yml`

**Purpose**: Complete Guardian CLI setup on remote Kali Linux servers with all security tools.

**Features**:

- Everything from local playbook
- Installs specific Python version via pyenv
- Creates Guardian virtual environment
- Runs Guardian's setup.sh script
- Configures systemd services for scheduled scans
- Creates convenient aliases and shortcuts
- Sets up Docker images (ZAP, BloodHound)

**Usage**:

```bash
ansible-playbook -i inventory/hosts.ini remote_playbook_guardian_enhanced.yml
```

**Duration**: ~30-45 minutes per host

### `Vagrantfile`

**Purpose**: Automated Kali Linux VM creation with Guardian CLI pre-installed.

**Providers Supported**:

- VirtualBox (Linux, macOS, Windows)
- Hyper-V (Windows)
- VMware Desktop

**VM Specifications**:

- **OS**: Kali Linux (latest rolling release)
- **Memory**: 4GB RAM (configurable)
- **CPUs**: 2 cores (configurable)
- **Hostname**: guardian-kali
- **User**: vagrant (password: vagrant)

**Network Configuration**:

- Private network with DHCP
- Port forwarding for ZAP (8080, 8443)
- Port forwarding for Neo4j/BloodHound (7474, 7687)

**Usage**:

```bash
# VirtualBox
vagrant up

# Hyper-V (Windows PowerShell as Admin)
vagrant up --provider=hyperv

# SSH into VM
vagrant ssh

# Stop VM
vagrant halt

# Destroy VM
vagrant destroy
```

## 🛠️ Customization

### Changing Python Version

Edit the playbook variable:

```yaml
vars:
  guardian_python_version: "3.13.0"  # Change to your desired version
```

### Changing Go Version

```yaml
vars:
  go_version: "1.22.0"  # Change to your desired version
```

### Adding Custom Tools

Add tasks to the playbook:

```yaml
- name: Install my custom tool
  ansible.builtin.git:
    repo: https://github.com/username/tool.git
    dest: "{{ tools_dir }}/tool"
    depth: 1
  become_user: "{{ username }}"

- name: Create wrapper script
  ansible.builtin.copy:
    dest: /usr/local/bin/tool
    mode: '0755'
    content: |
      #!/bin/bash
      cd {{ tools_dir }}/tool
      python3 tool.py "$@"
```

### Configuring Network Targets

For remote playbooks, edit the vars section:

```yaml
vars:
  network_targets:
    - "192.168.1.232"
    - "192.168.1.244"
    - "10.0.0.0/24"  # Add your targets
```

## 📋 Verifying Installation

After running the playbook, verify tools are installed:

```bash
# Check individual tools
which testssl
which jwt_tool
which graphqlcop
which xsstrike
which feroxbuster
which trivy

# Check Python tools
pip list | grep -E "arjun|dirsearch|schemathesis"

# Check Go tools (requires Go env vars in PATH)
source ~/.profile
which httpx nuclei subfinder

# Run Guardian verification
cd ~/level52-cli-deluxe
source venv/bin/activate
python -m cli.main --help
```

## 🐛 Troubleshooting

### Tools Not Found After Installation

**Problem**: Tools installed but not in PATH

**Solution**:

```bash
# Reload shell configuration
source ~/.bashrc
source ~/.profile

# Or logout and login again
exit
# Then SSH back in
```

### Go Tools Not Installing

**Problem**: `go install` fails or Go not found

**Solution**:

```bash
# Ensure Go environment is configured
export GOROOT="$HOME/.local/go"
export GOPATH="$HOME/go"
export PATH="$GOROOT/bin:$GOPATH/bin:$PATH"

# Verify Go installation
go version

# Manually install a tool
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### Python Tools Import Errors

**Problem**: `ModuleNotFoundError` when running Python tools

**Solution**:

```bash
# Activate Guardian virtual environment
cd ~/level52-cli-deluxe
source venv/bin/activate

# Reinstall requirements
pip install -r requirements.txt

# Or install missing package
pip install <package-name>
```

### Ansible Playbook Fails on Specific Task

**Problem**: Task fails during playbook execution

**Solution**:

```bash
# Run playbook in verbose mode
ansible-playbook -K local_playbook_kali.yml -vvv

# Skip specific tags (if task has tags)
ansible-playbook -K local_playbook_kali.yml --skip-tags "docker,metasploit"

# Run only specific tasks
ansible-playbook -K local_playbook_kali.yml --tags "go-tools"
```

### masscan Permission Denied

**Problem**: masscan requires root privileges

**Solution**:

```bash
# Set capabilities (done by playbook, but can be manual)
sudo setcap cap_net_raw,cap_net_admin+eip $(which masscan)

# Verify
getcap $(which masscan)
```

### Docker Not Starting

**Problem**: Docker service not running after installation

**Solution**:

```bash
# Enable and start Docker
sudo systemctl enable docker
sudo systemctl start docker

# Add user to docker group (logout/login required)
sudo usermod -aG docker $USER

# Or use newgrp to avoid logout
newgrp docker
```

## 📝 Best Practices

1. **Run Playbooks on Fresh Systems**: Best results on newly installed Kali Linux
2. **Check Internet Connection**: Many tools download from GitHub/PyPI
3. **Allow Sufficient Time**: Initial setup can take 30-45 minutes
4. **Review Logs**: Check `/tmp/ansible-*.log` if issues occur
5. **Test Incrementally**: After installation, test each tool category
6. **Keep Updated**: Re-run playbooks periodically to update tools

## 🔐 Security Considerations

- **Authorized Use Only**: Only deploy on systems you own or have permission to test
- **Firewall Rules**: Ensure outbound connections for tool downloads
- **Credentials**: Never commit API keys or passwords to version control
- **Network Isolation**: Consider running in isolated networks for pentesting
- **Resource Limits**: VMs should have adequate RAM/CPU for intensive scans

## 📚 Additional Resources

- [Guardian CLI Documentation](../README.md)
- [Guardian Setup Script](../setup.sh)
- [Vagrant Documentation](https://www.vagrantup.com/docs)
- [Ansible Documentation](https://docs.ansible.com/)
- [Kali Linux Documentation](https://www.kali.org/docs/)

## 🤝 Contributing

Found an issue or want to add more tools?

1. Fork the repository
2. Create a feature branch
3. Add your tool installation tasks to the playbook
4. Test thoroughly on a clean Kali system
5. Submit a pull request

## 📄 License

Same as Guardian CLI Deluxe - See [LICENSE](../LICENSE)

---

**Need Help?**

- Check the [Troubleshooting](#-troubleshooting) section
- Review playbook logs: `ansible-playbook ... -vvv`
- Open an issue on GitHub
- Consult setup.log in Guardian directory

---

*Last Updated: February 2026*
*Compatible with: Kali Linux 2024.1+, Ubuntu 22.04+*
