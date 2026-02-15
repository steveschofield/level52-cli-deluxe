# Guardian Playbook Upgrade Instructions

## Current Situation

Your `remote_playbook_guardian.yml` is working but missing these tools:
- testssl, kiterunner, jwt, graphqlcop, arjun, xsstrike, cmseek
- retire, linkfinder, xnlinkfinder, paramspider, schemathesis
- feroxbuster, godeye, corsscanner, trivy, bloodhound

## Solution Options

### Option 1: Quick Fix - Add Missing Tools to Existing Playbook (RECOMMENDED)

This approach adds the missing tools to your existing working playbook without changing anything else.

#### Steps:

1. **Backup your current playbook**:
   ```bash
   cd /Users/ss/code/level52-cli-deluxe/devops/ansible-playbooks
   cp remote_playbook_guardian.yml remote_playbook_guardian.yml.backup
   ```

2. **Add the missing tools section** to your existing playbook at line 350 (after the setup.sh task):

   Open `remote_playbook_guardian.yml` and add these tasks after the Guardian setup section:

   ```yaml
   # ===========================================
   # Install Missing Security Tools
   # ===========================================
   - name: Create tools directory
     ansible.builtin.file:
       path: "/opt/guardian-tools"
       state: directory
       mode: '0755'
       owner: "{{ username }}"
       group: "{{ username }}"

   - name: Clone testssl.sh
     ansible.builtin.git:
       repo: https://github.com/drwetter/testssl.sh.git
       dest: "/opt/guardian-tools/testssl.sh"
       version: master
       depth: 1
       force: yes
     become_user: "{{ username }}"

   - name: Create testssl symlink
     ansible.builtin.file:
       src: "/opt/guardian-tools/testssl.sh/testssl.sh"
       dest: /usr/local/bin/testssl
       state: link

   - name: Download kiterunner
     ansible.builtin.shell: |
       KR_VERSION=$(curl -s https://api.github.com/repos/assetnote/kiterunner/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
       curl -sSL "https://github.com/assetnote/kiterunner/releases/download/v${KR_VERSION}/kiterunner_${KR_VERSION}_linux_amd64.tar.gz" -o /tmp/kiterunner.tar.gz
       tar -xzf /tmp/kiterunner.tar.gz -C /tmp/
       mv /tmp/kr /usr/local/bin/kr
       chmod +x /usr/local/bin/kr
       rm -f /tmp/kiterunner.tar.gz
     args:
       creates: /usr/local/bin/kr

   - name: Install Python security tools
     ansible.builtin.pip:
       name:
         - arjun
         - dirsearch
         - schemathesis
         - wafw00f
         - sslyze
         - dnsrecon
         - xnlinkfinder
         - dnsgen
         - linkfinder-py
       state: latest
       executable: pip3

   - name: Install retire.js globally
     community.general.npm:
       name: retire
       global: yes
       state: present

   - name: Download feroxbuster
     ansible.builtin.shell: |
       FEROX_VERSION=$(curl -s https://api.github.com/repos/epi052/feroxbuster/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
       curl -sSL "https://github.com/epi052/feroxbuster/releases/download/v${FEROX_VERSION}/x86_64-linux-feroxbuster.zip" -o /tmp/feroxbuster.zip
       unzip -o /tmp/feroxbuster.zip -d /tmp/
       mv /tmp/feroxbuster /usr/local/bin/feroxbuster
       chmod +x /usr/local/bin/feroxbuster
       rm -f /tmp/feroxbuster.zip
     args:
       creates: /usr/local/bin/feroxbuster

   - name: Download and install Trivy
     ansible.builtin.shell: |
       TRIVY_VERSION=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
       curl -sSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" -o /tmp/trivy.tar.gz
       tar -xzf /tmp/trivy.tar.gz -C /tmp/
       mv /tmp/trivy /usr/local/bin/trivy
       chmod +x /usr/local/bin/trivy
       rm -f /tmp/trivy.tar.gz
     args:
       creates: /usr/local/bin/trivy
   ```

3. **Run the updated playbook**:
   ```bash
   cd /Users/ss/code/level52-cli-deluxe/devops/ansible-playbooks
   ansible-playbook -i inventory/hosts.ini remote_playbook_guardian.yml
   ```

### Option 2: Use Enhanced Playbook Script

I've already copied the enhanced playbook to your devops folder. Use the convenience script:

```bash
cd /Users/ss/code/level52-cli-deluxe/devops/ansible-playbooks
./run_guardian_enhanced.sh
```

**Note**: The enhanced playbook has all the tools but doesn't have the lab assessment script yet. It's a cleaner install.

### Option 3: Run Only Missing Tools Playbook

Create a minimal playbook that ONLY installs missing tools:

1. **Create `install_missing_tools.yml`**:

```yaml
---
- name: Install Missing Guardian Tools Only
  hosts: guardian_workers
  become: yes
  vars:
    username: 52pickup
    tools_dir: "/opt/guardian-tools"

  tasks:
    - name: Create tools directory
      ansible.builtin.file:
        path: "{{ tools_dir }}"
        state: directory
        mode: '0755'

    # Install all missing tools here (testssl, kiterunner, etc.)
    # ... (copy tasks from above)
```

2. **Run it**:
```bash
ansible-playbook -i inventory/hosts.ini install_missing_tools.yml
```

## Recommended Approach

**I recommend Option 1** because:
- ✅ Keeps your existing configuration (network targets, lab scripts, etc.)
- ✅ Only adds what's missing
- ✅ Minimal risk of breaking existing setup
- ✅ Can be run incrementally

## Quick Command Reference

### Test Connection
```bash
cd /Users/ss/code/level52-cli-deluxe/devops/ansible-playbooks
ansible -i inventory/hosts.ini guardian_workers -m ping
```

### Run Original Playbook
```bash
ansible-playbook -i inventory/hosts.ini remote_playbook_guardian.yml
```

### Run Enhanced Playbook
```bash
ansible-playbook -i inventory/hosts.ini remote_playbook_guardian_enhanced.yml
```

### Run with Verbose Output
```bash
ansible-playbook -i inventory/hosts.ini remote_playbook_guardian.yml -vv
```

### Run Specific Tasks (with tags, if you add them)
```bash
ansible-playbook -i inventory/hosts.ini remote_playbook_guardian.yml --tags "missing-tools"
```

## After Running the Playbook

1. **SSH into your server**:
   ```bash
   ssh 52pickup@192.168.1.148
   ```

2. **Verify tools**:
   ```bash
   which testssl
   which kr
   which feroxbuster
   which trivy
   retire --version
   pip3 list | grep arjun
   ```

3. **Test Guardian**:
   ```bash
   cd ~/level52-cli-deluxe
   source venv/bin/activate
   python -m cli.main workflow run --name recon --target 192.168.1.232
   ```

   You should see NO warnings about missing tools!

## Troubleshooting

### If playbook fails partway through

```bash
# Re-run from where it failed (Ansible is idempotent)
ansible-playbook -i inventory/hosts.ini remote_playbook_guardian.yml
```

### If specific task fails

```bash
# Skip failed tasks and continue
ansible-playbook -i inventory/hosts.ini remote_playbook_guardian.yml --start-at-task="Task Name"
```

### Check what will change (dry-run)

```bash
ansible-playbook -i inventory/hosts.ini remote_playbook_guardian.yml --check
```

## Files Created

- `remote_playbook_guardian_enhanced.yml` - Full enhanced playbook
- `run_guardian_enhanced.sh` - Convenience script to run enhanced playbook
- `UPGRADE_INSTRUCTIONS.md` - This file

## Need Help?

Check the logs on the remote server:
```bash
ssh 52pickup@192.168.1.148
tail -f ~/level52-cli-deluxe/setup.log
```
