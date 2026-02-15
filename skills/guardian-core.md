# Level52 CLI Deluxe - Core Pentesting Knowledge

## Steve's Environment Context

- MacBook Air M3, 24GB RAM
- Windows 10 Hyper-V running Ubuntu VMs
- Kali Linux Docker containers
- Ansible-deployed infrastructure
- Test targets: Juice Shop, custom vulnerable apps

## Critical Tool Configurations

### enum4linux - SMB Enumeration

**ALWAYS use null session to prevent interactive prompts:**

```bash
enum4linux -N -a <target>
```

**NEVER:** `enum4linux -a <target>` (breaks automation with password prompt)

### nmap - Network Scanning

- Prefer: `nmap -sV -sC -oA output <target>`
- For stealth: `nmap -sS -T2 <target>`
- UDP: `nmap -sU --top-ports 100 <target>`

## Automation Requirements

1. **Zero manual intervention** - all commands must be non-interactive
2. **Comprehensive fixes** - complete solutions, not workarounds
3. **Production-ready** - proper error handling
4. **Audit trails** - log all decisions and commands

## Known Issues & Solutions

### Interactive Password Prompts

- **Problem:** Tools like enum4linux, smbclient prompt for passwords
- **Solution:** Always use null session flags (-N, -N/A, etc.)
- **Detection:** If command hangs, assume interactive prompt

### Python Environment

- Running Python 3.12
- Virtual environments preferred
- Known compatibility issues resolved in setup scripts

### Docker Networking

- Containers can reach host VMs
- Hyper-V network: [specify your subnet if relevant]

## Testing Methodology Preferences

1. **Reconnaissance:** Passive info gathering first
2. **Scanning:** nmap for services, whatweb for web
3. **Enumeration:** Protocol-specific (SMB, HTTP, etc.)
4. **Vulnerability Analysis:** Correlate findings across tools
5. **Exploitation:** Documented, careful approach
6. **Post-exploitation:** Minimal footprint

## Tool Priority Order (when multiple options exist)

1. Native tools (nmap, enum4linux) over custom scripts
2. Non-interactive over interactive
3. Well-documented over obscure
4. Faster over slower (when accuracy equal)

## Severity Guidelines for Steve's Context

- **Critical:** RCE, auth bypass, data exposure in production-facing services
- **High:** Privilege escalation, significant info disclosure
- **Medium:** Missing security headers, weak configs
- **Low:** Info leaks with minimal impact
- **Info:** Observations, recommendations

## Command Generation Rules

- Include full paths when ambiguous
- Always add output flags (-oA, -o, etc.) for evidence
- Use short timeouts for hung tools (--timeout 30s)
- Verify tool exists before executing
