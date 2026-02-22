# Guardian CLI Homelab Testing Guide

Automated testing framework for validating Guardian workflows against your local infrastructure.

## Quick Start

```bash
# 1. Configure your targets
vi tests/homelab_targets.yaml

# 2. Check tools are installed
make homelab-check

# 3. Run validation (dry-run)
make homelab-dry

# 4. Run live tests
make homelab-recon-live
```

---

## The 4 Workflows

| Workflow | Purpose | Key Tools |
|----------|---------|-----------|
| **recon** | Reconnaissance & enumeration | subfinder, amass, nmap, dnsx, httpx |
| **web_pentest** | Web application security | nuclei, sqlmap, feroxbuster, xsstrike, zap |
| **network_pentest** | Network infrastructure | nmap, masscan, enum4linux, smbclient |
| **autonomous** | AI-driven pentesting | All tools (AI selects dynamically) |

---

## Configuration

Edit `tests/homelab_targets.yaml` to add your targets.

### Recon Targets

```yaml
targets:
  # External domain (passive only)
  - name: "my-domain"
    type: "domain"
    domain: "example.com"
    workflows:
      - recon
    passive_only: true
    tags: ["recon", "external"]

  # Internal subnet
  - name: "homelab-subnet"
    type: "network"
    cidr: "192.168.1.0/24"
    workflows:
      - recon
      - network_pentest
    tags: ["recon", "internal"]
```

### Web Targets

```yaml
  # Vulnerable web app (Juice Shop, DVWA, etc.)
  - name: "juice-shop"
    type: "web_application"
    url: "http://192.168.1.50:3000"
    workflows:
      - web_pentest
    expectations:
      min_findings: 5
      should_find: ["sql-injection", "xss"]
    tags: ["web", "vuln-app"]

  # Staging environment
  - name: "staging-app"
    type: "web_application"
    url: "https://staging.myapp.local"
    workflows:
      - web_pentest
    # Optional: whitebox testing with source code
    # source_path: "/path/to/source"
    tags: ["web", "staging"]
```

### Network Targets

```yaml
  # Linux server
  - name: "ubuntu-server"
    type: "host"
    host: "192.168.1.100"
    workflows:
      - recon
      - network_pentest
    tags: ["network", "linux"]

  # Windows server
  - name: "windows-dc"
    type: "active_directory"
    host: "192.168.1.10"
    domain: "lab.local"
    workflows:
      - network_pentest
      - active_directory
    tags: ["network", "windows", "ad"]
```

### Autonomous Targets

```yaml
  # AI-driven full assessment
  - name: "autonomous-lab"
    type: "web_application"
    url: "http://192.168.1.50:3000"
    workflows:
      - autonomous
    autonomous_config:
      max_steps: 25
      max_duration_minutes: 60
      ai_model: "gemini"
      safety_mode: true
    tags: ["autonomous", "ai"]
```

---

## Make Commands

### Validation (Dry Run)

```bash
make homelab-check      # Verify tools are installed
make homelab-dry        # Validate all workflows (no execution)
make homelab-smoke      # Quick smoke test
```

### Individual Workflows

```bash
# Dry run (validation only)
make homelab-recon
make homelab-web
make homelab-network
make homelab-autonomous

# Live execution (actual scans)
make homelab-recon-live
make homelab-web-live
make homelab-network-live
make homelab-autonomous-live
```

### All Workflows

```bash
make homelab-all        # Test all 4 workflows (validation)
make homelab-all-live   # Test all 4 workflows (live)
```

### Watch Mode

```bash
make homelab-watch      # Auto-retest when code changes
```

### Shortcuts

```bash
make hr    # homelab-recon
make hw    # homelab-web
make hn    # homelab-network
make ha    # homelab-autonomous
make hh    # homelab (all)
```

---

## Direct Script Usage

```bash
# Basic usage
python scripts/homelab_test.py --dry-run
python scripts/homelab_test.py --live

# Specific target
python scripts/homelab_test.py --target juice-shop --workflow web_pentest

# Specific scenario
python scripts/homelab_test.py --scenario recon
python scripts/homelab_test.py --scenario web
python scripts/homelab_test.py --scenario network
python scripts/homelab_test.py --scenario autonomous

# Filter by tags
python scripts/homelab_test.py --tags vuln-app web

# Watch mode
python scripts/homelab_test.py --watch

# Save results to JSON
python scripts/homelab_test.py --live --save
```

---

## Test Scenarios

Predefined in `homelab_targets.yaml`:

| Scenario | Description |
|----------|-------------|
| `smoke` | Quick validation test |
| `recon` | All recon targets |
| `web` | All web targets |
| `network` | All network targets |
| `autonomous` | All autonomous targets |
| `all_workflows` | Test all 4 workflows |
| `full` | Everything against everything |

```bash
python scripts/homelab_test.py --scenario smoke
python scripts/homelab_test.py --scenario all_workflows --live
```

---

## Available Tools

### Recon
- amass, subfinder, dnsx, httpx, nmap, masscan, naabu, puredns, whatweb, whois

### Web
- **Scanners**: nuclei, nikto, zap, feroxbuster, ffuf
- **Injection**: sqlmap, xsstrike, dalfox, commix
- **Custom**: cors_scanner, ssrf_scanner, xxe_scanner, idor_scanner, auth_scanner, csrf_tester, deserialization_scanner
- **API**: arjun, paramspider, ffuf, graphql_cop, schemathesis
- **JS**: linkfinder, subjs, xnlinkfinder, retire
- **Secrets**: gitleaks, trufflehog
- **SAST**: semgrep, trivy
- **Auth**: jwt_tool, hydra
- **CMS**: wpscan, cmseek
- **TLS**: sslyze, testssl

### Network
- nmap, masscan, enum4linux, enum4linux_ng, smbclient, snmpwalk, onesixtyone, showmount, metasploit, hydra, bloodhound

### Autonomous
- AI selects from all 50+ tools based on findings

---

## Results

Test results are saved to `test_results/`:

```
test_results/
├── test_run_20240215_143022.json
├── juice-shop_web_pentest_1707999022/
│   ├── report.json
│   └── findings/
└── ...
```

---

## Safety

1. **Dry run first**: Always run `--dry-run` before `--live`
2. **Passive only**: Use `passive_only: true` for external targets
3. **Safety mode**: Enable `safety_mode: true` for autonomous
4. **Live testing disabled by default**: Set `live_testing: true` in settings when ready

```yaml
settings:
  live_testing: false   # Change to true when ready
  tool_timeout: 120
  parallel_tests: 2
```

---

## Troubleshooting

### Tools not found

```bash
make homelab-check
# Shows which tools are missing
```

### Target not reachable

```bash
ping 192.168.1.100
# Ensure target is up and accessible
```

### Workflow validation fails

```bash
python scripts/homelab_test.py --dry-run --target my-target
# Check error output for YAML issues
```
