# Guardian Tools Configuration

This directory contains wrappers for various penetration testing tools.

## Available Tools

### Network Scanning
- **Nmap**: Comprehensive port scanning and service detection
  - Installation: `apt-get install nmap` or `choco install nmap`
  - Features: Port scanning, service version detection, OS fingerprinting

- **Masscan**: Ultra-fast TCP port scanner
  - Features: Fast large-scale port scanning, banner grabbing, rate limiting

- **Naabu**: Fast TCP port scanner
  - Installation: `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest`
  - Features: JSONL output, CDN exclusion, top-port presets

### Network Enumeration
- **enum4linux-ng**: SMB enumeration (primary)
  - Installation: `apt-get install enum4linux-ng`
  - Features: Modern SMB share/domain/user enumeration, structured output support

- **enum4linux**: legacy compatibility alias routed to enum4linux-ng in Guardian
  - Installation: `apt-get install enum4linux` (legacy package)

- **smbclient**: SMB share listing and access checks
  - Installation: `apt-get install smbclient`

- **showmount**: NFS export enumeration
  - Installation: `apt-get install nfs-common`

- **onesixtyone**: SNMP community brute force
  - Installation: `apt-get install onesixtyone`

- **snmpwalk**: SNMP enumeration
  - Installation: `apt-get install snmp`

### Web Reconnaissance  
- **httpx**: HTTP probing and technology detection
  - Installation: `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest`
  - Features: HTTP headers, status codes, technology fingerprinting

- **WhatWeb**: Web technology fingerprinting
  - Installation: `apt-get install whatweb` or `gem install whatweb`
  - Features: CMS detection, framework identification, plugin detection

- **Wafw00f**: Web Application Firewall detection
  - Installation: `pip install wafw00f`
  - Features: Detect WAF products, identify vendors

- **Katana**: Web crawler
  - Installation: `go install github.com/projectdiscovery/katana/cmd/katana@latest`
  - Features: Fast crawling with depth control, JSONL output

### OSINT / DNS
- **Amass**: Passive OSINT and asset discovery
  - Installation: `apt-get install amass` (Kali) or `snap install amass`

- **Whois**: WHOIS lookups
  - Installation: `apt-get install whois`

- **dnsrecon**: DNS enumeration
  - Installation: `pip install dnsrecon`

### Subdomain Enumeration
- **Subfinder**: Passive subdomain discovery
  - Installation: `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
  - Features: Multiple sources, DNS resolution

- **Amass**: Advanced network mapping and asset discovery
  - Features: Active/passive enumeration, ASN/CIDR discovery, relationship mapping

- **Asnmap**: ASN and prefix mapping
  - Installation: `go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest`
  - Features: ASN lookups, prefix enumeration, organization metadata

### Vulnerability Scanning
- **Nuclei**: Template-based vulnerability scanner
  - Installation: `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`
  - Features: Community templates, CVE detection, misconfigurations

- **Nikto**: Web vulnerability scanner
  - Installation: `apt-get install nikto`
  - Features: 6700+ potentially dangerous files/CGIs, outdated versions

- **Dalfox**: XSS scanner
  - Installation: `go install github.com/hahwul/dalfox/v2@latest`
  - Features: Parameter mining, reflected/stored XSS detection

- **SQLMap**: Automated SQL injection and database takeover
  - Installation: `pip install sqlmap` or `apt-get install sqlmap`
  - Features: SQL injection detection, database enumeration, risk levels

- **WPScan**: WordPress vulnerability scanner
  - Installation: `gem install wpscan` or download from [wpscan.com](https://wpscan.com/)
  - Features: Plugin/theme enumeration, vulnerability database, user enumeration

- **OWASP ZAP (headless)**: Web app scanning (baseline passive or full active)
  - Installation: Docker recommended: `docker pull ghcr.io/zaproxy/zaproxy:stable` (alternatives: `:bare`, `:weekly`, `:nightly`)
  - Features: Passive scan (baseline), optional active scan (full) when safe_mode is disabled
  - Example (baseline scan):
    - `docker run --rm --pull=missing -v <reports_dir>:/zap/wrk ghcr.io/zaproxy/zaproxy:stable bash -lc 'zap-baseline.py -t <target> -J /zap/wrk/<json> -r /zap/wrk/<html> -w /zap/wrk/<md> -m <minutes>'`
  - Example (daemon mode, long-running):
    - `docker run -d --name zapd -p 8080:8080 ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true`
    - Set `tools.zap.mode: daemon` and `tools.zap.api_url: http://127.0.0.1:8080`

### SSL/TLS Testing
- **TestSSL**: SSL/TLS security testing
  - Installation: Download from https://testssl.sh/
  - Features: Protocol support, cipher suites, certificate validation, vulnerabilities

- **SSLyze**: Advanced SSL/TLS configuration analyzer
  - Installation: `pip install sslyze`
  - Features: Certificate analysis, protocol support, vulnerability detection (Heartbleed, ROBOT)

### Content Discovery
- **FFuf**: Fast web fuzzer
  - Installation: `go install github.com/ffuf/ffuf/v2@latest`
  - Features: Advanced fuzzing, JSON output, recursion, filtering/matching, vhost fuzzing

- **Waybackurls**: Historical URL collection
  - Installation: `go install github.com/tomnomnom/waybackurls@latest`
  - Features: Extracts URLs from the Internet Archive/other sources

### Web App Testing
- **hydra**: Authentication testing
  - Installation: `apt-get install hydra`

- **jwt_tool**: JWT analysis and testing
  - Installation: `git clone https://github.com/ticarpi/jwt_tool`

- **graphql-cop**: GraphQL security testing
  - Installation: `git clone https://github.com/dolevf/graphql-cop.git` (run `./setup.sh` to wire a wrapper)

- **kiterunner**: API route discovery without OpenAPI
  - Installation: `go install github.com/assetnote/kiterunner@latest` (binary: `kr`)


- **upload-scanner**: File upload testing
  - Installation: project-specific

- **csrf-tester**: CSRF testing
  - Installation: project-specific

- **linkfinder / xnlinkfinder**: JavaScript endpoint extraction (modern replacement for JSParser)
  - Installation: `pip install linkfinder` or `pip install xnlinkfinder`
  - Note: xnlinkfinder is the preferred modern alternative

- **retire**: JavaScript library vulnerability scanning
  - Installation: `npm install -g retire`

## Tool Wrapper Architecture

Each tool wrapper inherits from `BaseTool` and implements:
- `get_command()`: Build command with parameters
- `parse_output()`: Parse tool output into structured data
- `_check_installation()`: Verify tool is available

## Adding New Tools

To add a new tool:

1. Create a new file in `tools/` directory
2. Inherit from `BaseTool`
3. Implement required methods
4. Add to `tools/__init__.py`
5. Register in `ToolAgent.available_tools`
6. Update prompt templates

Example:
```python
from tools.base_tool import BaseTool

class MyToolTool(BaseTool):
    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "mytool"
    
    def get_command(self, target, **kwargs):
        return ["mytool", target]
    
    def parse_output(self, output):
        return {"findings": []}
```

## Tool Configuration

Tools can be configured in `config/guardian.yaml`:

```yaml
tools:
  nmap:
    enabled: true
    default_args: "-sV -sC"
    timing: T4
  
  whatweb:
    enabled: true
    aggression: 1
  
  nikto:
    enabled: true
    tuning: "x"  # All tests except DoS
```

## Testing Tools

Check tool availability:
```python
from core.tool_agent import ToolAgent

tool_agent = ToolAgent(config, gemini, memory)
status = tool_agent.get_available_tools()
# Returns: {"nmap": True, "httpx": False, ...}
```
