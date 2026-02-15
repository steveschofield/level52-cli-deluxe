# God-Eye Integration

## Overview

God-Eye has been integrated into guardian-cli to enhance the reconnaissance workflow with comprehensive security assessments, including subdomain takeover detection, exposed configuration scanning, and JavaScript secret analysis.

## Integration Components

### 1. Tool Wrapper (`tools/godeye.py`)

A complete BaseTool implementation that wraps the god-eye CLI with:

- **Command building**: Full support for all god-eye flags
- **JSON output parsing**: Extracts subdomains, vulnerabilities, findings by severity, AI analysis
- **Security issue detection**: Subdomain takeover risks, exposed files, CORS misconfigurations
- **AI integration support**: Optional Ollama-powered analysis with configurable models
- **Technology aggregation**: Tracks discovered technologies and cloud providers

### 2. Configuration (`config/guardian.yaml`)

Added comprehensive god-eye configuration under `tools.godeye`:

```yaml
godeye:
  enabled: true
  concurrency: 500
  timeout: 10
  ports: "80,443,8080,8443,8000,8888"
  no_brute: false
  no_probe: false
  no_ports: false
  no_takeover: false
  active_only: false
  enable_ai: false
  ai_url: "http://localhost:11434"
  fast_model: "deepseek-r1:1.5b"
  deep_model: "qwen2.5-coder:7b"
  tool_timeout: 900
```

### 3. Workflow Integration (`workflows/recon.yaml`)

Added as a dedicated security assessment step after HTTP probing:

```yaml
- name: security_assessment
  type: tool
  tool: godeye
  objective: "Deep security assessment: subdomain takeover, exposed configs, secrets scanning"
  parameters:
    no_brute: true        # Skip DNS brute-force (already done by subfinder)
    active_only: true     # Focus on active hosts
    enable_ai: false      # Disable AI by default (enable via config)
  dependencies:
    - http_probing
```

## Features Provided

### Critical Security Checks (New Capabilities)

1. **Subdomain Takeover Detection**
   - 110+ fingerprints for vulnerable cloud services
   - Identifies dangling DNS records
   - Detects unclaimed cloud resources

2. **Exposed Sensitive Files**
   - `.git` repositories
   - `.env` files
   - Backup files
   - Configuration files
   - Source code leaks

3. **JavaScript Secret Scanning**
   - Hardcoded API keys
   - Access tokens
   - Credentials in client-side code

4. **Cloud Infrastructure Exposure**
   - AWS, GCP, Azure resource detection
   - S3 bucket enumeration
   - Cloud service identification

5. **CORS Misconfigurations**
   - Overly permissive policies
   - Origin reflection vulnerabilities

6. **Missing Security Headers**
   - HSTS, CSP, X-Frame-Options analysis
   - Security best practice checks

### AI-Powered Analysis (Optional)

When `enable_ai: true`:
- Context-aware vulnerability analysis
- Cascade model approach (fast triage → deep analysis)
- 8 specialized AI agents (when `multi_agent: true`)
- 100% local with Ollama (no external API calls)

## Usage

### Basic Reconnaissance

```bash
guardian recon --domain example.com
```

The security_assessment step will automatically run after HTTP probing.

### With AI Analysis

Enable AI in config:

```yaml
tools:
  godeye:
    enable_ai: true
    ai_url: "http://localhost:11434"
```

Or pass as parameter in workflow/manual execution.

### Standalone God-Eye Execution

```bash
guardian tool godeye --target example.com --enable-ai
```

## Output Structure

God-eye returns structured JSON with:

```json
{
  "subdomains": [...],
  "count": 25,
  "active_count": 18,
  "vulnerabilities": [...],
  "vulnerability_count": 3,
  "findings": {
    "critical": [],
    "high": [],
    "medium": [],
    "low": [],
    "info": []
  },
  "security_issues": [
    {
      "type": "subdomain_takeover",
      "subdomain": "old.example.com",
      "severity": "high"
    }
  ],
  "technologies": {"nginx": 5, "Node.js": 3},
  "cloud_providers": {"AWS": 2, "GCP": 1},
  "ai_findings": [...]
}
```

## Workflow Position

God-eye runs after `http_probing` to:
1. Leverage already-discovered active subdomains
2. Skip redundant DNS brute-forcing (done by subfinder)
3. Focus on security-specific checks
4. Feed findings into analyst agent for correlation

## Installation Requirements

### Automatic Installation (Recommended)

God-eye is automatically installed by the setup script:

```bash
./setup.sh
```

The script will install god-eye via `go install` and link it into your virtualenv.

### Manual Installation

If you need to install god-eye separately:

```bash
# Install god-eye
go install github.com/Vyntral/god-eye@latest

# Verify installation
god-eye -h
```

### AI Features (Optional)

For AI features, install Ollama:

```bash
# Install Ollama
curl https://ollama.ai/install.sh | sh

# Pull models
ollama pull deepseek-r1:1.5b
ollama pull qwen2.5-coder:7b
```

## Performance Considerations

- Default concurrency: 500 workers (adjust based on target size)
- Tool timeout: 900 seconds (15 minutes) for comprehensive scans
- Disable AI for faster results (enable for deeper analysis)
- Use `active_only: true` to reduce noise

## Integration with Existing Tools

### Complements

- **Subfinder**: Initial subdomain discovery
- **httpx**: HTTP service probing and tech detection
- **Nuclei**: Template-based vulnerability scanning
- **Analyst Agent**: Correlates god-eye findings with other tool outputs

### Reduces Overlap

- Configured with `no_brute: true` to avoid duplicating subfinder's work
- Focuses on security checks rather than general reconnaissance

## Future Enhancements

Potential improvements:
1. Dynamic AI model selection based on finding severity
2. Integration with existing guardian AI agents
3. Custom god-eye wordlists from guardian config
4. Real-time streaming of findings during long scans
5. Vulnerability correlation with exploit-db/metasploit

## References

- God-Eye Repository: https://github.com/Vyntral/god-eye
- Tool Wrapper: `tools/godeye.py`
- Configuration: `config/guardian.yaml` (line 345)
- Workflow: `workflows/recon.yaml` (line 37)
