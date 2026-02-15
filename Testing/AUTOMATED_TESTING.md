# Guardian CLI Automated Testing Framework

## Overview

The Guardian CLI Automated Testing Framework enables fully automated security testing in your homelab environment. It eliminates manual intervention by automatically deploying vulnerable targets, executing workflows, validating results, and generating comprehensive reports.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              Homelab Test Orchestrator                      │
│  (homelab_test_orchestrator.py)                            │
└─────────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   Target     │    │   Workflow   │    │  Validation  │
│  Deployment  │    │  Execution   │    │  & Reporting │
└──────────────┘    └──────────────┘    └──────────────┘
        │                   │                   │
        ▼                   ▼                   ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Docker      │    │  Guardian    │    │  Log         │
│  Compose     │    │  CLI         │    │  Analyzer    │
└──────────────┘    └──────────────┘    └──────────────┘
```

## Components

### 1. Homelab Test Orchestrator (`homelab_test_orchestrator.py`)

Central automation engine that coordinates the entire testing lifecycle.

**Features:**
- Automated target deployment via Docker Compose
- Workflow execution orchestration
- Result validation against expected baselines
- Comprehensive test reporting (JSON + HTML)
- Session comparison and trend analysis

### 2. Log Analyzer (`log_analyzer.py`)

Advanced log analysis and validation system.

**Features:**
- Session analysis (quality metrics, coverage, efficiency)
- Error detection and root cause analysis
- Finding correlation and deduplication
- Performance benchmarking
- Automated recommendations

### 3. Vulnerable Target Library

Curated collection of vulnerable applications for testing:

| Target | Type | Complexity | Primary Focus |
|--------|------|------------|---------------|
| DVWA | Web | Low | OWASP Top 10 basics |
| WebGoat | Web | Medium | Educational lessons |
| Juice Shop | Web | High | Modern web vulns |
| NodeGoat | Web | Medium | Node.js specific |
| Metasploitable3 | Network | High | Infrastructure |

## Quick Start

### Prerequisites

```bash
# Required
- Kali Linux (or compatible OS)
- Docker and Docker Compose
- Python 3.11+
- Guardian CLI installed (./setup.sh)

# Optional for advanced testing
- Metasploit Framework
- ZAP Docker image
```

### Installation

```bash
# 1. Navigate to Guardian directory
cd /path/to/guardian-cli-deluxe

# 2. Activate virtual environment
source venv/bin/activate

# 3. Make scripts executable
chmod +x homelab_test_orchestrator.py log_analyzer.py

# 4. Verify installation
python homelab_test_orchestrator.py --help
python log_analyzer.py --help
```

### Basic Usage

#### Run Complete Test Suite

```bash
# Test all targets with all workflows
python homelab_test_orchestrator.py --all
```

This will:
1. Deploy all vulnerable targets (DVWA, WebGoat, Juice Shop, etc.)
2. Run appropriate workflows against each target
3. Validate results against expected baselines
4. Generate comprehensive HTML + JSON reports
5. Teardown all targets

**Duration:** ~2-4 hours depending on configuration

#### Test Specific Target

```bash
# Run web workflow against DVWA
python homelab_test_orchestrator.py --target dvwa --workflow web
```

#### Deploy Targets Only

```bash
# Deploy all targets
python homelab_test_orchestrator.py --deploy-only

# Deploy specific target
python homelab_test_orchestrator.py --deploy-only --target juice-shop
```

#### Analyze Results

```bash
# Analyze latest session
python log_analyzer.py --session latest

# Compare all sessions
python log_analyzer.py --compare-all

# Generate detailed analysis report
python log_analyzer.py --session latest --output analysis_report.json
```

## Advanced Usage

### Custom Test Scenarios

Create custom test configurations by modifying the `TARGETS` dictionary in `homelab_test_orchestrator.py`:

```python
"custom-app": TestTarget(
    name="custom-app",
    description="My Custom Application",
    type="web",
    deployment="docker",
    docker_compose="deployments/custom-app-compose.yml",
    expected_findings={"critical": 2, "high": 5, "medium": 10},
    workflows=["web", "recon"]
)
```

### Continuous Integration

Run automated tests on schedule using cron:

```bash
# Add to crontab
0 2 * * * cd /path/to/guardian && ./venv/bin/python homelab_test_orchestrator.py --all > /var/log/guardian/nightly_$(date +\%Y\%m\%d).log 2>&1
```

### Custom Validation Rules

Extend `evaluate_results()` in `homelab_test_orchestrator.py` to add custom validation logic:

```python
# Check for specific CVEs
required_cves = ["CVE-2021-44228", "CVE-2020-8958"]
found_cves = [f.get("cve") for f in findings if f.get("cve")]
missing_cves = set(required_cves) - set(found_cves)

if missing_cves:
    evaluation["passed"] = False
    evaluation["checks"].append({
        "name": "Required CVE Detection",
        "passed": False,
        "expected": ", ".join(required_cves),
        "actual": ", ".join(found_cves),
        "details": f"Missing: {', '.join(missing_cves)}"
    })
```

## Workflows

### Available Workflows

1. **`recon`** - Reconnaissance workflow
   - Subdomain enumeration
   - Port scanning
   - Service fingerprinting
   - DNS enumeration
   - Best for: Domain-based targets

2. **`web`** - Web application testing
   - Content discovery
   - Vulnerability scanning
   - Authentication testing
   - API fuzzing
   - Best for: Web applications

3. **`network`** - Network infrastructure testing
   - Comprehensive port scanning
   - Service enumeration
   - SMB/NFS testing
   - Vulnerability assessment
   - Best for: Network ranges, servers

4. **`autonomous`** - AI-driven testing
   - Dynamic decision-making
   - Adaptive testing strategy
   - Best for: Complex or unknown targets

### Workflow Selection by Target

| Target | Recommended Workflows |
|--------|-----------------------|
| DVWA | `web`, `recon`, `autonomous` |
| WebGoat | `web`, `autonomous` |
| Juice Shop | `web`, `recon`, `autonomous` |
| NodeGoat | `web`, `autonomous` |
| Metasploitable3 | `network`, `recon`, `autonomous` |

## Validation & Quality Metrics

### Coverage Score (0-100)

Measures what percentage of expected tools successfully executed.

- **>= 80%**: Excellent coverage
- **60-79%**: Good coverage
- **< 60%**: Poor coverage (investigate tool failures)

**Calculation:** `(successful_expected_tools / total_expected_tools) * 100`

### Error Rate (0-100)

Percentage of tools that failed during execution.

- **< 10%**: Excellent
- **10-30%**: Acceptable
- **> 30%**: Poor (requires attention)

**Calculation:** `(failed_tools / total_tools) * 100`

### Efficiency Score (0-100)

Measures finding discovery rate relative to tool executions.

- **>= 50**: Highly efficient
- **30-49**: Moderate efficiency
- **< 30**: Low efficiency

**Calculation:** `min((total_findings / successful_tools) * 10, 100)`

## Reports

### Test Report Structure

After each test run, reports are generated in `test_results/`:

```
test_results/
├── test_report_20260124_120000.json    # Machine-readable results
└── test_report_20260124_120000.html    # Human-readable dashboard
```

### HTML Report Features

- **Summary Dashboard**: Success rate, total findings, duration
- **Test Matrix**: All tests with status, findings breakdown
- **Severity Heatmap**: Visual representation of findings
- **Links to Guardian Reports**: Direct links to detailed tool outputs

### JSON Report Schema

```json
{
  "test_run_id": "20260124_120000",
  "timestamp": "2026-01-24T12:00:00",
  "total_tests": 12,
  "successful_tests": 11,
  "failed_tests": 1,
  "results": [
    {
      "target": "dvwa",
      "workflow": "web",
      "session_id": "20260124_120030",
      "duration_seconds": 1847.3,
      "success": true,
      "findings_count": {
        "critical": 4,
        "high": 9,
        "medium": 15
      },
      "tools_executed": 23,
      "tools_successful": 22,
      "errors": [],
      "report_path": "reports/report_20260124_120030.html"
    }
  ]
}
```

## Troubleshooting

### Common Issues

#### Docker Containers Won't Start

```bash
# Check Docker status
systemctl status docker

# Check available resources
docker info | grep -E 'CPUs|Total Memory'

# View container logs
docker-compose -f deployments/dvwa-compose.yml logs
```

#### High Tool Failure Rate

1. Check tool installation:
   ```bash
   ./setup.sh 2>&1 | tee setup.log
   ```

2. Verify tool availability:
   ```bash
   python -m cli.main workflow list
   ```

3. Review Guardian logs:
   ```bash
   tail -f logs/guardian.log
   ```

#### No Findings Detected

Possible causes:
- Target not fully started (wait 30-60s after deployment)
- Network connectivity issues
- WAF/firewall blocking scans
- Tool configuration issues

**Debug steps:**
```bash
# Verify target is accessible
curl -I http://localhost:8081

# Check Guardian can reach target
python -m cli.main workflow run --name recon --target http://localhost:8081

# Review session logs
python log_analyzer.py --session latest
```

#### Timeout Issues

For long-running scans, increase timeouts in `config/guardian.yaml`:

```yaml
pentest:
  tool_timeout: 1800  # 30 minutes

workflows:
  timeout: 7200  # 2 hours

tools:
  nuclei:
    tool_timeout: 1800  # 30 minutes for Nuclei
```

## Performance Optimization

### Parallel Execution

Adjust parallel tool execution in `config/guardian.yaml`:

```yaml
pentest:
  max_parallel_tools: 3  # Increase for faster execution (uses more resources)
```

### Selective Testing

Test only critical tools by creating custom workflow:

```yaml
# workflows/quick_test.yaml
name: quick_test
description: Fast validation test

steps:
  - name: port_scan
    type: tool
    tool: nmap

  - name: vuln_scan
    type: tool
    tool: nuclei

  - name: analyze
    type: analysis
    agent: analyst
```

### Resource Allocation

For multiple concurrent targets:

```bash
# Increase Docker resources
# Docker Desktop -> Settings -> Resources
# - CPUs: 4+
# - Memory: 8GB+
# - Swap: 2GB+
```

## Best Practices

### 1. Baseline Establishment

Run tests multiple times to establish stable baselines:

```bash
# Run 3 iterations to establish baseline
for i in {1..3}; do
  python homelab_test_orchestrator.py --target dvwa --workflow web
  sleep 300  # Wait 5 minutes between runs
done

# Analyze variance
python log_analyzer.py --compare-all
```

### 2. Regression Testing

Compare new runs against baselines:

```python
# In homelab_test_orchestrator.py
baseline_findings = {"critical": 4, "high": 9, "medium": 15}
actual_findings = result.findings_count

# Alert on significant deviations
if actual_findings["critical"] < baseline_findings["critical"] * 0.7:
    warnings.append("Detection rate decreased by >30%")
```

### 3. Environment Isolation

Use Docker networks for isolation:

```yaml
# In docker-compose.yml
networks:
  guardian_test:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/16
```

### 4. Credential Management

Store test credentials in `.env`:

```bash
# .env
DVWA_USER=admin
DVWA_PASS=password
WEBGOAT_USER=webgoat
WEBGOAT_PASS=webgoat

# Load in orchestrator
from dotenv import load_dotenv
load_dotenv()
```

### 5. Scheduled Maintenance

Clean up old reports and containers:

```bash
#!/bin/bash
# cleanup.sh

# Remove reports older than 30 days
find reports/ -name "*.json" -mtime +30 -delete
find test_results/ -name "*.json" -mtime +30 -delete

# Prune Docker resources
docker system prune -af --volumes

# Restart Docker if memory usage high
docker stats --no-stream | awk '{if ($4 > "80%") system("systemctl restart docker")}'
```

## Integration Examples

### Slack Notifications

```python
import requests

def send_slack_notification(test_run_id, results):
    webhook_url = os.getenv("SLACK_WEBHOOK_URL")

    message = {
        "text": f"Guardian Test Run {test_run_id} Complete",
        "attachments": [{
            "color": "good" if results["passed"] else "danger",
            "fields": [
                {"title": "Success Rate", "value": f"{results['success_rate']}%"},
                {"title": "Critical Findings", "value": str(results["critical_count"])},
                {"title": "Duration", "value": f"{results['duration']}s"}
            ]
        }]
    }

    requests.post(webhook_url, json=message)
```

### Email Reports

```python
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

def email_report(report_path, recipients):
    msg = MIMEMultipart()
    msg['Subject'] = f'Guardian Test Report {test_run_id}'
    msg['From'] = 'guardian@example.com'
    msg['To'] = ', '.join(recipients)

    with open(report_path, 'rb') as f:
        att = MIMEApplication(f.read(), _subtype="html")
        att.add_header('Content-Disposition', 'attachment', filename='report.html')
        msg.attach(att)

    with smtplib.SMTP('smtp.example.com', 587) as server:
        server.starttls()
        server.login('user', 'pass')
        server.send_message(msg)
```

### JIRA Issue Creation

```python
from jira import JIRA

def create_jira_issues(critical_findings):
    jira = JIRA('https://jira.example.com', auth=('user', 'token'))

    for finding in critical_findings:
        issue = jira.create_issue(
            project='SEC',
            summary=f"Critical: {finding['title']}",
            description=finding['description'],
            issuetype={'name': 'Bug'},
            priority={'name': 'Critical'}
        )
        print(f"Created {issue.key}")
```

## Next Steps

1. **Expand Target Library**: Add your own vulnerable applications
2. **Custom Workflows**: Create workflows tailored to your tech stack
3. **CI/CD Integration**: Integrate with Jenkins, GitLab CI, or GitHub Actions
4. **Metrics Dashboard**: Build Grafana dashboard from JSON reports
5. **Machine Learning**: Train models on finding patterns for anomaly detection

## Support

- **Documentation**: See `docs/` directory
- **Issues**: GitHub Issues
- **Logs**: `logs/guardian.log`
- **Sessions**: `reports/session_*.json`
