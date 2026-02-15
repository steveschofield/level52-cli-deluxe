# Guardian CLI Automated Testing - Quick Start Guide

## 🚀 Get Testing in 5 Minutes

This guide will have you running fully automated security tests against vulnerable targets in your homelab within minutes.

---

## Prerequisites

```bash
# 1. Guardian CLI installed
cd /path/to/guardian-cli-deluxe
source venv/bin/activate

# 2. Docker running
docker --version  # Should show Docker version

# 3. Verify Guardian works
python -m cli.main --help
```

---

## Step 1: Deploy a Vulnerable Target (30 seconds)

```bash
# Deploy DVWA (Damn Vulnerable Web Application)
python homelab_test_orchestrator.py --deploy-only --target dvwa
```

**Expected output:**
```
Deploying target: dvwa (Damn Vulnerable Web Application)
Starting Docker containers...
Waiting for service to be ready...
✓ dvwa deployed successfully
```

**Verify it's running:**
```bash
# Check container
docker ps | grep dvwa

# Test web access
curl -I http://localhost:8081
```

---

## Step 2: Run Your First Automated Test (15-30 minutes)

```bash
# Run web workflow against DVWA
python homelab_test_orchestrator.py --target dvwa --workflow web
```

**What happens:**
1. ✅ Deploys DVWA container
2. 🔍 Runs comprehensive web application testing workflow
3. 📊 Validates results against expected baseline
4. 📄 Generates HTML + JSON reports
5. 🧹 Cleans up container

**Expected output:**
```
╭──────────────────────────────────────────────────────╮
│ Guardian CLI Automated Testing Suite                │
│ Test Run ID: 20260124_143022                        │
╰──────────────────────────────────────────────────────╯

Deploying target: dvwa (Damn Vulnerable Web Application)
✓ dvwa deployed successfully

Running workflow: web → dvwa
Command: python -m cli.main workflow run --name web --target http://localhost:8081 ...

✓ Workflow completed in 1847.3s

Evaluating results: dvwa / web
Overall: PASS

  ✓ Workflow Completion: Success (expected: Success)
  ✓ Critical Findings: 4 (expected: >= 2)
  ✓ High Findings: 9 (expected: >= 6)
  ✓ Tool Success Rate: 95.7% (expected: >= 70%)

Tearing down target: dvwa
✓ dvwa torn down successfully

Generating test report...
✓ JSON report saved: test_results/test_report_20260124_143022.json
✓ HTML report saved: test_results/test_report_20260124_143022.html
```

---

## Step 3: Review Results (2 minutes)

### Option A: View HTML Report

```bash
# Open in browser
open test_results/test_report_*.html  # macOS
xdg-open test_results/test_report_*.html  # Linux
```

**Report includes:**
- Summary dashboard with success/failure counts
- Findings breakdown by severity
- Tool execution statistics
- Links to detailed Guardian reports

### Option B: Analyze with Log Analyzer

```bash
# Analyze the latest session
python log_analyzer.py --session latest
```

**Output shows:**
```
╭──────────────────────────────────────────────────────╮
│ Session Analysis: 20260124_143030                    │
│ Target: http://localhost:8081                        │
│ Workflow: web_pentest                                │
│ Duration: 1847.3s                                    │
╰──────────────────────────────────────────────────────╯

Quality Metrics
┌─────────────┬────────┐
│ Metric      │  Score │
├─────────────┼────────┤
│ Coverage    │  87.5% │
│ Error Rate  │   4.3% │
│ Efficiency  │  52.1  │
└─────────────┴────────┘

Findings Summary
┌──────────┬───────┐
│ Severity │ Count │
├──────────┼───────┤
│ CRITICAL │     4 │
│ HIGH     │     9 │
│ MEDIUM   │    15 │
└──────────┴───────┘

Top Finding Tools
┌────────────┬──────────┐
│ Tool       │ Findings │
├────────────┼──────────┤
│ nuclei     │       12 │
│ nikto      │        8 │
│ dalfox     │        4 │
│ sqlmap     │        3 │
│ xsstrike   │        1 │
└────────────┴──────────┘
```

---

## Next Steps

### Test All Targets

```bash
# Run complete test suite (all targets, all workflows)
# Duration: ~2-4 hours
python homelab_test_orchestrator.py --all
```

**Targets tested:**
- DVWA (web)
- WebGoat (web)
- Juice Shop (web)
- NodeGoat (web)
- Metasploitable3 (network)

### Test Specific Workflow

```bash
# Run reconnaissance only
python homelab_test_orchestrator.py --target dvwa --workflow recon

# Run autonomous AI-driven testing
python homelab_test_orchestrator.py --target juice-shop --workflow autonomous

# Run network testing
python homelab_test_orchestrator.py --target metasploitable3 --workflow network
```

### Compare Multiple Runs

```bash
# Analyze all sessions
python log_analyzer.py --compare-all
```

**Shows trend analysis:**
```
Session Comparison
┌─────────────┬────────────┬──────────┬──────────┬─────────┬──────────┬───────────┬─────────┐
│ Session ID  │ Target     │ Workflow │ Duration │ Tools   │ Findings │ Coverage  │ Error % │
├─────────────┼────────────┼──────────┼──────────┼─────────┼──────────┼───────────┼─────────┤
│ 202601...   │ dvwa       │ web      │   1847.3 │  22/23  │       28 │     87.5% │    4.3% │
│ 202601...   │ juice-shop │ web      │   2103.1 │  21/23  │       45 │     91.3% │    8.7% │
│ 202601...   │ webgoat    │ web      │   1956.7 │  23/23  │       32 │    100.0% │    0.0% │
└─────────────┴────────────┴──────────┴──────────┴─────────┴──────────┴───────────┴─────────┘

Averages:
  Coverage: 92.9%
  Error Rate: 4.3%
  Findings per Session: 35.0
```

---

## Troubleshooting

### Container Won't Start

```bash
# Check Docker is running
systemctl status docker

# Check for port conflicts
netstat -tuln | grep 8081

# View container logs
docker-compose -f deployments/dvwa-compose.yml logs
```

### No Findings Detected

```bash
# Verify target is accessible
curl http://localhost:8081

# Check Guardian logs
tail -f logs/guardian.log

# Run with debug logging
python -m cli.main workflow run --name web --target http://localhost:8081 --config config/guardian.yaml
```

### Tool Failures

```bash
# Verify tool installation
./setup.sh 2>&1 | tee setup.log

# Check specific tool
which nuclei
nuclei -version

# Review tool execution logs
python log_analyzer.py --session latest --check-errors
```

---

## Common Workflows

### Daily Regression Testing

```bash
#!/bin/bash
# daily_test.sh

cd /path/to/guardian-cli-deluxe
source venv/bin/activate

# Run tests
python homelab_test_orchestrator.py --target dvwa --workflow web

# Email report
python -c "
from email.mime.text import MIMEText
import smtplib
import glob

latest_report = max(glob.glob('test_results/test_report_*.html'))

with open(latest_report) as f:
    msg = MIMEText(f.read(), 'html')
    msg['Subject'] = 'Guardian Daily Test Report'
    msg['From'] = 'guardian@example.com'
    msg['To'] = 'security-team@example.com'

    with smtplib.SMTP('localhost') as server:
        server.send_message(msg)
"
```

Add to crontab:
```bash
0 2 * * * /path/to/daily_test.sh > /var/log/guardian/daily_$(date +\%Y\%m\%d).log 2>&1
```

### Pre-Deployment Testing

```bash
#!/bin/bash
# pre_deploy_test.sh
# Run before deploying application changes

APP_URL="$1"

python homelab_test_orchestrator.py \
  --target custom \
  --workflow web \
  --config config/guardian.yaml

# Check exit code
if [ $? -eq 0 ]; then
  echo "✓ Security tests passed"
  exit 0
else
  echo "✗ Security tests failed - blocking deployment"
  exit 1
fi
```

### Continuous Monitoring

```bash
# Watch for new deployments and test automatically
inotifywait -m /path/to/deployments -e create |
while read path action file; do
  echo "New deployment detected: $file"
  python homelab_test_orchestrator.py --all
done
```

---

## Advanced Usage

### Custom Targets

Add your own vulnerable application:

```python
# In homelab_test_orchestrator.py

TARGETS = {
    # ... existing targets ...

    "my-app": TestTarget(
        name="my-app",
        description="My Custom Application",
        type="web",
        deployment="docker",
        docker_compose="deployments/my-app-compose.yml",
        expected_findings={"critical": 2, "high": 5, "medium": 10},
        workflows=["web", "recon"]
    )
}
```

### Custom Validation

Modify validation logic in `evaluate_results()`:

```python
# Check for specific CVEs
required_cves = ["CVE-2021-44228"]  # Log4Shell
found_cves = [f.get("cve") for f in findings if f.get("cve")]

if not all(cve in found_cves for cve in required_cves):
    evaluation["passed"] = False
    evaluation["checks"].append({
        "name": "Critical CVE Detection",
        "passed": False,
        "expected": ", ".join(required_cves),
        "actual": ", ".join(found_cves)
    })
```

---

## Best Practices

### 1. Start Small

Begin with a single target (DVWA) and workflow (web) before scaling up.

### 2. Establish Baselines

Run tests 3 times to establish stable baseline metrics:

```bash
for i in {1..3}; do
  python homelab_test_orchestrator.py --target dvwa --workflow web
  sleep 300
done

python log_analyzer.py --compare-all
```

### 3. Monitor Resource Usage

```bash
# Watch Docker resource consumption
docker stats

# Monitor system resources
htop
```

### 4. Regular Maintenance

```bash
# Clean old reports (keep last 30 days)
find reports/ -name "*.json" -mtime +30 -delete
find test_results/ -name "*.json" -mtime +30 -delete

# Prune Docker resources
docker system prune -af --volumes
```

### 5. Iterative Improvement

- Review failed tests and adjust tool configurations
- Update expected findings as targets evolve
- Refine validation thresholds based on trends

---

## Quick Reference

### Commands

```bash
# Deploy targets
python homelab_test_orchestrator.py --deploy-only [--target <name>]

# Run tests
python homelab_test_orchestrator.py --target <name> --workflow <workflow>
python homelab_test_orchestrator.py --all

# Teardown
python homelab_test_orchestrator.py --teardown-only [--target <name>]

# Analyze
python log_analyzer.py --session latest
python log_analyzer.py --compare-all
```

### Targets

- `dvwa` - Basic web vulnerabilities
- `webgoat` - Educational lessons
- `juice-shop` - Modern web app
- `nodegoat` - Node.js specific
- `metasploitable3` - Network testing

### Workflows

- `recon` - Reconnaissance
- `web` - Web application testing
- `network` - Network infrastructure
- `autonomous` - AI-driven testing

### Ports

- `8081` - DVWA
- `8082` - WebGoat
- `8083` - Juice Shop
- `8084` - NodeGoat
- `8085` - Metasploitable3

---

## Support

- **Documentation**: `AUTOMATED_TESTING.md` (comprehensive guide)
- **Architecture**: `ARCHITECTURE_REVIEW.md` (technical details)
- **Deployment**: `deployments/README.md` (target details)
- **Logs**: `logs/guardian.log`
- **Reports**: `test_results/` and `reports/`

---

## Summary

You now have a fully automated testing framework that can:

✅ **Deploy** vulnerable targets automatically
✅ **Execute** comprehensive security workflows
✅ **Validate** results against baselines
✅ **Report** findings with detailed analysis
✅ **Clean up** automatically after testing

**Next:** Run `python homelab_test_orchestrator.py --all` to test everything!

