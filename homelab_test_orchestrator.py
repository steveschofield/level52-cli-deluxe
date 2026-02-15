#!/usr/bin/env python3
"""
Guardian CLI Automated Homelab Testing Orchestrator
====================================================

Automates end-to-end testing of Guardian CLI against homelab vulnerable targets.
Downloads vulnerable apps, runs workflows, evaluates results, and generates reports.

Usage:
    # Run all workflows against all targets
    python homelab_test_orchestrator.py --all

    # Run specific workflow against specific target
    python homelab_test_orchestrator.py --workflow web --target dvwa

    # Deploy targets only
    python homelab_test_orchestrator.py --deploy-only

    # Evaluate existing results
    python homelab_test_orchestrator.py --evaluate-only --session latest
"""

import asyncio
import json
import subprocess
import sys
import time
import yaml
import ssl
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import argparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich import print as rprint

console = Console()
DEFAULT_HOST = "localhost"


@dataclass
class TestTarget:
    """Vulnerable target definition"""
    name: str
    description: str
    type: str  # web, network, mixed
    deployment: str  # docker, vm, url
    url: Optional[str] = None
    docker_compose: Optional[str] = None
    expected_findings: Optional[Dict[str, int]] = None  # {"critical": 5, "high": 10}
    workflows: Optional[List[str]] = None  # ["web", "recon"]


@dataclass
class TestResult:
    """Test execution result"""
    target: str
    workflow: str
    session_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    success: bool = False
    findings_count: Dict[str, int] = None  # {"critical": 0, "high": 0, ...}
    tools_executed: int = 0
    tools_successful: int = 0
    errors: List[str] = None
    report_path: Optional[str] = None
    session_path: Optional[str] = None


class HomelabOrchestrator:
    """Orchestrates automated testing in homelab environment"""

    # Predefined vulnerable targets for testing
    TARGETS = {
        "dvwa": TestTarget(
            name="dvwa",
            description="Damn Vulnerable Web Application",
            type="web",
            deployment="docker",
            docker_compose="deployments/dvwa-compose.yml",
            expected_findings={"critical": 3, "high": 8, "medium": 10},
            workflows=["web", "recon", "autonomous"]
        ),
        "webgoat": TestTarget(
            name="webgoat",
            description="OWASP WebGoat",
            type="web",
            deployment="docker",
            docker_compose="deployments/webgoat-compose.yml",
            expected_findings={"critical": 2, "high": 5, "medium": 15},
            workflows=["web", "autonomous"]
        ),
        "juice-shop": TestTarget(
            name="juice-shop",
            description="OWASP Juice Shop",
            type="web",
            deployment="docker",
            docker_compose="deployments/juice-shop-compose.yml",
            expected_findings={"critical": 4, "high": 10, "medium": 20},
            workflows=["web", "recon", "autonomous"]
        ),
        "metasploitable3": TestTarget(
            name="metasploitable3",
            description="Metasploitable 3",
            type="network",
            deployment="docker",
            docker_compose="deployments/metasploitable3-compose.yml",
            expected_findings={"critical": 10, "high": 15, "medium": 25},
            workflows=["network", "recon", "autonomous"]
        ),
        "nodegoat": TestTarget(
            name="nodegoat",
            description="OWASP NodeGoat",
            type="web",
            deployment="docker",
            docker_compose="deployments/nodegoat-compose.yml",
            expected_findings={"critical": 3, "high": 7, "medium": 12},
            workflows=["web", "autonomous"]
        ),
    }

    def __init__(self, config_path: str = "config/guardian.yaml"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.project_root = Path(__file__).parent
        self.deployments_dir = self.project_root / "deployments"
        self.reports_dir = self.project_root / "reports"
        self.test_results_dir = self.project_root / "test_results"
        self.test_results_dir.mkdir(exist_ok=True)

        # Results tracking
        self.results: List[TestResult] = []
        self.test_run_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    def _load_config(self) -> Dict:
        """Load Guardian configuration"""
        if not self.config_path.exists():
            console.print(f"[yellow]Warning:[/yellow] Config file not found: {self.config_path}")
            return {}

        with open(self.config_path) as f:
            return yaml.safe_load(f)

    def _run_command(self, cmd: List[str], cwd: Optional[Path] = None, timeout: int = 3600) -> tuple[int, str, str]:
        """Run shell command and return exit code, stdout, stderr"""
        try:
            result = subprocess.run(
                cmd,
                cwd=cwd or self.project_root,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", f"Command timed out after {timeout}s"
        except Exception as e:
            return -1, "", str(e)

    def deploy_target(self, target: TestTarget) -> bool:
        """Deploy a vulnerable target"""
        console.print(f"\n[bold cyan]Deploying target:[/bold cyan] {target.name} ({target.description})")

        if target.deployment == "docker":
            compose_file = self.deployments_dir / target.docker_compose

            if not compose_file.exists():
                console.print(f"[yellow]Creating Docker Compose file:[/yellow] {compose_file}")
                self._create_docker_compose(target, compose_file)

            # Start the container
            console.print(f"[cyan]Starting Docker containers...[/cyan]")
            exit_code, stdout, stderr = self._run_command(
                ["docker-compose", "-f", str(compose_file), "up", "-d"],
                timeout=300
            )

            if exit_code != 0:
                console.print(f"[bold red]Failed to deploy {target.name}:[/bold red] {stderr}")
                return False

            # Wait for service to be ready
            console.print(f"[cyan]Waiting for service to be ready...[/cyan]")
            time.sleep(10)  # Give container time to start

            console.print(f"[bold green]✓[/bold green] {target.name} deployed successfully")
            return True

        else:
            console.print(f"[yellow]Warning:[/yellow] Deployment type '{target.deployment}' not yet supported")
            return False

    def _create_docker_compose(self, target: TestTarget, compose_file: Path):
        """Create Docker Compose file for a target"""
        compose_file.parent.mkdir(parents=True, exist_ok=True)

        # Template Docker Compose configurations
        templates = {
            "dvwa": {
                "version": "3.8",
                "services": {
                    "dvwa": {
                        "image": "vulnerables/web-dvwa:latest",
                        "ports": ["8081:80"],
                        "environment": [
                            "MYSQL_HOST=mysql",
                            "MYSQL_DATABASE=dvwa",
                            "MYSQL_USER=dvwa",
                            "MYSQL_PASSWORD=p@ssw0rd"
                        ],
                        "depends_on": ["mysql"]
                    },
                    "mysql": {
                        "image": "mysql:5.7",
                        "environment": [
                            "MYSQL_ROOT_PASSWORD=rootpass",
                            "MYSQL_DATABASE=dvwa",
                            "MYSQL_USER=dvwa",
                            "MYSQL_PASSWORD=p@ssw0rd"
                        ]
                    }
                }
            },
            "webgoat": {
                "version": "3.8",
                "services": {
                    "webgoat": {
                        "image": "webgoat/webgoat:latest",
                        "ports": ["8082:8080", "9090:9090"],
                        "environment": ["TZ=America/New_York"]
                    }
                }
            },
            "juice-shop": {
                "version": "3.8",
                "services": {
                    "juice-shop": {
                        "image": "bkimminich/juice-shop:latest",
                        "ports": ["8083:3000"]
                    }
                }
            },
            "nodegoat": {
                "version": "3.8",
                "services": {
                    "nodegoat": {
                        "image": "owasp/nodegoat:latest",
                        "ports": ["8084:4000"],
                        "environment": [
                            "MONGODB_URI=mongodb://mongo:27017/nodegoat"
                        ],
                        "depends_on": ["mongo"]
                    },
                    "mongo": {
                        "image": "mongo:4.4"
                    }
                }
            },
            "metasploitable3": {
                "version": "3.8",
                "services": {
                    "metasploitable3": {
                        "image": "tleemcjr/metasploitable3-docker:latest",
                        "ports": [
                            "8085:80",
                            "8443:443",
                            "21:21",
                            "22:22",
                            "445:445",
                            "3306:3306"
                        ],
                        "privileged": True
                    }
                }
            }
        }

        template = templates.get(target.name)
        if template:
            with open(compose_file, 'w') as f:
                yaml.dump(template, f, default_flow_style=False)
            console.print(f"[green]Created Docker Compose file:[/green] {compose_file}")
        else:
            console.print(f"[yellow]No template for {target.name}, using generic[/yellow]")

    def teardown_target(self, target: TestTarget) -> bool:
        """Teardown a deployed target"""
        console.print(f"\n[bold cyan]Tearing down target:[/bold cyan] {target.name}")

        if target.deployment == "docker":
            compose_file = self.deployments_dir / target.docker_compose

            if not compose_file.exists():
                console.print(f"[yellow]Compose file not found, skipping teardown[/yellow]")
                return True

            exit_code, stdout, stderr = self._run_command(
                ["docker-compose", "-f", str(compose_file), "down", "-v"],
                timeout=120
            )

            if exit_code != 0:
                console.print(f"[yellow]Warning:[/yellow] Teardown had issues: {stderr}")
                return False

            console.print(f"[bold green]✓[/bold green] {target.name} torn down successfully")
            return True

        return True

    def run_workflow(self, workflow_name: str, target: TestTarget) -> TestResult:
        """Run a Guardian workflow against a target"""
        console.print(f"\n[bold magenta]Running workflow:[/bold magenta] {workflow_name} → {target.name}")

        # Determine target URL
        if target.deployment == "docker":
            # Map container ports to URLs
            port_map = {
                "dvwa": f"http://{DEFAULT_HOST}:8081",
                "webgoat": f"http://{DEFAULT_HOST}:8082",
                "juice-shop": f"http://{DEFAULT_HOST}:8083",
                "nodegoat": f"http://{DEFAULT_HOST}:8084",
                "metasploitable3": f"http://{DEFAULT_HOST}:8085"
            }
            target_url = port_map.get(target.name, f"http://{DEFAULT_HOST}")
        else:
            target_url = target.url or DEFAULT_HOST

        # Create result object
        result = TestResult(
            target=target.name,
            workflow=workflow_name,
            session_id="",
            start_time=datetime.now(),
            findings_count={},
            errors=[]
        )

        # Ensure target is reachable before running workflows
        if target_url.startswith(("http://", "https://")):
            if not self._wait_for_http_target(target_url):
                result.end_time = datetime.now()
                result.duration_seconds = (result.end_time - result.start_time).total_seconds()
                result.success = False
                result.errors.append(f"Target not reachable: {target_url}")
                console.print(f"[bold red]✗[/bold red] Target not reachable: {target_url}")
                self.results.append(result)
                return result

        # Build Guardian command
        cmd = [
            sys.executable, "-m", "cli.main",
            "workflow", "run",
            "--name", workflow_name,
            "--target", target_url,
            "--config", str(self.config_path)
        ]

        console.print(f"[dim]Command:[/dim] {' '.join(cmd)}")

        # Run the workflow
        exit_code, stdout, stderr = self._run_command(cmd, timeout=3600)

        result.end_time = datetime.now()
        result.duration_seconds = (result.end_time - result.start_time).total_seconds()
        result.success = (exit_code == 0)

        if exit_code != 0:
            result.errors.append(f"Workflow exited with code {exit_code}")
            if stderr:
                result.errors.append(stderr)

        # Parse results
        self._parse_workflow_results(result)

        # Display summary
        if result.success:
            console.print(f"[bold green]✓[/bold green] Workflow completed in {result.duration_seconds:.1f}s")
        else:
            console.print(f"[bold red]✗[/bold red] Workflow failed after {result.duration_seconds:.1f}s")

        self.results.append(result)
        return result

    def _wait_for_http_target(self, target_url: str, timeout_seconds: int = 60, interval_seconds: int = 5) -> bool:
        """Wait for an HTTP(S) target to be reachable."""
        console.print(f"[cyan]Checking target availability:[/cyan] {target_url}")
        deadline = time.monotonic() + timeout_seconds
        context = None
        if target_url.startswith("https://"):
            context = ssl._create_unverified_context()

        while time.monotonic() < deadline:
            try:
                req = urllib.request.Request(target_url, method="GET")
                with urllib.request.urlopen(req, timeout=10, context=context) as resp:
                    if 200 <= resp.status < 500:
                        return True
            except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
                time.sleep(interval_seconds)

        return False

    def _parse_workflow_results(self, result: TestResult):
        """Parse Guardian workflow results from session files"""
        # Find the latest session file
        sessions = sorted(self.reports_dir.glob("session_*.json"))
        if not sessions:
            console.print("[yellow]No session files found[/yellow]")
            return

        latest_session = sessions[-1]
        result.session_path = str(latest_session)
        result.session_id = latest_session.stem.replace("session_", "")

        try:
            with open(latest_session) as f:
                session_data = json.load(f)

            # Extract findings
            findings = session_data.get("findings", [])
            severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

            for finding in findings:
                severity = finding.get("severity", "info").lower()
                if severity in severity_count:
                    severity_count[severity] += 1

            result.findings_count = severity_count

            # Extract tool execution stats
            tool_executions = session_data.get("tool_executions", [])
            result.tools_executed = len(tool_executions)
            result.tools_successful = sum(1 for t in tool_executions if t.get("exit_code") == 0)

            # Find report path
            report_html = self.reports_dir / f"report_{result.session_id}.html"
            report_md = self.reports_dir / f"report_{result.session_id}.md"

            if report_html.exists():
                result.report_path = str(report_html)
            elif report_md.exists():
                result.report_path = str(report_md)

        except Exception as e:
            result.errors.append(f"Failed to parse session file: {e}")

    def evaluate_results(self, result: TestResult, target: TestTarget) -> Dict[str, Any]:
        """Evaluate test results against expected findings"""
        console.print(f"\n[bold yellow]Evaluating results:[/bold yellow] {target.name} / {result.workflow}")

        evaluation = {
            "target": target.name,
            "workflow": result.workflow,
            "passed": True,
            "checks": []
        }

        # Check 1: Workflow completed successfully
        check_success = {
            "name": "Workflow Completion",
            "passed": result.success,
            "expected": "Success",
            "actual": "Success" if result.success else "Failed",
            "details": result.errors if not result.success else None
        }
        evaluation["checks"].append(check_success)

        if not result.success:
            evaluation["passed"] = False

        # Check 2: Findings count meets expectations
        if target.expected_findings:
            for severity, expected_count in target.expected_findings.items():
                actual_count = result.findings_count.get(severity, 0)

                # Allow some tolerance (±20%)
                tolerance = max(1, int(expected_count * 0.2))
                passed = abs(actual_count - expected_count) <= tolerance

                check = {
                    "name": f"{severity.capitalize()} Findings",
                    "passed": passed,
                    "expected": f">= {expected_count - tolerance}",
                    "actual": str(actual_count),
                    "details": f"Expected ~{expected_count}, got {actual_count}"
                }
                evaluation["checks"].append(check)

                if not passed and severity in ["critical", "high"]:
                    evaluation["passed"] = False

        # Check 3: Tools executed successfully
        if result.tools_executed > 0:
            success_rate = result.tools_successful / result.tools_executed
            passed = success_rate >= 0.7  # At least 70% success rate

            check = {
                "name": "Tool Success Rate",
                "passed": passed,
                "expected": ">= 70%",
                "actual": f"{success_rate * 100:.1f}%",
                "details": f"{result.tools_successful}/{result.tools_executed} tools succeeded"
            }
            evaluation["checks"].append(check)

            if not passed:
                evaluation["passed"] = False

        # Display evaluation
        status = "[bold green]PASS[/bold green]" if evaluation["passed"] else "[bold red]FAIL[/bold red]"
        console.print(f"\nOverall: {status}")

        for check in evaluation["checks"]:
            status_icon = "✓" if check["passed"] else "✗"
            status_color = "green" if check["passed"] else "red"
            console.print(f"  [{status_color}]{status_icon}[/{status_color}] {check['name']}: {check['actual']} (expected: {check['expected']})")

        return evaluation

    def generate_test_report(self):
        """Generate comprehensive test report"""
        console.print(f"\n[bold cyan]Generating test report...[/bold cyan]")

        report_file = self.test_results_dir / f"test_report_{self.test_run_id}.json"
        html_report = self.test_results_dir / f"test_report_{self.test_run_id}.html"

        # Compile results
        report_data = {
            "test_run_id": self.test_run_id,
            "timestamp": datetime.now().isoformat(),
            "total_tests": len(self.results),
            "successful_tests": sum(1 for r in self.results if r.success),
            "failed_tests": sum(1 for r in self.results if not r.success),
            "results": [asdict(r) for r in self.results]
        }

        # Save JSON report
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)

        console.print(f"[green]✓ JSON report saved:[/green] {report_file}")

        # Generate HTML report
        self._generate_html_report(report_data, html_report)

        console.print(f"[green]✓ HTML report saved:[/green] {html_report}")

        # Display summary table
        self._display_summary_table()

    def _generate_html_report(self, report_data: Dict, output_file: Path):
        """Generate HTML test report"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Guardian CLI Automated Test Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .summary {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 20px 0; }}
        .summary-card {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }}
        .summary-card.success {{ background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); }}
        .summary-card.failure {{ background: linear-gradient(135deg, #eb3349 0%, #f45c43 100%); }}
        .summary-value {{ font-size: 36px; font-weight: bold; margin: 10px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #3498db; color: white; font-weight: bold; }}
        tr:hover {{ background: #f5f5f5; }}
        .success {{ color: #27ae60; font-weight: bold; }}
        .failure {{ color: #e74c3c; font-weight: bold; }}
        .severity-critical {{ background: #e74c3c; color: white; padding: 2px 8px; border-radius: 3px; }}
        .severity-high {{ background: #e67e22; color: white; padding: 2px 8px; border-radius: 3px; }}
        .severity-medium {{ background: #f39c12; color: white; padding: 2px 8px; border-radius: 3px; }}
        .severity-low {{ background: #3498db; color: white; padding: 2px 8px; border-radius: 3px; }}
        .timestamp {{ color: #7f8c8d; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Guardian CLI Automated Test Report</h1>
        <p class="timestamp">Generated: {report_data['timestamp']}</p>
        <p class="timestamp">Test Run ID: {report_data['test_run_id']}</p>

        <div class="summary">
            <div class="summary-card">
                <div>Total Tests</div>
                <div class="summary-value">{report_data['total_tests']}</div>
            </div>
            <div class="summary-card success">
                <div>Successful</div>
                <div class="summary-value">{report_data['successful_tests']}</div>
            </div>
            <div class="summary-card failure">
                <div>Failed</div>
                <div class="summary-value">{report_data['failed_tests']}</div>
            </div>
        </div>

        <h2>Test Results</h2>
        <table>
            <thead>
                <tr>
                    <th>Target</th>
                    <th>Workflow</th>
                    <th>Duration (s)</th>
                    <th>Status</th>
                    <th>Tools</th>
                    <th>Findings</th>
                    <th>Report</th>
                </tr>
            </thead>
            <tbody>
"""

        for result in report_data['results']:
            status_class = "success" if result['success'] else "failure"
            status_text = "✓ Success" if result['success'] else "✗ Failed"

            findings_html = ""
            if result.get('findings_count'):
                for severity, count in result['findings_count'].items():
                    if count > 0:
                        findings_html += f'<span class="severity-{severity}">{severity}: {count}</span> '

            report_link = ""
            if result.get('report_path'):
                report_link = f'<a href="{result["report_path"]}" target="_blank">View Report</a>'

            html_content += f"""
                <tr>
                    <td>{result['target']}</td>
                    <td>{result['workflow']}</td>
                    <td>{result.get('duration_seconds', 0):.1f}</td>
                    <td class="{status_class}">{status_text}</td>
                    <td>{result.get('tools_successful', 0)}/{result.get('tools_executed', 0)}</td>
                    <td>{findings_html}</td>
                    <td>{report_link}</td>
                </tr>
"""

        html_content += """
            </tbody>
        </table>
    </div>
</body>
</html>
"""

        with open(output_file, 'w') as f:
            f.write(html_content)

    def _display_summary_table(self):
        """Display summary table in console"""
        table = Table(title="Test Execution Summary")

        table.add_column("Target", style="cyan")
        table.add_column("Workflow", style="magenta")
        table.add_column("Duration", justify="right")
        table.add_column("Status", justify="center")
        table.add_column("Critical", justify="right", style="red")
        table.add_column("High", justify="right", style="yellow")
        table.add_column("Medium", justify="right", style="blue")

        for result in self.results:
            status = "✓" if result.success else "✗"
            status_style = "green" if result.success else "red"

            table.add_row(
                result.target,
                result.workflow,
                f"{result.duration_seconds:.1f}s",
                f"[{status_style}]{status}[/{status_style}]",
                str(result.findings_count.get("critical", 0)),
                str(result.findings_count.get("high", 0)),
                str(result.findings_count.get("medium", 0))
            )

        console.print("\n")
        console.print(table)

    def run_full_test_suite(self, targets: Optional[List[str]] = None, workflows: Optional[List[str]] = None):
        """Run full test suite across all targets and workflows"""
        console.print(Panel.fit(
            "[bold cyan]Guardian CLI Automated Testing Suite[/bold cyan]\n"
            f"Test Run ID: {self.test_run_id}",
            border_style="cyan"
        ))

        # Filter targets
        test_targets = []
        if targets:
            test_targets = [self.TARGETS[t] for t in targets if t in self.TARGETS]
        else:
            test_targets = list(self.TARGETS.values())

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:

            for target in test_targets:
                # Deploy target
                task = progress.add_task(f"[cyan]Deploying {target.name}...", total=None)
                if not self.deploy_target(target):
                    console.print(f"[red]Failed to deploy {target.name}, skipping...[/red]")
                    progress.remove_task(task)
                    continue
                progress.remove_task(task)

                # Determine workflows to run
                target_workflows = workflows or target.workflows or ["recon", "web"]

                # Run workflows
                for workflow in target_workflows:
                    task = progress.add_task(f"[magenta]Running {workflow} on {target.name}...", total=None)
                    result = self.run_workflow(workflow, target)
                    progress.remove_task(task)

                    # Evaluate results
                    self.evaluate_results(result, target)

                # Teardown target
                task = progress.add_task(f"[cyan]Tearing down {target.name}...", total=None)
                self.teardown_target(target)
                progress.remove_task(task)

        # Generate final report
        self.generate_test_report()

        # Print final summary
        success_rate = (self.results.count(lambda r: r.success) / len(self.results) * 100) if self.results else 0
        console.print(f"\n[bold cyan]Test Suite Complete![/bold cyan]")
        console.print(f"Success Rate: {success_rate:.1f}%")


def main():
    parser = argparse.ArgumentParser(
        description="Guardian CLI Automated Homelab Testing Orchestrator"
    )

    parser.add_argument("--all", action="store_true", help="Run all tests")
    parser.add_argument("--target", type=str, help="Specific target to test")
    parser.add_argument("--workflow", type=str, help="Specific workflow to run")
    parser.add_argument("--deploy-only", action="store_true", help="Only deploy targets")
    parser.add_argument("--teardown-only", action="store_true", help="Only teardown targets")
    parser.add_argument("--evaluate-only", action="store_true", help="Only evaluate existing results")
    parser.add_argument("--session", type=str, help="Session ID for evaluation")
    parser.add_argument("--config", type=str, default="config/guardian.yaml", help="Config file path")
    parser.add_argument("--target-url", type=str, help="Override target URL (for remote deployments)")

    args = parser.parse_args()

    orchestrator = HomelabOrchestrator(config_path=args.config)

    if args.deploy_only:
        targets = [args.target] if args.target else list(orchestrator.TARGETS.keys())
        for target_name in targets:
            target = orchestrator.TARGETS.get(target_name)
            if target:
                orchestrator.deploy_target(target)

    elif args.teardown_only:
        targets = [args.target] if args.target else list(orchestrator.TARGETS.keys())
        for target_name in targets:
            target = orchestrator.TARGETS.get(target_name)
            if target:
                orchestrator.teardown_target(target)

    elif args.evaluate_only:
        console.print("[yellow]Evaluation-only mode not yet implemented[/yellow]")

    elif args.all:
        orchestrator.run_full_test_suite()

    elif args.target and args.workflow:
        target = orchestrator.TARGETS.get(args.target)
        if not target:
            console.print(f"[red]Unknown target: {args.target}[/red]")
            sys.exit(1)

        if args.target_url:
            target = TestTarget(
                name=target.name,
                description=target.description,
                type=target.type,
                deployment="url",
                url=args.target_url,
                docker_compose=target.docker_compose,
                expected_findings=target.expected_findings,
                workflows=target.workflows,
            )

        orchestrator.deploy_target(target)
        result = orchestrator.run_workflow(args.workflow, target)
        orchestrator.evaluate_results(result, target)
        orchestrator.teardown_target(target)
        orchestrator.generate_test_report()

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
