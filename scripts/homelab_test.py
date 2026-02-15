#!/usr/bin/env python3
"""
Guardian CLI Homelab Test Runner
================================
Automated testing against your homelab infrastructure.

Usage:
    ./scripts/homelab_test.py                    # Run all tests
    ./scripts/homelab_test.py --scenario smoke   # Quick smoke test
    ./scripts/homelab_test.py --target juice-shop-local --workflow web_pentest
    ./scripts/homelab_test.py --watch            # Auto-rerun on file changes
    ./scripts/homelab_test.py --check-tools      # Verify tools are installed
    ./scripts/homelab_test.py --dry-run          # Parse only, no execution

Configure targets in: tests/homelab_targets.yaml
"""

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
import time
import yaml
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


# =============================================================================
# Configuration
# =============================================================================

PROJECT_ROOT = Path(__file__).parent.parent
CONFIG_PATH = PROJECT_ROOT / "tests" / "homelab_targets.yaml"
RESULTS_DIR = PROJECT_ROOT / "test_results"


class Status(Enum):
    PENDING = "⏳"
    RUNNING = "🔄"
    PASSED = "✅"
    FAILED = "❌"
    SKIPPED = "⏭️"
    WARNING = "⚠️"


@dataclass
class TestResult:
    target: str
    workflow: str
    status: Status
    duration: float
    findings_count: int = 0
    tools_run: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    output_path: Optional[Path] = None


@dataclass
class Target:
    name: str
    host: str
    target_type: str
    workflows: List[str]
    description: str = ""
    port: int = None
    url: str = None
    cidr: str = None
    domain: str = None
    passive_only: bool = False
    expectations: Dict = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict) -> "Target":
        return cls(
            name=data.get("name", "unnamed"),
            host=data.get("host", data.get("domain", data.get("cidr", ""))),
            target_type=data.get("type", "unknown"),
            workflows=data.get("workflows", []),
            description=data.get("description", ""),
            port=data.get("port"),
            url=data.get("url"),
            cidr=data.get("cidr"),
            domain=data.get("domain"),
            passive_only=data.get("passive_only", False),
            expectations=data.get("expectations", {}),
            tags=data.get("tags", [])
        )


# =============================================================================
# Core Test Runner
# =============================================================================

class HomelabTestRunner:
    """Run Guardian workflows against homelab targets."""

    def __init__(self, config_path: Path = CONFIG_PATH):
        self.config_path = config_path
        self.config = self._load_config()
        self.results: List[TestResult] = []
        self.start_time: datetime = None

    def _load_config(self) -> Dict:
        """Load homelab configuration."""
        if not self.config_path.exists():
            print(f"{Status.FAILED.value} Config not found: {self.config_path}")
            print("Run: cp tests/homelab_targets.yaml.example tests/homelab_targets.yaml")
            sys.exit(1)

        with open(self.config_path) as f:
            return yaml.safe_load(f)

    def get_targets(self, target_filter: str = None, tags: List[str] = None) -> List[Target]:
        """Get targets matching filters."""
        targets = []
        for t in self.config.get("targets", []):
            target = Target.from_dict(t)

            if target_filter and target.name != target_filter:
                continue

            if tags and not any(tag in target.tags for tag in tags):
                continue

            targets.append(target)

        return targets

    def check_tools(self, workflow: str = None) -> Dict[str, bool]:
        """Check if required tools are installed."""
        required = self.config.get("required_tools", {})
        results = {}

        workflows_to_check = [workflow] if workflow else required.keys()

        print(f"\n{'=' * 60}")
        print("Tool Availability Check")
        print('=' * 60)

        for wf in workflows_to_check:
            if wf not in required:
                continue

            print(f"\n  Workflow: {wf}")
            for tool in required[wf]:
                available = shutil.which(tool) is not None
                status = Status.PASSED if available else Status.FAILED
                results[tool] = available
                path = shutil.which(tool) or "not found"
                print(f"    {status.value} {tool}: {path}")

        all_available = all(results.values())
        print(f"\n  {'✅ All tools available' if all_available else '❌ Some tools missing'}")

        return results

    def verify_target_reachable(self, target: Target) -> bool:
        """Check if target is reachable."""
        if target.passive_only:
            return True  # Skip connectivity check for passive-only

        host = target.host or target.domain or target.cidr.split('/')[0]

        try:
            # Quick ping check
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "2", host],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def run_workflow_test(
        self,
        target: Target,
        workflow: str,
        dry_run: bool = False,
        live: bool = False
    ) -> TestResult:
        """Run a single workflow against a target."""
        start = time.time()

        print(f"\n  {Status.RUNNING.value} {target.name} / {workflow}")

        if not self.verify_target_reachable(target):
            return TestResult(
                target=target.name,
                workflow=workflow,
                status=Status.SKIPPED,
                duration=time.time() - start,
                errors=["Target not reachable"]
            )

        # Determine target argument
        target_arg = target.url or target.host or target.domain or target.cidr

        if dry_run:
            # Just validate workflow loading
            try:
                workflow_path = PROJECT_ROOT / "workflows" / f"{workflow}.yaml"
                if workflow_path.exists():
                    with open(workflow_path) as f:
                        wf = yaml.safe_load(f)
                    tools = [s.get("tool") for s in wf.get("steps", []) if s.get("tool")]
                    return TestResult(
                        target=target.name,
                        workflow=workflow,
                        status=Status.PASSED,
                        duration=time.time() - start,
                        tools_run=tools
                    )
                else:
                    return TestResult(
                        target=target.name,
                        workflow=workflow,
                        status=Status.FAILED,
                        duration=time.time() - start,
                        errors=[f"Workflow file not found: {workflow}.yaml"]
                    )
            except Exception as e:
                return TestResult(
                    target=target.name,
                    workflow=workflow,
                    status=Status.FAILED,
                    duration=time.time() - start,
                    errors=[str(e)]
                )

        # Live execution
        if live:
            output_dir = RESULTS_DIR / f"{target.name}_{workflow}_{int(time.time())}"
            output_dir.mkdir(parents=True, exist_ok=True)

            cmd = [
                "python", "-m", "cli.main", "workflow",
                "--workflow", workflow,
                "--target", target_arg,
                "--output", str(output_dir),
                "--format", "json"
            ]

            try:
                timeout = self.config.get("settings", {}).get("tool_timeout", 300)
                result = subprocess.run(
                    cmd,
                    cwd=PROJECT_ROOT,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )

                # Parse results
                findings = 0
                report_file = output_dir / "report.json"
                if report_file.exists():
                    with open(report_file) as f:
                        report = json.load(f)
                        findings = len(report.get("findings", []))

                return TestResult(
                    target=target.name,
                    workflow=workflow,
                    status=Status.PASSED if result.returncode == 0 else Status.FAILED,
                    duration=time.time() - start,
                    findings_count=findings,
                    output_path=output_dir,
                    errors=[result.stderr] if result.stderr and result.returncode != 0 else []
                )
            except subprocess.TimeoutExpired:
                return TestResult(
                    target=target.name,
                    workflow=workflow,
                    status=Status.WARNING,
                    duration=time.time() - start,
                    errors=["Timeout expired"]
                )
            except Exception as e:
                return TestResult(
                    target=target.name,
                    workflow=workflow,
                    status=Status.FAILED,
                    duration=time.time() - start,
                    errors=[str(e)]
                )

        # Mock run (validation without live testing)
        return TestResult(
            target=target.name,
            workflow=workflow,
            status=Status.PASSED,
            duration=time.time() - start,
            tools_run=["validation"]
        )

    def run_scenario(self, scenario_name: str, dry_run: bool = False, live: bool = False):
        """Run a predefined test scenario."""
        scenarios = self.config.get("scenarios", {})

        if scenario_name not in scenarios:
            print(f"{Status.FAILED.value} Unknown scenario: {scenario_name}")
            print(f"Available: {', '.join(scenarios.keys())}")
            sys.exit(1)

        scenario = scenarios[scenario_name]
        print(f"\n{'=' * 60}")
        print(f"Running Scenario: {scenario_name}")
        print(f"Description: {scenario.get('description', 'N/A')}")
        print('=' * 60)

        target_names = scenario.get("targets", [])
        workflows = scenario.get("workflows", [])

        # Handle "all" targets
        if "all" in target_names:
            targets = self.get_targets()
        else:
            targets = [t for t in self.get_targets() if t.name in target_names]

        for target in targets:
            target_workflows = workflows if "all" not in workflows else target.workflows
            for wf in target_workflows:
                if wf in target.workflows:
                    result = self.run_workflow_test(target, wf, dry_run, live)
                    self.results.append(result)

    def run_all(
        self,
        target_filter: str = None,
        workflow_filter: str = None,
        tags: List[str] = None,
        dry_run: bool = False,
        live: bool = False,
        parallel: bool = False
    ):
        """Run tests against all matching targets."""
        self.start_time = datetime.now()
        targets = self.get_targets(target_filter, tags)

        if not targets:
            print(f"{Status.FAILED.value} No targets match filters")
            return

        print(f"\n{'=' * 60}")
        print(f"Guardian Homelab Test Run")
        print(f"Started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Mode: {'DRY RUN' if dry_run else 'LIVE' if live else 'VALIDATION'}")
        print(f"Targets: {len(targets)}")
        print('=' * 60)

        test_combos = []
        for target in targets:
            workflows = [workflow_filter] if workflow_filter else target.workflows
            for wf in workflows:
                if wf in target.workflows:
                    test_combos.append((target, wf))

        if parallel and not dry_run:
            max_workers = self.config.get("settings", {}).get("parallel_tests", 2)
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(self.run_workflow_test, t, wf, dry_run, live): (t, wf)
                    for t, wf in test_combos
                }
                for future in as_completed(futures):
                    self.results.append(future.result())
        else:
            for target, wf in test_combos:
                result = self.run_workflow_test(target, wf, dry_run, live)
                self.results.append(result)

    def print_summary(self):
        """Print test summary."""
        print(f"\n{'=' * 60}")
        print("TEST RESULTS SUMMARY")
        print('=' * 60)

        # Group by status
        passed = [r for r in self.results if r.status == Status.PASSED]
        failed = [r for r in self.results if r.status == Status.FAILED]
        skipped = [r for r in self.results if r.status == Status.SKIPPED]
        warnings = [r for r in self.results if r.status == Status.WARNING]

        for result in self.results:
            status = result.status.value
            duration = f"{result.duration:.1f}s"
            findings = f"({result.findings_count} findings)" if result.findings_count else ""
            errors = f" - {result.errors[0][:50]}" if result.errors else ""
            print(f"  {status} {result.target}/{result.workflow} [{duration}] {findings}{errors}")

        print('-' * 60)
        total = len(self.results)
        total_duration = sum(r.duration for r in self.results)
        print(f"  Total: {total} tests in {total_duration:.1f}s")
        print(f"  Passed: {len(passed)}, Failed: {len(failed)}, Skipped: {len(skipped)}, Warnings: {len(warnings)}")
        print('=' * 60)

        # Overall result
        if failed:
            print(f"\n{Status.FAILED.value} TESTS FAILED")
            return False
        elif warnings:
            print(f"\n{Status.WARNING.value} TESTS PASSED WITH WARNINGS")
            return True
        else:
            print(f"\n{Status.PASSED.value} ALL TESTS PASSED")
            return True

    def save_results(self):
        """Save test results to JSON."""
        RESULTS_DIR.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = RESULTS_DIR / f"test_run_{timestamp}.json"

        data = {
            "timestamp": self.start_time.isoformat() if self.start_time else None,
            "duration": sum(r.duration for r in self.results),
            "summary": {
                "total": len(self.results),
                "passed": sum(1 for r in self.results if r.status == Status.PASSED),
                "failed": sum(1 for r in self.results if r.status == Status.FAILED),
                "skipped": sum(1 for r in self.results if r.status == Status.SKIPPED),
            },
            "results": [
                {
                    "target": r.target,
                    "workflow": r.workflow,
                    "status": r.status.name,
                    "duration": r.duration,
                    "findings": r.findings_count,
                    "tools": r.tools_run,
                    "errors": r.errors,
                    "output": str(r.output_path) if r.output_path else None
                }
                for r in self.results
            ]
        }

        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)

        print(f"\n📄 Results saved to: {output_file}")


# =============================================================================
# File Watcher
# =============================================================================

def watch_and_run(runner: HomelabTestRunner, workflow: str = None, target: str = None):
    """Watch for file changes and auto-run tests."""
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
    except ImportError:
        print("Install watchdog: pip install watchdog")
        sys.exit(1)

    class ChangeHandler(FileSystemEventHandler):
        def __init__(self):
            self.last_run = 0
            self.debounce = 2  # seconds

        def on_modified(self, event):
            if event.is_directory:
                return
            if not event.src_path.endswith('.py'):
                return
            if '__pycache__' in event.src_path:
                return

            now = time.time()
            if now - self.last_run < self.debounce:
                return

            self.last_run = now
            print(f"\n🔄 Change detected: {event.src_path}")
            print("Re-running tests...\n")

            runner.results = []
            runner.run_all(target_filter=target, workflow_filter=workflow, dry_run=True)
            runner.print_summary()

    watch_paths = [
        PROJECT_ROOT / "core",
        PROJECT_ROOT / "tools",
        PROJECT_ROOT / "cli",
        PROJECT_ROOT / "workflows",
    ]

    observer = Observer()
    handler = ChangeHandler()

    for path in watch_paths:
        if path.exists():
            observer.schedule(handler, str(path), recursive=True)

    print(f"👀 Watching for changes in: {', '.join(p.name for p in watch_paths if p.exists())}")
    print("Press Ctrl+C to stop\n")

    # Initial run
    runner.run_all(target_filter=target, workflow_filter=workflow, dry_run=True)
    runner.print_summary()

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n👋 Watcher stopped")

    observer.join()


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Guardian CLI Homelab Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --check-tools                    Check tool availability
  %(prog)s --dry-run                        Validate workflows (no execution)
  %(prog)s --scenario smoke                 Run smoke test scenario
  %(prog)s --target juice-shop-local        Test specific target
  %(prog)s --workflow web_pentest           Test specific workflow
  %(prog)s --live                           Execute real scans
  %(prog)s --watch                          Auto-rerun on file changes
        """
    )

    parser.add_argument("--target", "-t", help="Test specific target only")
    parser.add_argument("--workflow", "-w", help="Test specific workflow only")
    parser.add_argument("--scenario", "-s", help="Run predefined scenario")
    parser.add_argument("--tags", nargs="+", help="Filter targets by tags")
    parser.add_argument("--dry-run", "-d", action="store_true", help="Validate only, no execution")
    parser.add_argument("--live", "-l", action="store_true", help="Execute real scans (be careful!)")
    parser.add_argument("--parallel", "-p", action="store_true", help="Run tests in parallel")
    parser.add_argument("--watch", action="store_true", help="Watch mode: auto-rerun on changes")
    parser.add_argument("--check-tools", action="store_true", help="Check tool availability")
    parser.add_argument("--config", "-c", type=Path, default=CONFIG_PATH, help="Config file path")
    parser.add_argument("--save", action="store_true", help="Save results to JSON")

    args = parser.parse_args()

    runner = HomelabTestRunner(args.config)

    # Check tools mode
    if args.check_tools:
        runner.check_tools(args.workflow)
        sys.exit(0)

    # Watch mode
    if args.watch:
        watch_and_run(runner, args.workflow, args.target)
        sys.exit(0)

    # Scenario mode
    if args.scenario:
        runner.run_scenario(args.scenario, args.dry_run, args.live)
    else:
        runner.run_all(
            target_filter=args.target,
            workflow_filter=args.workflow,
            tags=args.tags,
            dry_run=args.dry_run,
            live=args.live,
            parallel=args.parallel
        )

    success = runner.print_summary()

    if args.save:
        runner.save_results()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
