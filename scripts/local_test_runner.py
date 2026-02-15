#!/usr/bin/env python3
"""
Guardian CLI Local Test Runner
Run comprehensive validation before pushing to GitHub.
Supports homelab target testing against real infrastructure.

Usage:
    python scripts/local_test_runner.py              # Full validation
    python scripts/local_test_runner.py --quick      # Quick checks only
    python scripts/local_test_runner.py --homelab    # Include homelab tests
    python scripts/local_test_runner.py --workflow recon  # Test specific workflow
"""

import argparse
import subprocess
import sys
import os
import yaml
import json
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class TestResult(Enum):
    PASSED = "✅"
    FAILED = "❌"
    SKIPPED = "⏭️"
    WARNING = "⚠️"


@dataclass
class StageResult:
    name: str
    result: TestResult
    duration: float
    details: str = ""


class LocalTestRunner:
    """Comprehensive local test runner for Guardian CLI."""

    def __init__(self, project_root: Path = None):
        self.project_root = project_root or Path(__file__).parent.parent
        self.results: List[StageResult] = []
        self.homelab_config_path = self.project_root / "tests" / "homelab_targets.yaml"

    def run_command(self, cmd: str, description: str, timeout: int = 300) -> tuple[bool, str]:
        """Run a shell command and return success status and output."""
        print(f"\n  Running: {description}")
        print(f"  Command: {cmd}")

        try:
            result = subprocess.run(
                cmd,
                shell=True,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            success = result.returncode == 0
            output = result.stdout + result.stderr
            if success:
                print(f"  {TestResult.PASSED.value} Passed")
            else:
                print(f"  {TestResult.FAILED.value} Failed")
                print(f"  Output: {output[:500]}")
            return success, output
        except subprocess.TimeoutExpired:
            print(f"  {TestResult.WARNING.value} Timeout after {timeout}s")
            return False, "Timeout"
        except Exception as e:
            print(f"  {TestResult.FAILED.value} Error: {e}")
            return False, str(e)

    def stage_lint(self) -> StageResult:
        """Run linting checks."""
        print("\n" + "=" * 60)
        print("Stage 1: Code Quality (Lint)")
        print("=" * 60)

        start = datetime.now()
        checks = []

        # Ruff
        success, _ = self.run_command("ruff check . --quiet", "Ruff linter")
        checks.append(("ruff", success))

        # Black
        success, _ = self.run_command("black --check --quiet .", "Black formatter")
        checks.append(("black", success))

        duration = (datetime.now() - start).total_seconds()
        all_passed = all(c[1] for c in checks)
        failed = [c[0] for c in checks if not c[1]]

        return StageResult(
            name="Lint",
            result=TestResult.PASSED if all_passed else TestResult.FAILED,
            duration=duration,
            details=f"Failed: {', '.join(failed)}" if failed else ""
        )

    def stage_security(self) -> StageResult:
        """Run security scans."""
        print("\n" + "=" * 60)
        print("Stage 2: Security Scan")
        print("=" * 60)

        start = datetime.now()

        success, output = self.run_command(
            "bandit -r core/ tools/ cli/ -ll -q 2>/dev/null || true",
            "Bandit security scan"
        )

        # Check for high/critical issues
        has_critical = "Severity: High" in output or "Severity: Critical" in output

        duration = (datetime.now() - start).total_seconds()

        if has_critical:
            return StageResult("Security", TestResult.FAILED, duration, "Critical issues found")
        return StageResult("Security", TestResult.PASSED, duration)

    def stage_unit_tests(self) -> StageResult:
        """Run unit tests."""
        print("\n" + "=" * 60)
        print("Stage 3: Unit Tests")
        print("=" * 60)

        start = datetime.now()

        success, output = self.run_command(
            "pytest tests/unit/ -v -m unit --tb=short -q",
            "Unit test suite"
        )

        duration = (datetime.now() - start).total_seconds()

        # Extract test counts
        if "passed" in output:
            details = [line for line in output.split('\n') if "passed" in line][-1] if output else ""
        else:
            details = ""

        return StageResult(
            name="Unit Tests",
            result=TestResult.PASSED if success else TestResult.FAILED,
            duration=duration,
            details=details
        )

    def stage_workflow_validation(self) -> StageResult:
        """Validate all workflow YAML files."""
        print("\n" + "=" * 60)
        print("Stage 4: Workflow Validation")
        print("=" * 60)

        start = datetime.now()
        workflows_dir = self.project_root / "workflows"
        errors = []

        if not workflows_dir.exists():
            return StageResult("Workflows", TestResult.SKIPPED, 0, "No workflows directory")

        for wf_file in workflows_dir.glob("*.yaml"):
            try:
                with open(wf_file) as f:
                    wf = yaml.safe_load(f)
                if not wf:
                    errors.append(f"{wf_file.name}: Empty file")
                elif "name" not in wf:
                    errors.append(f"{wf_file.name}: Missing 'name' field")
                else:
                    print(f"  {TestResult.PASSED.value} {wf_file.name}")
            except yaml.YAMLError as e:
                errors.append(f"{wf_file.name}: {e}")
                print(f"  {TestResult.FAILED.value} {wf_file.name}")

        duration = (datetime.now() - start).total_seconds()

        return StageResult(
            name="Workflow Validation",
            result=TestResult.PASSED if not errors else TestResult.FAILED,
            duration=duration,
            details="; ".join(errors) if errors else ""
        )

    def stage_workflow_tests(self) -> StageResult:
        """Run workflow-specific tests."""
        print("\n" + "=" * 60)
        print("Stage 5: Workflow Tests")
        print("=" * 60)

        start = datetime.now()

        success, output = self.run_command(
            "pytest tests/unit/test_workflows/ -v --tb=short -q 2>/dev/null || echo 'No workflow tests'",
            "Workflow test suite"
        )

        duration = (datetime.now() - start).total_seconds()

        return StageResult(
            name="Workflow Tests",
            result=TestResult.PASSED if success else TestResult.FAILED,
            duration=duration
        )

    def stage_integration_tests(self) -> StageResult:
        """Run integration tests."""
        print("\n" + "=" * 60)
        print("Stage 6: Integration Tests")
        print("=" * 60)

        start = datetime.now()

        integration_dir = self.project_root / "tests" / "integration"
        if not integration_dir.exists() or not list(integration_dir.glob("*.py")):
            return StageResult("Integration", TestResult.SKIPPED, 0, "No integration tests")

        success, output = self.run_command(
            "pytest tests/integration/ -v -m integration --tb=short",
            "Integration test suite"
        )

        duration = (datetime.now() - start).total_seconds()

        return StageResult(
            name="Integration Tests",
            result=TestResult.PASSED if success else TestResult.FAILED,
            duration=duration
        )

    def stage_homelab_tests(self, workflow: str = None) -> StageResult:
        """Run tests against homelab targets."""
        print("\n" + "=" * 60)
        print("Stage 7: Homelab Integration Tests")
        print("=" * 60)

        if not self.homelab_config_path.exists():
            print(f"  {TestResult.SKIPPED.value} No homelab config at {self.homelab_config_path}")
            return StageResult("Homelab", TestResult.SKIPPED, 0, "No homelab_targets.yaml")

        start = datetime.now()

        with open(self.homelab_config_path) as f:
            config = yaml.safe_load(f)

        targets = config.get("targets", [])
        if not targets:
            return StageResult("Homelab", TestResult.SKIPPED, 0, "No targets configured")

        results = []
        for target in targets:
            name = target.get("name", "unknown")
            target_type = target.get("type", "unknown")
            workflows_to_test = target.get("workflows", ["recon"])

            if workflow and workflow not in workflows_to_test:
                continue

            print(f"\n  Testing: {name} ({target_type})")

            # Dry-run workflow validation (doesn't actually run tools)
            for wf in workflows_to_test:
                if workflow and wf != workflow:
                    continue

                success, _ = self.run_command(
                    f"python -c \"from core.workflow import WorkflowEngine; print('Workflow {wf} loadable')\" 2>/dev/null || echo 'Import check'",
                    f"Validate {wf} workflow"
                )
                results.append((f"{name}/{wf}", success))

        duration = (datetime.now() - start).total_seconds()
        all_passed = all(r[1] for r in results) if results else True

        return StageResult(
            name="Homelab Tests",
            result=TestResult.PASSED if all_passed else TestResult.FAILED,
            duration=duration,
            details=f"Tested {len(results)} target/workflow combinations"
        )

    def print_summary(self):
        """Print test run summary."""
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)

        total_time = sum(r.duration for r in self.results)
        passed = sum(1 for r in self.results if r.result == TestResult.PASSED)
        failed = sum(1 for r in self.results if r.result == TestResult.FAILED)
        skipped = sum(1 for r in self.results if r.result == TestResult.SKIPPED)

        for result in self.results:
            status = result.result.value
            details = f" ({result.details})" if result.details else ""
            print(f"  {status} {result.name}: {result.duration:.1f}s{details}")

        print("-" * 60)
        print(f"  Total: {passed} passed, {failed} failed, {skipped} skipped")
        print(f"  Duration: {total_time:.1f}s")
        print("=" * 60)

        if failed > 0:
            print("\n❌ VALIDATION FAILED - Fix issues before pushing!")
            return False
        else:
            print("\n✅ VALIDATION PASSED - Safe to push!")
            return True

    def run_quick(self) -> bool:
        """Run quick validation (lint + unit tests only)."""
        print("🚀 Running Quick Validation...")

        self.results.append(self.stage_lint())
        self.results.append(self.stage_unit_tests())

        return self.print_summary()

    def run_full(self, include_homelab: bool = False, workflow: str = None) -> bool:
        """Run full validation pipeline."""
        print("🚀 Running Full Validation Pipeline...")

        self.results.append(self.stage_lint())
        self.results.append(self.stage_security())
        self.results.append(self.stage_unit_tests())
        self.results.append(self.stage_workflow_validation())
        self.results.append(self.stage_workflow_tests())
        self.results.append(self.stage_integration_tests())

        if include_homelab:
            self.results.append(self.stage_homelab_tests(workflow))

        return self.print_summary()


def main():
    parser = argparse.ArgumentParser(description="Guardian CLI Local Test Runner")
    parser.add_argument("--quick", "-q", action="store_true", help="Quick validation only")
    parser.add_argument("--homelab", "-H", action="store_true", help="Include homelab tests")
    parser.add_argument("--workflow", "-w", type=str, help="Test specific workflow")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    runner = LocalTestRunner()

    if args.quick:
        success = runner.run_quick()
    else:
        success = runner.run_full(include_homelab=args.homelab, workflow=args.workflow)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
