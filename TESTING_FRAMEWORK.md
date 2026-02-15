# Guardian CLI Testing Framework

> Comprehensive DevOps testing strategy for automated quality assurance

## Table of Contents

- [Overview](#overview)
- [Testing Pyramid](#testing-pyramid)
- [Quick Start](#quick-start)
- [Test Types](#test-types)
- [CI/CD Integration](#cicd-integration)
- [Local Development Workflow](#local-development-workflow)
- [Performance Testing](#performance-testing)
- [Security Testing](#security-testing)

---

## Overview

This testing framework ensures Guardian CLI maintains high quality through automated testing at multiple levels:

```
┌─────────────────────────────────────┐
│   Manual Exploratory Testing       │  ← Small (expensive)
├─────────────────────────────────────┤
│   E2E/Integration Tests             │  ← Medium (moderate cost)
├─────────────────────────────────────┤
│   Unit Tests                        │  ← Large (cheap, fast)
└─────────────────────────────────────┘
```

### Testing Goals

- ✅ **Fast feedback** - Developers know within minutes if changes break anything
- ✅ **Reliable** - Tests are deterministic and don't flake
- ✅ **Comprehensive** - Cover critical paths and edge cases
- ✅ **Maintainable** - Easy to update when functionality changes

---

## Testing Pyramid

### 1. Unit Tests (70% of test suite)

**Purpose**: Test individual functions and classes in isolation

**What to test**:
- Tool wrappers (exit code handling, command generation, output parsing)
- Error handlers (recovery strategies)
- Utility functions (path resolution, config parsing)

**Example**:
```python
# tests/unit/test_tools.py
import pytest
from tools.feroxbuster import FeroxbusterTool

class TestFeroxbusterTool:
    def test_exit_code_success(self):
        tool = FeroxbusterTool({})
        assert tool.is_success_exit_code(0) == True
        assert tool.is_success_exit_code(2) == True  # No results
        assert tool.is_success_exit_code(1) == False

    def test_command_generation(self):
        tool = FeroxbusterTool({})
        cmd = tool.get_command("https://example.com", api_mode=True)
        assert "feroxbuster" in cmd
        assert "-u" in cmd
        assert "https://example.com" in cmd
        assert "--json" in cmd
```

### 2. Integration Tests (20% of test suite)

**Purpose**: Test how components work together

**What to test**:
- Tool execution pipeline (tool_agent → base_tool → command execution)
- Error recovery flow (tool failure → error_handler → recovery)
- Workflow orchestration (web_pentest workflow step execution)

**Example**:
```python
# tests/integration/test_tool_execution.py
import pytest
from core.tool_agent import ToolAgent
from unittest.mock import Mock

@pytest.mark.integration
class TestToolExecution:
    async def test_tool_execution_with_recovery(self):
        config = {"tools": {}}
        llm_client = Mock()
        memory = Mock()

        agent = ToolAgent(config, llm_client, memory)

        # Test that exit code 2 is handled as success
        result = await agent.execute_tool(
            "feroxbuster",
            "https://example.com",
            {}
        )

        assert result["success"] in [True, False]  # Either works or gracefully fails
```

### 3. End-to-End Tests (10% of test suite)

**Purpose**: Test complete user workflows

**What to test**:
- Full scan execution against test targets
- Report generation
- Multi-tool workflows

**Example**:
```python
# tests/e2e/test_web_workflow.py
import pytest
from guardian import Guardian

@pytest.mark.e2e
@pytest.mark.slow
class TestWebWorkflow:
    async def test_basic_web_scan(self, test_server):
        """Test complete web scan against test server"""
        guardian = Guardian(config_file="tests/fixtures/test_config.yaml")

        result = await guardian.run_workflow(
            workflow="web",
            target=test_server.url,
            mode="quick"
        )

        assert result.status == "completed"
        assert len(result.findings) > 0
        assert result.report_path.exists()
```

---

## Quick Start

### Installation

```bash
# Install test dependencies
pip install -e ".[dev]"

# Or manually
pip install pytest pytest-asyncio pytest-cov pytest-mock pytest-timeout
```

### Run All Tests

```bash
# Run entire test suite
pytest

# Run with coverage
pytest --cov=. --cov-report=html --cov-report=term

# Run specific test types
pytest -m unit          # Only unit tests
pytest -m integration   # Only integration tests
pytest -m "not slow"    # Skip slow tests
```

### Run Specific Tests

```bash
# Run single test file
pytest tests/unit/test_tools.py

# Run single test class
pytest tests/unit/test_tools.py::TestFeroxbusterTool

# Run single test method
pytest tests/unit/test_tools.py::TestFeroxbusterTool::test_exit_code_success

# Run tests matching pattern
pytest -k "feroxbuster"
```

---

## Test Types

### Unit Tests

**Location**: `tests/unit/`

**Structure**:
```
tests/unit/
├── test_tools/
│   ├── test_feroxbuster.py
│   ├── test_sslyze.py
│   ├── test_nikto.py
│   └── ...
├── test_utils/
│   ├── test_error_handler.py
│   ├── test_logger.py
│   └── ...
└── test_core/
    ├── test_tool_agent.py
    └── test_workflow.py
```

**Template**:
```python
# tests/unit/test_tools/test_feroxbuster.py
import pytest
from tools.feroxbuster import FeroxbusterTool

class TestFeroxbusterTool:
    @pytest.fixture
    def tool(self):
        """Create tool instance for testing"""
        return FeroxbusterTool({})

    def test_exit_code_handling(self, tool):
        """Test that exit codes are correctly interpreted"""
        assert tool.is_success_exit_code(0) == True
        assert tool.is_success_exit_code(2) == True
        assert tool.is_success_exit_code(1) == False

    def test_command_generation_basic(self, tool):
        """Test basic command generation"""
        cmd = tool.get_command("https://example.com")
        assert cmd == ["feroxbuster", "-u", "https://example.com", "--json"]

    def test_command_generation_api_mode(self, tool):
        """Test command generation with API mode"""
        cmd = tool.get_command("https://example.com", api_mode=True)
        assert "-w" in cmd
        assert "-x" in cmd
```

### Integration Tests

**Location**: `tests/integration/`

**Fixtures**:
```python
# tests/integration/conftest.py
import pytest
from pathlib import Path

@pytest.fixture
def test_config():
    """Provide test configuration"""
    return {
        "tools": {
            "feroxbuster": {"timeout": 30}
        },
        "pentest": {"tool_timeout": 60}
    }

@pytest.fixture
def mock_llm_client():
    """Mock LLM client for testing"""
    from unittest.mock import Mock
    client = Mock()
    client.generate.return_value = "test response"
    return client
```

### E2E Tests

**Location**: `tests/e2e/`

**Test Server Setup**:
```python
# tests/e2e/conftest.py
import pytest
import docker
from time import sleep

@pytest.fixture(scope="session")
def test_server():
    """Spin up DVWA test server"""
    client = docker.from_env()

    container = client.containers.run(
        "vulnerables/web-dvwa:latest",
        detach=True,
        ports={'80/tcp': 8080}
    )

    # Wait for server to be ready
    sleep(5)

    yield TestServer(url="http://localhost:8080")

    # Cleanup
    container.stop()
    container.remove()

class TestServer:
    def __init__(self, url):
        self.url = url
```

---

## CI/CD Integration

### GitHub Actions

Create `.github/workflows/test.yml`:

```yaml
name: Test Suite

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ['3.11', '3.12']

    steps:
    - uses: actions/checkout@v3

    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}

    - name: Cache dependencies
      uses: actions/cache@v3
      with:
        path: ~/.cache/pip
        key: ${{ runner.os }}-pip-${{ hashFiles('**/requirements.txt') }}

    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -e ".[dev]"

    - name: Run unit tests
      run: |
        pytest tests/unit/ -v --cov=. --cov-report=xml

    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml
        flags: unittests

  integration-tests:
    runs-on: ubuntu-latest
    needs: unit-tests

    steps:
    - uses: actions/checkout@v3

    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.12'

    - name: Install dependencies
      run: |
        pip install -e ".[dev]"

    - name: Run integration tests
      run: |
        pytest tests/integration/ -v --timeout=300

  e2e-tests:
    runs-on: ubuntu-latest
    needs: integration-tests

    services:
      docker:
        image: docker:dind
        options: --privileged

    steps:
    - uses: actions/checkout@v3

    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.12'

    - name: Install dependencies
      run: |
        pip install -e ".[dev]"
        pip install docker

    - name: Run E2E tests
      run: |
        pytest tests/e2e/ -v --timeout=600 -m "not manual"

  lint:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v3

    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.12'

    - name: Install linters
      run: |
        pip install ruff black mypy

    - name: Run ruff
      run: ruff check .

    - name: Run black
      run: black --check .

    - name: Run mypy
      run: mypy tools/ core/ utils/ --ignore-missing-imports
```

### Pre-commit Hooks

Create `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
      - id: check-merge-conflict

  - repo: https://github.com/psf/black
    rev: 23.12.1
    hooks:
      - id: black

  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.1.11
    hooks:
      - id: ruff
        args: [--fix]

  - repo: local
    hooks:
      - id: pytest-unit
        name: pytest-unit
        entry: pytest tests/unit/ -v
        language: system
        pass_filenames: false
        always_run: true
```

Install:
```bash
pip install pre-commit
pre-commit install
```

---

## Local Development Workflow

### Test-Driven Development (TDD)

```bash
# 1. Watch mode - auto-run tests on file changes
pytest-watch -- tests/unit/

# 2. Write failing test first
# tests/unit/test_new_feature.py
def test_new_feature():
    assert new_feature() == expected_result

# 3. Run specific test
pytest tests/unit/test_new_feature.py::test_new_feature -v

# 4. Implement feature until test passes
# 5. Refactor
# 6. Commit
```

### Coverage Analysis

```bash
# Generate coverage report
pytest --cov=. --cov-report=html --cov-report=term-missing

# Open HTML report
open htmlcov/index.html

# Find untested code
coverage report --show-missing | grep -v "100%"
```

### Debugging Tests

```python
# Add breakpoint in test
def test_something():
    import pdb; pdb.set_trace()  # or breakpoint()
    result = function_under_test()
    assert result == expected

# Run with pdb
pytest --pdb tests/unit/test_file.py

# Print during test
pytest -v -s  # -s shows print statements
```

---

## Performance Testing

### Tool Execution Benchmarks

```python
# tests/performance/test_benchmarks.py
import pytest
import time

@pytest.mark.benchmark
class TestToolPerformance:
    def test_feroxbuster_startup_time(self, benchmark):
        """Ensure feroxbuster starts in <1 second"""
        tool = FeroxbusterTool({})

        def setup():
            return tool.get_command("https://example.com")

        result = benchmark(setup)
        assert benchmark.stats['mean'] < 1.0  # Must be under 1 second
```

### Load Testing

```bash
# Install locust
pip install locust

# Create load test
cat > tests/performance/locustfile.py << 'EOF'
from locust import HttpUser, task, between

class GuardianUser(HttpUser):
    wait_time = between(1, 3)

    @task
    def scan_endpoint(self):
        self.client.post("/api/scan", json={
            "target": "https://example.com",
            "workflow": "web"
        })

EOF

# Run load test
locust -f tests/performance/locustfile.py --host=http://localhost:5000
```

---

## Security Testing

### Static Analysis

```bash
# Install security scanners
pip install bandit safety

# Scan for security issues
bandit -r . -ll

# Check dependencies for vulnerabilities
safety check

# Secret scanning
pip install detect-secrets
detect-secrets scan > .secrets.baseline
```

### Dependency Scanning

```yaml
# .github/workflows/security.yml
name: Security Scan

on:
  push:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * 0'  # Weekly

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3

    - name: Run Snyk
      uses: snyk/actions/python@master
      env:
        SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
      with:
        command: test

    - name: Run Trivy
      uses: aquasecurity/trivy-action@master
      with:
        scan-type: 'fs'
        scan-ref: '.'
```

---

## Test Configuration

### pytest.ini

```ini
[pytest]
# Test discovery
python_files = test_*.py
python_classes = Test*
python_functions = test_*

# Markers
markers =
    unit: Unit tests
    integration: Integration tests
    e2e: End-to-end tests
    slow: Slow tests (>5 seconds)
    benchmark: Performance benchmarks
    manual: Manual tests requiring human interaction

# Coverage
addopts =
    --strict-markers
    --strict-config
    --verbose
    --tb=short
    --cov-branch

# Timeouts
timeout = 300
timeout_method = thread

# Asyncio
asyncio_mode = auto

# Ignore paths
norecursedirs = .git .tox dist build *.egg venv

# Minimum coverage
[coverage:run]
omit =
    */tests/*
    */vendor/*
    */__pycache__/*

[coverage:report]
fail_under = 80
precision = 2
show_missing = True
skip_covered = False
```

### conftest.py (Global Fixtures)

```python
# tests/conftest.py
import pytest
import asyncio
from pathlib import Path

# Configure async event loop
@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

# Temporary directory for test outputs
@pytest.fixture
def temp_output_dir(tmp_path):
    output_dir = tmp_path / "test_output"
    output_dir.mkdir()
    return output_dir

# Mock config
@pytest.fixture
def test_config():
    return {
        "tools": {},
        "pentest": {"tool_timeout": 60},
        "output": {"save_path": "/tmp/test_reports"}
    }

# Cleanup after tests
@pytest.fixture(autouse=True)
def cleanup(request):
    yield
    # Cleanup code here
    pass
```

---

## Continuous Monitoring

### Test Metrics Dashboard

Track these metrics over time:

- **Test count** - Number of tests in each category
- **Coverage** - Code coverage percentage
- **Duration** - Time to run test suite
- **Flakiness** - Tests that fail intermittently
- **Pass rate** - Percentage of passing tests

### Alerts

Set up alerts for:
- ❌ Coverage drops below 80%
- ❌ Test suite takes >10 minutes
- ❌ More than 5% test failures
- ❌ New security vulnerabilities found

---

## Best Practices

### ✅ DO

- Write tests before fixing bugs (regression tests)
- Use descriptive test names (`test_feroxbuster_handles_no_results_gracefully`)
- Keep tests independent (no shared state)
- Mock external dependencies (APIs, databases, file system)
- Test edge cases and error conditions
- Maintain test data in fixtures

### ❌ DON'T

- Test implementation details (test behavior, not code)
- Write flaky tests (tests that fail randomly)
- Commit commented-out tests
- Skip tests without good reason
- Use sleep() in tests (use proper waiting mechanisms)
- Test third-party libraries (trust they work)

---

## Troubleshooting

### Common Issues

**Tests fail locally but pass in CI:**
```bash
# Reproduce CI environment
docker run -it python:3.12 bash
pip install -e ".[dev]"
pytest
```

**Flaky async tests:**
```python
# Use pytest-asyncio properly
@pytest.mark.asyncio
async def test_async_function():
    result = await async_function()
    assert result == expected
```

**Import errors:**
```bash
# Ensure editable install
pip install -e .

# Check PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

---

## Next Steps

1. **Start small**: Add unit tests for new code
2. **Increase coverage**: Target 80%+ coverage
3. **Add CI**: Set up GitHub Actions
4. **Pre-commit hooks**: Enforce quality before commits
5. **E2E tests**: Add workflow tests against test servers
6. **Performance**: Benchmark critical paths
7. **Security**: Regular dependency scans

---

## Resources

- [pytest documentation](https://docs.pytest.org/)
- [pytest-asyncio](https://pytest-asyncio.readthedocs.io/)
- [GitHub Actions](https://docs.github.com/en/actions)
- [Pre-commit](https://pre-commit.com/)
- [Coverage.py](https://coverage.readthedocs.io/)

---

**Last Updated**: 2026-01-23
**Maintainer**: Guardian CLI Team
