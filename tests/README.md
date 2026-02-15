# Guardian CLI Test Suite

Quick reference for testing Guardian CLI.

## Quick Start

```bash
# 1. Install test dependencies
make install-dev

# 2. Run unit tests
make test-unit

# 3. Check coverage
make coverage

# 4. Format code
make format

# 5. Run all checks before committing
make lint && make test-unit
```

## Test Structure

```
tests/
├── conftest.py              # Global fixtures
├── unit/                    # Unit tests (70% of suite)
│   ├── test_tools/          # Tool wrapper tests
│   │   ├── test_feroxbuster.py
│   │   ├── test_exit_codes.py
│   │   └── ...
│   └── test_utils/          # Utility tests
│       └── test_error_handler.py
├── integration/             # Integration tests (20%)
├── e2e/                     # End-to-end tests (10%)
└── fixtures/                # Test data
```

## Running Tests

### By Type
```bash
make test-unit          # Unit tests only
make test-integration   # Integration tests only
make test-e2e          # E2E tests only
make test-fast         # Skip slow tests
```

### By Pattern
```bash
pytest -k feroxbuster   # Tests matching "feroxbuster"
pytest tests/unit/test_tools/test_feroxbuster.py  # Single file
```

### With Coverage
```bash
make coverage          # Generate coverage report
make coverage-open     # Open in browser
```

### Watch Mode
```bash
make test-watch        # Auto-run on file changes
```

## Writing Tests

### Unit Test Template

```python
# tests/unit/test_tools/test_mytool.py
import pytest
from tools.mytool import MyTool

class TestMyTool:
    @pytest.fixture
    def tool(self, test_config):
        return MyTool(test_config)

    def test_exit_code_handling(self, tool):
        assert tool.is_success_exit_code(0) == True

    def test_command_generation(self, tool):
        cmd = tool.get_command("https://example.com")
        assert "mytool" in cmd
```

### Integration Test Template

```python
# tests/integration/test_workflow.py
import pytest

@pytest.mark.integration
class TestWorkflow:
    async def test_tool_execution(self):
        # Test tool execution pipeline
        pass
```

## CI/CD

Tests run automatically on:
- **Push to main/develop** - Full test suite
- **Pull requests** - Unit + integration tests
- **Nightly** - Full suite + E2E tests

## Debugging

```bash
# Run with verbose output
pytest -vv

# Show print statements
pytest -s

# Drop into debugger on failure
pytest --pdb

# Run specific test with debugging
pytest tests/unit/test_tools/test_feroxbuster.py::TestFeroxbusterTool::test_exit_code_success -vv -s
```

## Coverage Goals

- **Minimum**: 70% overall
- **Target**: 80%+ overall
- **New code**: 90%+ (enforced in PR reviews)

## Resources

- [Full Testing Guide](../TESTING_FRAMEWORK.md)
- [pytest documentation](https://docs.pytest.org/)
- [GitHub Actions workflows](../.github/workflows/)
