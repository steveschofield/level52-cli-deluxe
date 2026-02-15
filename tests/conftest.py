"""
Global pytest configuration and fixtures
"""
import pytest
import asyncio
from pathlib import Path
from typing import Dict, Any
from unittest.mock import MagicMock, AsyncMock

# Import workflow fixtures
pytest_plugins = ["tests.fixtures.workflow_fixtures"]


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def test_config() -> Dict[str, Any]:
    """Provide test configuration"""
    return {
        "tools": {
            "feroxbuster": {"timeout": 30},
            "nikto": {"timeout": 30},
        },
        "pentest": {
            "tool_timeout": 60,
            "max_threads": 4
        },
        "output": {
            "save_path": "/tmp/test_reports",
            "format": "json"
        },
        "logging": {
            "level": "DEBUG",
            "log_tool_executions": True
        }
    }


@pytest.fixture
def temp_output_dir(tmp_path):
    """Create temporary directory for test outputs"""
    output_dir = tmp_path / "test_output"
    output_dir.mkdir()
    return output_dir


@pytest.fixture(autouse=True)
def cleanup_test_files(request):
    """Cleanup test files after each test"""
    yield
    # Add cleanup logic here if needed
    pass
