"""
Test environment variable expansion in configuration
"""

import os
import tempfile
import yaml
from pathlib import Path
from utils.helpers import load_config


def test_env_var_expansion_basic():
    """Test basic environment variable expansion"""
    # Set test environment variables
    os.environ["TEST_API_KEY"] = "test_value_123"
    os.environ["TEST_TIMEOUT"] = "30"

    # Create temporary config
    config_content = """
    api:
      key: "${TEST_API_KEY}"
      timeout: "${TEST_TIMEOUT}"
    """

    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(config_content)
        config_path = f.name

    try:
        # Load config
        config = load_config(config_path)

        # Verify expansion
        assert config["api"]["key"] == "test_value_123"
        assert config["api"]["timeout"] == "30"
    finally:
        # Cleanup
        Path(config_path).unlink()
        del os.environ["TEST_API_KEY"]
        del os.environ["TEST_TIMEOUT"]


def test_env_var_expansion_with_defaults():
    """Test environment variable expansion with default values"""
    # Ensure variable doesn't exist
    if "NONEXISTENT_VAR" in os.environ:
        del os.environ["NONEXISTENT_VAR"]

    # Create temporary config
    config_content = """
    api:
      key: "${NONEXISTENT_VAR:-default_key}"
      timeout: "${MISSING_TIMEOUT:-60}"
    """

    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(config_content)
        config_path = f.name

    try:
        # Load config
        config = load_config(config_path)

        # Verify defaults are used
        assert config["api"]["key"] == "default_key"
        assert config["api"]["timeout"] == "60"
    finally:
        # Cleanup
        Path(config_path).unlink()


def test_env_var_expansion_empty_default():
    """Test environment variable expansion with empty default"""
    # Ensure variable doesn't exist
    if "EMPTY_VAR" in os.environ:
        del os.environ["EMPTY_VAR"]

    # Create temporary config
    config_content = """
    api:
      key: "${EMPTY_VAR:-}"
    """

    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(config_content)
        config_path = f.name

    try:
        # Load config
        config = load_config(config_path)

        # Verify empty string is used
        assert config["api"]["key"] == ""
    finally:
        # Cleanup
        Path(config_path).unlink()


def test_env_var_expansion_nested():
    """Test environment variable expansion in nested structures"""
    os.environ["NESTED_KEY"] = "nested_value"
    os.environ["LIST_ITEM"] = "item_from_env"

    # Create temporary config
    config_content = """
    osint:
      sources:
        github:
          token: "${NESTED_KEY}"
    tools:
      - name: "${LIST_ITEM}"
      - name: "static_value"
    """

    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(config_content)
        config_path = f.name

    try:
        # Load config
        config = load_config(config_path)

        # Verify nested expansion
        assert config["osint"]["sources"]["github"]["token"] == "nested_value"
        assert config["tools"][0]["name"] == "item_from_env"
        assert config["tools"][1]["name"] == "static_value"
    finally:
        # Cleanup
        Path(config_path).unlink()
        del os.environ["NESTED_KEY"]
        del os.environ["LIST_ITEM"]


def test_env_var_no_expansion_without_syntax():
    """Test that strings without ${} syntax are not expanded"""
    os.environ["MY_VAR"] = "should_not_appear"

    # Create temporary config
    config_content = """
    api:
      key: "MY_VAR"
      path: "/path/to/MY_VAR"
    """

    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(config_content)
        config_path = f.name

    try:
        # Load config
        config = load_config(config_path)

        # Verify no expansion without ${} syntax
        assert config["api"]["key"] == "MY_VAR"
        assert config["api"]["path"] == "/path/to/MY_VAR"
    finally:
        # Cleanup
        Path(config_path).unlink()
        del os.environ["MY_VAR"]


def test_osint_api_keys_expansion():
    """Test OSINT API key expansion as configured in guardian.yaml"""
    # Set test API keys
    os.environ["GITHUB_TOKEN"] = "ghp_test123"

    # Create temporary config matching guardian.yaml structure
    config_content = """
    osint:
      enabled: true
      sources:
        github:
          enabled: true
          token: "${GITHUB_TOKEN:-}"
    """

    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(config_content)
        config_path = f.name

    try:
        # Load config
        config = load_config(config_path)

        # Verify API keys are expanded
        assert config["osint"]["sources"]["github"]["token"] == "ghp_test123"
    finally:
        # Cleanup
        Path(config_path).unlink()
        del os.environ["GITHUB_TOKEN"]


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
