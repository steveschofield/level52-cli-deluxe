"""
Unit tests for error handler
"""
import pytest
from utils.error_handler import ErrorHandler, ToolExecutionError


@pytest.mark.unit
class TestErrorHandler:
    """Test error handling and recovery strategies"""

    @pytest.fixture
    def error_handler(self, test_config):
        return ErrorHandler(test_config)

    def test_exit_code_127_tool_not_installed(self, error_handler):
        """Test that exit code 127 (command not found) is handled"""
        error = ToolExecutionError("test_tool", "Command not found", exit_code=127)
        result = error_handler._recover_tool_error(error, {})

        assert result["success"] == False
        assert "not installed" in result["reason"]
        assert "suggestion" in result

    def test_exit_code_124_timeout(self, error_handler):
        """Test that exit code 124 (timeout) allows continuation"""
        error = ToolExecutionError("test_tool", "Timeout", exit_code=124)
        result = error_handler._recover_tool_error(error, {})

        assert result["success"] == True
        assert "timed out" in result["reason"]
        assert result["action"] == "continue_without_result"

    def test_exit_code_1_warnings(self, error_handler):
        """Test that exit code 1 (warnings) allows continuation"""
        error = ToolExecutionError("test_tool", "Warning", exit_code=1)
        result = error_handler._recover_tool_error(error, {})

        assert result["success"] == True
        assert "warnings" in result["reason"] or "no findings" in result["reason"]
        assert result["action"] == "continue_with_partial_results"

    def test_exit_code_2_no_results(self, error_handler):
        """Test that exit code 2 (no results) allows continuation"""
        error = ToolExecutionError("test_tool", "No results", exit_code=2)
        result = error_handler._recover_tool_error(error, {})

        assert result["success"] == True
        assert "no findings" in result["reason"]
        assert result["action"] == "continue_with_empty_results"

    def test_exit_code_60_ssl_failure(self, error_handler):
        """Test that exit code 60 (SSL cert failure) allows continuation"""
        error = ToolExecutionError("headers", "SSL verification failed", exit_code=60)
        result = error_handler._recover_tool_error(error, {})

        assert result["success"] == True
        assert "SSL" in result["reason"]
        assert result["action"] == "continue_with_partial_results"

    def test_unknown_exit_code_fails(self, error_handler):
        """Test that unknown exit codes are treated as failures"""
        error = ToolExecutionError("test_tool", "Unknown error", exit_code=99)
        result = error_handler._recover_tool_error(error, {})

        assert result["success"] == False
        assert "99" in result["reason"]
