"""
Unit tests for FeroxbusterTool
"""
import pytest
from tools.feroxbuster import FeroxbusterTool


class TestFeroxbusterTool:
    """Test FeroxbusterTool functionality"""

    @pytest.fixture
    def tool(self, test_config):
        """Create tool instance for testing"""
        return FeroxbusterTool(test_config)

    def test_exit_code_success(self, tool):
        """Test that exit code 0 is considered success"""
        assert tool.is_success_exit_code(0) == True

    def test_exit_code_no_results(self, tool):
        """Test that exit code 2 (no results) is considered success"""
        assert tool.is_success_exit_code(2) == True

    def test_exit_code_failure(self, tool):
        """Test that other exit codes are considered failures"""
        assert tool.is_success_exit_code(1) == False
        assert tool.is_success_exit_code(3) == False
        assert tool.is_success_exit_code(127) == False

    def test_command_generation_basic(self, tool):
        """Test basic command generation"""
        cmd = tool.get_command("https://example.com")

        assert "feroxbuster" in cmd
        assert "-u" in cmd
        assert "https://example.com" in cmd
        assert "--json" in cmd

    def test_command_generation_api_mode(self, tool):
        """Test command generation with API mode enabled"""
        cmd = tool.get_command("https://example.com", api_mode=True)

        assert "-w" in cmd
        assert "-x" in cmd
        # Check for API-specific extensions
        extensions_idx = cmd.index("-x")
        extensions = cmd[extensions_idx + 1]
        assert "json" in extensions
        assert "xml" in extensions

    def test_parse_output_valid_json(self, tool):
        """Test parsing valid JSON output"""
        json_output = """
        {"type":"response","url":"https://example.com/api/users","status":200,"content_length":1234,"word_count":100}
        {"type":"response","url":"https://example.com/api/posts","status":404,"content_length":0,"word_count":0}
        """

        result = tool.parse_output(json_output.strip())

        assert "endpoints" in result
        assert len(result["endpoints"]) == 2
        assert result["total_found"] == 2

    def test_parse_output_identifies_api_endpoints(self, tool):
        """Test that API endpoints are correctly identified"""
        json_output = """
        {"type":"response","url":"https://example.com/api/users","status":200,"content_length":1234,"word_count":100}
        {"type":"response","url":"https://example.com/static/image.jpg","status":200,"content_length":5000,"word_count":0}
        """

        result = tool.parse_output(json_output.strip())

        assert result["api_count"] == 1
        assert "https://example.com/api/users" in result["api_endpoints"]

    def test_parse_output_empty(self, tool):
        """Test parsing empty output"""
        result = tool.parse_output("")

        assert result["endpoints"] == []
        assert result["api_endpoints"] == []
        assert result["total_found"] == 0

    def test_parse_output_invalid_json(self, tool):
        """Test parsing invalid JSON gracefully"""
        invalid_output = "This is not valid JSON"

        result = tool.parse_output(invalid_output)

        # Should return empty results, not crash
        assert result["endpoints"] == []
        assert result["total_found"] == 0
