"""
Unit tests for GobusterTool
"""
import pytest
from tools.gobuster import GobusterTool


class TestGobusterTool:
    """Test GobusterTool functionality"""

    @pytest.fixture
    def tool(self, test_config):
        return GobusterTool(test_config)

    def test_exit_code_success(self, tool):
        assert tool.is_success_exit_code(0) is True

    def test_exit_code_no_results(self, tool):
        # gobuster exits 1 when no results found / scan completes cleanly
        assert tool.is_success_exit_code(1) is True

    def test_exit_code_failure(self, tool):
        assert tool.is_success_exit_code(2) is False
        assert tool.is_success_exit_code(127) is False

    def test_command_basic(self, tool):
        cmd = tool.get_command("https://example.com")
        assert "gobuster" in cmd
        assert "dir" in cmd
        assert "-u" in cmd
        assert "https://example.com" in cmd
        assert "-w" in cmd
        assert "-q" in cmd
        assert "--no-progress" in cmd
        assert "--no-error" in cmd
        assert "--no-color" in cmd

    def test_command_thread_default(self, tool):
        cmd = tool.get_command("https://example.com")
        t_idx = cmd.index("-t")
        assert int(cmd[t_idx + 1]) <= 10  # throttled by default

    def test_command_delay(self, tool):
        cmd = tool.get_command("https://example.com", delay_ms=200)
        assert "--delay" in cmd
        delay_idx = cmd.index("--delay")
        assert cmd[delay_idx + 1] == "200ms"

    def test_command_extensions(self, tool):
        cmd = tool.get_command("https://example.com", extensions="php,html")
        assert "-x" in cmd
        x_idx = cmd.index("-x")
        assert "php" in cmd[x_idx + 1]

    def test_command_wordlist_override(self, tool):
        cmd = tool.get_command("https://example.com", wordlist="/tmp/custom.txt")
        w_idx = cmd.index("-w")
        assert cmd[w_idx + 1] == "/tmp/custom.txt"

    def test_parse_output_basic(self, tool):
        output = (
            "/admin                (Status: 200) [Size: 12345]\n"
            "/login                (Status: 301) [Size: 234] [--> /login/]\n"
            "/api/v1               (Status: 200) [Size: 8888]\n"
        )
        result = tool.parse_output(output)

        assert result["total_found"] == 3
        assert len(result["endpoints"]) == 3
        assert result["endpoints"][0]["path"] == "/admin"
        assert result["endpoints"][0]["status"] == 200
        assert result["endpoints"][1]["redirect"] == "/login/"

    def test_parse_output_api_detection(self, tool):
        output = (
            "/admin                (Status: 200) [Size: 100]\n"
            "/api/v1               (Status: 200) [Size: 500]\n"
        )
        result = tool.parse_output(output)
        assert result["api_count"] == 1
        assert "/api/v1" in result["api_endpoints"]

    def test_parse_output_urls_populated(self, tool):
        output = "/admin                (Status: 200) [Size: 100]\n"
        result = tool.parse_output(output)
        assert "/admin" in result["urls"]

    def test_parse_output_empty(self, tool):
        result = tool.parse_output("")
        assert result["endpoints"] == []
        assert result["total_found"] == 0
        assert result["urls"] == []

    def test_parse_output_noise_ignored(self, tool):
        output = (
            "Gobuster v3.8.2 by OJ Reeves\n"
            "This is some banner text\n"
            "/admin                (Status: 200) [Size: 100]\n"
            "Progress: 100/100\n"
        )
        result = tool.parse_output(output)
        assert result["total_found"] == 1
