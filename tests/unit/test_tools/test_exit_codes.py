"""
Test exit code handling across all tools with custom is_success_exit_code()
"""
import pytest
from tools.sslyze import SSLyzeTool
from tools.headers import HeadersTool
from tools.subjs import SubjsTool
from tools.feroxbuster import FeroxbusterTool
from tools.arjun import ArjunTool
from tools.nikto import NiktoTool
from tools.schemathesis import SchemathesisTool


@pytest.mark.unit
class TestExitCodeHandling:
    """Test that all tools properly handle their specific exit codes"""

    @pytest.fixture
    def test_config(self):
        return {}

    @pytest.mark.parametrize("tool_class,success_codes,failure_codes", [
        (SSLyzeTool, [0, 2], [1, 3, 127]),
        (HeadersTool, [0, 60], [1, 2, 127]),
        (SubjsTool, [0, 2], [1, 3, 127]),
        (FeroxbusterTool, [0, 2], [1, 3, 127]),
        (ArjunTool, [0, 2], [1, 3, 127]),
        (NiktoTool, [0, 1], [2, 3, 127]),
        (SchemathesisTool, [0, 1], [2, 3, 127]),
    ])
    def test_exit_code_interpretation(self, test_config, tool_class, success_codes, failure_codes):
        """Test that each tool correctly interprets its exit codes"""
        tool = tool_class(test_config)

        # Test success codes
        for code in success_codes:
            assert tool.is_success_exit_code(code) == True, \
                f"{tool_class.__name__} should treat exit code {code} as success"

        # Test failure codes
        for code in failure_codes:
            assert tool.is_success_exit_code(code) == False, \
                f"{tool_class.__name__} should treat exit code {code} as failure"

    def test_sslyze_target_unreachable(self, test_config):
        """Test SSLyze exit code 2 (target unreachable) is success"""
        tool = SSLyzeTool(test_config)
        assert tool.is_success_exit_code(2) == True

    def test_headers_ssl_cert_failure(self, test_config):
        """Test headers tool exit code 60 (SSL cert failure) is success"""
        tool = HeadersTool(test_config)
        assert tool.is_success_exit_code(60) == True

    def test_nikto_no_findings(self, test_config):
        """Test Nikto exit code 1 (no findings) is success"""
        tool = NiktoTool(test_config)
        assert tool.is_success_exit_code(1) == True

    def test_schemathesis_schema_not_found(self, test_config):
        """Test schemathesis exit code 1 (schema not found) is success"""
        tool = SchemathesisTool(test_config)
        assert tool.is_success_exit_code(1) == True
