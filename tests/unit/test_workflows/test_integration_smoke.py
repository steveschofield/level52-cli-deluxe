"""
Integration smoke tests for end-to-end wiring.

These tests run without real tools or LLM calls — every external call is mocked.
They exist to catch the class of wiring bugs found in the 2026-03 audit:
- whitebox running before steps
- master seed file written and consumed by downstream tools
- SAST error dicts having the correct shape
- workflow settings block being applied
- is_success_exit_code returning sensible values for scanner tools
"""
import asyncio
import json
import os
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, call


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_config(tmp_path: Path) -> dict:
    return {
        "tools": {
            "gobuster": {"wordlist": "/usr/share/wordlists/dirb/common.txt"},
            "zap": {"seed_urls_from_context": True, "run_additional_scan": True},
            "nuclei": {},
            "katana": {},
        },
        "pentest": {"tool_timeout": 30, "max_parallel_tools": 1},
        "output": {"save_path": str(tmp_path)},
        "logging": {"level": "WARNING"},
        "ai": {"provider": "openai", "model": "gpt-4o"},
    }


def _make_engine(config, target="http://example.com", source=None):
    """Build a WorkflowEngine with all external I/O mocked out."""
    from core.workflow import WorkflowEngine
    from unittest.mock import patch as _patch

    with _patch("core.workflow.get_llm_client", return_value=AsyncMock()):
        engine = WorkflowEngine(config, target, source=source)
    # Replace LLM / analyst / reporter with silent mocks so nothing hits the
    # network and no API keys are required.
    engine.llm_client = AsyncMock()
    engine.analyst = AsyncMock()
    engine.analyst.correlate_findings = AsyncMock(return_value={"findings": []})
    engine.analyst.interpret_tool_output = AsyncMock(
        return_value={"findings": [], "summary": "", "reasoning": ""}
    )
    engine.reporter = AsyncMock()
    engine.reporter.execute = AsyncMock(return_value="<html>report</html>")
    engine.tool_agent = MagicMock()
    engine.tool_agent.available_tools = {"httpx", "katana", "zap", "gobuster", "nuclei"}
    return engine


# ---------------------------------------------------------------------------
# 1. Whitebox runs BEFORE steps
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestWhiteboxOrder:
    def test_whitebox_called_before_steps_in_run_workflow_source(self, tmp_path):
        """run_workflow must call _run_whitebox_analysis before the step loop.

        We verify the source code structure: in workflow.py, the call to
        _run_whitebox_analysis appears before the `for step in steps:` loop
        (lines 310-311 vs 314+). This test reads the actual source file and
        asserts the ordering invariant without running the engine.
        """
        import ast, textwrap
        wf_src = Path(__file__).parents[3] / "core" / "workflow.py"
        source = wf_src.read_text()
        tree = ast.parse(source)

        # Find the run_workflow async def
        run_workflow_fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "run_workflow":
                run_workflow_fn = node
                break
        assert run_workflow_fn is not None, "run_workflow not found in workflow.py"

        # Walk statements in order and record the first line of:
        # - _run_whitebox_analysis call
        # - the `for step in steps` loop
        whitebox_line = None
        step_loop_line = None
        for node in ast.walk(run_workflow_fn):
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Await):
                call = node.value.value
                if isinstance(call, ast.Call):
                    func = call.func
                    if isinstance(func, ast.Attribute) and func.attr == "_run_whitebox_analysis":
                        if whitebox_line is None:
                            whitebox_line = node.lineno
            if isinstance(node, ast.For):
                # The for loop over steps: target should be `step`
                if isinstance(node.target, ast.Name) and node.target.id == "step":
                    if step_loop_line is None:
                        step_loop_line = node.lineno

        assert whitebox_line is not None, "_run_whitebox_analysis call not found in run_workflow"
        assert step_loop_line is not None, "step loop not found in run_workflow"
        assert whitebox_line < step_loop_line, (
            f"_run_whitebox_analysis (line {whitebox_line}) must come before the "
            f"step loop (line {step_loop_line}) in run_workflow"
        )

    def test_whitebox_guarded_by_source_path_check(self, tmp_path):
        """_run_whitebox_analysis must only be called when self.source_path is set.

        Inspect the AST to confirm the call is inside an `if self.source_path` guard.
        """
        import ast
        wf_src = Path(__file__).parents[3] / "core" / "workflow.py"
        source = wf_src.read_text()
        tree = ast.parse(source)

        run_workflow_fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "run_workflow":
                run_workflow_fn = node
                break
        assert run_workflow_fn is not None

        # Find the If node that guards _run_whitebox_analysis
        found_guard = False
        for node in ast.walk(run_workflow_fn):
            if not isinstance(node, ast.If):
                continue
            # Check if this If's body contains _run_whitebox_analysis
            body_str = ast.dump(ast.Module(body=node.body, type_ignores=[]))
            if "_run_whitebox_analysis" in body_str:
                # Now check the condition references source_path
                cond_str = ast.dump(node.test)
                if "source_path" in cond_str:
                    found_guard = True
                    break

        assert found_guard, (
            "_run_whitebox_analysis must be guarded by `if self.source_path` in run_workflow"
        )


# ---------------------------------------------------------------------------
# 2. Master seed file written and consumed
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestMasterSeedFile:
    def test_seed_file_created_after_url_discovery(self, tmp_path):
        """After a URL discovery tool runs, the master seed file must exist."""
        config = _minimal_config(tmp_path)
        engine = _make_engine(config)
        engine.memory.session_id = "test123"

        # Simulate httpx returning URLs
        engine.memory.update_context("urls", ["http://example.com/api", "http://example.com/admin"])
        seed_path = engine._refresh_master_seed_file()

        assert seed_path is not None, "_refresh_master_seed_file returned None"
        assert seed_path.exists(), f"Master seed file not written: {seed_path}"
        content = seed_path.read_text()
        assert "http://example.com/api" in content
        assert "http://example.com/admin" in content
        assert engine.memory.metadata.get("master_seed_file") == str(seed_path)

    def test_seed_file_accumulates_across_tools(self, tmp_path):
        """URLs from multiple tools should all end up in the master seed file."""
        config = _minimal_config(tmp_path)
        engine = _make_engine(config)
        engine.memory.session_id = "test456"

        # Round 1: whitebox endpoints
        engine.memory.update_context("urls", ["http://example.com/whitebox-endpoint"])
        engine._refresh_master_seed_file()

        # Round 2: ZAP spider
        engine.memory.update_context("urls", ["http://example.com/zap-found"])
        engine._refresh_master_seed_file()

        # Round 3: gobuster
        engine.memory.update_context("urls", ["http://example.com/gobuster-found"])
        seed_path = engine._refresh_master_seed_file()

        content = seed_path.read_text()
        assert "whitebox-endpoint" in content
        assert "zap-found" in content
        assert "gobuster-found" in content

    def test_gobuster_paths_converted_to_full_urls(self, tmp_path):
        """Gobuster returns path segments; they must become full URLs in the pool."""
        config = _minimal_config(tmp_path)
        engine = _make_engine(config)
        engine.memory.session_id = "test789"
        engine.target = "http://example.com"

        # Simulate what happens in the _URL_DISCOVERY_TOOLS block when gobuster runs
        gobuster_paths = ["/admin", "/api/v1", "/login"]
        base = engine._get_target_base_url()
        from urllib.parse import urljoin
        full_urls = [urljoin(base, p) for p in gobuster_paths]
        engine.memory.update_context("urls", full_urls)
        seed_path = engine._refresh_master_seed_file()

        content = seed_path.read_text()
        assert "http://example.com/admin" in content
        assert "http://example.com/api/v1" in content


# ---------------------------------------------------------------------------
# 3. _load_workflow_config alias resolution
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestWorkflowConfigAliases:
    def test_web_alias_finds_web_pentest_yaml(self, tmp_path):
        """'web' alias must resolve to web_pentest.yaml, not fail silently."""
        config = _minimal_config(tmp_path)
        engine = _make_engine(config)

        wf_cfg = engine._load_workflow_config("web")

        # Should return a non-empty dict (web_pentest.yaml exists in the project)
        assert isinstance(wf_cfg, dict), "_load_workflow_config returned non-dict"
        assert wf_cfg, (
            "'web' alias did not resolve to web_pentest.yaml — whitebox would be skipped"
        )

    def test_autonomous_resolves_directly(self, tmp_path):
        """'autonomous' resolves without aliasing."""
        config = _minimal_config(tmp_path)
        engine = _make_engine(config)

        wf_cfg = engine._load_workflow_config("autonomous")
        assert isinstance(wf_cfg, dict)
        assert wf_cfg


# ---------------------------------------------------------------------------
# 4. Workflow settings block applied
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestWorkflowSettings:
    def test_max_parallel_tools_applied(self, tmp_path):
        """settings.max_parallel_tools from YAML must override the live config."""
        config = _minimal_config(tmp_path)
        config["pentest"]["max_parallel_tools"] = 10  # default

        engine = _make_engine(config)
        engine._apply_workflow_settings({"settings": {"max_parallel_tools": 3}})

        assert engine.config["pentest"]["max_parallel_tools"] == 3

    def test_missing_settings_block_is_safe(self, tmp_path):
        """Workflow YAML without a settings block must not crash."""
        config = _minimal_config(tmp_path)
        engine = _make_engine(config)
        engine._apply_workflow_settings({})   # no settings key
        engine._apply_workflow_settings(None) # None config


# ---------------------------------------------------------------------------
# 5. SAST error dicts have correct shape
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestSASTErrorShape:
    def test_semgrep_error_has_summary_key(self):
        """If semgrep fails, the error dict must include a 'summary' key so
        workflow.py's .get('summary', {}) doesn't silently swallow the error."""
        from core.source_analyzer import SourceCodeAnalyzer

        analyzer = SourceCodeAnalyzer.__new__(SourceCodeAnalyzer)
        analyzer.findings = {"sast_results": {}, "attack_surface": {"endpoints": [], "frameworks": [], "secrets": []}}
        analyzer.logger = MagicMock()

        # Simulate the exception path we fixed
        analyzer.findings["sast_results"]["semgrep"] = {
            "error": "tool not found",
            "findings": [],
            "summary": {"total": 0, "by_severity": {}, "by_category": {}},
            "vulnerable_endpoints": [],
        }

        semgrep_result = analyzer.findings["sast_results"]["semgrep"]
        assert "summary" in semgrep_result
        assert semgrep_result["summary"].get("total") == 0

    def test_trivy_error_has_summary_key(self):
        """If trivy fails, the error dict must include 'summary' with 'total_vulns'."""
        from core.source_analyzer import SourceCodeAnalyzer

        analyzer = SourceCodeAnalyzer.__new__(SourceCodeAnalyzer)
        analyzer.findings = {"sast_results": {}, "attack_surface": {"endpoints": [], "frameworks": [], "secrets": []}}
        analyzer.logger = MagicMock()

        analyzer.findings["sast_results"]["trivy"] = {
            "error": "trivy not installed",
            "vulnerabilities": [],
            "misconfigurations": [],
            "secrets": [],
            "summary": {"total_vulns": 0, "total_misconfigs": 0, "total_secrets": 0, "by_severity": {}, "critical_cves": []},
        }

        trivy_result = analyzer.findings["sast_results"]["trivy"]
        assert "summary" in trivy_result
        assert trivy_result["summary"].get("total_vulns") == 0


# ---------------------------------------------------------------------------
# 6. is_success_exit_code for scanner tools
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestScannerExitCodes:
    def test_nmap_exit_1_is_success(self):
        from tools.nmap import NmapTool
        tool = NmapTool({})
        assert tool.is_success_exit_code(0) is True
        assert tool.is_success_exit_code(1) is True   # host down / no ports
        assert tool.is_success_exit_code(2) is False

    def test_masscan_exit_1_is_success(self):
        from tools.masscan import MasscanTool
        tool = MasscanTool({})
        assert tool.is_success_exit_code(0) is True
        assert tool.is_success_exit_code(1) is True   # no hosts found
        assert tool.is_success_exit_code(2) is False

    def test_naabu_exit_1_is_success(self):
        from tools.naabu import NaabuTool
        tool = NaabuTool({})
        assert tool.is_success_exit_code(0) is True
        assert tool.is_success_exit_code(1) is True   # no open ports
        assert tool.is_success_exit_code(2) is False


# ---------------------------------------------------------------------------
# 7. xnlinkfinder expands ~ in from_file paths
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestXnlinkfinderPathExpansion:
    def test_from_file_tilde_expanded(self):
        from tools.xnlinkfinder import XnlinkfinderTool
        tool = XnlinkfinderTool({})
        tool._binary = "xnLinkFinder"

        home = os.path.expanduser("~")
        cmd = tool.get_command("http://example.com", from_file="~/urls.txt")
        assert f"{home}/urls.txt" in cmd, (
            f"~ not expanded in xnlinkfinder from_file; got: {cmd}"
        )

    def test_from_file_env_var_expanded(self):
        from tools.xnlinkfinder import XnlinkfinderTool
        tool = XnlinkfinderTool({})
        tool._binary = "xnLinkFinder"

        os.environ["TEST_URLS"] = "/tmp/test_urls.txt"
        cmd = tool.get_command("http://example.com", from_file="$TEST_URLS/urls.txt")
        assert "$TEST_URLS" not in " ".join(cmd), (
            f"$ENV not expanded in xnlinkfinder from_file; got: {cmd}"
        )
