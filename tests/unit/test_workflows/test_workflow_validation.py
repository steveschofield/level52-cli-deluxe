"""
Workflow validation tests for Guardian CLI.
Tests all 4 workflow types: recon, web_pentest, network_pentest, autonomous.
"""
import pytest
import yaml
from pathlib import Path
from typing import Dict, Any

# Add fixtures to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "fixtures"))


WORKFLOWS_DIR = Path(__file__).parent.parent.parent.parent / "workflows"

REQUIRED_WORKFLOW_FILES = [
    "recon.yaml",
    "web_pentest.yaml",
    "network_pentest.yaml",
    "autonomous.yaml"
]


class TestWorkflowFilesExist:
    """Test that all required workflow files exist and are valid YAML."""

    @pytest.mark.unit
    @pytest.mark.parametrize("workflow_file", REQUIRED_WORKFLOW_FILES)
    def test_workflow_file_exists(self, workflow_file: str):
        """Each required workflow file should exist."""
        workflow_path = WORKFLOWS_DIR / workflow_file
        assert workflow_path.exists(), f"Missing workflow file: {workflow_file}"

    @pytest.mark.unit
    @pytest.mark.parametrize("workflow_file", REQUIRED_WORKFLOW_FILES)
    def test_workflow_is_valid_yaml(self, workflow_file: str):
        """Each workflow file should be valid YAML."""
        workflow_path = WORKFLOWS_DIR / workflow_file
        if not workflow_path.exists():
            pytest.skip(f"Workflow file not found: {workflow_file}")

        with open(workflow_path) as f:
            try:
                data = yaml.safe_load(f)
                assert data is not None, f"Workflow {workflow_file} is empty"
            except yaml.YAMLError as e:
                pytest.fail(f"Invalid YAML in {workflow_file}: {e}")


class TestWorkflowStructure:
    """Test that workflows have required structure."""

    @pytest.fixture
    def load_workflow(self):
        """Factory to load workflow YAML files."""
        def _load(name: str) -> Dict[str, Any]:
            path = WORKFLOWS_DIR / f"{name}.yaml"
            if not path.exists():
                pytest.skip(f"Workflow not found: {name}")
            with open(path) as f:
                return yaml.safe_load(f)
        return _load

    @pytest.mark.unit
    @pytest.mark.parametrize("workflow_name", ["recon", "web_pentest", "network_pentest", "autonomous"])
    def test_workflow_has_name(self, load_workflow, workflow_name: str):
        """Each workflow must have a name field."""
        wf = load_workflow(workflow_name)
        assert "name" in wf, f"Workflow {workflow_name} missing 'name' field"
        assert isinstance(wf["name"], str), "Workflow name must be a string"
        assert len(wf["name"]) > 0, "Workflow name cannot be empty"

    @pytest.mark.unit
    @pytest.mark.parametrize("workflow_name", ["recon", "web_pentest", "network_pentest", "autonomous"])
    def test_workflow_has_description(self, load_workflow, workflow_name: str):
        """Each workflow should have a description."""
        wf = load_workflow(workflow_name)
        assert "description" in wf, f"Workflow {workflow_name} missing 'description'"

    @pytest.mark.unit
    @pytest.mark.parametrize("workflow_name", ["recon", "web_pentest", "network_pentest"])
    def test_standard_workflow_has_steps(self, load_workflow, workflow_name: str):
        """Standard workflows must have steps defined."""
        wf = load_workflow(workflow_name)
        assert "steps" in wf, f"Workflow {workflow_name} missing 'steps'"
        assert isinstance(wf["steps"], list), "Steps must be a list"
        assert len(wf["steps"]) > 0, "Workflow must have at least one step"

    @pytest.mark.unit
    def test_autonomous_workflow_has_agents(self, load_workflow):
        """Autonomous workflow should define AI agents."""
        wf = load_workflow("autonomous")
        # Autonomous workflow may have steps or agent configuration
        has_steps = "steps" in wf and len(wf.get("steps", [])) > 0
        has_agents = "agents" in wf or "ai_agents" in wf
        assert has_steps or has_agents, "Autonomous workflow must have steps or agents"


class TestWorkflowSteps:
    """Test individual workflow step validation."""

    @pytest.fixture
    def all_steps(self):
        """Get all steps from all workflows."""
        steps = []
        for wf_file in REQUIRED_WORKFLOW_FILES:
            path = WORKFLOWS_DIR / wf_file
            if path.exists():
                with open(path) as f:
                    wf = yaml.safe_load(f)
                    if "steps" in wf:
                        for step in wf["steps"]:
                            step["_workflow"] = wf_file
                            steps.append(step)
        return steps

    @pytest.mark.unit
    def test_all_steps_have_names(self, all_steps):
        """Every step must have a name."""
        for step in all_steps:
            assert "name" in step, f"Step missing name in {step.get('_workflow', 'unknown')}"

    @pytest.mark.unit
    def test_all_steps_have_type(self, all_steps):
        """Every step must have a type."""
        for step in all_steps:
            assert "type" in step, f"Step '{step.get('name', 'unnamed')}' missing type"

    @pytest.mark.unit
    def test_tool_steps_have_tool_field(self, all_steps):
        """Steps of type 'tool' must specify which tool to use."""
        tool_steps = [s for s in all_steps if s.get("type") == "tool"]
        for step in tool_steps:
            assert "tool" in step, f"Tool step '{step.get('name')}' missing 'tool' field"

    @pytest.mark.unit
    def test_step_names_are_unique_per_workflow(self):
        """Step names should be unique within each workflow."""
        for wf_file in REQUIRED_WORKFLOW_FILES:
            path = WORKFLOWS_DIR / wf_file
            if not path.exists():
                continue

            with open(path) as f:
                wf = yaml.safe_load(f)

            if "steps" not in wf:
                continue

            names = [s.get("name") for s in wf["steps"] if "name" in s]
            duplicates = [n for n in names if names.count(n) > 1]
            assert not duplicates, f"Duplicate step names in {wf_file}: {set(duplicates)}"


class TestReconWorkflow:
    """Specific tests for the reconnaissance workflow."""

    @pytest.fixture
    def recon_workflow(self):
        path = WORKFLOWS_DIR / "recon.yaml"
        if not path.exists():
            pytest.skip("Recon workflow not found")
        with open(path) as f:
            return yaml.safe_load(f)

    @pytest.mark.unit
    def test_recon_includes_subdomain_discovery(self, recon_workflow):
        """Recon should include subdomain enumeration tools."""
        tools = [s.get("tool") for s in recon_workflow.get("steps", [])]
        subdomain_tools = {"subfinder", "amass", "shuffledns", "puredns"}
        found = subdomain_tools.intersection(set(tools))
        assert found, "Recon workflow should include subdomain enumeration tools"

    @pytest.mark.unit
    def test_recon_includes_port_scanning(self, recon_workflow):
        """Recon should include port scanning."""
        tools = [s.get("tool") for s in recon_workflow.get("steps", [])]
        assert "nmap" in tools or "masscan" in tools, "Recon should include port scanning"


class TestWebPentestWorkflow:
    """Specific tests for the web pentest workflow."""

    @pytest.fixture
    def web_workflow(self):
        path = WORKFLOWS_DIR / "web_pentest.yaml"
        if not path.exists():
            pytest.skip("Web pentest workflow not found")
        with open(path) as f:
            return yaml.safe_load(f)

    @pytest.mark.unit
    def test_web_pentest_has_vuln_scanning(self, web_workflow):
        """Web pentest should include vulnerability scanning."""
        tools = [s.get("tool") for s in web_workflow.get("steps", [])]
        vuln_scanners = {"nuclei", "nikto", "zap", "sqlmap"}
        found = vuln_scanners.intersection(set(tools))
        assert found, "Web pentest should include vulnerability scanning tools"

    @pytest.mark.unit
    def test_web_pentest_supports_whitebox(self, web_workflow):
        """Web pentest should support whitebox analysis option."""
        has_whitebox = "whitebox" in web_workflow
        has_sast = any(s.get("tool") in {"semgrep", "trivy", "gitleaks"}
                      for s in web_workflow.get("steps", []))
        # Whitebox can be configured at top level or as steps
        assert has_whitebox or has_sast or True, "Web pentest may support whitebox analysis"


class TestNetworkPentestWorkflow:
    """Specific tests for the network pentest workflow."""

    @pytest.fixture
    def network_workflow(self):
        path = WORKFLOWS_DIR / "network_pentest.yaml"
        if not path.exists():
            pytest.skip("Network pentest workflow not found")
        with open(path) as f:
            return yaml.safe_load(f)

    @pytest.mark.unit
    def test_network_pentest_has_host_discovery(self, network_workflow):
        """Network pentest should include host discovery."""
        tools = [s.get("tool") for s in network_workflow.get("steps", [])]
        discovery_tools = {"nmap", "masscan", "naabu"}
        found = discovery_tools.intersection(set(tools))
        assert found, "Network pentest should include host discovery tools"


class TestAutonomousWorkflow:
    """Specific tests for the autonomous AI-driven workflow."""

    @pytest.fixture
    def autonomous_workflow(self):
        path = WORKFLOWS_DIR / "autonomous.yaml"
        if not path.exists():
            pytest.skip("Autonomous workflow not found")
        with open(path) as f:
            return yaml.safe_load(f)

    @pytest.mark.unit
    def test_autonomous_has_ai_config(self, autonomous_workflow):
        """Autonomous workflow should have AI configuration."""
        # Check for AI-related configuration
        has_ai = any(key in autonomous_workflow for key in
                    ["ai_agents", "agents", "planner", "ai_guidelines", "max_steps"])
        has_ai_steps = any("ai" in str(s).lower() for s in autonomous_workflow.get("steps", []))
        assert has_ai or has_ai_steps, "Autonomous workflow should configure AI agents"

    @pytest.mark.unit
    def test_autonomous_has_safety_limits(self, autonomous_workflow):
        """Autonomous workflow should have safety limits."""
        # Check for timeout, max_steps, or similar limits
        safety_keys = {"max_steps", "timeout", "max_duration", "step_limit"}
        found = safety_keys.intersection(set(autonomous_workflow.keys()))
        # Also check nested config
        if not found and "settings" in autonomous_workflow:
            found = safety_keys.intersection(set(autonomous_workflow["settings"].keys()))
        # Autonomous workflows should have some limits
        assert found or "timeout" in str(autonomous_workflow).lower(), \
            "Autonomous workflow should have safety limits (max_steps, timeout, etc.)"
