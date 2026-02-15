"""
Workflow-specific test fixtures for Guardian CLI.
Provides mock data and configurations for testing all 4 workflow types.
"""
import pytest
from typing import Dict, Any, List
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock


# =============================================================================
# Mock Tool Outputs - Simulated responses from security tools
# =============================================================================

MOCK_TOOL_OUTPUTS = {
    # Recon workflow tools
    "amass": {
        "success": {
            "exit_code": 0,
            "stdout": "example.com\napi.example.com\ndev.example.com\nstaging.example.com",
            "subdomains": ["example.com", "api.example.com", "dev.example.com", "staging.example.com"]
        },
        "failure": {"exit_code": 1, "stderr": "No results found", "subdomains": []}
    },
    "subfinder": {
        "success": {
            "exit_code": 0,
            "stdout": "www.example.com\nmail.example.com\nftp.example.com",
            "subdomains": ["www.example.com", "mail.example.com", "ftp.example.com"]
        }
    },
    "nmap": {
        "success": {
            "exit_code": 0,
            "stdout": "PORT     STATE SERVICE VERSION\n22/tcp   open  ssh     OpenSSH 8.9\n80/tcp   open  http    nginx 1.18\n443/tcp  open  https   nginx 1.18",
            "ports": [22, 80, 443],
            "services": {"22": "ssh", "80": "http", "443": "https"}
        },
        "no_ports": {"exit_code": 0, "stdout": "All 1000 scanned ports are filtered", "ports": []}
    },
    "whois": {
        "success": {
            "exit_code": 0,
            "stdout": "Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar\nCreation Date: 1995-08-14",
            "registrar": "Example Registrar"
        }
    },
    # Web pentest tools
    "httpx": {
        "success": {
            "exit_code": 0,
            "stdout": "https://example.com [200] [nginx] [Example Site]",
            "live_hosts": ["https://example.com"],
            "technologies": ["nginx"]
        }
    },
    "nuclei": {
        "success": {
            "exit_code": 0,
            "findings": [
                {"template": "cve-2021-44228", "severity": "critical", "host": "example.com"},
                {"template": "xss-reflected", "severity": "medium", "host": "example.com/search"}
            ]
        },
        "clean": {"exit_code": 0, "findings": []}
    },
    "sqlmap": {
        "success": {
            "exit_code": 0,
            "vulnerable": True,
            "injection_type": "boolean-based blind",
            "parameter": "id"
        },
        "not_vulnerable": {"exit_code": 0, "vulnerable": False}
    },
    "feroxbuster": {
        "success": {
            "exit_code": 0,
            "discovered": ["/admin", "/api", "/backup", "/.git"],
            "status_codes": {"200": 3, "403": 1}
        }
    },
    "wafw00f": {
        "success": {"exit_code": 0, "waf_detected": "Cloudflare"},
        "no_waf": {"exit_code": 0, "waf_detected": None}
    },
    # Network pentest tools
    "masscan": {
        "success": {
            "exit_code": 0,
            "open_ports": [22, 80, 443, 3389, 8080],
            "hosts": ["192.168.1.1", "192.168.1.10", "192.168.1.100"]
        }
    },
    # SAST tools (whitebox)
    "semgrep": {
        "success": {
            "exit_code": 0,
            "findings": [
                {"rule_id": "python.lang.security.audit.eval-detected", "severity": "WARNING", "path": "app.py", "line": 42},
                {"rule_id": "python.flask.security.audit.hardcoded-secret", "severity": "ERROR", "path": "config.py", "line": 15}
            ]
        }
    },
    "trivy": {
        "success": {
            "exit_code": 0,
            "vulnerabilities": [
                {"id": "CVE-2023-1234", "severity": "HIGH", "package": "requests", "installed": "2.25.0", "fixed": "2.31.0"}
            ]
        }
    },
    "gitleaks": {
        "success": {
            "exit_code": 0,
            "findings": [
                {"rule": "aws-access-key", "file": ".env.example", "line": 3}
            ]
        },
        "clean": {"exit_code": 0, "findings": []}
    }
}


# =============================================================================
# Workflow Configurations
# =============================================================================

WORKFLOW_CONFIGS = {
    "recon": {
        "name": "reconnaissance",
        "target": "example.com",
        "expected_tools": ["amass", "whois", "subfinder", "dnsx", "nmap"],
        "expected_phases": ["passive_osint", "subdomain_discovery", "port_scanning"],
        "timeout_minutes": 60
    },
    "web_pentest": {
        "name": "web_application_pentest",
        "target": "https://example.com",
        "expected_tools": ["httpx", "nuclei", "feroxbuster", "sqlmap", "wafw00f"],
        "expected_phases": ["discovery", "scanning", "exploitation"],
        "whitebox_tools": ["semgrep", "trivy", "gitleaks"],
        "timeout_minutes": 120
    },
    "network_pentest": {
        "name": "network_infrastructure_pentest",
        "target": "192.168.1.0/24",
        "expected_tools": ["nmap", "masscan", "enum4linux"],
        "expected_phases": ["host_discovery", "port_scanning", "service_enumeration"],
        "timeout_minutes": 90
    },
    "autonomous": {
        "name": "autonomous_pentest",
        "target": "example.com",
        "expected_agents": ["planner", "tool_selector", "analyst", "reporter"],
        "max_steps": 25,
        "timeout_minutes": 120
    }
}


# =============================================================================
# Pytest Fixtures
# =============================================================================

@pytest.fixture
def mock_tool_output():
    """Factory fixture for getting mock tool outputs."""
    def _get_output(tool_name: str, scenario: str = "success") -> Dict[str, Any]:
        if tool_name not in MOCK_TOOL_OUTPUTS:
            return {"exit_code": 0, "stdout": f"Mock output for {tool_name}"}
        return MOCK_TOOL_OUTPUTS[tool_name].get(scenario, MOCK_TOOL_OUTPUTS[tool_name]["success"])
    return _get_output


@pytest.fixture
def workflow_config():
    """Factory fixture for getting workflow configurations."""
    def _get_config(workflow_name: str) -> Dict[str, Any]:
        return WORKFLOW_CONFIGS.get(workflow_name, {})
    return _get_config


@pytest.fixture
def mock_recon_workflow(mock_tool_output):
    """Complete mock for recon workflow execution."""
    return {
        "workflow": "recon",
        "target": "example.com",
        "results": {
            "amass": mock_tool_output("amass"),
            "subfinder": mock_tool_output("subfinder"),
            "nmap": mock_tool_output("nmap"),
            "whois": mock_tool_output("whois")
        },
        "summary": {
            "subdomains_found": 7,
            "open_ports": 3,
            "duration_seconds": 180
        }
    }


@pytest.fixture
def mock_web_pentest_workflow(mock_tool_output):
    """Complete mock for web pentest workflow execution."""
    return {
        "workflow": "web_pentest",
        "target": "https://example.com",
        "results": {
            "httpx": mock_tool_output("httpx"),
            "nuclei": mock_tool_output("nuclei"),
            "feroxbuster": mock_tool_output("feroxbuster"),
            "wafw00f": mock_tool_output("wafw00f")
        },
        "findings": [
            {"severity": "critical", "type": "cve", "id": "CVE-2021-44228"},
            {"severity": "medium", "type": "xss", "location": "/search"}
        ],
        "summary": {
            "vulnerabilities_found": 2,
            "critical": 1,
            "high": 0,
            "medium": 1,
            "duration_seconds": 600
        }
    }


@pytest.fixture
def mock_network_pentest_workflow(mock_tool_output):
    """Complete mock for network pentest workflow execution."""
    return {
        "workflow": "network_pentest",
        "target": "192.168.1.0/24",
        "results": {
            "nmap": mock_tool_output("nmap"),
            "masscan": mock_tool_output("masscan")
        },
        "summary": {
            "hosts_discovered": 3,
            "services_found": 15,
            "duration_seconds": 300
        }
    }


@pytest.fixture
def mock_autonomous_workflow(mock_tool_output):
    """Complete mock for autonomous workflow execution."""
    return {
        "workflow": "autonomous",
        "target": "example.com",
        "steps_executed": 12,
        "agent_decisions": [
            {"agent": "planner", "action": "start_recon", "reasoning": "Begin with passive reconnaissance"},
            {"agent": "tool_selector", "tool": "subfinder", "reasoning": "Enumerate subdomains first"},
            {"agent": "analyst", "finding": "Found 5 subdomains", "next_action": "scan_ports"},
        ],
        "findings": mock_tool_output("nuclei")["findings"],
        "summary": {
            "total_steps": 12,
            "tools_used": 8,
            "vulnerabilities_found": 2,
            "duration_seconds": 1800
        }
    }


@pytest.fixture
def mock_whitebox_results(mock_tool_output):
    """Mock results for whitebox/SAST analysis."""
    return {
        "semgrep": mock_tool_output("semgrep"),
        "trivy": mock_tool_output("trivy"),
        "gitleaks": mock_tool_output("gitleaks"),
        "correlation": {
            "sast_dast_matches": [
                {"sast_finding": "hardcoded-secret", "dast_finding": "exposed-credentials", "confidence": 0.95}
            ]
        }
    }


@pytest.fixture
def mock_tool_executor():
    """Mock tool executor for testing workflow without running actual tools."""
    executor = MagicMock()
    executor.run = AsyncMock(return_value={"exit_code": 0, "stdout": "success"})
    executor.is_available = MagicMock(return_value=True)
    return executor


@pytest.fixture
def mock_ai_provider():
    """Mock AI provider for testing without API calls."""
    provider = MagicMock()
    provider.analyze = AsyncMock(return_value={
        "analysis": "Mock AI analysis of findings",
        "recommendations": ["Fix critical vulnerabilities", "Update dependencies"],
        "risk_score": 7.5
    })
    provider.plan = AsyncMock(return_value={
        "steps": ["Run reconnaissance", "Scan for vulnerabilities", "Generate report"],
        "reasoning": "Standard pentest methodology"
    })
    return provider


@pytest.fixture
def sample_workflow_yaml(tmp_path) -> Path:
    """Create a sample workflow YAML for testing."""
    workflow_content = """
name: test_workflow
description: Test workflow for unit tests

steps:
  - name: test_step_1
    type: tool
    tool: nmap
    objective: "Test port scan"
    parameters:
      ports: "80,443"

  - name: test_step_2
    type: tool
    tool: httpx
    objective: "Test HTTP discovery"
    dependencies:
      - test_step_1
"""
    workflow_file = tmp_path / "test_workflow.yaml"
    workflow_file.write_text(workflow_content)
    return workflow_file


@pytest.fixture
def all_workflow_mocks(mock_recon_workflow, mock_web_pentest_workflow,
                       mock_network_pentest_workflow, mock_autonomous_workflow):
    """Convenience fixture providing all workflow mocks."""
    return {
        "recon": mock_recon_workflow,
        "web_pentest": mock_web_pentest_workflow,
        "network_pentest": mock_network_pentest_workflow,
        "autonomous": mock_autonomous_workflow
    }
