"""
BloodHound MCP Tool Wrapper for Guardian

Integrates BloodHound AD attack path analysis via the MCP Security Hub.
BloodHound identifies attack paths in Active Directory environments by
analyzing relationships between users, groups, computers, and permissions.

Capabilities (75+ tools via bloodhound-mcp):
- Attack path discovery (shortest paths to Domain Admin)
- Kerberoastable/AS-REP roastable user detection
- Unconstrained/constrained delegation analysis
- ACL abuse path detection
- Session and local admin enumeration
- Trust relationship mapping

Requires:
- Docker installed and running
- bloodhound-mcp image (ghcr.io/fuzzinglabs/bloodhound-mcp:latest)
- Neo4j database with BloodHound data (via SharpHound collection)
"""

import asyncio
import json
import os
from typing import List, Dict, Any, Optional
from tools.base_tool import BaseTool


class BloodhoundTool(BaseTool):
    """
    Wrapper for BloodHound MCP server - Active Directory attack path analysis.

    This tool delegates to the bloodhound-mcp Docker container which provides
    75+ analysis tools for AD security assessment.
    """

    # Key BloodHound MCP tools organized by category
    MCP_TOOLS = {
        # Attack Path Analysis
        "find_shortest_path": "Find shortest attack path between two nodes",
        "find_all_paths": "Find all attack paths to a target",
        "find_path_to_da": "Find paths to Domain Admins",
        "find_path_to_highvalue": "Find paths to high-value targets",

        # User Analysis
        "get_kerberoastable_users": "Find Kerberoastable users",
        "get_asreproastable_users": "Find AS-REP roastable users",
        "get_users_with_spn": "Find users with SPNs set",
        "get_privileged_users": "Enumerate privileged users",
        "get_users_with_dcsync": "Find users with DCSync rights",

        # Delegation Analysis
        "get_unconstrained_delegation": "Find unconstrained delegation",
        "get_constrained_delegation": "Find constrained delegation",
        "get_rbcd_targets": "Find RBCD attack targets",

        # ACL Analysis
        "get_acl_abuse_paths": "Find ACL abuse opportunities",
        "get_genericall_on_users": "Find GenericAll on users",
        "get_genericwrite_on_users": "Find GenericWrite on users",
        "get_writedacl_paths": "Find WriteDACL abuse paths",
        "get_writeowner_paths": "Find WriteOwner abuse paths",

        # Computer Analysis
        "get_domain_controllers": "List domain controllers",
        "get_computers_with_laps": "Find computers with LAPS",
        "get_computers_without_laps": "Find computers without LAPS",
        "get_computers_with_sessions": "Find computers with active sessions",

        # Group Analysis
        "get_domain_admins": "List Domain Admins members",
        "get_enterprise_admins": "List Enterprise Admins members",
        "get_nested_group_membership": "Analyze nested group memberships",

        # Trust Analysis
        "get_domain_trusts": "Map domain trust relationships",
        "get_forest_trusts": "Map forest trust relationships",

        # Statistics
        "get_domain_stats": "Get domain statistics",
        "get_attack_surface_stats": "Get attack surface summary",
    }

    def __init__(self, config: Dict[str, Any]):
        # MCP-specific configuration
        mcp_config = config.get("mcp", {}).get("servers", {}).get("bloodhound", {})
        self.docker_image = mcp_config.get(
            "image",
            "ghcr.io/fuzzinglabs/bloodhound-mcp:latest"
        )
        self.neo4j_uri = mcp_config.get("neo4j_uri", "bolt://localhost:7687")
        self.neo4j_user = mcp_config.get("neo4j_user", "neo4j")
        self.neo4j_password = mcp_config.get("neo4j_password", "")
        self.timeout = mcp_config.get("timeout", 300)
        # Set tool name before parent init
        self.tool_name = "bloodhound"
        super().__init__(config)

    def _check_installation(self) -> bool:
        """Check if Docker/Podman and the MCP image are available"""
        docker_image = getattr(self, "docker_image", "ghcr.io/fuzzinglabs/bloodhound-mcp:latest")
        try:
            import subprocess
            import shutil

            # Check Docker or Podman is available
            container_cmd = None
            if shutil.which("docker"):
                container_cmd = "docker"
            elif shutil.which("podman"):
                container_cmd = "podman"

            if not container_cmd:
                self.logger.warning("Docker/Podman not available for BloodHound MCP")
                return False

            result = subprocess.run(
                [container_cmd, "info"],
                capture_output=True,
                timeout=10
            )
            if result.returncode != 0:
                self.logger.warning(f"{container_cmd} not running for BloodHound MCP")
                return False

            # Check if image exists (don't pull automatically)
            result = subprocess.run(
                [container_cmd, "images", "-q", docker_image],
                capture_output=True,
                text=True,
                timeout=10
            )
            if not result.stdout.strip():
                self.logger.warning(
                    f"BloodHound MCP image not found. Run: {container_cmd} pull {docker_image}"
                )
                # Still return True - we can pull on demand
            return True
        except Exception as e:
            self.logger.warning(f"BloodHound availability check failed: {e}")
            return False

    def get_command(self, target: str, **kwargs) -> List[str]:
        """
        Build Docker command for BloodHound MCP.

        Note: This returns the docker run command. The actual JSON-RPC
        request is sent via stdin during execution.

        Args:
            target: Domain or specific node to analyze
            **kwargs:
                - tool: Specific MCP tool to run (default: find_path_to_da)
                - start_node: Starting node for path queries
                - end_node: Ending node for path queries
                - max_depth: Maximum path depth (default: 10)
        """
        cmd = [
            "docker", "run", "-i", "--rm",
            "--network", "host",  # Connect to local Neo4j
            "-e", f"NEO4J_URI={self.neo4j_uri}",
            "-e", f"NEO4J_USER={self.neo4j_user}",
        ]

        # Add password if configured
        if self.neo4j_password:
            cmd.extend(["-e", f"NEO4J_PASSWORD={self.neo4j_password}"])

        cmd.append(self.docker_image)
        return cmd

    def _build_mcp_request(
        self,
        tool: str,
        arguments: Dict[str, Any],
        request_id: int = 1
    ) -> str:
        """Build JSON-RPC request for MCP server"""
        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": arguments
            }
        }
        return json.dumps(request)

    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Execute BloodHound analysis via MCP.

        Args:
            target: Domain name or specific node to analyze
            **kwargs:
                - tool: MCP tool name (default: get_attack_surface_stats)
                - Additional tool-specific arguments

        Returns:
            Dict with BloodHound analysis results
        """
        if not self.is_available:
            raise RuntimeError("BloodHound MCP is not available (Docker required)")

        # Determine which tool to run
        tool_name = kwargs.get("tool", "get_attack_surface_stats")
        if tool_name not in self.MCP_TOOLS:
            # Default to attack surface stats if unknown tool
            self.logger.warning(f"Unknown BloodHound tool '{tool_name}', using get_attack_surface_stats")
            tool_name = "get_attack_surface_stats"

        # Build tool arguments
        arguments = {"domain": target}

        # Add path-specific arguments
        if "path" in tool_name.lower():
            if kwargs.get("start_node"):
                arguments["start_node"] = kwargs["start_node"]
            if kwargs.get("end_node"):
                arguments["end_node"] = kwargs["end_node"]
            arguments["max_depth"] = kwargs.get("max_depth", 10)

        # Build command and request
        docker_cmd = self.get_command(target, **kwargs)
        mcp_request = self._build_mcp_request(tool_name, arguments)

        self.logger.info(f"Running BloodHound MCP: {tool_name} on {target}")

        from datetime import datetime
        start_time = datetime.now()
        process: asyncio.subprocess.Process | None = None

        try:
            process = await asyncio.create_subprocess_exec(
                *docker_cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(input=(mcp_request + "\n").encode()),
                timeout=self.timeout
            )

            duration = (datetime.now() - start_time).total_seconds()

            # Parse response
            output = stdout.decode('utf-8', errors='replace')
            error = stderr.decode('utf-8', errors='replace')

            parsed = self.parse_output(output)

            return {
                "tool": "bloodhound",
                "mcp_tool": tool_name,
                "target": target,
                "command": " ".join(docker_cmd),
                "timestamp": start_time.isoformat(),
                "exit_code": process.returncode,
                "duration": duration,
                "raw_output": output,
                "error": error if error else None,
                "parsed": parsed
            }

        except asyncio.CancelledError:
            try:
                if process and process.returncode is None:
                    process.kill()
                    await process.communicate()
            except Exception:
                pass
            raise
        except asyncio.TimeoutError:
            self.logger.error(f"BloodHound MCP timed out after {self.timeout}s")
            try:
                if process and process.returncode is None:
                    process.kill()
                    await process.communicate()
            except Exception:
                pass
            raise
        except Exception as e:
            self.logger.error(f"BloodHound MCP execution failed: {e}")
            raise

    def parse_output(self, output: str) -> Dict[str, Any]:
        """
        Parse BloodHound MCP JSON-RPC response.

        Returns structured data with:
        - Attack paths found
        - Vulnerable users/computers
        - Statistics and summaries
        """
        result = {
            "attack_paths": [],
            "kerberoastable_users": [],
            "asreproastable_users": [],
            "delegation_issues": [],
            "acl_abuse_paths": [],
            "privileged_users": [],
            "domain_stats": {},
            "findings": [],
            "raw_response": output
        }

        if not output.strip():
            return result

        try:
            # Parse JSON-RPC response
            for line in output.strip().split('\n'):
                if not line.strip():
                    continue
                try:
                    response = json.loads(line)
                    if "result" in response:
                        data = response["result"]
                        result = self._extract_findings(data, result)
                        break
                    elif "error" in response:
                        result["error"] = response["error"]
                        break
                except json.JSONDecodeError:
                    continue

        except Exception as e:
            self.logger.warning(f"Failed to parse BloodHound output: {e}")
            result["parse_error"] = str(e)

        return result

    def _extract_findings(
        self,
        data: Dict[str, Any],
        result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract security findings from BloodHound response"""

        # Handle different response types
        if isinstance(data, dict):
            content = data.get("content", [])
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        text = item.get("text", "")
                        try:
                            parsed_data = json.loads(text)
                            result = self._categorize_findings(parsed_data, result)
                        except json.JSONDecodeError:
                            # Plain text result
                            result["findings"].append({"type": "text", "data": text})

        return result

    def _categorize_findings(
        self,
        data: Any,
        result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Categorize findings by type"""

        if isinstance(data, list):
            for item in data:
                finding = self._classify_finding(item)
                if finding:
                    category = finding.get("category", "findings")
                    if category in result and isinstance(result[category], list):
                        result[category].append(finding)
                    else:
                        result["findings"].append(finding)

        elif isinstance(data, dict):
            # Statistics or single finding
            if "users" in data or "computers" in data or "groups" in data:
                result["domain_stats"] = data
            else:
                result["findings"].append(data)

        return result

    def _classify_finding(self, item: Any) -> Optional[Dict[str, Any]]:
        """Classify a finding into appropriate category"""
        if not isinstance(item, dict):
            return {"type": "unknown", "data": item}

        # Detect finding type based on content
        if "path" in item or "nodes" in item:
            return {"category": "attack_paths", **item}
        elif "spn" in str(item).lower() or "kerberoast" in str(item).lower():
            return {"category": "kerberoastable_users", **item}
        elif "asrep" in str(item).lower():
            return {"category": "asreproastable_users", **item}
        elif "delegation" in str(item).lower():
            return {"category": "delegation_issues", **item}
        elif any(x in str(item).lower() for x in ["genericall", "writedacl", "writeowner"]):
            return {"category": "acl_abuse_paths", **item}
        elif any(x in str(item).lower() for x in ["admin", "privileged", "dcsync"]):
            return {"category": "privileged_users", **item}
        else:
            return {"category": "findings", **item}

    async def run_comprehensive_analysis(self, domain: str) -> Dict[str, Any]:
        """
        Run comprehensive BloodHound analysis on a domain.

        Executes multiple tools to build complete attack surface picture:
        1. Domain statistics
        2. Path to Domain Admins
        3. Kerberoastable users
        4. AS-REP roastable users
        5. Delegation issues
        6. ACL abuse paths

        Args:
            domain: Target domain name

        Returns:
            Comprehensive analysis results
        """
        tools_to_run = [
            "get_domain_stats",
            "find_path_to_da",
            "get_kerberoastable_users",
            "get_asreproastable_users",
            "get_unconstrained_delegation",
            "get_acl_abuse_paths",
        ]

        results = {
            "domain": domain,
            "analysis_type": "comprehensive",
            "tool_results": {},
            "summary": {
                "total_paths_to_da": 0,
                "kerberoastable_count": 0,
                "asreproastable_count": 0,
                "delegation_issues": 0,
                "acl_abuse_paths": 0,
                "risk_level": "unknown"
            }
        }

        for tool in tools_to_run:
            try:
                tool_result = await self.execute(domain, tool=tool)
                results["tool_results"][tool] = tool_result.get("parsed", {})
            except Exception as e:
                self.logger.warning(f"BloodHound tool {tool} failed: {e}")
                results["tool_results"][tool] = {"error": str(e)}

        # Calculate summary
        self._calculate_summary(results)

        return results

    def _calculate_summary(self, results: Dict[str, Any]) -> None:
        """Calculate risk summary from analysis results"""
        summary = results["summary"]

        for tool, data in results.get("tool_results", {}).items():
            if isinstance(data, dict):
                if "attack_paths" in data:
                    summary["total_paths_to_da"] += len(data["attack_paths"])
                if "kerberoastable_users" in data:
                    summary["kerberoastable_count"] += len(data["kerberoastable_users"])
                if "asreproastable_users" in data:
                    summary["asreproastable_count"] += len(data["asreproastable_users"])
                if "delegation_issues" in data:
                    summary["delegation_issues"] += len(data["delegation_issues"])
                if "acl_abuse_paths" in data:
                    summary["acl_abuse_paths"] += len(data["acl_abuse_paths"])

        # Calculate risk level
        risk_score = (
            summary["total_paths_to_da"] * 10 +
            summary["kerberoastable_count"] * 3 +
            summary["asreproastable_count"] * 5 +
            summary["delegation_issues"] * 8 +
            summary["acl_abuse_paths"] * 4
        )

        if risk_score >= 50:
            summary["risk_level"] = "critical"
        elif risk_score >= 25:
            summary["risk_level"] = "high"
        elif risk_score >= 10:
            summary["risk_level"] = "medium"
        elif risk_score > 0:
            summary["risk_level"] = "low"
        else:
            summary["risk_level"] = "minimal"
