"""
MCP (Model Context Protocol) Client for Guardian

Enables Guardian to interact with Dockerized MCP security servers
such as BloodHound, radare2, YARA, and other tools from the
FuzzingLabs MCP Security Hub.

Protocol: JSON-RPC 2.0 over stdin/stdout
"""

import asyncio
import json
import subprocess
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime

from utils.logger import get_logger


@dataclass
class MCPServerConfig:
    """Configuration for an MCP server"""
    name: str
    image: str
    capabilities: List[str] = field(default_factory=list)
    volumes: List[str] = field(default_factory=list)
    env: List[str] = field(default_factory=list)
    network: Optional[str] = None
    timeout: int = 300


class MCPClient:
    """
    Client for invoking MCP (Model Context Protocol) security servers.

    MCP servers run as Docker containers and communicate via JSON-RPC 2.0
    over stdin/stdout. This client handles:
    - Docker container lifecycle
    - JSON-RPC request/response handling
    - Tool enumeration and invocation
    - Error handling and timeouts

    Example usage:
        client = MCPClient(config)
        tools = await client.list_tools("bloodhound")
        result = await client.call_tool("bloodhound", "find_path", {
            "start_node": "user@domain.local",
            "end_node": "Domain Admins"
        })
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = get_logger(config)
        self._request_id = 0
        self._servers: Dict[str, MCPServerConfig] = {}
        self._load_server_configs()

    def _load_server_configs(self) -> None:
        """Load MCP server configurations from guardian.yaml"""
        mcp_config = self.config.get("mcp", {})
        if not mcp_config.get("enabled", False):
            return

        servers = mcp_config.get("servers", {})
        for name, server_cfg in servers.items():
            if not server_cfg:
                continue
            if server_cfg.get("enabled") is False:
                self.logger.debug(f"MCP server '{name}' disabled by config")
                continue
            self._servers[name] = MCPServerConfig(
                name=name,
                image=server_cfg.get("image", f"ghcr.io/fuzzinglabs/{name}-mcp:latest"),
                capabilities=server_cfg.get("capabilities", []),
                volumes=server_cfg.get("volumes", []),
                env=server_cfg.get("env", []),
                network=server_cfg.get("network"),
                timeout=server_cfg.get("timeout", 300)
            )

    def _next_request_id(self) -> int:
        """Generate next JSON-RPC request ID"""
        self._request_id += 1
        return self._request_id

    def _build_docker_command(self, server: MCPServerConfig) -> List[str]:
        """Build docker run command for an MCP server"""
        cmd = ["docker", "run", "-i", "--rm"]

        # Add capabilities
        for cap in server.capabilities:
            cmd.extend(["--cap-add", cap])

        # Add volumes
        for vol in server.volumes:
            cmd.extend(["-v", vol])

        # Add environment variables
        for env_var in server.env:
            cmd.extend(["-e", env_var])

        # Add network if specified
        if server.network:
            cmd.extend(["--network", server.network])

        # Add image
        cmd.append(server.image)

        return cmd

    async def _send_request(
        self,
        server_name: str,
        method: str,
        params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Send a JSON-RPC request to an MCP server.

        Args:
            server_name: Name of the MCP server
            method: JSON-RPC method to call
            params: Optional parameters for the method

        Returns:
            JSON-RPC response result

        Raises:
            RuntimeError: If server not configured or request fails
        """
        if server_name not in self._servers:
            raise RuntimeError(f"MCP server '{server_name}' not configured")

        server = self._servers[server_name]
        docker_cmd = self._build_docker_command(server)

        # Build JSON-RPC request
        request = {
            "jsonrpc": "2.0",
            "id": self._next_request_id(),
            "method": method
        }
        if params:
            request["params"] = params

        request_json = json.dumps(request) + "\n"

        self.logger.debug(f"MCP request to {server_name}: {method}")

        process: Optional[asyncio.subprocess.Process] = None
        try:
            # Run docker container and pipe request
            process = await asyncio.create_subprocess_exec(
                *docker_cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(input=request_json.encode()),
                timeout=server.timeout
            )

            if process.returncode != 0:
                error_msg = stderr.decode('utf-8', errors='replace')
                raise RuntimeError(f"MCP server error: {error_msg}")

            # Parse JSON-RPC response
            response_text = stdout.decode('utf-8', errors='replace').strip()
            if not response_text:
                raise RuntimeError("Empty response from MCP server")

            # Handle multiple JSON objects (some servers send multiple responses)
            for line in response_text.split('\n'):
                if line.strip():
                    try:
                        response = json.loads(line)
                        if "result" in response or "error" in response:
                            break
                    except json.JSONDecodeError:
                        continue
            else:
                response = json.loads(response_text.split('\n')[0])

            if "error" in response:
                error = response["error"]
                raise RuntimeError(f"MCP error: {error.get('message', error)}")

            return response.get("result", {})

        except asyncio.CancelledError:
            try:
                if process and process.returncode is None:
                    process.kill()
                    await process.communicate()
            except Exception:
                pass
            raise
        except asyncio.TimeoutError:
            self.logger.error(f"MCP server {server_name} timed out")
            try:
                if process and process.returncode is None:
                    process.kill()
                    await process.communicate()
            except Exception:
                pass
            raise RuntimeError(f"MCP server '{server_name}' timed out after {server.timeout}s")
        except Exception as e:
            self.logger.error(f"MCP request failed: {e}")
            raise

    async def list_tools(self, server_name: str) -> List[Dict[str, Any]]:
        """
        List available tools from an MCP server.

        Args:
            server_name: Name of the MCP server

        Returns:
            List of tool definitions with name, description, and parameters
        """
        result = await self._send_request(server_name, "tools/list")
        return result.get("tools", [])

    async def call_tool(
        self,
        server_name: str,
        tool_name: str,
        arguments: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Call a tool on an MCP server.

        Args:
            server_name: Name of the MCP server
            tool_name: Name of the tool to call
            arguments: Tool arguments

        Returns:
            Tool execution result
        """
        params = {
            "name": tool_name,
            "arguments": arguments
        }
        return await self._send_request(server_name, "tools/call", params)

    def is_server_available(self, server_name: str) -> bool:
        """Check if an MCP server is configured"""
        return server_name in self._servers

    def get_available_servers(self) -> List[str]:
        """Get list of configured MCP server names"""
        return list(self._servers.keys())

    async def check_docker_available(self) -> bool:
        """Check if Docker is available"""
        try:
            process = await asyncio.create_subprocess_exec(
                "docker", "info",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await process.wait()
            return process.returncode == 0
        except Exception:
            return False

    async def pull_server_image(self, server_name: str) -> bool:
        """Pull the Docker image for an MCP server"""
        if server_name not in self._servers:
            return False

        server = self._servers[server_name]
        self.logger.info(f"Pulling MCP server image: {server.image}")

        try:
            process = await asyncio.create_subprocess_exec(
                "docker", "pull", server.image,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.wait()
            return process.returncode == 0
        except Exception as e:
            self.logger.error(f"Failed to pull image {server.image}: {e}")
            return False
