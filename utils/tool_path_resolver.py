"""
Tool path discovery utilities.

Resolves tool binaries from config overrides or PATH.
"""

import os
import shutil
from pathlib import Path
from typing import Optional, Dict

from utils.logger import get_logger


class ToolPathResolver:
    """Resolves tool paths from config or system PATH."""

    def __init__(self, config: Dict | None):
        self.config = config or {}
        self.tool_paths = (self.config.get("tools", {}) or {}).get("paths", {}) or {}
        self.auto_discover = (self.config.get("tools", {}) or {}).get("auto_discover", True)
        self._cache: Dict[str, Optional[str]] = {}
        self.logger = get_logger(self.config)

    def resolve_tool_path(self, tool_name: str) -> Optional[str]:
        """Resolve tool path from config or PATH."""
        if not tool_name:
            return None

        if tool_name in self._cache:
            return self._cache[tool_name]

        # Configured path override
        if tool_name in self.tool_paths:
            configured_path = str(self.tool_paths[tool_name])
            configured_path = os.path.expandvars(os.path.expanduser(configured_path))
            if Path(configured_path).exists():
                self._cache[tool_name] = configured_path
                return configured_path
            self.logger.warning(
                f"Configured path for {tool_name} does not exist: {configured_path}"
            )

        # Auto-discover from PATH
        if self.auto_discover:
            path = shutil.which(tool_name)
            if path:
                self._cache[tool_name] = path
                return path

        self._cache[tool_name] = None
        return None

    def is_tool_available(self, tool_name: str) -> bool:
        """Check if tool is available."""
        return self.resolve_tool_path(tool_name) is not None

    def get_all_available_tools(self) -> Dict[str, str]:
        """Get all available tools and their paths."""
        available: Dict[str, str] = {}

        for tool_name in self.tool_paths.keys():
            path = self.resolve_tool_path(tool_name)
            if path:
                available[tool_name] = path

        if self.auto_discover:
            common_tools = [
                "nmap",
                "nikto",
                "sqlmap",
                "ffuf",
                "whatweb",
                "wafw00f",
                "nuclei",
                "subfinder",
                "masscan",
                "hydra",
                "amass",
                "testssl.sh",
                "sslyze",
                "arjun",
                "kiterunner",
                "feroxbuster",
            ]
            for tool in common_tools:
                if tool in available:
                    continue
                path = self.resolve_tool_path(tool)
                if path:
                    available[tool] = path

        return available

    def validate_required_tools(self, required_tools: list[str]) -> tuple[bool, list[str]]:
        """Validate that required tools are available."""
        missing = []
        for tool in required_tools:
            if not self.is_tool_available(tool):
                missing.append(tool)

        return len(missing) == 0, missing
