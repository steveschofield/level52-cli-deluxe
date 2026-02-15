"""
graphql-cop tool wrapper for GraphQL testing
"""

import os
import shutil
import sys
from typing import Dict, Any, List
from pathlib import Path

from tools.base_tool import BaseTool


class GraphqlCopTool(BaseTool):
    """graphql-cop wrapper"""

    def __init__(self, config):
        self._script = None
        super().__init__(config)
        self.tool_name = "graphql-cop"

    def is_success_exit_code(self, exit_code: int) -> bool:
        """
        GraphQL-cop exit codes:
        0 = Success
        1 = No GraphQL endpoint found or tests failed (expected if target doesn't have GraphQL)
        """
        return exit_code == 0

    def _check_installation(self) -> bool:
        cfg = (self.config or {}).get("tools", {}).get("graphql_cop", {}) or {}
        binary = cfg.get("binary")
        script = cfg.get("script")

        if script and os.path.isfile(str(script)):
            self._script = str(script)
            return True

        repo_root = Path(__file__).resolve().parent.parent
        vendored = repo_root / "tools" / "vendor" / "graphql-cop" / "graphql-cop.py"
        if vendored.is_file():
            self._script = str(vendored)
            return True

        if binary and os.path.isfile(str(binary)):
            return True

        if shutil.which("graphql-cop"):
            return True

        return False

    def get_command(self, target: str, **kwargs) -> List[str]:
        cfg = (self.config or {}).get("tools", {}).get("graphql_cop", {}) or {}
        args = kwargs.get("args") if "args" in kwargs else cfg.get("args")

        if args:
            args = str(args).replace("{target}", target)
            if self._script:
                return [sys.executable, self._script] + args.split()
            binary = cfg.get("binary") or "graphql-cop"
            return [binary] + args.split()

        raise ValueError("graphql-cop requires args in config (e.g., -t https://host/graphql)")

    def parse_output(self, output: str) -> Dict[str, Any]:
        result = {"raw": output}

        # Check if GraphQL endpoint wasn't found (common and expected)
        if "connection refused" in output.lower() or "404" in output or "not found" in output.lower():
            result["endpoint_not_found"] = True
            result["note"] = "GraphQL endpoint not available (expected if target doesn't use GraphQL)"

        return result
