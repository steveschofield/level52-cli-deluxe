"""
subjs wrapper for JavaScript URL extraction
"""

from typing import Dict, Any, List
from tools.base_tool import BaseTool


class SubjsTool(BaseTool):
    """subjs wrapper"""

    def is_success_exit_code(self, exit_code: int) -> bool:
        """
        subjs exit codes:
        0 = Success
        2 = No results found or input file empty (not a failure)
        """
        return exit_code in (0, 2)

    def get_command(self, target: str, **kwargs) -> List[str]:
        """
        Build subjs command.

        subjs expects input file with -i flag (not -iL).
        Usage: subjs -i urls.txt
        """
        command = ["subjs"]

        # subjs requires an input file with -i flag
        if kwargs.get("from_file"):
            command.extend(["-i", kwargs["from_file"]])
        else:
            # If no file provided, we need to create a temp file or pipe stdin
            # For now, pass target as input file path if it exists
            command.extend(["-i", target])

        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        urls = [line.strip() for line in output.splitlines() if line.strip()]
        return {"urls": urls}
