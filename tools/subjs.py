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

        subjs expects an input file of URLs via -i.  It cannot operate on a
        bare host/IP — it needs a seed list of page/JS URLs to scrape from.
        Raises ValueError when no seed file is available so the caller skips
        the tool rather than spawning a process that will immediately fail.
        """
        from_file = kwargs.get("from_file")
        if not from_file:
            raise ValueError(
                "subjs requires a URL seed file (from_file); skipping — "
                "run after web crawling has produced a URL list"
            )

        return ["subjs", "-i", from_file]

    def parse_output(self, output: str) -> Dict[str, Any]:
        urls = [line.strip() for line in output.splitlines() if line.strip()]
        return {"urls": urls}
