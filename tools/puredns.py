"""
puredns wrapper for DNS resolution
"""

import os
from typing import Dict, Any, List
from tools.base_tool import BaseTool


class PurednsTool(BaseTool):
    """puredns wrapper"""

    def get_command(self, target: str, **kwargs) -> List[str]:
        config = self.config.get("tools", {}).get("puredns", {})

        # Usually used as resolver for shuffledns; here simple resolve mode
        command = ["puredns", "resolve", target]

        resolvers = kwargs.get("resolvers") or config.get("resolvers")
        if resolvers:
            resolvers = os.path.expandvars(os.path.expanduser(str(resolvers)))
            command.extend(["-r", resolvers])

        wordlist = kwargs.get("wordlist") or config.get("wordlist")
        if wordlist:
            wordlist = os.path.expandvars(os.path.expanduser(str(wordlist)))
            command.extend(["-w", wordlist])
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        return {"resolved": lines}
