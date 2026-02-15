"""
shuffledns wrapper for permutation-based DNS enumeration
"""

import os
from typing import Dict, Any, List
from tools.base_tool import BaseTool


class ShufflednsTool(BaseTool):
    """shuffledns wrapper"""

    def get_command(self, target: str, **kwargs) -> List[str]:
        config = self.config.get("tools", {}).get("shuffledns", {})
        command = ["shuffledns", "-d", target]

        wordlist = kwargs.get("wordlist") or config.get("wordlist")
        if wordlist:
            wordlist = os.path.expandvars(os.path.expanduser(str(wordlist)))
            command.extend(["-w", wordlist])

        resolvers = kwargs.get("resolvers") or config.get("resolvers")
        if resolvers:
            resolvers = os.path.expandvars(os.path.expanduser(str(resolvers)))
            command.extend(["-r", resolvers])

        massdns = kwargs.get("massdns") or config.get("massdns")
        if massdns:
            massdns = os.path.expandvars(os.path.expanduser(str(massdns)))
            command.extend(["-m", massdns])

        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        return {"subdomains": lines}
