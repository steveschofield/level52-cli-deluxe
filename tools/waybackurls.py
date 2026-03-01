"""
waybackurls tool wrapper for historical URL enumeration
"""

from typing import Dict, Any, List

from tools.base_tool import BaseTool


class WaybackurlsTool(BaseTool):
    """waybackurls wrapper"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "waybackurls"

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build waybackurls command"""
        command = ["waybackurls"]

        from_file = kwargs.get("from_file")
        if from_file:
            # waybackurls has no -l flag; accepts domains as positional args or stdin.
            # Read domain list from file and pass each as a separate argument.
            try:
                with open(from_file) as fh:
                    domains = [ln.strip() for ln in fh if ln.strip()]
                command.extend(domains if domains else [target])
            except OSError:
                command.append(target)
        else:
            command.append(target)

        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse plain-text URL output"""
        urls = []
        for line in output.strip().splitlines():
            url = line.strip()
            if url and url not in urls:
                urls.append(url)

        return {"urls": urls}
