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

        if kwargs.get("from_file"):
            command.extend(["-l", kwargs["from_file"]])
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
