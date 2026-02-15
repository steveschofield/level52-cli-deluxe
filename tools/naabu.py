"""
naabu tool wrapper for fast port scanning
"""

import json
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class NaabuTool(BaseTool):
    """naabu port scanner wrapper"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "naabu"

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build naabu command"""
        config = self.config.get("tools", {}).get("naabu", {})

        command = ["naabu", "-json"]

        # Rate limit
        rate = config.get("rate", 1000)
        if rate:
            command.extend(["-rate", str(rate)])

        # Port selection: prefer explicit ports, fall back to top ports
        ports = config.get("ports")
        top_ports = config.get("top_ports", 100)
        if ports:
            command.extend(["-p", str(ports)])
        elif top_ports:
            command.extend(["-top-ports", str(top_ports)])

        # Exclude CDN ranges if configured
        if config.get("exclude_cdn", True):
            command.append("-exclude-cdn")

        # Input target(s)
        if kwargs.get("from_file"):
            command.extend(["-list", kwargs["from_file"]])
        else:
            command.extend(["-host", target])

        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse naabu JSONL output"""
        results = {
            "hosts": {},
            "open_ports": []
        }

        for line in output.strip().splitlines():
            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            host = data.get("host") or data.get("ip")
            port = data.get("port")
            protocol = data.get("proto") or data.get("protocol")

            if host and port:
                entry = {"host": host, "port": port, "protocol": protocol}
                results["open_ports"].append(entry)

                host_ports = results["hosts"].setdefault(host, [])
                host_ports.append(port)

        return results
