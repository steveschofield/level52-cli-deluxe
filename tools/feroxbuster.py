"""
Feroxbuster tool wrapper for directory and API endpoint discovery
"""

import json
from typing import Dict, Any, List
from tools.base_tool import BaseTool


class FeroxbusterTool(BaseTool):
    """Feroxbuster directory/API endpoint scanner wrapper"""

    def is_success_exit_code(self, exit_code: int) -> bool:
        """
        feroxbuster exit codes:
        0 = Success
        2 = No results found or target unreachable (not a failure)
        """
        return exit_code in (0, 2)

    def get_command(self, target: str, **kwargs) -> List[str]:
        command = ["feroxbuster", "-u", target, "--json"]
        
        # API-focused wordlists
        if kwargs.get("api_mode"):
            command.extend(["-w", "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"])
            command.extend(["-x", "json,xml,php,asp,aspx,jsp"])
        
        if kwargs.get("wordlist"):
            command.extend(["-w", kwargs["wordlist"]])
            
        if kwargs.get("extensions"):
            command.extend(["-x", kwargs["extensions"]])
            
        if kwargs.get("depth"):
            command.extend(["-d", str(kwargs["depth"])])
            
        return command
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse Feroxbuster JSON output"""
        endpoints = []
        api_endpoints = []
        
        for line in output.strip().split('\n'):
            if not line:
                continue
            try:
                data = json.loads(line)
                if data.get("type") == "response":
                    url = data.get("url", "")
                    status = data.get("status", 0)
                    
                    endpoints.append({
                        "url": url,
                        "status": status,
                        "length": data.get("content_length", 0),
                        "words": data.get("word_count", 0)
                    })
                    
                    # Identify potential API endpoints
                    if any(api_indicator in url.lower() for api_indicator in 
                          ["/api/", "/v1/", "/v2/", ".json", "/rest/", "/graphql"]):
                        api_endpoints.append(url)
                        
            except json.JSONDecodeError:
                continue
        
        return {
            "endpoints": endpoints,
            "api_endpoints": api_endpoints,
            "total_found": len(endpoints),
            "api_count": len(api_endpoints)
        }