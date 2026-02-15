"""
WhatWeb tool wrapper for web technology fingerprinting
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class WhatWebTool(BaseTool):
    """WhatWeb technology fingerprinting wrapper"""
    
    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "whatweb"
        self._last_log_path = None
    
    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build whatweb command"""
        self._last_log_path = None
        command = ["whatweb"]
        
        # JSON output for parsing (write to file to avoid stream-close issues)
        out_dir = Path((self.config or {}).get("output", {}).get("save_path", "./reports"))
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        log_file = out_dir / f"whatweb_{ts}.json"
        self._last_log_path = str(log_file)
        command.append(f"--log-json={self._last_log_path}")
        
        # Aggression level (1-4)
        aggression = kwargs.get("aggression", 1)
        command.extend(["-a", str(aggression)])
        
        # Follow redirects
        if kwargs.get("follow_redirects", True):
            command.append("--follow-redirect=always")
        
        # User agent
        user_agent = kwargs.get("user_agent", "Guardian-Pentest-Tool")
        command.extend(["--user-agent", user_agent])
        
        # Target
        command.append(target)
        
        return command
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse whatweb JSON output"""
        results = {
            "technologies": [],
            "web_server": None,
            "programming_languages": [],
            "cms": None,
            "javascript_frameworks": [],
            "http_status": None,
            "plugins": []
        }

        raw_output = output
        if self._last_log_path and os.path.isfile(self._last_log_path):
            try:
                with open(self._last_log_path, "r", encoding="utf-8") as f:
                    raw_output = f.read()
            except Exception:
                raw_output = output

        # Parse JSON lines
        for line in raw_output.strip().split('\n'):
            if not line:
                continue
            
            try:
                data = json.loads(line)
                
                # HTTP status
                if "http_status" in data:
                    results["http_status"] = data["http_status"]
                
                # Extract plugins (technologies)
                plugins = data.get("plugins", {})
                
                for plugin_name, plugin_data in plugins.items():
                    tech = {
                        "name": plugin_name,
                        "version": None,
                        "categories": []
                    }
                    
                    # Extract version if available
                    if isinstance(plugin_data, dict):
                        version = plugin_data.get("version")
                        if version:
                            tech["version"] = version[0] if isinstance(version, list) else version
                    
                    results["plugins"].append(tech)
                    
                    # Categorize common technologies
                    plugin_lower = plugin_name.lower()
                    
                    if plugin_name in ["Apache", "nginx", "IIS", "LiteSpeed"]:
                        results["web_server"] = tech
                    elif plugin_name in ["PHP", "Python", "Ruby", "ASP.NET"]:
                        results["programming_languages"].append(plugin_name)
                    elif plugin_name in ["WordPress", "Joomla", "Drupal"]:
                        results["cms"] = tech
                    elif plugin_name in ["jQuery", "React", "Vue", "Angular"]:
                        results["javascript_frameworks"].append(plugin_name)
                    
                    results["technologies"].append(plugin_name)
                
            except json.JSONDecodeError:
                continue
        
        return results
