"""
FFuf tool wrapper for fast web fuzzing
"""

import os
import json
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class FFufTool(BaseTool):
    """FFuf fast web fuzzer wrapper"""
    
    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "ffuf"
        self._last_output_file = None
    
    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build ffuf command"""
        config = self.config.get("tools", {}).get("ffuf", {})
        
        command = ["ffuf"]
        
        # Target URL with FUZZ keyword unless explicitly disabled
        append_fuzz = kwargs.get("append_fuzz", True)
        if append_fuzz and "FUZZ" not in target:
            target = f"{target}/FUZZ"
        command.extend(["-u", target])
        
        # Wordlist (required)
        wordlist = kwargs.get("wordlist", config.get("wordlist", "/usr/share/wordlists/dirb/common.txt"))
        wordlist = os.path.expandvars(os.path.expanduser(wordlist))
        command.extend(["-w", wordlist])
        
        # JSON output for parsing
        command.extend(["-of", "json"])
        output_file = kwargs.get("output_file")
        if output_file:
            output_file = os.path.expandvars(os.path.expanduser(str(output_file)))
            self._last_output_file = output_file
            command.extend(["-o", output_file])
        else:
            self._last_output_file = None
            command.extend(["-o", "-"])  # Output to stdout
        
        # Threads
        threads = config.get("threads", 40)
        command.extend(["-t", str(threads)])
        
        # Timeout
        timeout = config.get("timeout", 10)
        command.extend(["-timeout", str(timeout)])
        
        # Filter by status code
        if "filter_status" in kwargs:
            command.extend(["-fc", kwargs["filter_status"]])
        
        # Match status code
        if "match_status" in kwargs:
            command.extend(["-mc", kwargs["match_status"]])
        else:
            # Default: match success codes
            command.extend(["-mc", "200,204,301,302,307,401,403"])
        
        # Filter by size
        if "filter_size" in kwargs:
            command.extend(["-fs", str(kwargs["filter_size"])])
        
        # Extensions
        if "extensions" in kwargs:
            command.extend(["-e", kwargs["extensions"]])

        # Custom headers
        headers = kwargs.get("headers")
        if headers:
            if isinstance(headers, list):
                for h in headers:
                    if h:
                        command.extend(["-H", str(h)])
            else:
                command.extend(["-H", str(headers)])
        
        # Recursion
        if kwargs.get("recursion"):
            command.append("-recursion")
            recursion_depth = kwargs.get("recursion_depth", 1)
            command.extend(["-recursion-depth", str(recursion_depth)])
        
        # Follow redirects
        if config.get("follow_redirects", False):
            command.append("-r")
        
        # Rate limit (requests per second)
        if "rate" in kwargs:
            command.extend(["-rate", str(kwargs["rate"])])
        
        # Silent mode (less verbose)
        command.append("-s")
        
        return command
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse ffuf JSON output"""
        results = {
            "discovered_paths": [],
            "status_codes": {},
            "sizes": {},
            "total_requests": 0,
            "total_filtered": 0
        }
        
        try:
            raw_output = output.strip()
            file_output = None
            if self._last_output_file and os.path.exists(self._last_output_file):
                try:
                    with open(self._last_output_file, "r", encoding="utf-8") as f:
                        file_output = f.read().strip()
                except OSError:
                    file_output = None

            data = None
            for candidate in (raw_output, file_output):
                if not candidate:
                    continue
                try:
                    data = json.loads(candidate)
                    break
                except json.JSONDecodeError:
                    continue

            if not data:
                return results

            # Extract results
            if "results" in data:
                for result in data["results"]:
                    url = result.get("url", "")
                    status = result.get("status", 0)
                    length = result.get("length", 0)

                    results["discovered_paths"].append({
                        "url": url,
                        "status": status,
                        "length": length,
                        "words": result.get("words", 0),
                        "lines": result.get("lines", 0)
                    })

                    results["status_codes"][url] = status
                    results["sizes"][url] = length

            # Extract metadata
            if "config" in data:
                results["total_requests"] = data.get("config", {}).get("matcher", {}).get("count", 0)

        except json.JSONDecodeError:
            # Fallback: ignore invalid JSON
            pass
        
        return results
