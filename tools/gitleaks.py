import os
import json
import tempfile
import uuid
from typing import List, Dict, Any
from tools.base_tool import BaseTool

class GitleaksTool(BaseTool):
    """Wrapper for Gitleaks - Secret Scanning Tool"""
    
    def get_command(self, target: str, **kwargs) -> List[str]:
        # Gitleaks usually scans git repos or directories
        # Target can be a path or a repo URL
        
        cmd = ["gitleaks", "detect"]
        
        # Determine source type
        if target.startswith("http") or target.startswith("git@"):
            # It's a remote repo, need to clone first or use specific flag if supported
            # Gitleaks 'detect' works on local; 'git' command might be needed
            # For simplicity, we assume target is a local path in typical CLI usage, 
            # OR we use 'git clone' before (but that's outside tool scope).
            # Actually, gitleaks has a 'git' mode or input from pipe. 
            # Let's assume the user points it to a source directory.
            cmd.extend(["--source", target])
        else:
            cmd.extend(["--source", target])
            
        # Output to JSON
        self.output_file = os.path.join(tempfile.gettempdir(), f"guardian-gitleaks-{uuid.uuid4().hex}.json")
        cmd.extend(["--report-path", self.output_file, "--report-format", "json"])
        
        if kwargs.get("verbose"):
            cmd.append("-v")

        return cmd
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        result = {
            "leaks": [],
            "count": 0,
            "raw_output": output
        }
        
        if not hasattr(self, "output_file") or not os.path.exists(self.output_file):
            return result

        try:
            with open(self.output_file, 'r') as f:
                data = json.load(f)
            if isinstance(data, list):
                result["leaks"] = data
                result["count"] = len(data)
        except Exception as e:
            self.logger.error(f"Error parsing Gitleaks JSON: {e}")
        finally:
            try:
                os.remove(self.output_file)
            except OSError:
                pass

        return result
