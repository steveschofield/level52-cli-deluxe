import os
import json
import tempfile
import uuid
from typing import List, Dict, Any
from tools.base_tool import BaseTool

class DnsReconTool(BaseTool):
    """Wrapper for DnsRecon - DNS Enumeration Script"""
    
    def get_command(self, target: str, **kwargs) -> List[str]:
        cmd = ["dnsrecon", "-d", target]
        
        # Output to JSON
        self.output_file = os.path.join(tempfile.gettempdir(), f"guardian-dnsrecon-{uuid.uuid4().hex}.json")
        cmd.extend(["-j", self.output_file])
        
        # Tool options
        if kwargs.get("type"):
            cmd.extend(["-t", kwargs["type"]]) # std, rvl, brt, etc.
            
        if kwargs.get("dictionary"):
            cmd.extend(["-D", kwargs["dictionary"]])
            
        if kwargs.get("threads"):
            cmd.extend(["--threads", str(kwargs["threads"])])

        return cmd
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        result = {
            "records": [],
            "raw_output": output
        }
        
        if not hasattr(self, "output_file") or not os.path.exists(self.output_file):
            return result

        try:
            with open(self.output_file, 'r') as f:
                data = json.load(f)
            if isinstance(data, list):
                result["records"] = data
        except Exception as e:
            self.logger.error(f"Error parsing DnsRecon JSON: {e}")
        finally:
            try:
                os.remove(self.output_file)
            except OSError:
                pass

        return result
