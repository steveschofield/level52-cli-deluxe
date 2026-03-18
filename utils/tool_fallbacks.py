"""
Fallback tool implementations for missing ProjectDiscovery tools
Uses alternative tools when httpx is not available
"""

import asyncio
from typing import Dict, Any


class HttpxFallback:
    """Fallback for httpx using curl"""
    
    def __init__(self, config):
        self.config = config
    
    async def probe_url(self, url: str) -> Dict[str, Any]:
        """Probe single URL using curl"""
        try:
            cmd = [
                "curl", "-s", "-I", "-L", "--max-time", "10",
                "--user-agent", "Guardian-Scanner/1.0",
                url
            ]
            
            result = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if result.returncode == 0:
                headers = stdout.decode('utf-8', errors='ignore')
                status_code = self._extract_status_code(headers)
                server = self._extract_header(headers, 'Server')
                
                return {
                    "url": url,
                    "status_code": status_code,
                    "server": server,
                    "method": "GET",
                    "success": True
                }
            else:
                return {"url": url, "success": False, "error": stderr.decode()}
                
        except Exception as e:
            return {"url": url, "success": False, "error": str(e)}
    
    def _extract_status_code(self, headers: str) -> int:
        """Extract HTTP status code from headers"""
        lines = headers.split('\n')
        for line in lines:
            if line.startswith('HTTP/'):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        return int(parts[1])
                    except ValueError:
                        pass
        return 0
    
    def _extract_header(self, headers: str, header_name: str) -> str:
        """Extract specific header value"""
        lines = headers.split('\n')
        for line in lines:
            if line.lower().startswith(header_name.lower() + ':'):
                return line.split(':', 1)[1].strip()
        return ""
