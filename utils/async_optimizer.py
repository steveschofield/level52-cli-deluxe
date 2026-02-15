"""
Async optimization utilities for Guardian
Handles parallel tool execution and memory management
"""

import asyncio
import gzip
import json
from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime

class AsyncOptimizer:
    """Handles async optimizations for Guardian workflow"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.max_parallel = config.get("pentest", {}).get("max_parallel_tools", 5)
        self.compress_outputs = config.get("output", {}).get("compress_large_outputs", True)
        self.max_output_mb = config.get("output", {}).get("max_output_size_mb", 50)
        self.truncate_verbose = config.get("output", {}).get("truncate_verbose_tools", True)
        
    async def execute_parallel_tools(self, tool_tasks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Execute multiple tools in parallel with concurrency limit"""
        semaphore = asyncio.Semaphore(self.max_parallel)
        
        async def execute_with_limit(task):
            async with semaphore:
                return await task["executor"](**task["kwargs"])
        
        # Execute all tasks with concurrency limit
        results = await asyncio.gather(
            *[execute_with_limit(task) for task in tool_tasks],
            return_exceptions=True
        )
        
        # Handle exceptions
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed_results.append({
                    "success": False,
                    "error": str(result),
                    "tool": tool_tasks[i].get("tool", "unknown")
                })
            else:
                processed_results.append(result)
        
        return processed_results
    
    def optimize_tool_output(self, output: str, tool_name: str) -> str:
        """Optimize tool output for memory and AI processing"""
        if not output:
            return output
            
        # Check size
        size_mb = len(output.encode('utf-8')) / (1024 * 1024)
        
        # Compress large outputs
        if self.compress_outputs and size_mb > self.max_output_mb:
            return self._compress_output(output)
        
        # Truncate verbose tools
        if self.truncate_verbose and tool_name in {"nmap", "nuclei", "testssl", "sslyze"}:
            return self._truncate_verbose_output(output, tool_name)
        
        return output
    
    def _compress_output(self, output: str) -> str:
        """Compress large output and return reference"""
        compressed = gzip.compress(output.encode('utf-8'))
        
        # Save compressed output
        output_dir = Path(self.config.get("output", {}).get("save_path", "./reports"))
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        compressed_file = output_dir / f"compressed_output_{timestamp}.gz"
        
        with open(compressed_file, 'wb') as f:
            f.write(compressed)
        
        return f"[COMPRESSED OUTPUT SAVED TO: {compressed_file}]\n{output[:1000]}...\n[TRUNCATED - FULL OUTPUT IN COMPRESSED FILE]"
    
    def _truncate_verbose_output(self, output: str, tool_name: str) -> str:
        """Intelligently truncate verbose tool outputs"""
        lines = output.split('\n')
        
        if tool_name == "nmap":
            # Keep scan summary and open ports, truncate detailed service info
            important_lines = []
            for line in lines:
                if any(keyword in line.lower() for keyword in ["open", "filtered", "scan report", "host is up"]):
                    important_lines.append(line)
            
            if len(important_lines) < len(lines) // 2:
                return '\n'.join(important_lines[:100]) + f"\n[TRUNCATED - {len(lines) - len(important_lines)} verbose lines removed]"
        
        elif tool_name == "nuclei":
            # Keep only findings, remove verbose scanning info
            findings = [line for line in lines if any(severity in line.lower() for severity in ["critical", "high", "medium", "low", "info"]) and "[" in line]
            if findings:
                return '\n'.join(findings[:50]) + f"\n[TRUNCATED - Showing top 50 findings]"
        
        # Default truncation
        if len(lines) > 500:
            return '\n'.join(lines[:250] + [f"[TRUNCATED - {len(lines) - 250} lines removed]"] + lines[-50:])
        
        return output
    
    async def batch_ai_requests(self, requests: List[Dict[str, Any]], batch_size: int = 3) -> List[Any]:
        """Batch AI requests to avoid rate limits"""
        results = []
        
        for i in range(0, len(requests), batch_size):
            batch = requests[i:i + batch_size]
            batch_results = await asyncio.gather(
                *[req["executor"](**req["kwargs"]) for req in batch],
                return_exceptions=True
            )
            results.extend(batch_results)
            
            # Small delay between batches
            if i + batch_size < len(requests):
                await asyncio.sleep(1)
        
        return results