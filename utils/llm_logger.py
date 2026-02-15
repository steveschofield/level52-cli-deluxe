"""
LLM Request/Response Logging Utility
Logs all LLM interactions to JSONL files for audit and debugging
"""

import json
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional


class LLMLogger:
    """Logs LLM requests and responses to JSONL files"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Check if logging is enabled
        logging_cfg = config.get("logging", {})
        self.log_requests = logging_cfg.get("log_llm_requests", False)
        self.log_responses = logging_cfg.get("log_llm_responses", False)
        
        if self.log_requests or self.log_responses:
            # Create reports directory
            output_dir = Path(config.get("output", {}).get("save_path", "./reports"))
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Create log file (static name per session directory)
            self.log_file = output_dir / "llm_io.jsonl"
    
    def log_request(self, call_id: str, provider: str, model: str, prompt: str, 
                   system_prompt: Optional[str] = None, context: Optional[list] = None) -> None:
        """Log LLM request"""
        if not self.log_requests:
            return
            
        entry = {
            "event": "request",
            "call_id": call_id,
            "timestamp": datetime.now().isoformat(),
            "provider": provider,
            "model": model,
            "prompt": prompt,
            "system_prompt": system_prompt,
            "context": context
        }
        
        self._write_entry(entry)
    
    def log_response(self, call_id: str, response: str, usage: Optional[Dict[str, Any]] = None,
                    request_id: Optional[str] = None, duration_ms: Optional[float] = None) -> None:
        """Log LLM response"""
        if not self.log_responses:
            return
            
        entry = {
            "event": "response", 
            "call_id": call_id,
            "timestamp": datetime.now().isoformat(),
            "response": response,
            "usage": usage,
            "request_id": request_id,
            "duration_ms": duration_ms
        }
        
        self._write_entry(entry)
    
    def log_error(self, call_id: str, error: str, error_type: Optional[str] = None) -> None:
        """Log LLM error"""
        if not (self.log_requests or self.log_responses):
            return
            
        entry = {
            "event": "error",
            "call_id": call_id, 
            "timestamp": datetime.now().isoformat(),
            "error": error,
            "error_type": error_type
        }
        
        self._write_entry(entry)
    
    def _write_entry(self, entry: Dict[str, Any]) -> None:
        """Write entry to JSONL file"""
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            # Silently fail to avoid breaking the main workflow
            pass


# Global logger instance
_llm_logger: Optional[LLMLogger] = None


def init_llm_logger(config: Dict[str, Any]) -> None:
    """Initialize global LLM logger"""
    global _llm_logger
    _llm_logger = LLMLogger(config)


def get_llm_logger() -> Optional[LLMLogger]:
    """Get global LLM logger instance"""
    return _llm_logger


def log_llm_request(provider: str, model: str, prompt: str, 
                   system_prompt: Optional[str] = None, context: Optional[list] = None) -> str:
    """Log LLM request and return call ID"""
    call_id = str(uuid.uuid4())
    if _llm_logger:
        _llm_logger.log_request(call_id, provider, model, prompt, system_prompt, context)
    return call_id


def log_llm_response(call_id: str, response: str, usage: Optional[Dict[str, Any]] = None,
                    request_id: Optional[str] = None, duration_ms: Optional[float] = None) -> None:
    """Log LLM response"""
    if _llm_logger:
        _llm_logger.log_response(call_id, response, usage, request_id, duration_ms)


def log_llm_error(call_id: str, error: str, error_type: Optional[str] = None) -> None:
    """Log LLM error"""
    if _llm_logger:
        _llm_logger.log_error(call_id, error, error_type)
