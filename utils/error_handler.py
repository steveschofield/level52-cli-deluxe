"""
Robust error handling system for Guardian
Provides comprehensive exception management and recovery
"""

import asyncio
import traceback
from typing import Dict, Any, Optional, Callable, Type
from functools import wraps
from datetime import datetime
from pathlib import Path

from utils.logger import get_logger


class GuardianError(Exception):
    """Base exception for Guardian-specific errors"""
    def __init__(self, message: str, error_code: str = None, context: Dict[str, Any] = None):
        super().__init__(message)
        self.error_code = error_code or "GUARDIAN_ERROR"
        self.context = context or {}
        self.timestamp = datetime.now().isoformat()


class ToolExecutionError(GuardianError):
    """Tool execution specific errors"""
    def __init__(self, tool_name: str, message: str, exit_code: int = None, **kwargs):
        super().__init__(message, f"TOOL_{tool_name.upper()}_ERROR", kwargs)
        self.tool_name = tool_name
        self.exit_code = exit_code


class AIProviderError(GuardianError):
    """AI provider specific errors"""
    def __init__(self, provider: str, message: str, **kwargs):
        super().__init__(message, f"AI_{provider.upper()}_ERROR", kwargs)
        self.provider = provider


class ScopeValidationError(GuardianError):
    """Scope validation errors"""
    def __init__(self, target: str, reason: str, **kwargs):
        super().__init__(f"Invalid target {target}: {reason}", "SCOPE_ERROR", kwargs)
        self.target = target
        self.reason = reason


class ErrorHandler:
    """Centralized error handling and recovery system"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = get_logger(config)
        self.error_log_path = Path(config.get("output", {}).get("save_path", "./reports")) / "errors.log"
        self.error_log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Recovery strategies
        self.recovery_strategies = {
            ToolExecutionError: self._recover_tool_error,
            AIProviderError: self._recover_ai_error,
            ScopeValidationError: self._recover_scope_error,
            asyncio.TimeoutError: self._recover_timeout_error,
            ConnectionError: self._recover_connection_error,
        }
    
    def handle_error(self, error: Exception, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Handle and log error with recovery attempt"""
        context = context or {}
        
        # Log error details
        error_info = {
            "type": type(error).__name__,
            "message": str(error),
            "timestamp": datetime.now().isoformat(),
            "context": context,
            "traceback": traceback.format_exc()
        }
        
        self.logger.error(f"Error occurred: {error_info['type']} - {error_info['message']}")
        self._log_error_to_file(error_info)
        
        # Attempt recovery
        recovery_result = self._attempt_recovery(error, context)
        
        return {
            "error": error_info,
            "recovery": recovery_result,
            "can_continue": recovery_result.get("success", False)
        }
    
    def _attempt_recovery(self, error: Exception, context: Dict[str, Any]) -> Dict[str, Any]:
        """Attempt to recover from error"""
        error_type = type(error)
        
        # Find matching recovery strategy
        for exc_type, strategy in self.recovery_strategies.items():
            if isinstance(error, exc_type):
                try:
                    return strategy(error, context)
                except Exception as recovery_error:
                    self.logger.error(f"Recovery failed: {recovery_error}")
                    return {"success": False, "reason": str(recovery_error)}
        
        # Default recovery
        return {"success": False, "reason": "No recovery strategy available"}
    
    def _recover_tool_error(self, error: ToolExecutionError, context: Dict[str, Any]) -> Dict[str, Any]:
        """Recover from tool execution errors"""
        if error.exit_code == 127:  # Command not found
            return {
                "success": False,
                "reason": f"Tool {error.tool_name} not installed",
                "suggestion": f"Install {error.tool_name} and retry"
            }

        if error.exit_code == 124:  # Timeout
            return {
                "success": True,
                "reason": "Tool execution timed out",
                "action": "continue_without_result"
            }

        if error.exit_code == 1:  # General error - often means "no results"
            return {
                "success": True,
                "reason": "Tool completed with warnings or no findings",
                "action": "continue_with_partial_results"
            }

        if error.exit_code == 2:  # No results found (common in scanners)
            return {
                "success": True,
                "reason": "Tool completed with no findings",
                "action": "continue_with_empty_results"
            }

        if error.exit_code == 60:  # SSL certificate verification failure (curl)
            return {
                "success": True,
                "reason": "SSL certificate verification failed - treated as acceptable for pentest",
                "action": "continue_with_partial_results"
            }

        return {"success": False, "reason": f"Tool {error.tool_name} failed with exit code {error.exit_code}"}
    
    def _recover_ai_error(self, error: AIProviderError, context: Dict[str, Any]) -> Dict[str, Any]:
        """Recover from AI provider errors"""
        if "rate limit" in str(error).lower():
            return {
                "success": True,
                "reason": "Rate limit hit",
                "action": "retry_with_backoff",
                "delay": 60
            }
        
        if "authentication" in str(error).lower():
            return {
                "success": False,
                "reason": "Authentication failed",
                "suggestion": "Check API credentials"
            }
        
        return {"success": False, "reason": "AI provider error"}
    
    def _recover_scope_error(self, error: ScopeValidationError, context: Dict[str, Any]) -> Dict[str, Any]:
        """Recover from scope validation errors"""
        return {
            "success": False,
            "reason": f"Target {error.target} out of scope",
            "suggestion": "Update scope configuration or use different target"
        }
    
    def _recover_timeout_error(self, error: asyncio.TimeoutError, context: Dict[str, Any]) -> Dict[str, Any]:
        """Recover from timeout errors"""
        return {
            "success": True,
            "reason": "Operation timed out",
            "action": "continue_without_result"
        }
    
    def _recover_connection_error(self, error: ConnectionError, context: Dict[str, Any]) -> Dict[str, Any]:
        """Recover from connection errors"""
        return {
            "success": True,
            "reason": "Connection failed",
            "action": "retry_with_backoff",
            "delay": 30
        }
    
    def _log_error_to_file(self, error_info: Dict[str, Any]):
        """Log error to file for audit trail"""
        try:
            with open(self.error_log_path, 'a', encoding='utf-8') as f:
                f.write(f"{error_info['timestamp']}: {error_info['type']} - {error_info['message']}\n")
                if error_info.get('context'):
                    f.write(f"Context: {error_info['context']}\n")
                f.write("---\n")
        except Exception as log_error:
            self.logger.warning(f"Failed to log error to file: {log_error}")


def with_error_handling(error_handler: ErrorHandler = None, context: Dict[str, Any] = None):
    """Decorator for robust error handling"""
    def decorator(func: Callable):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                if error_handler:
                    result = error_handler.handle_error(e, context)
                    if result["can_continue"]:
                        return {"success": False, "error": str(e), "recovery": result["recovery"]}
                raise
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if error_handler:
                    result = error_handler.handle_error(e, context)
                    if result["can_continue"]:
                        return {"success": False, "error": str(e), "recovery": result["recovery"]}
                raise
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    return decorator


def safe_execute(func: Callable, *args, error_handler: ErrorHandler = None, **kwargs) -> Dict[str, Any]:
    """Safely execute function with error handling"""
    try:
        if asyncio.iscoroutinefunction(func):
            return asyncio.run(func(*args, **kwargs))
        else:
            return {"success": True, "result": func(*args, **kwargs)}
    except Exception as e:
        if error_handler:
            return error_handler.handle_error(e)
        return {"success": False, "error": str(e)}