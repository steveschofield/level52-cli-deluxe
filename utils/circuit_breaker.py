"""
Circuit breaker and enhanced error recovery for Guardian
Prevents cascading failures and provides intelligent backoff
"""

import asyncio
import time
from enum import Enum
from typing import Dict, Any, Callable, Optional
from dataclasses import dataclass, field
from collections import defaultdict

from utils.logger import get_logger


class CircuitState(Enum):
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreakerConfig:
    failure_threshold: int = 5
    recovery_timeout: int = 60
    expected_exception: type = Exception


class CircuitBreaker:
    """Circuit breaker pattern implementation"""
    
    def __init__(self, config: CircuitBreakerConfig):
        self.config = config
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time = None
        self.success_count = 0
    
    async def call(self, func: Callable, *args, **kwargs):
        """Execute function with circuit breaker protection"""
        if self.state == CircuitState.OPEN:
            if self._should_attempt_reset():
                self.state = CircuitState.HALF_OPEN
            else:
                raise Exception("Circuit breaker is OPEN")
        
        try:
            result = await func(*args, **kwargs) if asyncio.iscoroutinefunction(func) else func(*args, **kwargs)
            self._on_success()
            return result
        except self.config.expected_exception as e:
            self._on_failure()
            raise e
    
    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset"""
        return (
            self.last_failure_time and
            time.time() - self.last_failure_time >= self.config.recovery_timeout
        )
    
    def _on_success(self):
        """Handle successful execution"""
        self.failure_count = 0
        if self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.CLOSED
    
    def _on_failure(self):
        """Handle failed execution"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.config.failure_threshold:
            self.state = CircuitState.OPEN


class EnhancedErrorHandler:
    """Enhanced error handler with circuit breakers and intelligent recovery"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = get_logger(config)
        
        # Circuit breakers for different components
        self.circuit_breakers = {
            "ai_provider": CircuitBreaker(CircuitBreakerConfig(failure_threshold=3, recovery_timeout=120)),
            "tool_execution": CircuitBreaker(CircuitBreakerConfig(failure_threshold=5, recovery_timeout=60)),
            "network_operations": CircuitBreaker(CircuitBreakerConfig(failure_threshold=3, recovery_timeout=30))
        }
        
        # Failure tracking
        self.failure_counts = defaultdict(int)
        self.last_failures = defaultdict(float)
        
        # Recovery strategies
        self.recovery_backoff = {
            "ai_provider": [5, 15, 30, 60, 120],
            "tool_execution": [2, 5, 10, 20],
            "network_operations": [1, 3, 5, 10]
        }
    
    async def execute_with_protection(self, component: str, func: Callable, *args, **kwargs) -> Dict[str, Any]:
        """Execute function with circuit breaker protection"""
        if component not in self.circuit_breakers:
            component = "tool_execution"  # Default
        
        circuit_breaker = self.circuit_breakers[component]
        
        try:
            result = await circuit_breaker.call(func, *args, **kwargs)
            return {"success": True, "result": result}
        except Exception as e:
            return await self._handle_protected_failure(component, e, func, *args, **kwargs)
    
    async def _handle_protected_failure(self, component: str, error: Exception, func: Callable, *args, **kwargs) -> Dict[str, Any]:
        """Handle failure with intelligent recovery"""
        self.failure_counts[component] += 1
        self.last_failures[component] = time.time()
        
        self.logger.error(f"{component} failure #{self.failure_counts[component]}: {error}")
        
        # Attempt recovery based on error type
        if "rate limit" in str(error).lower():
            return await self._handle_rate_limit(component, func, *args, **kwargs)
        elif "timeout" in str(error).lower():
            return await self._handle_timeout(component, func, *args, **kwargs)
        elif "connection" in str(error).lower():
            return await self._handle_connection_error(component, func, *args, **kwargs)
        
        return {"success": False, "error": str(error), "component": component}
    
    async def _handle_rate_limit(self, component: str, func: Callable, *args, **kwargs) -> Dict[str, Any]:
        """Handle rate limit with exponential backoff"""
        backoff_delays = self.recovery_backoff.get(component, [5, 15, 30])
        attempt = min(self.failure_counts[component] - 1, len(backoff_delays) - 1)
        delay = backoff_delays[attempt]
        
        self.logger.info(f"Rate limit hit for {component}, waiting {delay}s before retry")
        await asyncio.sleep(delay)
        
        try:
            result = await func(*args, **kwargs) if asyncio.iscoroutinefunction(func) else func(*args, **kwargs)
            self.failure_counts[component] = 0  # Reset on success
            return {"success": True, "result": result, "recovered": True}
        except Exception as e:
            return {"success": False, "error": str(e), "recovery_failed": True}
    
    async def _handle_timeout(self, component: str, func: Callable, *args, **kwargs) -> Dict[str, Any]:
        """Handle timeout with reduced parameters"""
        self.logger.info(f"Timeout for {component}, attempting with reduced scope")
        
        # Reduce timeout or scope if possible
        if "timeout" in kwargs:
            kwargs["timeout"] = max(kwargs["timeout"] * 0.7, 30)
        
        try:
            result = await func(*args, **kwargs) if asyncio.iscoroutinefunction(func) else func(*args, **kwargs)
            return {"success": True, "result": result, "recovered": True, "reduced_scope": True}
        except Exception as e:
            return {"success": False, "error": str(e), "recovery_failed": True}
    
    async def _handle_connection_error(self, component: str, func: Callable, *args, **kwargs) -> Dict[str, Any]:
        """Handle connection errors with retry"""
        max_retries = 3
        base_delay = 2
        
        for attempt in range(max_retries):
            delay = base_delay * (2 ** attempt)  # Exponential backoff
            self.logger.info(f"Connection error for {component}, retry {attempt + 1}/{max_retries} in {delay}s")
            await asyncio.sleep(delay)
            
            try:
                result = await func(*args, **kwargs) if asyncio.iscoroutinefunction(func) else func(*args, **kwargs)
                self.failure_counts[component] = 0  # Reset on success
                return {"success": True, "result": result, "recovered": True, "attempt": attempt + 1}
            except Exception as e:
                if attempt == max_retries - 1:
                    return {"success": False, "error": str(e), "max_retries_exceeded": True}
                continue
    
    def get_component_health(self) -> Dict[str, Dict[str, Any]]:
        """Get health status of all components"""
        health = {}
        for component, circuit_breaker in self.circuit_breakers.items():
            health[component] = {
                "state": circuit_breaker.state.value,
                "failure_count": circuit_breaker.failure_count,
                "total_failures": self.failure_counts[component],
                "last_failure": self.last_failures.get(component),
                "healthy": circuit_breaker.state == CircuitState.CLOSED
            }
        return health
    
    def reset_component(self, component: str):
        """Manually reset a component's circuit breaker"""
        if component in self.circuit_breakers:
            self.circuit_breakers[component].state = CircuitState.CLOSED
            self.circuit_breakers[component].failure_count = 0
            self.failure_counts[component] = 0
            self.logger.info(f"Reset circuit breaker for {component}")


def with_circuit_breaker(component: str, error_handler: EnhancedErrorHandler):
    """Decorator for circuit breaker protection"""
    def decorator(func: Callable):
        async def wrapper(*args, **kwargs):
            return await error_handler.execute_with_protection(component, func, *args, **kwargs)
        return wrapper
    return decorator