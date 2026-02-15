"""
Base classes for OSINT clients
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import logging


class OSINTClient(ABC):
    """Base class for OSINT intelligence clients"""

    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        self.config = config
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self.enabled = self._get_enabled_status()

    @abstractmethod
    def _get_enabled_status(self) -> bool:
        """Check if this OSINT source is enabled in config"""
        pass

    def log_info(self, message: str):
        """Log info message"""
        if self.logger:
            self.logger.info(f"[{self.__class__.__name__}] {message}")

    def log_warning(self, message: str):
        """Log warning message"""
        if self.logger:
            self.logger.warning(f"[{self.__class__.__name__}] {message}")

    def log_error(self, message: str):
        """Log error message"""
        if self.logger:
            self.logger.error(f"[{self.__class__.__name__}] {message}")

    def log_debug(self, message: str):
        """Log debug message"""
        if self.logger:
            self.logger.debug(f"[{self.__class__.__name__}] {message}")
