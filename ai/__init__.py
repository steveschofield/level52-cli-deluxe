"""AI package for Guardian"""

# Avoid eager imports of provider clients so optional dependencies don't break other providers.
from .provider_factory import get_llm_client

__all__ = ["get_llm_client"]
