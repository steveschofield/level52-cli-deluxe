"""
Factory for selecting the LLM backend based on configuration.
"""

from typing import Any, Dict


def get_llm_client(config: Dict[str, Any]) -> Any:
    """
    Return the appropriate LLM client based on config["ai"]["provider"].
    Supported providers: gemini, ollama, openrouter, huggingface.
    """
    ai_cfg = config.get("ai") or {}
    provider = ai_cfg.get("provider", "gemini").lower()

    if provider == "gemini":
        from ai.gemini_client import GeminiClient
        return GeminiClient(config)
    if provider == "ollama":
        from ai.ollama_client import OllamaClient
        return OllamaClient(config)
    if provider == "openrouter":
        from ai.openrouter_client import OpenRouterClient
        return OpenRouterClient(config)
    if provider in {"huggingface", "hf", "hf-serverless"}:
        ai_cfg = config.get("ai") or {}
        base_url = str(ai_cfg.get("base_url") or ai_cfg.get("hf_base_url") or "").strip().rstrip("/")
        endpoint_url = str(ai_cfg.get("endpoint_url") or ai_cfg.get("hf_endpoint_url") or "").strip()

        # If configured for the HF Router OpenAI-compatible /v1 API, use the router client.
        # Example base_url: https://router.huggingface.co/v1
        if "/v1" in (endpoint_url or base_url):
            from ai.huggingface_router_client import HuggingFaceRouterClient
            return HuggingFaceRouterClient(config)

        from ai.huggingface_client import HuggingFaceClient
        return HuggingFaceClient(config)

    if provider in {"huggingface-router", "hf-router"}:
        from ai.huggingface_router_client import HuggingFaceRouterClient
        return HuggingFaceRouterClient(config)

    raise ValueError(f"Unsupported AI provider: {provider}")
