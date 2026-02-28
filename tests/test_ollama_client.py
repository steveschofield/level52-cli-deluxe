from ai.ollama_client import OllamaClient


class FakeChatOllama:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


def test_ollama_client_clamps_large_context_for_large_models(monkeypatch):
    monkeypatch.setattr("ai.ollama_client.ChatOllama", FakeChatOllama)

    client = OllamaClient(
        {
            "ai": {
                "model": "qwen3.5:35b",
                "base_url": "http://127.0.0.1:11434",
                "context_window": 200000,
            }
        }
    )

    assert client.context_window == 16384
    assert client.llm.kwargs["options"]["num_ctx"] == 16384


def test_ollama_client_respects_explicit_safe_limit_override(monkeypatch):
    monkeypatch.setattr("ai.ollama_client.ChatOllama", FakeChatOllama)

    client = OllamaClient(
        {
            "ai": {
                "model": "qwen3.5:35b",
                "base_url": "http://127.0.0.1:11434",
                "context_window": 200000,
                "max_safe_context_window": 8192,
            }
        }
    )

    assert client.context_window == 8192
    assert client.llm.kwargs["options"]["num_ctx"] == 8192
