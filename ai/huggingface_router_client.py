"""
Hugging Face Router client for Guardian.

Hugging Face provides an OpenAI-compatible API surface via:
  https://router.huggingface.co/v1

This client uses the OpenAI Chat Completions style endpoint:
  POST /chat/completions
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import httpx
from dotenv import load_dotenv

from utils.logger import get_logger


def _role_from_message(msg: Any) -> Optional[str]:
    if msg is None:
        return None
    if isinstance(msg, dict):
        role = msg.get("role")
        if isinstance(role, str):
            return role
        msg_type = msg.get("type") or msg.get("message_type")
        if isinstance(msg_type, str):
            t = msg_type.lower()
            if t in {"system", "human", "ai", "assistant", "user"}:
                return {"human": "user", "ai": "assistant"}.get(t, t)
    msg_type = getattr(msg, "type", None)
    if isinstance(msg_type, str):
        t = msg_type.lower()
        if t in {"system", "human", "ai", "assistant", "user"}:
            return {"human": "user", "ai": "assistant"}.get(t, t)
    return None


def _content_from_message(msg: Any) -> Optional[str]:
    if msg is None:
        return None
    if isinstance(msg, dict):
        content = msg.get("content")
        return content if isinstance(content, str) else None
    content = getattr(msg, "content", None)
    return content if isinstance(content, str) else None


class HuggingFaceRouterClient:
    """OpenAI-compatible chat completions client via Hugging Face Router."""

    def __init__(self, config: Dict[str, Any]):
        load_dotenv()

        self.config = config
        self.logger = get_logger(config)

        ai_config = (config or {}).get("ai", {}) or {}

        token = (
            os.getenv("HF_TOKEN")
            or os.getenv("HUGGINGFACEHUB_API_TOKEN")
            or os.getenv("HUGGINGFACE_API_TOKEN")
            or ""
        ).strip()
        if not token:
            raise ValueError(
                "Hugging Face token not found. Set one of: HF_TOKEN / HUGGINGFACEHUB_API_TOKEN / HUGGINGFACE_API_TOKEN."
            )

        self.model_name = ai_config.get("model") or "openai/gpt-oss-120b"
        self.temperature = ai_config.get("temperature", 0.2)
        self.max_tokens = ai_config.get("max_tokens", 8000)

        self.base_url = (ai_config.get("base_url") or os.getenv("HF_ROUTER_BASE_URL") or "https://router.huggingface.co/v1").rstrip(
            "/"
        )

        timeout_s = ai_config.get("timeout", 60)
        try:
            timeout_s = float(timeout_s)
        except Exception:
            timeout_s = 60.0

        self._timeout = httpx.Timeout(timeout_s)
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        self._async = httpx.AsyncClient(base_url=self.base_url, headers=self._headers, timeout=self._timeout)
        self._sync = httpx.Client(base_url=self.base_url, headers=self._headers, timeout=self._timeout)

        self.last_usage: Optional[Dict[str, Any]] = None
        self.last_request_id: Optional[str] = None
        self.last_model: Optional[str] = None

        self.logger.info(f"Initialized HuggingFace Router model: {self.model_name} @ {self.base_url}")

    def _build_messages(
        self, prompt: str, system_prompt: Optional[str] = None, context: Optional[list] = None
    ) -> List[Dict[str, str]]:
        ai_cfg = (self.config or {}).get("ai", {}) or {}
        max_input_chars = ai_cfg.get("max_input_chars")
        try:
            max_input_chars = int(max_input_chars) if max_input_chars is not None else None
        except Exception:
            max_input_chars = None

        messages: List[Dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        if context:
            for msg in context:
                role = _role_from_message(msg) or "user"
                content = _content_from_message(msg)
                if not content:
                    continue
                messages.append({"role": role, "content": content})

        messages.append({"role": "user", "content": prompt})

        if max_input_chars and max_input_chars > 0:
            def total_chars(msgs: List[Dict[str, str]]) -> int:
                return sum(len(m.get("content") or "") for m in msgs)

            while len(messages) > 2 and total_chars(messages) > max_input_chars:
                drop_idx = 1 if messages and messages[0].get("role") == "system" else 0
                if drop_idx >= len(messages) - 1:
                    break
                messages.pop(drop_idx)

            over = total_chars(messages) - max_input_chars
            if over > 0 and messages:
                last = messages[-1]
                if last.get("role") == "user":
                    content = last.get("content") or ""
                    keep = max(0, len(content) - over)
                    last["content"] = content[-keep:] if keep else ""

        return messages

    def _payload(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "model": self.model_name,
            "messages": messages,
            "temperature": float(self.temperature) if self.temperature is not None else 0.2,
        }
        if self.max_tokens is not None:
            payload["max_tokens"] = int(self.max_tokens)
        return payload

    def _extract_text(self, data: Dict[str, Any]) -> str:
        if "error" in data and data["error"]:
            raise RuntimeError(f"HuggingFace Router error: {data['error']}")

        self.last_usage = data.get("usage")
        self.last_model = data.get("model") or self.model_name
        try:
            return data["choices"][0]["message"]["content"]
        except Exception:
            raise RuntimeError(f"Unexpected HuggingFace Router response shape: {data}")

    async def generate(
        self, prompt: str, system_prompt: Optional[str] = None, context: Optional[list] = None
    ) -> str:
        messages = self._build_messages(prompt, system_prompt, context)
        payload = self._payload(messages)
        try:
            resp = await self._async.post("/chat/completions", json=payload)
            self.last_request_id = (
                resp.headers.get("x-request-id")
                or resp.headers.get("x-amzn-requestid")
                or resp.headers.get("x-correlation-id")
            )
            resp.raise_for_status()
            return self._extract_text(resp.json())
        except Exception as e:
            self.logger.error(f"HuggingFace Router API error: {e}")
            raise

    def generate_sync(
        self, prompt: str, system_prompt: Optional[str] = None, context: Optional[list] = None
    ) -> str:
        messages = self._build_messages(prompt, system_prompt, context)
        payload = self._payload(messages)
        try:
            resp = self._sync.post("/chat/completions", json=payload)
            self.last_request_id = (
                resp.headers.get("x-request-id")
                or resp.headers.get("x-amzn-requestid")
                or resp.headers.get("x-correlation-id")
            )
            resp.raise_for_status()
            return self._extract_text(resp.json())
        except Exception as e:
            self.logger.error(f"HuggingFace Router API error: {e}")
            raise

    async def generate_with_reasoning(
        self, prompt: str, system_prompt: str, context: Optional[list] = None
    ) -> Dict[str, str]:
        enhanced_prompt = f"""{prompt}

Please structure your response as:
1. REASONING: Explain your thought process and decision-making
2. RESPONSE: Provide your final answer or recommendation
"""

        response = await self.generate(enhanced_prompt, system_prompt, context)
        parts = {"reasoning": "", "response": ""}
        if "REASONING:" in response and "RESPONSE:" in response:
            reasoning_start = response.find("REASONING:") + len("REASONING:")
            response_start = response.find("RESPONSE:") + len("RESPONSE:")
            parts["reasoning"] = response[reasoning_start : response.find("RESPONSE:")].strip()
            parts["response"] = response[response_start:].strip()
        else:
            parts["response"] = response
            parts["reasoning"] = "No explicit reasoning provided"
        return parts

