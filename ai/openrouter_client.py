"""
OpenRouter API client for Guardian

OpenRouter exposes an OpenAI-compatible Chat Completions API:
https://openrouter.ai/docs
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any, Dict, List, Optional

import httpx
from dotenv import load_dotenv

from utils.logger import get_logger


def _role_from_message(msg: Any) -> Optional[str]:
    """
    Best-effort mapping from common message objects to OpenAI roles.
    Supports LangChain messages, dicts, and simple tuples.
    """
    if msg is None:
        return None

    if isinstance(msg, dict):
        role = msg.get("role")
        if isinstance(role, str):
            return role

        # LangChain-style serialized dicts sometimes carry "type"
        msg_type = msg.get("type") or msg.get("message_type")
        if isinstance(msg_type, str):
            t = msg_type.lower()
            if t in {"system", "human", "ai", "assistant", "user"}:
                return {"human": "user", "ai": "assistant"}.get(t, t)

    # LangChain message objects typically expose `.type`
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


class OpenRouterClient:
    """OpenRouter client wrapper using httpx (OpenAI-compatible chat completions)."""

    def __init__(self, config: Dict[str, Any]):
        load_dotenv()

        self.config = config
        self.logger = get_logger(config)

        ai_config = config.get("ai", {}) or {}

        api_key = os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            raise ValueError(
                "OPENROUTER_API_KEY not found in environment. "
                "Please set it in .env file or environment variables."
            )

        self.model_name = ai_config.get("model", "openai/gpt-4o-mini")
        self.temperature = ai_config.get("temperature", 0.2)
        self.max_tokens = ai_config.get("max_tokens", 8000)
        self.base_url = (ai_config.get("base_url") or os.getenv("OPENROUTER_BASE_URL") or "https://openrouter.ai/api/v1").rstrip("/")

        site_url = ai_config.get("site_url") or os.getenv("OPENROUTER_SITE_URL")
        app_name = ai_config.get("app_name") or os.getenv("OPENROUTER_APP_NAME")

        timeout_s = ai_config.get("timeout", 60)
        try:
            timeout_s = float(timeout_s)
        except Exception:
            timeout_s = 60.0

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        if site_url:
            headers["HTTP-Referer"] = site_url
        if app_name:
            headers["X-Title"] = app_name

        self._timeout = httpx.Timeout(timeout_s)
        self._headers = headers
        self._async = httpx.AsyncClient(base_url=self.base_url, headers=self._headers, timeout=self._timeout)
        self._sync = httpx.Client(base_url=self.base_url, headers=self._headers, timeout=self._timeout)

        retries = ai_config.get("openrouter_max_retries", ai_config.get("max_retries", 3))
        try:
            retries = int(retries)
        except Exception:
            retries = 3
        self._max_retries = max(1, retries)

        self.last_usage: Optional[Dict[str, Any]] = None
        self.last_request_id: Optional[str] = None
        self.last_model: Optional[str] = None

        self.logger.info(f"Initialized OpenRouter model: {self.model_name} @ {self.base_url}")

    def _build_messages(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context: Optional[list] = None,
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
            for item in context:
                role = _role_from_message(item)
                content = _content_from_message(item)
                if role and content:
                    messages.append({"role": role, "content": content})

        messages.append({"role": "user", "content": prompt})

        # Best-effort prompt size cap (keeps system prompt + most recent context).
        if max_input_chars and max_input_chars > 0:
            def total_chars(msgs: List[Dict[str, str]]) -> int:
                return sum(len(m.get("content") or "") for m in msgs)

            # Drop oldest non-system messages until under budget.
            while len(messages) > 2 and total_chars(messages) > max_input_chars:
                # Preserve system message at index 0 if present.
                drop_idx = 1 if messages and messages[0].get("role") == "system" else 0
                # Never drop the final user message.
                if drop_idx >= len(messages) - 1:
                    break
                messages.pop(drop_idx)

            # If still too big, truncate the final user prompt.
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
            "temperature": self.temperature,
        }
        if self.max_tokens is not None:
            payload["max_tokens"] = self.max_tokens
        return payload

    def _extract_text(self, data: Dict[str, Any]) -> str:
        if "error" in data and data["error"]:
            raise RuntimeError(f"OpenRouter error: {data['error']}")

        self.last_usage = data.get("usage")
        self.last_model = data.get("model") or self.model_name

        try:
            return data["choices"][0]["message"]["content"]
        except Exception:
            raise RuntimeError(f"Unexpected OpenRouter response shape: {data}")

    def _format_http_error(self, resp: httpx.Response) -> str:
        status = resp.status_code
        body_text = (resp.text or "").strip()
        message = body_text

        try:
            data = resp.json()
            err = data.get("error") if isinstance(data, dict) else None
            if isinstance(err, dict):
                msg = err.get("message")
                code = err.get("code")
                if msg and code:
                    message = f"{msg} (code={code})"
                elif msg:
                    message = str(msg)
            elif isinstance(err, str):
                message = err
        except Exception:
            pass

        message = (message or body_text or "unknown error").strip()
        lowered = message.lower()
        if status == 404 and "migrate to the paid slug" in lowered:
            message += " | Hint: remove ':free' from the model slug or choose another available model."

        return f"HTTP {status}: {message[:2000]}"

    async def _post_with_retries(self, payload: Dict[str, Any]) -> httpx.Response:
        backoff_s = 1.0
        last_err: Optional[Exception] = None
        retryable_statuses = {429, 500, 502, 503, 504}
        for attempt in range(self._max_retries):
            try:
                resp = await self._async.post("/chat/completions", json=payload)
                if resp.status_code < 400:
                    return resp

                err = RuntimeError(self._format_http_error(resp))
                if resp.status_code in retryable_statuses and attempt < self._max_retries - 1:
                    last_err = err
                    await asyncio.sleep(backoff_s)
                    backoff_s = min(backoff_s * 2.0, 10.0)
                    continue
                raise err
            except httpx.RequestError as e:
                last_err = e
                if attempt < self._max_retries - 1:
                    await asyncio.sleep(backoff_s)
                    backoff_s = min(backoff_s * 2.0, 10.0)
                    continue
                raise RuntimeError(f"OpenRouter request failed after retries: {e}") from e
            except RuntimeError:
                raise
            except Exception as e:
                last_err = e
                if attempt < self._max_retries - 1:
                    await asyncio.sleep(backoff_s)
                    backoff_s = min(backoff_s * 2.0, 10.0)
                    continue
                raise RuntimeError(f"OpenRouter request failed after retries: {e}") from e
        raise RuntimeError(f"OpenRouter request failed after retries: {last_err or 'unknown error'}")

    def _post_with_retries_sync(self, payload: Dict[str, Any]) -> httpx.Response:
        backoff_s = 1.0
        last_err: Optional[Exception] = None
        retryable_statuses = {429, 500, 502, 503, 504}
        for attempt in range(self._max_retries):
            try:
                resp = self._sync.post("/chat/completions", json=payload)
                if resp.status_code < 400:
                    return resp

                err = RuntimeError(self._format_http_error(resp))
                if resp.status_code in retryable_statuses and attempt < self._max_retries - 1:
                    last_err = err
                    time.sleep(backoff_s)
                    backoff_s = min(backoff_s * 2.0, 10.0)
                    continue
                raise err
            except httpx.RequestError as e:
                last_err = e
                if attempt < self._max_retries - 1:
                    time.sleep(backoff_s)
                    backoff_s = min(backoff_s * 2.0, 10.0)
                    continue
                raise RuntimeError(f"OpenRouter request failed after retries: {e}") from e
            except RuntimeError:
                raise
            except Exception as e:
                last_err = e
                if attempt < self._max_retries - 1:
                    time.sleep(backoff_s)
                    backoff_s = min(backoff_s * 2.0, 10.0)
                    continue
                raise RuntimeError(f"OpenRouter request failed after retries: {e}") from e
        raise RuntimeError(f"OpenRouter request failed after retries: {last_err or 'unknown error'}")

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context: Optional[list] = None,
    ) -> str:
        messages = self._build_messages(prompt, system_prompt, context)
        payload = self._payload(messages)

        try:
            resp = await self._post_with_retries(payload)
            self.last_request_id = (
                resp.headers.get("x-request-id")
                or resp.headers.get("x-openrouter-request-id")
                or resp.headers.get("request-id")
            )
            return self._extract_text(resp.json())
        except Exception as e:
            self.logger.error(f"OpenRouter API error: {e}")
            raise

    def generate_sync(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context: Optional[list] = None,
    ) -> str:
        messages = self._build_messages(prompt, system_prompt, context)
        payload = self._payload(messages)

        try:
            resp = self._post_with_retries_sync(payload)
            self.last_request_id = (
                resp.headers.get("x-request-id")
                or resp.headers.get("x-openrouter-request-id")
                or resp.headers.get("request-id")
            )
            return self._extract_text(resp.json())
        except Exception as e:
            self.logger.error(f"OpenRouter API error: {e}")
            raise

    async def generate_with_reasoning(
        self,
        prompt: str,
        system_prompt: str,
        context: Optional[list] = None,
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
