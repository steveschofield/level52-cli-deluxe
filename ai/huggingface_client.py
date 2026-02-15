"""
Hugging Face Serverless Inference API client for Guardian.

Docs:
  https://api-inference.huggingface.co/models/<MODEL_ID>

This client uses plain text generation (text-generation pipeline). Many instruct/chat models
expect a specific chat template; Guardian provides a simple prompt builder and relies on the
model to behave reasonably. For best results, point to an instruct-tuned model and/or provide
an appropriate system prompt.
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any, Dict, List, Optional

import httpx
from dotenv import load_dotenv

from utils.logger import get_logger


class HuggingFaceClient:
    """Hugging Face Serverless Inference API (text-generation) client."""

    def __init__(self, config: Dict[str, Any]):
        load_dotenv()

        self.config = config
        self.logger = get_logger(config)

        ai_config = (config or {}).get("ai", {}) or {}

        self.model_name = ai_config.get("model") or ai_config.get("hf_model") or "meta-llama/Meta-Llama-3-8B-Instruct"
        self.temperature = ai_config.get("temperature", 0.2)
        self.max_tokens = ai_config.get("max_tokens", 8000)

        self.base_url = (
            ai_config.get("base_url")
            or ai_config.get("hf_base_url")
            or os.getenv("HF_INFERENCE_BASE_URL")
            # Hugging Face has migrated serverless routing to router.huggingface.co.
            # The routed serverless endpoint prefix is /hf-inference/models/<MODEL_ID>.
            or "https://router.huggingface.co/hf-inference/models"
        ).rstrip("/")
        self.base_url = self._normalize_base_url(self.base_url)

        # Optional: override to a fully qualified endpoint URL (serverless or dedicated endpoint).
        self.endpoint_url = (
            ai_config.get("endpoint_url")
            or ai_config.get("hf_endpoint_url")
            or os.getenv("HF_INFERENCE_ENDPOINT_URL")
            or ""
        ).strip()

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
        self._token = token

        timeout_s = ai_config.get("timeout", 60)
        try:
            timeout_s = float(timeout_s)
        except Exception:
            timeout_s = 60.0

        self._timeout = httpx.Timeout(timeout_s)
        self._headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

        self._async = httpx.AsyncClient(headers=self._headers, timeout=self._timeout)
        self._sync = httpx.Client(headers=self._headers, timeout=self._timeout)

        self.last_usage: Optional[Dict[str, Any]] = None
        self.last_request_id: Optional[str] = None
        self.last_model: Optional[str] = None

        self.logger.info(f"Initialized HuggingFace model: {self.model_name} @ {self._resolved_endpoint()}")

    @staticmethod
    def _normalize_base_url(base_url: str) -> str:
        """
        Map legacy HF serverless base URLs to the new router endpoint when possible.
        """
        b = (base_url or "").strip().rstrip("/")
        if not b:
            return b

        # Legacy:
        #   https://api-inference.huggingface.co/models
        # New:
        #   https://router.huggingface.co/hf-inference/models
        if "api-inference.huggingface.co" in b:
            return "https://router.huggingface.co/hf-inference/models"
        return b

    def _resolved_endpoint(self) -> str:
        if self.endpoint_url:
            return self.endpoint_url
        return f"{self.base_url}/{self.model_name}"

    def _build_text_prompt(
        self, prompt: str, system_prompt: Optional[str], context: Optional[list]
    ) -> str:
        parts: List[str] = []
        if system_prompt:
            parts.append(system_prompt.strip())

        if context:
            for item in context:
                content = None
                if isinstance(item, dict):
                    content = item.get("content")
                else:
                    content = getattr(item, "content", None)
                if isinstance(content, str) and content.strip():
                    parts.append(content.strip())

        parts.append(prompt)
        text = "\n\n".join(parts).strip()

        ai_cfg = (self.config or {}).get("ai", {}) or {}
        max_input_chars = ai_cfg.get("max_input_chars")
        try:
            max_input_chars = int(max_input_chars) if max_input_chars is not None else None
        except Exception:
            max_input_chars = None
        if max_input_chars and max_input_chars > 0 and len(text) > max_input_chars:
            text = text[-max_input_chars:]

        return text

    def _payload(self, text_prompt: str) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if self.temperature is not None:
            params["temperature"] = float(self.temperature)
        if self.max_tokens is not None:
            params["max_new_tokens"] = int(self.max_tokens)

        # HF supports "options": {"wait_for_model": true} but it can increase latency;
        # we instead handle 503 with a small retry loop.
        return {"inputs": text_prompt, "parameters": params}

    def _extract_text(self, data: Any) -> str:
        if isinstance(data, dict) and data.get("error"):
            err = str(data.get("error"))
            if "api-inference.huggingface.co" in err and "router.huggingface.co" in err:
                raise RuntimeError(
                    "HuggingFace Serverless Inference API base URL has changed. "
                    "Set `ai.base_url` to `https://router.huggingface.co/hf-inference/models` "
                    "or omit it to use the new default."
                )
            raise RuntimeError(f"HuggingFace error: {err}")

        # Common shapes:
        # - [{"generated_text": "..."}]
        # - {"generated_text": "..."}
        # - {"generated_text": "...", ...}
        if isinstance(data, list) and data:
            item = data[0]
            if isinstance(item, dict) and isinstance(item.get("generated_text"), str):
                return item["generated_text"]
        if isinstance(data, dict) and isinstance(data.get("generated_text"), str):
            return data["generated_text"]

        raise RuntimeError(f"Unexpected HuggingFace response shape: {data!r}")

    async def _post_with_retries(self, url: str, payload: Dict[str, Any]) -> httpx.Response:
        ai_cfg = (self.config or {}).get("ai", {}) or {}
        retries = ai_cfg.get("hf_max_retries", 4)
        try:
            retries = int(retries)
        except Exception:
            retries = 4

        backoff_s = 1.0
        last_err: Optional[Exception] = None
        for attempt in range(max(1, retries)):
            try:
                resp = await self._async.post(url, json=payload)
                self.last_request_id = (
                    resp.headers.get("x-request-id")
                    or resp.headers.get("x-amzn-requestid")
                    or resp.headers.get("x-correlation-id")
                )
                if resp.status_code in {404, 410}:
                    # 410 is commonly returned when a model is not served by the Serverless Inference API.
                    # 404 is typically an invalid model id or an access-controlled repository without access.
                    hint = (
                        "The requested model is not available on the Hugging Face Serverless Inference API, "
                        "or your token lacks access to it. If the repo is gated (e.g., Llama), accept the model "
                        "terms on Hugging Face and ensure your token has permission. Otherwise, pick a different "
                        "serverless-supported model or use a dedicated Inference Endpoint and set `ai.endpoint_url`."
                    )
                    raise RuntimeError(f"HTTP {resp.status_code} from Hugging Face for {url}. {hint} Body: {resp.text[:2000]}")
                if resp.status_code in {503, 429}:
                    # 503 often indicates model is loading. 429 indicates rate limit.
                    last_err = RuntimeError(f"HTTP {resp.status_code}: {resp.text[:2000]}")
                    await asyncio.sleep(backoff_s)
                    backoff_s = min(backoff_s * 2.0, 10.0)
                    continue
                resp.raise_for_status()
                return resp
            except Exception as e:
                last_err = e
                await asyncio.sleep(backoff_s)
                backoff_s = min(backoff_s * 2.0, 10.0)
        raise RuntimeError(f"HuggingFace request failed after retries: {last_err}")

    def _post_with_retries_sync(self, url: str, payload: Dict[str, Any]) -> httpx.Response:
        ai_cfg = (self.config or {}).get("ai", {}) or {}
        retries = ai_cfg.get("hf_max_retries", 4)
        try:
            retries = int(retries)
        except Exception:
            retries = 4

        backoff_s = 1.0
        last_err: Optional[Exception] = None
        for attempt in range(max(1, retries)):
            try:
                resp = self._sync.post(url, json=payload)
                self.last_request_id = (
                    resp.headers.get("x-request-id")
                    or resp.headers.get("x-amzn-requestid")
                    or resp.headers.get("x-correlation-id")
                )
                if resp.status_code in {404, 410}:
                    hint = (
                        "The requested model is not available on the Hugging Face Serverless Inference API, "
                        "or your token lacks access to it. If the repo is gated (e.g., Llama), accept the model "
                        "terms on Hugging Face and ensure your token has permission. Otherwise, pick a different "
                        "serverless-supported model or use a dedicated Inference Endpoint and set `ai.endpoint_url`."
                    )
                    raise RuntimeError(f"HTTP {resp.status_code} from Hugging Face for {url}. {hint} Body: {resp.text[:2000]}")
                if resp.status_code in {503, 429}:
                    last_err = RuntimeError(f"HTTP {resp.status_code}: {resp.text[:2000]}")
                    time.sleep(backoff_s)
                    backoff_s = min(backoff_s * 2.0, 10.0)
                    continue
                resp.raise_for_status()
                return resp
            except Exception as e:
                last_err = e
                time.sleep(backoff_s)
                backoff_s = min(backoff_s * 2.0, 10.0)
        raise RuntimeError(f"HuggingFace request failed after retries: {last_err}")

    async def generate(
        self, prompt: str, system_prompt: Optional[str] = None, context: Optional[list] = None
    ) -> str:
        text_prompt = self._build_text_prompt(prompt, system_prompt, context)
        payload = self._payload(text_prompt)

        url = self._resolved_endpoint()
        try:
            resp = await self._post_with_retries(url, payload)
            self.last_model = self.model_name
            return self._extract_text(resp.json())
        except Exception as e:
            self.logger.error(f"HuggingFace API error: {e}")
            raise

    def generate_sync(
        self, prompt: str, system_prompt: Optional[str] = None, context: Optional[list] = None
    ) -> str:
        text_prompt = self._build_text_prompt(prompt, system_prompt, context)
        payload = self._payload(text_prompt)

        url = self._resolved_endpoint()
        try:
            resp = self._post_with_retries_sync(url, payload)
            self.last_model = self.model_name
            return self._extract_text(resp.json())
        except Exception as e:
            self.logger.error(f"HuggingFace API error: {e}")
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
