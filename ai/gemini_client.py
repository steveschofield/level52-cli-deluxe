"""
Google Gemini client for Guardian.

Supports two auth paths:
1) API key (AI Studio): set `GOOGLE_API_KEY`
2) Higher-limit ADC + Vertex AI: run `gcloud auth application-default login` and set `ai.vertexai: true`
   plus `ai.project` (project id or project number) and optional `ai.location`.

Implementation prefers the modern `google-genai` SDK when installed, and falls back to
LangChain's `langchain-google-genai` client if needed.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

from utils.logger import get_logger


class GeminiClient:
    """Gemini API/Vertex AI wrapper with optional ADC support."""

    def __init__(self, config: Dict[str, Any]):
        load_dotenv()

        self.config = config
        self.logger = get_logger(config)

        ai_config = (config or {}).get("ai", {}) or {}

        self.model_name = ai_config.get("model", "gemini-2.5-pro")
        self.temperature = ai_config.get("temperature", 0.2)
        self.max_tokens = ai_config.get("max_tokens", 8000)

        self.api_key = os.getenv("GOOGLE_API_KEY")

        # Vertex AI / ADC config (recommended for higher limits).
        self.vertexai = bool(ai_config.get("vertexai", False) or ai_config.get("use_vertexai", False))
        self.project = (
            ai_config.get("project")
            or ai_config.get("project_id")
            or ai_config.get("gcp_project")
            or os.getenv("GOOGLE_CLOUD_PROJECT")
        )
        self.location = ai_config.get("location") or ai_config.get("gcp_location") or "us-central1"

        self._backend = "google-genai"
        self._genai = None
        self._lc_llm = None
        self._lc_SystemMessage = None
        self._lc_HumanMessage = None

        # Prefer google-genai when installed.
        try:
            from google import genai  # type: ignore
            from google.auth.exceptions import DefaultCredentialsError  # type: ignore
            import google.auth  # type: ignore

            if self.vertexai or (not self.api_key):
                if not self.project:
                    raise ValueError(
                        "Gemini Vertex AI auth selected but no project configured. "
                        "Set ai.project (project id or project number) or env GOOGLE_CLOUD_PROJECT."
                    )
                # Preflight: ensure ADC creds exist before starting a long run.
                try:
                    google.auth.default()
                except DefaultCredentialsError as cred_err:
                    raise ValueError(
                        "Gemini Vertex AI requires Application Default Credentials (ADC), but none were found. "
                        "Run: gcloud auth application-default login\n"
                        "Then re-run Guardian.\n"
                        f"Details: {cred_err}"
                    ) from cred_err
                self._genai = genai.Client(
                    vertexai=True,
                    project=str(self.project),
                    location=str(self.location),
                )
                self.logger.info(
                    f"Initialized Gemini (Vertex AI) model: {self.model_name} (project={self.project}, location={self.location})"
                )
            else:
                self._genai = genai.Client(api_key=self.api_key)
                self.logger.info(f"Initialized Gemini (API key) model: {self.model_name}")
        except Exception as e:
            self._backend = "langchain"
            try:
                from langchain_google_genai import ChatGoogleGenerativeAI  # type: ignore
                from langchain_core.messages import HumanMessage, SystemMessage  # type: ignore

                if not self.api_key:
                    raise ValueError(
                        "GOOGLE_API_KEY not found and google-genai is unavailable/failed to initialize. "
                        "Install google-genai or set GOOGLE_API_KEY."
                    )

                self._lc_SystemMessage = SystemMessage
                self._lc_HumanMessage = HumanMessage
                self._lc_llm = ChatGoogleGenerativeAI(
                    model=self.model_name,
                    google_api_key=self.api_key,
                    temperature=self.temperature,
                    max_output_tokens=self.max_tokens,
                    convert_system_message_to_human=True,
                )
                self.logger.info(f"Initialized Gemini (LangChain fallback) model: {self.model_name}")
            except Exception as e2:
                msg = (
                    "Failed to initialize Gemini client. "
                    "Install `google-genai` for Vertex AI/ADC support (recommended), "
                    "or ensure `langchain-google-genai` is installed for legacy API-key mode. "
                    f"Details: {e} / fallback failed: {e2}"
                )
                self.logger.error(msg)
                raise RuntimeError(msg)

    def _build_text_prompt(
        self,
        prompt: str,
        system_prompt: Optional[str],
        context: Optional[list],
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
            # Keep the tail (usually contains the latest tool output and the user's ask).
            text = text[-max_input_chars:]

        return text

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context: Optional[list] = None,
    ) -> str:
        return await asyncio.to_thread(self.generate_sync, prompt, system_prompt, context)

    def generate_sync(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context: Optional[list] = None,
    ) -> str:
        try:
            if self._backend == "langchain":
                messages: List[Any] = []
                if system_prompt:
                    messages.append(self._lc_SystemMessage(content=system_prompt))
                if context:
                    messages.extend(context)
                messages.append(self._lc_HumanMessage(content=prompt))
                resp = self._lc_llm.invoke(messages)
                return resp.content

            text_prompt = self._build_text_prompt(prompt, system_prompt, context)

            # Use google-genai SDK. Prefer typed config if available.
            config = None
            try:
                from google.genai import types  # type: ignore

                config = types.GenerateContentConfig(
                    temperature=float(self.temperature),
                    max_output_tokens=int(self.max_tokens) if self.max_tokens is not None else None,
                )
            except Exception:
                config = {
                    "temperature": float(self.temperature),
                    "max_output_tokens": int(self.max_tokens) if self.max_tokens is not None else None,
                }

            resp = self._genai.models.generate_content(
                model=self.model_name,
                contents=text_prompt,
                config=config,
            )

            text = getattr(resp, "text", None)
            if isinstance(text, str) and text.strip():
                return text

            # Best-effort extraction from candidates.
            candidates = getattr(resp, "candidates", None) or []
            if candidates:
                content = getattr(candidates[0], "content", None)
                parts = getattr(content, "parts", None) or []
                if parts and hasattr(parts[0], "text"):
                    return str(parts[0].text)

            return str(resp)
        except Exception as e:
            self.logger.error(f"Gemini API error: {e}")
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
