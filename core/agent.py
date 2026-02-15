"""
Base agent class for all Guardian AI agents
"""

import asyncio
import json
import os
import time
import random
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from core.memory import PentestMemory
from utils.logger import get_logger
from utils.prompt_loader import log_prompt_template_paths


class BaseAgent(ABC):
    """Base class for all AI agents in Guardian"""
    
    def __init__(
        self,
        name: str,
        config: Dict[str, Any],
        llm_client: Any,
        memory: PentestMemory
    ):
        self.name = name
        self.config = config
        self.llm = llm_client
        self.memory = memory
        self.logger = get_logger(config)
        log_prompt_template_paths(config, self.logger)
    
    @abstractmethod
    async def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute the agent's primary function"""
        pass
    
    async def think(self, prompt: str, system_prompt: str) -> Dict[str, str]:
        """
        Use AI to think through a problem with reasoning
        
        Returns:
            Dict with 'reasoning' and 'response' keys
        """
        ai_cfg = (self.config or {}).get("ai", {}) or {}
        pentest_cfg = (self.config or {}).get("pentest", {}) or {}

        # Get model name for model-specific timeout overrides
        model_name = getattr(self.llm, "model", None) or getattr(self.llm, "model_name", None)
        model_timeouts = ai_cfg.get("model_timeouts", {})

        # Check for model-specific timeout first, then fall back to defaults
        llm_timeout = None
        if model_name and model_timeouts:
            llm_timeout = model_timeouts.get(model_name)

        # Backwards compatible: config/guardian.yaml uses ai.timeout, while newer configs use ai.llm_timeout_seconds.
        if llm_timeout is None:
            llm_timeout = (
                ai_cfg.get("llm_timeout_seconds")
                or ai_cfg.get("timeout")
                or pentest_cfg.get("llm_timeout_seconds")
                or pentest_cfg.get("timeout")
                or 120
            )
        try:
            llm_timeout = float(llm_timeout)
        except Exception:
            llm_timeout = 120.0

        started = time.time()
        call_id = uuid4().hex
        retry_count = ai_cfg.get("llm_retry_count", 2)
        backoff_s = ai_cfg.get("llm_retry_backoff_seconds", 2)
        max_backoff_s = ai_cfg.get("llm_retry_max_backoff_seconds", 30)
        jitter_s = ai_cfg.get("llm_retry_jitter_seconds", 0.5)
        try:
            retry_count = int(retry_count)
        except Exception:
            retry_count = 2
        try:
            backoff_s = float(backoff_s)
        except Exception:
            backoff_s = 2.0
        try:
            max_backoff_s = float(max_backoff_s)
        except Exception:
            max_backoff_s = 30.0
        try:
            jitter_s = float(jitter_s)
        except Exception:
            jitter_s = 0.5

        self._maybe_log_llm_request(call_id=call_id, prompt=prompt, system_prompt=system_prompt)

        attempt = 0
        while True:
            attempt_started = time.time()
            try:
                result = await asyncio.wait_for(
                    self.llm.generate_with_reasoning(
                        prompt=prompt,
                        system_prompt=system_prompt
                    ),
                    timeout=llm_timeout
                )

                usage = getattr(self.llm, "last_usage", None)
                request_id = getattr(self.llm, "last_request_id", None)
                model = getattr(self.llm, "last_model", None)
                bits: list[str] = []
                if isinstance(usage, dict):
                    prompt_tokens = usage.get("prompt_tokens")
                    completion_tokens = usage.get("completion_tokens")
                    total_tokens = usage.get("total_tokens")
                    if model:
                        bits.append(f"model={model}")
                    if request_id:
                        bits.append(f"request_id={request_id}")
                    tok = []
                    if prompt_tokens is not None:
                        tok.append(f"prompt={prompt_tokens}")
                    if completion_tokens is not None:
                        tok.append(f"completion={completion_tokens}")
                    if total_tokens is not None:
                        tok.append(f"total={total_tokens}")
                    if tok:
                        bits.append("tokens(" + ", ".join(tok) + ")")
                if bits:
                    self.logger.info(f"[{self.name}] LLM usage: " + " ".join(bits))

                self._maybe_log_llm_response(
                    call_id=call_id,
                    prompt=prompt,
                    system_prompt=system_prompt,
                    response=result.get("response", ""),
                    reasoning=result.get("reasoning", ""),
                    usage=usage if isinstance(usage, dict) else None,
                    request_id=request_id if isinstance(request_id, str) else None,
                    model=model if isinstance(model, str) else None,
                )

                # Log AI decision
                context = {"prompt": prompt[:200]}
                if isinstance(usage, dict):
                    context["llm_usage"] = usage
                if request_id:
                    context["llm_request_id"] = request_id
                if model:
                    context["llm_model"] = model
                self.logger.log_ai_decision(
                    agent=self.name,
                    decision=result["response"],
                    reasoning=result["reasoning"],
                    context=context
                )
                self.logger.debug(
                    f"[{self.name}] LLM call completed in {time.time() - attempt_started:.2f}s"
                )
                
                # Store in memory
                self.memory.add_ai_decision(
                    agent=self.name,
                    decision=result["response"],
                    reasoning=result["reasoning"]
                )
                
                return result

            except asyncio.TimeoutError:
                elapsed = time.time() - attempt_started
                total_elapsed = time.time() - started
                if attempt < retry_count:
                    delay = min(max_backoff_s, backoff_s * (2 ** attempt))
                    if jitter_s > 0:
                        delay += random.uniform(0, jitter_s)
                    self.logger.warning(
                        f"[{self.name}] LLM timeout after {elapsed:.2f}s (attempt {attempt + 1}/{retry_count + 1}); "
                        f"retrying in {delay:.2f}s"
                    )
                    await asyncio.sleep(delay)
                    attempt += 1
                    continue
                self.logger.error(f"Agent {self.name} LLM call timed out after {total_elapsed:.2f}s")
                self._maybe_log_llm_error(
                    call_id=call_id,
                    prompt=prompt,
                    system_prompt=system_prompt,
                    error=f"timeout after {total_elapsed:.2f}s",
                )
                raise
            except Exception as e:
                self.logger.error(f"Agent {self.name} thinking error: {e}")
                self._maybe_log_llm_error(
                    call_id=call_id,
                    prompt=prompt,
                    system_prompt=system_prompt,
                    error=str(e),
                )
                raise

    def _llm_io_enabled(self) -> bool:
        """
        Enable full request/response logging when:
        - env LSG_LOG_LLM_REQUESTS=1, OR
        - config.ai.log_llm_requests/log_llm_responses/log_llm_io_file is true
        """
        ai_cfg = (self.config or {}).get("ai", {}) or {}
        env_on = os.getenv("LSG_LOG_LLM_REQUESTS", "").strip() in {"1", "true", "TRUE", "yes", "YES"}
        cfg_on = bool(
            ai_cfg.get("log_llm_requests")
            or ai_cfg.get("log_llm_responses")
            or ai_cfg.get("log_llm_io_file")
            or ai_cfg.get("log_llm_full_io")
        )
        return env_on or cfg_on

    def _llm_io_path(self, out_dir: Path) -> Path:
        session_id = getattr(self.memory, "session_id", None) or "unknown"

        path = getattr(self.memory, "llm_io_log_path", None)
        if not isinstance(path, (str, Path)) or not str(path):
            path = out_dir / "llm_io.jsonl"
            try:
                setattr(self.memory, "llm_io_log_path", str(path))
            except Exception:
                pass
        return Path(str(path))

    def _maybe_log_llm_request(self, call_id: str, prompt: str, system_prompt: str) -> None:
        if not self._llm_io_enabled():
            return

        # Keep console readable: full prompts go to file; console shows only a short marker unless debug is on.
        self.logger.info(f"[{self.name}] LLM request: system_prompt={len(system_prompt)} chars, prompt={len(prompt)} chars")

        ai_cfg = (self.config or {}).get("ai", {}) or {}
        save_file = bool(
            ai_cfg.get("log_llm_io_file")
            or ai_cfg.get("log_llm_full_io")
            or os.getenv("LSG_DEBUG_SAVE_OUTPUT", "").strip() in {"1", "true", "TRUE", "yes", "YES"}
        )
        if not save_file:
            return

        out_dir = Path((self.config or {}).get("output", {}).get("save_path", "./reports"))
        out_dir.mkdir(parents=True, exist_ok=True)

        record = {
            "timestamp": datetime.now().isoformat(),
            "event": "request",
            "call_id": call_id,
            "agent": self.name,
            "provider": ((self.config or {}).get("ai", {}) or {}).get("provider"),
            "model": ((self.config or {}).get("ai", {}) or {}).get("model"),
            "system_prompt": system_prompt,
            "prompt": prompt,
        }

        path = self._llm_io_path(out_dir)
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception as e:
            self.logger.warning(f"[{self.name}] Failed to write LLM request log: {e}")

    def _maybe_log_llm_response(
        self,
        call_id: str,
        prompt: str,
        system_prompt: str,
        response: str,
        reasoning: str,
        usage: Optional[Dict[str, Any]],
        request_id: Optional[str],
        model: Optional[str],
    ) -> None:
        if not self._llm_io_enabled():
            return

        ai_cfg = (self.config or {}).get("ai", {}) or {}
        save_file = bool(
            ai_cfg.get("log_llm_io_file")
            or ai_cfg.get("log_llm_full_io")
            or os.getenv("LSG_DEBUG_SAVE_OUTPUT", "").strip() in {"1", "true", "TRUE", "yes", "YES"}
        )

        self.logger.info(f"[{self.name}] LLM response: {len(response or '')} chars")

        if not save_file:
            return

        out_dir = Path((self.config or {}).get("output", {}).get("save_path", "./reports"))
        out_dir.mkdir(parents=True, exist_ok=True)

        record = {
            "timestamp": datetime.now().isoformat(),
            "event": "response",
            "call_id": call_id,
            "agent": self.name,
            "provider": ((self.config or {}).get("ai", {}) or {}).get("provider"),
            "model": model or ((self.config or {}).get("ai", {}) or {}).get("model"),
            "request_id": request_id,
            "response": response,
            "reasoning": reasoning,
            "usage": usage,
        }

        path = self._llm_io_path(out_dir)
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception as e:
            self.logger.warning(f"[{self.name}] Failed to write LLM IO log: {e}")

    def _maybe_log_llm_error(self, call_id: str, prompt: str, system_prompt: str, error: str) -> None:
        if not self._llm_io_enabled():
            return

        ai_cfg = (self.config or {}).get("ai", {}) or {}
        save_file = bool(
            ai_cfg.get("log_llm_io_file")
            or ai_cfg.get("log_llm_full_io")
            or os.getenv("LSG_DEBUG_SAVE_OUTPUT", "").strip() in {"1", "true", "TRUE", "yes", "YES"}
        )
        if not save_file:
            return

        out_dir = Path((self.config or {}).get("output", {}).get("save_path", "./reports"))
        out_dir.mkdir(parents=True, exist_ok=True)

        record = {
            "timestamp": datetime.now().isoformat(),
            "event": "error",
            "call_id": call_id,
            "agent": self.name,
            "provider": ((self.config or {}).get("ai", {}) or {}).get("provider"),
            "model": ((self.config or {}).get("ai", {}) or {}).get("model"),
            "error": error,
        }

        path = self._llm_io_path(out_dir)
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception as e:
            self.logger.warning(f"[{self.name}] Failed to write LLM error log: {e}")
    
    def log_action(self, action: str, details: str):
        """Log an agent action"""
        self.logger.info(f"[{self.name}] {action}: {details}")
