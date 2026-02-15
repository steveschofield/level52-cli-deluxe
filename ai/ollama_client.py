"""
Ollama API client for Guardian
Uses langchain-ollama ChatOllama to talk to a local Ollama server
"""

import os
from typing import Optional, Dict, Any

from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage, SystemMessage
from dotenv import load_dotenv

from utils.logger import get_logger


class OllamaClient:
    """Ollama client wrapper"""

    def __init__(self, config: Dict[str, Any]):
        load_dotenv()

        self.config = config
        self.logger = get_logger(config)

        ai_config = config.get("ai", {})
        self.model_name = ai_config.get("model", "llama3")
        self.temperature = ai_config.get("temperature", 0.2)
        self.max_tokens = ai_config.get("max_tokens")  # mapped to num_predict if provided
        self.base_url = ai_config.get("base_url") or os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
        # Context window size (Ollama option: num_ctx)
        self.context_window = (
            ai_config.get("context_window")
            or ai_config.get("num_ctx")
            or ai_config.get("ollama_num_ctx")
            or os.getenv("OLLAMA_NUM_CTX")
        )
        try:
            self.context_window = int(self.context_window) if self.context_window is not None else None
        except Exception:
            self.context_window = None

        try:
            options: Dict[str, Any] = {}  # avoid unsupported defaults
            if self.context_window:
                options["num_ctx"] = int(self.context_window)

            self.llm = ChatOllama(
                model=self.model_name,
                temperature=self.temperature,
                base_url=self.base_url,
                num_predict=self.max_tokens,
                options=options,
            )
            self.logger.info(f"Initialized Ollama model: {self.model_name} @ {self.base_url}")
        except Exception as e:
            self.logger.error(f"Failed to initialize Ollama client: {e}")
            raise

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context: Optional[list] = None
    ) -> str:
        """Generate a response from Ollama"""
        messages = []

        if system_prompt:
            messages.append(SystemMessage(content=system_prompt))
        if context:
            messages.extend(context)

        messages.append(HumanMessage(content=prompt))

        try:
            response = await self.llm.ainvoke(messages)
            return response.content
        except Exception as e:
            self.logger.error(f"Ollama API error: {e}")
            raise

    def generate_sync(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context: Optional[list] = None
    ) -> str:
        """Synchronous version of generate"""
        messages = []

        if system_prompt:
            messages.append(SystemMessage(content=system_prompt))
        if context:
            messages.extend(context)

        messages.append(HumanMessage(content=prompt))

        try:
            response = self.llm.invoke(messages)
            return response.content
        except Exception as e:
            self.logger.error(f"Ollama API error: {e}")
            raise

    async def generate_with_reasoning(
        self,
        prompt: str,
        system_prompt: str,
        context: Optional[list] = None
    ) -> Dict[str, str]:
        """
        Generate response with explicit reasoning

        Returns:
            Dict with 'reasoning' and 'response' keys
        """
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

            parts["reasoning"] = response[reasoning_start:response.find("RESPONSE:")].strip()
            parts["response"] = response[response_start:].strip()
        else:
            parts["response"] = response
            parts["reasoning"] = "No explicit reasoning provided"

        return parts
