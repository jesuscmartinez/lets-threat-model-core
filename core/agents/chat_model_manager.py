import logging
import re
from langchain.chat_models import init_chat_model
from langchain_core.rate_limiters import InMemoryRateLimiter
from langchain_core.language_models.chat_models import BaseChatModel
from typing import Optional
from pydantic import SecretStr


logger = logging.getLogger(__name__)

# Initialize rate limiter (Exponential backoff happens in retries)
rate_limiter = InMemoryRateLimiter(
    requests_per_second=7,  # OpenAI limit is 500 per minute
    check_every_n_seconds=0.1,  # Wake up every 100ms to check the limit
    max_bucket_size=10,  # Maximum burst requests
)


class ChatModelManager:
    @classmethod
    def get_model(
        cls,
        provider: str,
        model: str,
        base_url: Optional[str] = "http://localhost:11434",
        api_key: Optional[SecretStr] = None,
        top_p: float = 1.0,
        temperature: float = 0.0,
        frequency_penalty=0.0,
        presence_penalty=0.0,
        rate_limiter: Optional[InMemoryRateLimiter] = rate_limiter,
    ) -> BaseChatModel:
        """
        Get a chat model dynamically based on the provider with rate limiting & retries.

        Args:
            provider: The model provider ('llama', 'openai', 'anthropic')
            model: The model name to use
            api_key: API key for the provider (if required)
            temperature: Temperature setting for response randomness
            rate_limiter: Optional rate limiter
            max_retries: Maximum number of retry attempts

        Returns:
            LangChain-compatible chat model instance with retry functionality
        """
        try:
            init_kwargs = {
                "model_provider": provider,
                "model": model,
                "temperature": temperature,
                "top_p": top_p,
                "frequency_penalty": frequency_penalty,
                "presence_penalty": presence_penalty,
                "rate_limiter": rate_limiter,
            }
            if provider.lower() == "anthropic":
                init_kwargs["api_key"] = api_key

                del init_kwargs["frequency_penalty"]
                del init_kwargs["presence_penalty"]
            elif provider.lower() == "openai":
                init_kwargs["api_key"] = api_key

                if re.match(r"o\d-", model.lower()):
                    del init_kwargs["top_p"]
                    del init_kwargs["frequency_penalty"]
                    del init_kwargs["presence_penalty"]
                    del init_kwargs["temperature"]

            elif provider.lower() == "ollama":
                init_kwargs["base_url"] = base_url

            return init_chat_model(**init_kwargs)

        except Exception as e:
            raise RuntimeError(f"❌ Failed to create model instance: {str(e)}")
