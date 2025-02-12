import os
from dotenv import load_dotenv
import logging
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from typing import Optional
from langchain_core.rate_limiters import InMemoryRateLimiter
from langchain_core.language_models.chat_models import BaseChatModel


# Load environment variables
load_dotenv()

# Configure logging
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=log_level,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

rate_limiter = InMemoryRateLimiter(
    requests_per_second=7,  # OpenAi limit is 500 per minute https://platform.openai.com/settings/organization/limits
    check_every_n_seconds=0.1,  # Wake up every 100 ms to check whether allowed to make a request,
    max_bucket_size=10,  # Controls the maximum burst size.
)


class ChatModelManager:
    @classmethod
    def get_model(
        cls,
        model_name: Optional[str] = None,
        anthropic_api_key: Optional[str] = None,
        openai_api_key: Optional[str] = None,
        temperature: float = 0.7,
        rate_limiter: InMemoryRateLimiter = rate_limiter,
    ) -> BaseChatModel:
        """
        Get a chat model dynamically using LangChain, based on user input or environment variables.

        :param model_name: The model key to use (e.g., 'anthropic', 'gpt4', 'gpt4mini', 'openai').
        :param anthropic_api_key: API key for Anthropic (if using Claude models).
        :param openai_api_key: API key for OpenAI (if using GPT models).
        :param temperature: Temperature setting for response randomness.
        :return: LangChain-compatible chat model instance.
        """

        # Load API keys from environment variables if not explicitly provided
        anthropic_api_key = anthropic_api_key or os.getenv("ANTHROPIC_API_KEY", None)
        openai_api_key = openai_api_key or os.getenv("OPENAI_API_KEY", None)

        # Define available models dynamically using LangChain
        base_models = {
            "anthropic": ChatAnthropic(
                model="claude-3-haiku-20240307",
                temperature=temperature,
                rate_limiter=rate_limiter,
                anthropic_api_key=anthropic_api_key,
            ),
            "openai": ChatOpenAI(
                temperature=temperature,
                rate_limiter=rate_limiter,
                openai_api_key=openai_api_key,
            ),
            "gpt-4o": ChatOpenAI(
                model="gpt-4o",
                temperature=temperature,
                rate_limiter=rate_limiter,
                openai_api_key=openai_api_key,
            ),
            "gpt-4o-mini": ChatOpenAI(
                model="gpt-4o-mini",
                temperature=temperature,
                rate_limiter=rate_limiter,
                openai_api_key=openai_api_key,
            ),
        }

        selected_model_key = model_name

        if selected_model_key not in base_models:
            raise ValueError(
                f"Invalid model selection: {selected_model_key}. "
                f"Choose from {list(base_models.keys())}."
            )

        return base_models[selected_model_key]
