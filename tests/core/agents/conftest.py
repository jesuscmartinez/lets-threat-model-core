import os
from dotenv import load_dotenv
from pydantic import SecretStr
import pytest

from core.agents.chat_model_manager import ChatModelManager

pytestmark = pytest.mark.agent


@pytest.fixture
def llm_model():
    load_dotenv()
    provider = "openai"
    model_name = "gpt-4o-mini"
    api_key = SecretStr(os.getenv("PROVIDER_API_KEY", ""))
    llm_model = ChatModelManager.get_model(
        provider=provider, api_key=api_key, model=model_name
    )
    return llm_model
