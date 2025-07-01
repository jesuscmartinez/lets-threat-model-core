import pytest
from unittest.mock import patch, MagicMock
from core.agents.chat_model_manager import ChatModelManager, rate_limiter
from pydantic import SecretStr
from langchain_core.language_models.chat_models import BaseChatModel


@pytest.fixture
def mock_init_chat_model():
    """Fixture to mock `init_chat_model`"""
    with patch("core.agents.chat_model_manager.init_chat_model") as mock:
        mock.return_value = MagicMock(spec=BaseChatModel)
        yield mock


@pytest.mark.parametrize(
    "provider, model, expected_call",
    [
        (
            "anthropic",
            "test_model",
            {
                "model_provider": "anthropic",
                "model": "test_model",
                "temperature": 0.0,
                "top_p": 1.0,
                "rate_limiter": rate_limiter,
                "api_key": SecretStr("test_api_key"),
            },
        ),
        (
            "openai",
            "test_model",
            {
                "model_provider": "openai",
                "model": "test_model",
                "temperature": 0.0,
                "top_p": 1.0,
                "frequency_penalty": 0.0,
                "presence_penalty": 0.0,
                "rate_limiter": rate_limiter,
                "api_key": SecretStr("test_api_key"),
            },
        ),
        (
            "openai",
            "o3-test_model",
            {
                "model_provider": "openai",
                "model": "o3-test_model",
                "rate_limiter": rate_limiter,
                "api_key": SecretStr("test_api_key"),
            },
        ),
        (
            "ollama",
            "test_model",
            {
                "model_provider": "ollama",
                "model": "test_model",
                "temperature": 0.0,
                "top_p": 1.0,
                "frequency_penalty": 0.0,
                "presence_penalty": 0.0,
                "rate_limiter": rate_limiter,
                "base_url": "http://localhost:11434",
            },
        ),
    ],
)
def test_get_model(mock_init_chat_model, provider, model, expected_call):
    """Test model creation with different providers."""

    created_model = ChatModelManager.get_model(
        provider=provider, model=model, api_key=SecretStr("test_api_key")
    )

    mock_init_chat_model.assert_called_once_with(**expected_call)
    assert isinstance(created_model, BaseChatModel)


def test_get_model_exception(mock_init_chat_model):
    """Test exception handling in `get_model`."""
    mock_init_chat_model.side_effect = Exception("Test exception")

    with pytest.raises(
        RuntimeError, match="❌ Failed to create model instance: Test exception"
    ):
        ChatModelManager.get_model(provider="openai", model="test_model")
