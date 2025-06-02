import pytest
from unittest.mock import MagicMock
from core.agents.agent_tools import AgentHelper, get_model_name
from langchain.chat_models.base import BaseChatModel


@pytest.fixture
def agent_helper():
    """Fixture to create a fresh AgentHelper instance for each test."""
    return AgentHelper()


@pytest.fixture
def input_data():
    """Fixture for test input data."""
    return {
        "uuid": "71c640e4-6d34-460c-ad31-53e34102f0c5",
        "nested": {
            "uuid": "df0190c9-5481-4109-89ea-9cb0f93dfea0",
            "items": [
                {"uuid": "b8cdd8d5-a2b1-40c4-bbfc-72c8430d98ed"},
                {"uuid": "da571bf2-1c16-4db2-9cf2-8d6993e87af4"},
            ],
        },
        "references": {
            "_uuid": "71c640e4-6d34-460c-ad31-53e34102f0c5",
            "_uuids": [
                "b8cdd8d5-a2b1-40c4-bbfc-72c8430d98ed",
                "da571bf2-1c16-4db2-9cf2-8d6993e87af4",
            ],
        },
    }


@pytest.fixture
def expected_output():
    """Fixture for expected output after UUID conversion."""
    return {
        "uuid": "uuid_1",
        "nested": {
            "uuid": "uuid_2",
            "items": [
                {"uuid": "uuid_3"},
                {"uuid": "uuid_4"},
            ],
        },
        "references": {
            "_uuid": "uuid_1",
            "_uuids": [
                "uuid_3",
                "uuid_4",
            ],
        },
    }


def test_convert_uuids_to_ids(agent_helper, input_data, expected_output):
    """Test converting UUIDs to numbered placeholders."""
    result = agent_helper.convert_uuids_to_ids(input_data)
    assert result == expected_output


def test_convert_ids_to_uuids(agent_helper, input_data):
    """Test converting numbered placeholders back to UUIDs."""
    converted = agent_helper.convert_uuids_to_ids(input_data)
    restored = agent_helper.convert_ids_to_uuids(converted)
    assert restored == input_data


def test_get_model_name():
    """Test retrieving the model name."""
    model = MagicMock(spec=BaseChatModel)

    model.model_name = "test_model"
    assert get_model_name(model) == "test_model"

    del model.model_name
    model.model = "test_model_v2"
    assert get_model_name(model) == "test_model_v2"

    del model.model
    assert get_model_name(model) == "Unknown Model"
