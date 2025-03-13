import copy
import pytest
import json
from unittest.mock import AsyncMock, MagicMock
from langchain_core.language_models.chat_models import BaseChatModel
from core.agents.agent_tools import AgentHelper
from core.agents.threat_model_data_agent import (
    ThreatModelDataAgent,
    ThreatModelDataStateModel,
)


# -----------------------------------------------------------------------------
# Fixtures for Reusability
# -----------------------------------------------------------------------------


@pytest.fixture
def mock_agent():
    """Fixture to create a mock ThreatModelDataAgent instance."""
    mock_model = MagicMock(spec=BaseChatModel)
    agent = ThreatModelDataAgent(model=mock_model)
    agent.agent_helper = MagicMock(spec=AgentHelper)
    return agent


@pytest.fixture
def valid_state():
    """Fixture for a valid ThreatModelDataStateModel instance with literal strings."""
    # Using .construct to bypass any validators that might introduce mocks.
    return ThreatModelDataStateModel(
        threat_model={
            "asset": {"uuid": "1234"},
            "repos": [{"uuid": "5678"}],
            "data_flow_reports": [{"uuid": "91011"}],
            "threats": [{"uuid": "1213"}],
        },
        title="Initial Title",
        summary="Initial Summary",
    )


# -----------------------------------------------------------------------------
# Unit Tests for `initialize` Method
# -----------------------------------------------------------------------------


def test_initialize_valid_data(mock_agent, valid_state):
    """Test successful initialization with valid data."""
    # Patch the conversion function so that it replaces a given uuid with a placeholder.
    mock_agent.agent_helper.convert_uuids_to_ids = MagicMock(
        side_effect=lambda x: {"uuid_X": x["uuid"]}
    )

    new_state = mock_agent.initialize(valid_state)

    assert new_state.threat_model["asset"] == {"uuid_X": "1234"}
    assert new_state.threat_model["data_flow_reports"] == [{"uuid_X": "91011"}]
    assert new_state.threat_model["threats"] == [{"uuid_X": "1213"}]


# -----------------------------------------------------------------------------
# Unit Tests for `generate` (Async) Method
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_generate(mock_agent, mocker, valid_state):
    """Test the generate method for correctly invoking the LLM chain."""
    # Expected LLM result.
    mock_result = {
        "title": "Mock Threat Model Title",
        "summary": "Mock summary of threat model analysis.",
    }

    # Create a mock chain that simulates the asynchronous LLM call.
    patched_chain = AsyncMock(return_value=mock_result)

    # Patch the `with_structured_output` method on the agent's model to return our mock chain.
    mocker.patch.object(
        mock_agent.model, "with_structured_output", return_value=patched_chain
    )

    # Call the async generate method.
    new_state = await mock_agent.generate(valid_state)

    assert new_state.title == "Mock Threat Model Title"
    assert new_state.summary == "Mock summary of threat model analysis."


# -----------------------------------------------------------------------------
# Unit Test for Running the Workflow
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_workflow_run(mock_agent, valid_state):
    """
    Test that the workflow from get_workflow() runs correctly.

    We patch the agent's initialize and generate methods with dummy functions.
    The dummy initialize adds a key to the threat_model asset.
    The dummy generate (an async function) updates the title and summary.
    """

    # Dummy synchronous initialize: convert state to dict if needed, modify it.
    def dummy_initialize(state):
        if not isinstance(state, dict):
            state = state.dict()
        new_state = copy.deepcopy(state)
        new_state["threat_model"]["asset"]["dummy"] = "initialized"
        return new_state

    # Dummy asynchronous generate: update title and summary.
    async def dummy_generate(state):
        if not isinstance(state, dict):
            state = state.dict()
        new_state = copy.deepcopy(state)
        new_state["title"] = "Generated Title"
        new_state["summary"] = "Generated Summary"
        return new_state

    # Patch the agent's methods.
    mock_agent.initialize = dummy_initialize
    mock_agent.generate = dummy_generate

    # Obtain the compiled workflow.
    workflow = mock_agent.get_workflow()  # Returns a CompiledStateGraph.

    # Run the workflow asynchronously using ainvoke.
    result_state = await workflow.ainvoke(valid_state.dict())

    # Assert that the workflow has executed as expected.
    assert (
        result_state["title"] == "Generated Title"
    ), "Title was not updated by generate."
    assert (
        result_state["summary"] == "Generated Summary"
    ), "Summary was not updated by generate."
    assert (
        result_state["threat_model"]["asset"].get("dummy") == "initialized"
    ), "Initialize did not update asset correctly."
