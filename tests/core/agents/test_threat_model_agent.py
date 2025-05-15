import pytest
import copy
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch

# Assuming these imports reflect your actual module structure.
from core.models.dtos.Threat import AgentThreat
from core.models.enums import StrideCategory
from core.agents.threat_model_agent import ThreatModelAgent, ThreatGraphStateModel

# -----------------------------------------------------------------------------
# Fixtures and Helpers
# -----------------------------------------------------------------------------


@pytest.fixture
def mock_agent_helper():
    """Returns a mocked AgentHelper."""
    helper = MagicMock()
    helper.convert_uuids_to_ids.side_effect = lambda x: {"mocked": "data"}
    helper.convert_ids_to_uuids.side_effect = lambda x: {"converted": "uuid"}
    return helper


@pytest.fixture
def mock_base_model():
    """Returns a mocked BaseChatModel."""
    model = MagicMock()
    model.with_structured_output.return_value = AsyncMock()
    return model


@pytest.fixture
def threat_graph_state():
    """Returns a default ThreatGraphStateModel for testing."""
    return ThreatGraphStateModel(
        data_flow_report={
            "processes": [{"name": "TestProcess"}],
            "external_entities": [],
            "data_stores": [],
            "trust_boundaries": [],
        },
        threats=[],
        asset={"name": "TestAsset"},
    )


@pytest.fixture
def threat_model_agent(mock_base_model, mock_agent_helper):
    """Returns an initialized ThreatModelAgent with mocks injected."""
    agent = ThreatModelAgent(mock_base_model)
    agent.agent_helper = mock_agent_helper
    return agent


# -----------------------------------------------------------------------------
# Tests: initialize()
# -----------------------------------------------------------------------------


def test_initialize_converts_uuids(threat_model_agent, threat_graph_state):
    updated_state = threat_model_agent.initialize(threat_graph_state)

    assert updated_state.asset == {"mocked": "data"}
    assert updated_state.data_flow_report == {"mocked": "data"}
    threat_model_agent.agent_helper.convert_uuids_to_ids.assert_called()


# -----------------------------------------------------------------------------
# Tests: clean_up()
# -----------------------------------------------------------------------------


def test_finalize_converts_ids(threat_model_agent, threat_graph_state):
    threat_graph_state.threats = [{"mocked_id": "value"}]

    updated_state = threat_model_agent.finalize(threat_graph_state)

    assert updated_state.threats == [{"converted": "uuid"}]
    threat_model_agent.agent_helper.convert_ids_to_uuids.assert_called()


# -----------------------------------------------------------------------------
# Tests: analyze() (async)
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_analyze_processes_components(threat_model_agent, threat_graph_state):
    # Mock _process_component to simulate async component processing
    mock_result = [{"name": "Threat1", "stride_category": "Tampering"}]

    threat_model_agent._process_component = AsyncMock(return_value=mock_result)

    updated_state = await threat_model_agent.analyze(threat_graph_state)

    assert updated_state.threats == mock_result
    assert threat_model_agent._process_component.call_count == 1


@pytest.mark.asyncio
async def test_analyze_handles_exceptions(threat_model_agent, threat_graph_state):
    # Simulate a component processing error
    threat_model_agent._process_component = AsyncMock(side_effect=Exception("Boom"))

    updated_state = await threat_model_agent.analyze(threat_graph_state)

    assert updated_state.threats == []
    assert threat_model_agent._process_component.call_count == 1


# -----------------------------------------------------------------------------
# Tests: _process_component() (async)
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_process_component_success(threat_model_agent):
    """Test _process_component with model."""
    mock_chain = AsyncMock()
    mock_chain.ainvoke.return_value = {
        "threats": [{"name": "Threat1", "stride_category": "Spoofing"}]
    }

    asset = {"name": "TestAsset"}
    report = {"processes": [{"name": "TestProcess"}]}
    component = {"name": "TestComponent"}

    threats = await threat_model_agent._process_component(
        component, asset, report, mock_chain
    )

    assert threats == [{"name": "Threat1", "stride_category": "Spoofing"}]


@pytest.mark.asyncio
async def test_process_component_exception(threat_model_agent):
    mock_chain = AsyncMock()
    mock_chain.ainvoke.side_effect = Exception("Processing Error")

    asset = {"name": "TestAsset"}
    report = {"processes": [{"name": "TestProcess"}]}
    component = {"name": "TestComponent"}

    threats = await threat_model_agent._process_component(
        component, asset, report, mock_chain
    )

    assert threats == []


# -----------------------------------------------------------------------------
# Tests: consolidate_threats()
# -----------------------------------------------------------------------------


def test_consolidate_threats(threat_model_agent, threat_graph_state):
    # Set up fake threats grouped by STRIDE
    threat_graph_state.threats = [
        {"name": "Threat1", "stride_category": "Spoofing"},
        {"name": "Threat2", "stride_category": "Spoofing"},
    ]

    # Create a mock chain response: when invoke() is called, it returns the expected consolidated threat.
    mock_chain = MagicMock()
    mock_chain.return_value = {
        "threats": [{"name": "ConsolidatedThreat", "stride_category": "Spoofing"}]
    }

    # Patch the model's with_structured_output method to return our mock chain.
    threat_model_agent.model.with_structured_output.return_value = mock_chain

    updated_state = threat_model_agent.consolidate_threats(threat_graph_state)

    # Assert that the threats have been consolidated as expected.
    assert updated_state.threats == [
        {"name": "ConsolidatedThreat", "stride_category": "Spoofing"}
    ]


@pytest.mark.asyncio
async def test_get_workflow_run_threat_model_agent(
    threat_model_agent, threat_graph_state
):
    """
    Test that the workflow returned by get_workflow() executes correctly.

    We replace the agent's key workflow methods (initialize, analyze, finalize)
    with dummy implementations that modify the state in predictable ways:
      - initialize: adds a marker key in the asset.
      - analyze: adds a threat.
      - finalize: returns the state unchanged.
    Then we run the compiled workflow asynchronously using ainvoke and verify
    that the resulting state reflects those modifications.
    """

    # Dummy synchronous implementation for initialize.
    def dummy_initialize(state):
        # Convert to dict if necessary.
        if not isinstance(state, dict):
            state = state.dict()
        new_state = copy.deepcopy(state)
        # For ThreatGraphStateModel, asset is a top-level key.
        new_state["asset"]["dummy"] = "initialized"
        return new_state

    # Dummy asynchronous implementation for analyze.
    async def dummy_analyze(state):
        if not isinstance(state, dict):
            state = state.dict()
        new_state = copy.deepcopy(state)
        # Add a threat.
        new_state["threats"] = [
            {"name": "Analyzed Threat", "stride_category": "Tampering"}
        ]
        return new_state

    # Dummy synchronous finalize that returns the state unchanged.
    def dummy_finalize(state):
        return copy.deepcopy(state)

    # Patch the agent's methods with our dummy functions.
    threat_model_agent.initialize = dummy_initialize
    threat_model_agent.analyze = dummy_analyze
    threat_model_agent.finalize = dummy_finalize

    # Obtain the compiled workflow. This returns a runnable (compiled) workflow graph.
    workflow = threat_model_agent.get_workflow()

    # Run the workflow asynchronously using ainvoke. We pass the dict representation.
    result_state = await workflow.ainvoke(threat_graph_state.dict())

    # Assert that the workflow has executed as expected.
    assert (
        result_state["asset"].get("dummy") == "initialized"
    ), "Initialize did not update asset correctly."
    assert result_state["threats"] == [
        {"name": "Analyzed Threat", "stride_category": "Tampering"}
    ], "Analyze did not add the expected threat."
