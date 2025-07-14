import pytest

from core.agents.merge_data_flows_agent import (
    MergeDataFlowAgent,
    StateModel,
)

pytestmark = pytest.mark.agent


async def test_merge_data_flow_reports(llm_model):

    reference_output = {
        "external_entities": [{"name": "User"}, {"name": "GitHub"}],
        "processes": [{"name": "Process1"}, {"name": "Process2"}],
        "data_stores": [],
        "trust_boundaries": [],
    }

    # Prepare two simple reports
    report1 = {
        "external_entities": [{"name": "User"}],
        "processes": [{"name": "Process1"}],
        "data_stores": [],
        "trust_boundaries": [],
    }
    report2 = {
        "external_entities": [{"name": "GitHub"}],
        "processes": [{"name": "Process2"}],
        "data_stores": [],
        "trust_boundaries": [],
    }

    # Initialize state
    state = StateModel(
        data_flow_reports=[report1, report2],
        merged_data_flow_report={},
        justification="",
    )

    agent = MergeDataFlowAgent(model=llm_model)

    result = await agent.merge(state)
    output = result.merged_data_flow_report

    print(f"LLM Output:\n{output}")

    print(f"Reference Output:\n{reference_output}")

    # Assertions on merged report
    assert output["external_entities"] == [{"name": "User"}, {"name": "GitHub"}]
    assert output["processes"] == [{"name": "Process1"}, {"name": "Process2"}]
