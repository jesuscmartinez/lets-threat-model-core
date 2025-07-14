import pytest
from core.agents.threat_model_agent import ThreatModelAgent, ThreatGraphStateModel
from pprint import pprint

from langchain.evaluation import load_evaluator
from langchain_core.runnables import RunnableLambda

pytestmark = pytest.mark.agent


async def test_threat_model_data_generate(
    llm_model, data_flow_report_full, asset, threats
):
    agent = ThreatModelAgent(model=llm_model)

    state = ThreatGraphStateModel(
        data_flow_report=data_flow_report_full.model_dump(mode="json"),
        threats=[],
        asset=asset.model_dump(mode="json"),
    )

    result = await agent.analyze(state=state)
    threats = result.threats

    # Filter threats with a matching component UUID
    from uuid import UUID

    matching_component_id = UUID("550e8400-e29b-41d4-a716-446655440003")
    matching_threats = [
        t
        for t in result.threats
        if matching_component_id in getattr(t, "component_uuids", [])
    ]

    print("Matching Threats for component ID 550e8400-e29b-41d4-a716-446655440003:")
    pprint(matching_threats)

    eval_chain = load_evaluator(
        llm=llm_model, evaluator="pairwise_string", criteria="similarity"
    )

    expected_threat = str(threats[0])  # since you expect only one
    matching_threat_text = str(matching_threats[0])

    eval_result = eval_chain.evaluate_string_pairs(
        prediction=matching_threat_text,
        prediction_b=expected_threat,
        input="Threat modeling result",
    )

    print("Evaluated Matching Threat:")
    pprint(matching_threat_text)
    print("Evaluation Result:")
    pprint(eval_result)
