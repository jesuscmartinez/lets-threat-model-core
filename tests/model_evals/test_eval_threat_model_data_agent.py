import pytest
from core.agents.threat_model_data_agent import (
    ThreatModelDataAgent,
    ThreatModelDataStateModel,
)

pytestmark = pytest.mark.agent


async def test_threat_model_data_generate(
    llm_model,
    threat_model,
):
    agent = ThreatModelDataAgent(model=llm_model)
    state = {"threat_model": threat_model.model_dump(mode="json")}
    state_model = ThreatModelDataStateModel(**state)

    result = await agent.generate(state_model)

    # Assert title and summary are generated
    assert hasattr(result, "title")
    assert isinstance(result.title, str)
    assert result.title != ""
    assert hasattr(result, "summary")
    assert isinstance(result.summary, str)
    assert result.summary != ""
