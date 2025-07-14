import pytest

from core.agents.mitre_attack_agent import MitreAttackAgent, AttackGraphStateModel
from core.models.dtos.MitreAttack import AgentAttack

pytestmark = pytest.mark.agent


async def test_mitre_attack_agent_analysis(llm_model, data_flow_report_full):
    # Prepare a report with one external entity and one process
    data = data_flow_report_full.model_dump(mode="json")

    state = AttackGraphStateModel(data_flow_report=data)

    agent = MitreAttackAgent(model=llm_model)

    # Run full workflow
    state = await agent.analyze(state)

    # Assert that the correct number of attacks was generated
    assert isinstance(state.attacks, list)
    assert len(state.attacks) > 20

    # Basic presence checks for components in generated attacks
    assert any(a.component == "GitHub" for a in state.attacks)
    assert any(a.component == "Threat Model Data Boundary" for a in state.attacks)
