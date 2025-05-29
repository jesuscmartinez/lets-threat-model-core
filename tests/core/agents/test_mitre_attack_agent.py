import pytest
import asyncio
from uuid import uuid4
from core.agents.mitre_attack_agent import (
    MitreAttackAgent,
    AttackGraphStateModel,
    Result,
)
import core.agents.mitre_attack_agent as mitre_module
from langchain_core.language_models.chat_models import BaseChatModel
from core.models.dtos.MitreAttack import AgentAttack


class DummyModel(BaseChatModel):
    def with_structured_output(self, schema):
        # Stub for chaining prompts; return self for simplicity
        return self

    def __ror__(self, other):
        # Support the 'prompt | model' chaining operator
        return self

    @property
    def _llm_type(self):
        # Return a dummy llm type
        return "dummy"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        # Return a dummy response structure
        return {"generations": [], "llm_output": {}}


@pytest.fixture
def agent() -> MitreAttackAgent:
    return MitreAttackAgent(model=DummyModel())


def test_initialize_converts_uuids(monkeypatch, agent):
    state = AttackGraphStateModel(data_flow_report={"foo": "bar"})
    # Stub out convert_uuids_to_ids
    monkeypatch.setattr(
        agent.agent_helper, "convert_uuids_to_ids", lambda x: {"converted": True}
    )
    new_state = agent.initialize(state)
    assert new_state.data_flow_report == {"converted": True}


def test_finalize_converts_ids(monkeypatch, agent):
    state = AttackGraphStateModel()
    state.attacks = [{"a": 1}, {"b": 2}]
    # Stub out convert_ids_to_uuids
    monkeypatch.setattr(
        agent.agent_helper,
        "convert_ids_to_uuids",
        lambda threat: {"uuid_converted": threat},
    )
    new_state = agent.finalize(state)
    assert new_state.attacks == [
        {"uuid_converted": {"a": 1}},
        {"uuid_converted": {"b": 2}},
    ]


@pytest.mark.asyncio
async def test_process_component_success(monkeypatch, agent):
    component = {"name": "comp1"}
    report = {}

    # Stub ainvoke_with_retry to return a successful attack Result object
    async def fake_ainvoke(chain, data):
        return Result(
            attacks=[
                AgentAttack(
                    component_id=uuid4(),
                    attack_tactic="Tactic",
                    technique_id="T1234",
                    technique_name="Some Technique",
                    reason_for_relevance="Relevant for test",
                    mitigation="Test mitigation",
                )
            ]
        )

    monkeypatch.setattr(mitre_module, "ainvoke_with_retry", fake_ainvoke)

    attacks = await agent._process_component(component, report, chain=None)
    assert isinstance(attacks, list)
    assert len(attacks) == 1
    assert attacks[0].attack_tactic == "Tactic"
    assert attacks[0].technique_id == "T1234"
    assert attacks[0].technique_name == "Some Technique"


@pytest.mark.asyncio
async def test_process_component_exception(monkeypatch, agent, caplog):
    component = {"name": "comp2"}
    report = {}

    # Stub ainvoke_with_retry to raise an exception
    async def fake_ainvoke(chain, data):
        raise ValueError("failure")

    monkeypatch.setattr(mitre_module, "ainvoke_with_retry", fake_ainvoke)

    attacks = await agent._process_component(component, report, chain=None)
    assert attacks == []
    # Verify that an error was logged
    assert "Error analyzing component" in caplog.text


@pytest.mark.asyncio
async def test_analyze_with_none_report(agent):
    state = AttackGraphStateModel()
    state.data_flow_report = {}
    new_state = await agent.analyze(state)
    # When report is empty, attacks should be set to an empty list
    assert new_state.attacks == []


@pytest.mark.asyncio
async def test_analyze_with_empty_report(agent):
    state = AttackGraphStateModel()
    # Default data_flow_report is an empty dict
    new_state = await agent.analyze(state)
    assert new_state.attacks == []


def test_get_workflow(agent):
    workflow = agent.get_workflow()
    # Ensure a workflow object is returned
    assert workflow is not None
