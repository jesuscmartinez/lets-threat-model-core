import pytest
import asyncio
from unittest.mock import AsyncMock

from langchain_core.runnables import Runnable

import core.agents.threat_model_agent as tma
from core.agents.threat_model_agent import ThreatModelAgent, ThreatGraphStateModel
from langchain_core.language_models.chat_models import BaseChatModel


class DummyRunnable(Runnable):
    def invoke(self, input, config=None):
        return {"responses": [[{"threats": [{"name": "dummy"}]}]]}

    async def ainvoke(self, input, config=None):
        return {"responses": [[{"threats": [{"name": "dummy"}]}]]}


class DummyModel(BaseChatModel):
    def with_structured_output(self, schema):
        # Stub for chaining prompts; return self for simplicity
        return self

    def bind_tools(self, tools, **kwargs):
        # Stub for binding tools; return self for simplicity
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


def test_initialize(monkeypatch):
    agent = ThreatModelAgent(model=DummyModel())
    state = ThreatGraphStateModel(asset={"foo": "bar"}, data_flow_report={"baz": 1})
    # Stub out convert_uuids_to_ids to verify it's called correctly
    monkeypatch.setattr(
        agent.agent_helper, "convert_uuids_to_ids", lambda x: f"converted-{repr(x)}"
    )

    new_state = agent.initialize(state)

    assert new_state.asset == "converted-{'foo': 'bar'}"
    assert new_state.data_flow_report == "converted-{'baz': 1}"


def test_finalize(monkeypatch):
    agent = ThreatModelAgent(model=DummyModel())
    state = ThreatGraphStateModel()
    # Pretend we already have two raw threat dicts
    state.threats = [{"a": 1}, {"b": 2}]
    # Stub out convert_ids_to_uuids
    monkeypatch.setattr(
        agent.agent_helper,
        "convert_ids_to_uuids",
        lambda threat: f"uuid-{repr(threat)}",
    )

    new_state = agent.finalize(state)

    assert new_state.threats == [
        "uuid-{'a': 1}",
        "uuid-{'b': 2}",
    ]


async def test_analyze_aggregates_all_components(monkeypatch):
    monkeypatch.setattr(
        tma, "create_extractor", lambda *args, **kwargs: DummyRunnable()
    )
    agent = ThreatModelAgent(model=DummyModel())
    # Create a state with two external_entities and no other components
    state = ThreatGraphStateModel(
        asset={"unused": True},
        data_flow_report={
            "external_entities": [
                {"name": "CompA"},
                {"name": "CompB"},
            ],
            "processes": [],
            "data_stores": [],
            "trust_boundaries": [],
        },
    )

    # Stub out _process_component to return a single‐item list named after the component
    async def fake_process_component(component, asset, report, chain):
        return [{"component_name": component["name"]}]

    monkeypatch.setattr(agent, "_process_component", fake_process_component)

    # Run the async analyze method
    result_state = await agent.analyze(state)

    # Verify threats were aggregated for both components
    assert {"component_name": "CompA"} in result_state.threats
    assert {"component_name": "CompB"} in result_state.threats
    assert len(result_state.threats) == 2
