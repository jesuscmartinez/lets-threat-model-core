import copy
from typing import List
import pytest
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, MagicMock, patch
from pydantic import BaseModel, SecretStr

from core.agents.repo_data_flow_agent import DataFlowAgent, GraphStateModel
from core.agents.repo_data_flow_agent_config import RepoDataFlowAgentConfig
from core.agents.agent_tools import AgentHelper
from core.models.dtos.File import File
from core.models.dtos.DataFlowReport import (
    AgentDataFlowReport,
    ExternalEntity,
    Process,
    DataStore,
    TrustBoundary,
)
from git import Repo as GitRepo
from langgraph.graph import StateGraph, START, END
from langchain_core.language_models.chat_models import BaseChatModel


@pytest.fixture
def agent_config():
    # Create a MagicMock that enforces RepoDataFlowAgentConfig attributes
    mock_config = MagicMock(spec=RepoDataFlowAgentConfig)

    # Provide default values for the mock's fields
    mock_config.exclude_patterns = [
        "**/node_modules/**",
        "*.log",
        "*.tmp",
        "test/**",
        "tests/**",
        "**/test/**",
        "**/tests/**",
        "**/__pycache__/**",
        ".DS_Store",
        "**/*.png",
        "**/*.jpg",
        "**/*.scss",
        "*.git/**",
        "*.gitignore",
        "*.dockerignore",
    ]
    mock_config.include_patterns = [
        "README.md",
        "docker-compose.yml",
        "swagger.yml",
        "Dockerfile",
    ]

    # Provide any other fields that your code references
    mock_config.categorize_only = False
    mock_config.completion_threshold = 0.8
    mock_config.context_window = 128000
    mock_config.max_output_tokens = 16384
    mock_config.review_max_file_in_batch = 3
    mock_config.review_token_buffer = 0.5
    mock_config.categorize_max_file_in_batch = 30
    mock_config.categorize_token_buffer = 0.5
    mock_config.categorize_only = False
    mock_config.completion_threshold = 0.8

    return mock_config


@pytest.fixture
def data_flow_agent(agent_config):
    """
    Create a DataFlowAgent instance with our SimpleChatModel, dummy config, and a temporary directory.
    """
    temp_dir = TemporaryDirectory()
    base_chat_model = MagicMock(spec=BaseChatModel)
    base_chat_model.get_num_tokens.return_value = 10
    agent = DataFlowAgent(
        directory=temp_dir.name,
        username="dummy_user",
        password=SecretStr("dummy_pass"),
        categorization_model=base_chat_model,
        review_model=base_chat_model,
        config=agent_config,
    )
    agent.agent_helper = MagicMock(spec=AgentHelper)
    agent.agent_helper.convert_uuids_to_ids.side_effect = lambda x: {"converted": x}
    agent.agent_helper.convert_ids_to_uuids.side_effect = lambda x: {"restored": x}
    return agent


@pytest.fixture
def initial_graph_state():
    return GraphStateModel(
        should_review=set(),
        could_review=set(),
        should_not_review=set(),
        data_flow_report={},
        reviewed=set(),
        could_not_review=set(),
    )


# -----------------------------------------------------------------------------
# Node Function Tests
# -----------------------------------------------------------------------------
def test_initialize(data_flow_agent, initial_graph_state):
    initial_graph_state.data_flow_report = {"dummy": "value"}
    updated_state = data_flow_agent.initialize(initial_graph_state)
    assert updated_state.data_flow_report == {"converted": {"dummy": "value"}}
    data_flow_agent.agent_helper.convert_uuids_to_ids.assert_called_once_with(
        {"dummy": "value"}
    )


def test_finalize(data_flow_agent, initial_graph_state):
    initial_graph_state.data_flow_report = {"dummy": "value"}
    updated_state = data_flow_agent.finalize(initial_graph_state)
    assert updated_state.data_flow_report == {"restored": {"dummy": "value"}}
    data_flow_agent.agent_helper.convert_ids_to_uuids.assert_called_once_with(
        {"dummy": "value"}
    )


def test_rules_categorization(data_flow_agent, initial_graph_state, tmp_path):
    test_dir = tmp_path / "repo"
    test_dir.mkdir()
    (test_dir / "README.md").write_text("This is a README file.")
    (test_dir / "temp.tmp").write_text("Temporary file.")
    data_flow_agent.directory = str(test_dir)
    updated_state = data_flow_agent.rules_categorization(initial_graph_state)
    included_files = {f.file_path for f in updated_state.should_review}
    excluded_files = {f.file_path for f in updated_state.should_not_review}
    assert "README.md" in included_files
    assert "temp.tmp" in excluded_files


async def test_categorize_files(data_flow_agent, mocker, initial_graph_state):
    dummy_file = File(file_path="dummy.py", justification="")
    state = copy.deepcopy(initial_graph_state)
    state.should_review.add(dummy_file)
    state.could_review.add(dummy_file)

    # We'll parse the LLM output into these fields
    class CategorizationResult(BaseModel):
        should_review: List[File]
        could_review: List[File]
        should_not_review: List[File]

    mock_result = CategorizationResult(
        should_review=[dummy_file],
        could_review=[],
        should_not_review=[],
    )

    # Create a mock chain that simulates the asynchronous LLM call.
    patched_chain = AsyncMock(return_value=mock_result)

    # Patch the model's with_structured_output method to return our mock chain.
    data_flow_agent.categorize_model.with_structured_output.return_value = patched_chain

    updated_state = await data_flow_agent.categorize_files(state)
    assert (
        dummy_file in updated_state.should_review
        or dummy_file in updated_state.could_review
    )


def test_categorize_only(data_flow_agent):
    data_flow_agent.config.categorize_only = True
    assert data_flow_agent.categorize_only({}) is True
    data_flow_agent.config.categorize_only = False
    assert data_flow_agent.categorize_only({}) is False


def test_done_reviewing(data_flow_agent, initial_graph_state):
    data_flow_agent.config.categorize_only = False
    data_flow_agent.config.completion_threshold = 0.5
    assert data_flow_agent.done_reviewing(initial_graph_state) is True

    dummy_file = File(file_path="dummy.py", justification="")
    initial_graph_state.should_review.add(dummy_file)
    initial_graph_state.reviewed = {dummy_file}
    assert data_flow_agent.done_reviewing(initial_graph_state) is True


def test_get_report_stats(data_flow_agent, initial_graph_state):

    initial_graph_state.should_review = {File(file_path="a.md", justification="test")}
    initial_graph_state.could_review = {File(file_path="b.py", justification="")}
    initial_graph_state.should_not_review = {File(file_path="c.txt", justification="")}
    initial_graph_state.reviewed = {File(file_path="d.md", justification="")}
    initial_graph_state.could_not_review = {File(file_path="e.tmp", justification="")}
    initial_graph_state.data_flow_report = AgentDataFlowReport(
        overview="Test overview",
        external_entities=[ExternalEntity(name="Entity1", description="Desc1")],
        processes=[Process(name="Proc1", description="DescP")],
        data_stores=[DataStore(name="Store1", description="DescS")],
        trust_boundaries=[TrustBoundary(name="Boundary1", description="DescB")],
    )
    stats = data_flow_agent.get_report_stats(initial_graph_state)
    assert "Total Files:" in stats
    assert "Reviewed:" in stats
    assert "External Entities:" in stats
    assert "Trust Boundaries:" in stats


# -----------------------------------------------------------------------------
# Integration Test for the Entire Workflow
# -----------------------------------------------------------------------------
async def test_workflow_run(data_flow_agent, initial_graph_state):

    def dummy_initialize(state: GraphStateModel) -> GraphStateModel:
        state.data_flow_report = {"converted": True}
        return state

    def dummy_rules_categorization(state: GraphStateModel) -> GraphStateModel:
        from core.models.dtos.File import File

        dummy_file = File(file_path="dummy.md", justification="matched include rule")
        state.should_review.add(dummy_file)
        return state

    def dummy_categorize_only(state: GraphStateModel) -> bool:
        return True

    def dummy_review_files(state: GraphStateModel) -> GraphStateModel:
        state.reviewed = state.should_review.copy()
        return state

    def dummy_categorize_filepaths(state: GraphStateModel) -> GraphStateModel:
        return state

    def dummy_done_reviewing(state: GraphStateModel) -> bool:
        return True

    def dummy_finalize(state: GraphStateModel) -> GraphStateModel:
        state.data_flow_report = {"final": "report"}
        return state

    data_flow_agent.initialize = dummy_initialize
    data_flow_agent.rules_categorization = dummy_rules_categorization
    data_flow_agent.categorize_only = dummy_categorize_only
    data_flow_agent.review_files = dummy_review_files
    data_flow_agent.categorize_files = dummy_categorize_filepaths
    data_flow_agent.done_reviewing = dummy_done_reviewing
    data_flow_agent.finalize = dummy_finalize

    workflow = data_flow_agent.get_workflow()
    result_state = await workflow.ainvoke(initial_graph_state.dict())
    assert result_state
