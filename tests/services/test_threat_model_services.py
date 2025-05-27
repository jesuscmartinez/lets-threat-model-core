import uuid
import pytest
import json
from uuid import uuid4, UUID
from unittest.mock import patch, AsyncMock, MagicMock

from pydantic import SecretStr

# Import models and services from your project.
from core.models.dtos.Asset import Asset
from core.models.dtos.Repository import Repository
from core.models.dtos.ThreatModel import ThreatModel
from core.models.dtos.DataFlowReport import DataFlowReport
from core.models.dtos.Threat import Threat
from core.models.enums import DataClassification, AuthnType, StrideCategory, Level
from core.services.threat_model_config import ThreatModelConfig
from core.services.threat_model_services import (
    generate_threat_model,
    generate_data_flow,
    generate_threats,
    generate_threat_model_data,
    process_remote_repository,
    clone_repository,
)


# -------------------------------
# Fixtures
# -------------------------------


@pytest.fixture
def threat_model_config() -> ThreatModelConfig:
    return ThreatModelConfig(
        llm_provider="openai",
        categorization_agent_llm="gpt-4o-mini",
        report_agent_llm="gpt-4o-mini",
        threat_model_agent_llm="gpt-4o-mini",
        username="user",
        pat=SecretStr("token"),
        context_window=2048,
        max_output_tokens=512,
        review_max_file_in_batch=10,
        review_token_buffer=100,
        categorize_max_file_in_batch=10,
        categorize_token_buffer=100,
        categorize_only=False,
        completion_threshold=0.9,
        review_agent_llm="review_model",
    )


@pytest.fixture
def test_asset() -> Asset:
    return Asset(
        id=UUID("4fab6f10-fe7d-444c-a6ff-0cb81a0d8cf1"),
        name="Test Asset",
        description="Test asset description",
        internet_facing=False,
        authn_type=AuthnType.NONE,
        data_classification=DataClassification.PUBLIC,
    )


@pytest.fixture
def test_repos(test_asset) -> list[Repository]:
    # Provide only URL or local_path (not both) to avoid validation errors.
    return [
        Repository(
            id=UUID("4fab6f10-fe7d-444c-a6ff-0cb81a0d8cf2"),
            name="Test Repo",
            description="A test repository",
            url="https://example.com/repo",
            asset_id=test_asset.id,
        )
    ]


@pytest.fixture
def test_data_flow_report(test_repos) -> DataFlowReport:
    # Create a minimal DataFlowReport; adjust fields as needed.
    return DataFlowReport(
        id=uuid.UUID("57a20a0f-f0d1-4c83-a1fb-7c195ad44bef"),
        repository_id=test_repos[0].id,
        overview="Test description",
        external_entities=[],
        processes=[],
        should_review=[],
        reviewed=[],
        could_review=[],
        should_not_review=[],
        could_not_review=[],
    )


# -------------------------------
# Tests for generate_threat_model
# -------------------------------


@pytest.mark.asyncio
async def test_generate_threat_model(
    test_asset, test_repos, test_data_flow_report, threat_model_config
):
    with patch(
        "core.services.threat_model_services.generate_data_flow", new_callable=AsyncMock
    ) as mock_generate_data_flow, patch(
        "core.services.threat_model_services.generate_threats", new_callable=AsyncMock
    ) as mock_generate_threats, patch(
        "core.services.threat_model_services.generate_threat_model_data",
        new_callable=AsyncMock,
    ) as mock_generate_threat_model_data, patch(
        "core.services.threat_model_services.generate_dataflow_diagram",
        return_value="diagram",
    ):
        # Setup mock returns
        mocked_data_flow_report = DataFlowReport(
            id=uuid.UUID("57a20a0f-f0d1-4c83-a1fb-7c195ad44be4"),
            repository_id=test_repos[0].id,
            overview="overview",
            external_entities=[],
            processes=[],
            data_stores=[],
            trust_boundaries=[],
            should_review=[],
            reviewed=[],
            could_review=[],
            should_not_review=[],
            could_not_review=[],
        )
        mock_generate_data_flow.return_value = mocked_data_flow_report

        mock_generate_threats.return_value = [
            Threat(
                id=UUID("90537b65-2f32-48ca-8fc2-389f902f55c2"),
                data_flow_report_id=mocked_data_flow_report.id,
                name="Test Threat",
                description="Test Description",
                stride_category=StrideCategory.SPOOFING,
                component_names=["Component1"],
                component_ids=[UUID("a20df271-5105-4768-9a04-b9fc8103dc0b")],
                attack_vector="Network",
                impact_level=Level.HIGH,
                risk_rating=Level.CRITICAL,
                mitigations=["Mitigation1"],
            )
        ]

        mock_generate_threat_model_data.return_value = {
            "title": "Test Threat Model",
            "summary": "Test Summary",
        }

        # Act
        threat_model = await generate_threat_model(
            test_asset, test_repos, threat_model_config
        )

        # Assert
        assert threat_model.name == "Test Threat Model"
        assert threat_model.summary == "Test Summary"
        assert len(threat_model.data_flow_reports) == 1
        assert len(threat_model.threats) == 1


# -------------------------------
# Test for generate_data_flow (local repository)
# -------------------------------


@pytest.mark.asyncio
async def test_generate_data_flow_local_repo(mocker, threat_model_config):
    """
    Test generate_data_flow when processing a local repository.
    """
    local_repo = Repository(
        id=uuid.UUID("4fab6f10-fe7d-444c-a6ff-0cb81a0d8cf2"),
        name="Test Local Repo",
        local_path="/path/to/local/repo",
        asset_id=uuid.UUID("4fab6f10-fe7d-444c-a6ff-0cb81a0d8cf1"),
    )

    # Patch Path.exists() and Path.is_dir() to return True
    mocker.patch("core.services.threat_model_services.Path.exists", return_value=True)
    mocker.patch("core.services.threat_model_services.Path.is_dir", return_value=True)

    mock_workflow = AsyncMock()
    mock_workflow.ainvoke.return_value = {
        "data_flow_report": {},
        "could_review": [],
        "reviewed": [],
        "should_review": [],
        "could_not_review": [],
        "should_not_review": [],
    }

    mocker.patch(
        "core.agents.repo_data_flow_agent.DataFlowAgent.get_workflow",
        return_value=mock_workflow,
    )

    mocker.patch(
        "core.services.threat_model_services.generate_dataflow_diagram",
        return_value="mocked_diagram",
    )

    # Act
    data_flow_report = await generate_data_flow(local_repo, threat_model_config)

    # Assert
    assert data_flow_report.repository_id == local_repo.id


# -------------------------------
# Test for process_remote_repository
# -------------------------------


@pytest.mark.asyncio
async def test_process_remote_repository_calls_clone_repository(mocker):
    repository = Repository(
        id=uuid.UUID("4fab6f10-fe7d-444c-a6ff-0cb81a0d8cf2"),
        name="Test Remote Repo",
        url="https://github.com/example/repo.git",
        asset_id=uuid.UUID("4fab6f10-fe7d-444c-a6ff-0cb81a0d8cf1"),
    )

    config = ThreatModelConfig(
        llm_provider="openai",
        categorization_agent_llm="gpt-4o-mini",
        report_agent_llm="gpt-4o-mini",
        threat_model_agent_llm="gpt-4o-mini",
        username="testuser",
        pat=SecretStr("testpat"),
        context_window=2048,
        max_output_tokens=512,
        review_max_file_in_batch=10,
        review_token_buffer=100,
        categorize_max_file_in_batch=10,
        categorize_token_buffer=100,
        categorize_only=False,
        completion_threshold=0.9,
    )

    # Patch clone_repository and create_data_flow_agent
    mock_clone_repo = mocker.patch(
        "core.services.threat_model_services.clone_repository"
    )

    mock_agent = MagicMock()
    mock_workflow = AsyncMock()
    mock_workflow.ainvoke.return_value = {
        "data_flow_report": {},
        "could_review": [],
        "reviewed": [],
        "should_review": [],
        "could_not_review": [],
        "should_not_review": [],
    }
    mock_agent.get_workflow.return_value = mock_workflow

    mock_create_agent = mocker.patch(
        "core.services.threat_model_services.create_data_flow_agent",
        return_value=mock_agent,
    )

    mocker.patch(
        "core.agents.repo_data_flow_agent.DataFlowAgent.get_workflow",
        return_value=mock_workflow,
    )

    # Act
    result = await process_remote_repository(repository, config)

    # Assert
    mock_clone_repo.assert_called_once()
    mock_create_agent.assert_called_once()
    mock_workflow.ainvoke.assert_called_once()
    assert "data_flow_report" in result


# -------------------------------
# Test for clone_repository (GitHub clone)
# -------------------------------


def test_clone_repository_with_github(mocker):
    username = "myuser"
    pat = SecretStr("ghp_12345FAKETOKEN")
    github_repo_url = "github.com/myuser/myrepo.git"
    temp_dir = "/tmp/clonedir"

    mock_git_repo = mocker.patch(
        "core.services.threat_model_services.GitRepo.clone_from"
    )

    mock_repo = MagicMock()
    mock_repo.head.reference.name = "main"
    mock_repo.head.commit.hexsha = "abcdef123456"
    mock_git_repo.return_value = mock_repo

    # Act
    result = clone_repository(username, pat, github_repo_url, temp_dir)

    # Assert
    expected_url = f"https://{username}:{pat.get_secret_value()}@{github_repo_url}"
    mock_git_repo.assert_called_once_with(expected_url, temp_dir)
    assert result.head.reference.name == "main"
    assert result.head.commit.hexsha == "abcdef123456"


# -------------------------------
# Test for generate_threats
# -------------------------------


@pytest.mark.asyncio
async def test_generate_threats(
    mocker, threat_model_config, test_asset, test_data_flow_report
):
    mock_result = {
        "threats": [
            {
                "id": "bd977e86-67fe-4cc3-9d1c-a1c112abf94c",
                "name": "Sample Threat 1",
                "description": "Description for threat 1",
                "attack_vector": "Network",
                "impact_level": "High",
                "stride_category": "Tampering",
                "component_names": ["Component1", "Component2"],
                "component_ids": ["72a151d3-0817-4559-a09f-310ffdf8dfbd"],
                "risk_rating": "Critical",
                "mitigations": ["Mitigation1", "Mitigation2"],
            }
        ]
    }

    mock_workflow = AsyncMock()
    mock_workflow.ainvoke.return_value = mock_result
    mocker.patch(
        "core.agents.threat_model_agent.ThreatModelAgent.get_workflow",
        return_value=mock_workflow,
    )

    threats = await generate_threats(
        test_asset, test_data_flow_report, threat_model_config
    )
    assert len(threats) == 1
    assert threats[0].data_flow_report_id == test_data_flow_report.id


# -------------------------------
# Test for generate_threat_model_data
# -------------------------------


@pytest.mark.asyncio
async def test_generate_threat_model_data(
    mocker, threat_model_config, test_asset, test_repos
):
    threat_model = ThreatModel(
        id=uuid.UUID("4fab6f10-fe7d-444c-a6ff-0cb81a0d8c20"),
        name="Test Model",
        summary="Test Summary",
        asset=test_asset,
        repos=test_repos,
        data_flow_reports=[],
        threats=[],
    )

    mock_result = {
        "title": "Generated Title",
        "summary": "Generated Summary",
    }

    mock_workflow = AsyncMock()
    mock_workflow.ainvoke.return_value = mock_result
    mocker.patch(
        "core.agents.threat_model_data_agent.ThreatModelDataAgent.get_workflow",
        return_value=mock_workflow,
    )

    threat_model_data = await generate_threat_model_data(
        threat_model, threat_model_config
    )
    assert threat_model_data["title"] == "Generated Title"
    assert threat_model_data["summary"] == "Generated Summary"
