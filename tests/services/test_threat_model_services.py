import pytest
from uuid import UUID, uuid4
from unittest.mock import patch, AsyncMock

from core.models.dtos.Asset import Asset
from core.models.dtos.Repository import Repository
from core.models.dtos.ThreatModel import ThreatModel
from core.models.dtos.DataFlowReport import DataFlowReport
from core.models.dtos.Threat import Threat
from core.services.threat_model_config import ThreatModelConfig

from core.services.threat_model_services import (
    generate_threat_model,
    generate_data_flow,
    generate_threats,
    generate_threat_model_data,
)


@pytest.fixture
def threat_model_config() -> ThreatModelConfig:
    return ThreatModelConfig(
        llm_provider="openai",
        categorization_agent_llm="gpt-4o-mini",
        report_agent_llm="gpt-4o-mini",
        threat_model_agent_llm="gpt-4o-mini",
        username="user",
        pat="token",
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
        id="4fab6f10-fe7d-444c-a6ff-0cb81a0d8cf1",
        name="Test Asset",
        internet_facing=False,
        authn_type="None",
        data_classification="Public",
    )


@pytest.fixture
def test_repos(test_asset) -> list[Repository]:
    return [
        Repository(
            id="4fab6f10-fe7d-444c-a6ff-0cb81a0d8cf2",
            name="Test Repo",
            url="http://test.repo",
            asset_id=test_asset.id,
        )
    ]


@pytest.fixture
def test_data_flow_report(test_repos) -> DataFlowReport:
    """
    Fixture that creates a default DataFlowReport object
    associated with the first test repository.
    """
    return DataFlowReport(
        id="4fab6f10-fe7d-444c-a6ff-0cb81a0d8cf5",
        repository_id=test_repos[0].id,
        overview="Sample overview of data flow",
        external_entities=[],
        processes=[],
        data_stores=[],
        trust_boundaries=[],
    )


@pytest.mark.asyncio
async def test_generate_threat_model(
    test_asset, test_repos, test_data_flow_report, threat_model_config
):
    """
    Test the high-level generation of a ThreatModel from an Asset and Repos.
    """
    with patch(
        "core.services.threat_model_services.generate_data_flow",
        new_callable=AsyncMock,
    ) as mock_generate_data_flow, patch(
        "core.services.threat_model_services.generate_threats",
        new_callable=AsyncMock,
    ) as mock_generate_threats, patch(
        "core.services.threat_model_services.generate_threat_model_data",
        new_callable=AsyncMock,
    ) as mock_generate_threat_model_data, patch(
        "core.services.reports.generate_mermaid_from_dataflow",
        return_value="diagram",
    ):

        # Mock return values
        mocked_data_flow_report = DataFlowReport(
            id="4fab6f10-fe7d-444c-a6ff-0cb81a0d8cf3",
            repository_id=test_repos[0].id,
            overview="overview",
            external_entities=[],
            processes=[],
            data_stores=[],
            trust_boundaries=[],
        )
        mock_generate_data_flow.return_value = mocked_data_flow_report

        mock_generate_threats.return_value = [
            Threat(
                id="90537b65-2f32-48ca-8fc2-389f902f55c2",
                data_flow_report_id=mocked_data_flow_report.id,
                name="Test Threat",
                description="Test Description",
                stride_category="Spoofing",
                component_names=["Component1"],
                component_ids=["comp1"],
                attack_vector="Network",
                impact_level="High",
                risk_rating="Critical",
                mitigations=["Mitigation1"],
            )
        ]

        mock_generate_threat_model_data.return_value = {
            "title": "Test Threat Model",
            "summary": "Test Summary",
        }

        # Run code under test
        threat_model = await generate_threat_model(
            test_asset, test_repos, threat_model_config
        )

        # Verify results
        assert threat_model.name == "Test Threat Model"
        assert threat_model.summary == "Test Summary"
        assert len(threat_model.data_flow_reports) == 1
        assert len(threat_model.threats) == 1


@pytest.mark.asyncio
async def test_generate_data_flow(mocker, threat_model_config, test_repos):
    """
    Test generation of a data flow report from a repository.
    """
    # The result you expect from the agent call
    mock_result = {
        "data_flow_report": {},
        "could_not_review": set(),
        "could_review": set(),
        "should_not_review": set(),
        "should_review": set(),
        "reviewed": set(),
    }

    # Create a mock "workflow" object that has an async ainvoke() method
    mock_workflow = AsyncMock()
    mock_workflow.ainvoke.return_value = mock_result

    # Patch get_workflow so that whenever code calls data_flow_agent.get_workflow(),
    # it actually returns our mock_workflow
    mocker.patch(
        "core.agents.repo_data_flow_agent.DataFlowAgent.get_workflow",
        return_value=mock_workflow,
    )

    # Now call the real function that uses DataFlowAgent internally
    data_flow_report = await generate_data_flow(test_repos[0], threat_model_config)

    # If your generate_data_flow logic sets the repository_id to the repo's id:
    assert data_flow_report.repository_id == test_repos[0].id


@pytest.mark.asyncio
async def test_generate_threats(
    mocker, threat_model_config, test_asset, test_data_flow_report
):
    """
    Test generation of Threat objects given an asset and a data flow report.
    """
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
            },
            {
                "id": "4e8a6a86-76a8-43e1-a70a-7426402b8fd1",
                "name": "Sample Threat 2",
                "description": "Description for threat 2",
                "attack_vector": "Local",
                "impact_level": "Medium",
                "stride_category": "Elevation of Privilege",
                "component_names": ["ComponentX"],
                "component_ids": ["27f64ece-7e01-490b-87a4-0675ebba4048"],
                "risk_rating": "High",
                "mitigations": ["MitigationA"],
            },
        ]
    }

    # Create a mock "workflow" object that has an async ainvoke() method
    mock_workflow = AsyncMock()
    mock_workflow.ainvoke.return_value = mock_result

    # Patch get_workflow so that whenever code calls data_flow_agent.get_workflow(),
    # it actually returns our mock_workflow
    mocker.patch(
        "core.agents.threat_model_agent.ThreatModelAgent.get_workflow",
        return_value=mock_workflow,
    )

    threats = await generate_threats(
        test_asset, test_data_flow_report, threat_model_config
    )

    assert len(threats) == 2
    assert threats[0].data_flow_report_id == test_data_flow_report.id


@pytest.mark.asyncio
async def test_generate_threat_model_data(
    mocker, threat_model_config, test_asset, test_repos
):
    """
    Test generation of final threat model data (title, summary, etc.).
    """
    threat_model = ThreatModel(
        id="4fab6f10-fe7d-444c-a6ff-0cb81a0d8c20",
        name="Test Model",
        summary="Test Summary",
        asset=test_asset,
        repos=test_repos,
        data_flow_diagrams=[],
        data_flow_reports=[],
        threats=[],
    )

    # Create a mock "workflow" object that has an async ainvoke() method
    mock_result = {
        "title": "Generated Title",
        "summary": "Generated Summary",
    }
    mock_workflow = AsyncMock()
    mock_workflow.ainvoke.return_value = mock_result

    # Patch get_workflow so that whenever code calls data_flow_agent.get_workflow(),
    # it actually returns our mock_workflow
    mocker.patch(
        "core.agents.threat_model_data_agent.ThreatModelDataAgent.get_workflow",
        return_value=mock_workflow,
    )

    threat_model_data = await generate_threat_model_data(
        threat_model, threat_model_config
    )

    assert threat_model_data["title"] == "Generated Title"
    assert threat_model_data["summary"] == "Generated Summary"
