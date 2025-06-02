import asyncio
import uuid
from pathlib import Path
from tempfile import TemporaryDirectory
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from core.services.threat_model_services import (
    generate_data_flow,
    generate_mitre_attack,
    generate_threats,
    generate_threat_model_data,
    generate_threat_model,
    clone_repository,
)
from core.services.threat_model_config import ThreatModelConfig
from core.models.dtos.Asset import Asset
from core.models.dtos.Repository import Repository
from core.models.dtos.DataFlowReport import DataFlowReport
from core.models.dtos.ThreatModel import ThreatModel


@pytest.fixture
def dummy_config():
    return ThreatModelConfig()


@pytest.fixture
def dummy_asset():
    return Asset(uuid=uuid.uuid4(), name="TestAsset")


@pytest.fixture
def dummy_repo(tmp_path, dummy_asset):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    return Repository(
        uuid=uuid.uuid4(),
        name="TestRepo",
        local_path=str(repo_dir),
        asset_uuid=dummy_asset.uuid,
    )


@pytest.fixture
def dummy_report(dummy_repo):
    return DataFlowReport(
        repository_uuid=dummy_repo.uuid,
    )


@pytest.mark.asyncio
async def test_generate_data_flow_monkeypatched_process(dummy_config, dummy_repo):
    # stub the local/remote processing functions
    fake_end_state = {
        "data_flow_report": {
            "overview": "OV",
            "external_entities": [],
            "processes": [],
            "data_stores": [],
            "trust_boundaries": [],
        }
    }
    with patch(
        "core.services.threat_model_services.process_local_repository",
        new=AsyncMock(return_value=fake_end_state),
    ):
        report: DataFlowReport = await generate_data_flow(dummy_repo, dummy_config)
        assert isinstance(report, DataFlowReport)
        assert report.overview == "OV"
        assert report.repository_uuid == dummy_repo.uuid


@pytest.mark.asyncio
async def test_generate_mitre_attack(monkeypatch, dummy_config, dummy_report):

    # stub out the MitreAttackAgent and its workflow
    fake_agent = MagicMock()
    fake_wf = fake_agent.get_workflow.return_value
    fake_wf.ainvoke = AsyncMock(
        return_value={
            "attacks": [
                {
                    "technique": "T1000",
                    "description": "desc",
                    "component": "comp",
                    "component_uuid": str(uuid.uuid4()),
                }
            ]
        }
    )
    monkeypatch.setattr(
        "core.services.threat_model_services.MitreAttackAgent",
        lambda model: fake_agent,
    )

    attacks = await generate_mitre_attack(dummy_report, dummy_config)
    assert len(attacks) == 1
    assert hasattr(attacks[0], "uuid")


@pytest.mark.asyncio
async def test_generate_threats(monkeypatch, dummy_config, dummy_asset, dummy_report):

    # stub out the ThreatModelAgent and its workflow
    fake_agent = MagicMock()
    fake_wf = fake_agent.get_workflow.return_value
    fake_wf.ainvoke = AsyncMock(return_value={"threats": [{"name": "Threat1"}]})
    monkeypatch.setattr(
        "core.services.threat_model_services.ThreatModelAgent",
        lambda model: fake_agent,
    )

    threats = await generate_threats(dummy_asset, dummy_report, dummy_config)
    assert len(threats) == 1
    assert threats[0].data_flow_report_uuid == dummy_report.uuid


@pytest.mark.asyncio
async def test_generate_threat_model_data(
    monkeypatch, dummy_config, dummy_asset, dummy_repo, dummy_report
):
    # a minimal ThreatModel
    tm = ThreatModel(
        uuid=uuid.uuid4(),
        name="",
        summary="",
        asset=dummy_asset,
        repos=[dummy_repo],
        data_flow_reports=[dummy_report],
    )
    # stub out the DataAgent
    fake_agent = MagicMock()
    fake_wf = fake_agent.get_workflow.return_value
    fake_wf.ainvoke = AsyncMock(
        return_value={"title": "NEW TITLE", "summary": "NEW SUMMARY"}
    )
    monkeypatch.setattr(
        "core.services.threat_model_services.ThreatModelDataAgent",
        lambda model: fake_agent,
    )

    result = await generate_threat_model_data(tm, dummy_config)
    assert result["title"] == "NEW TITLE"
    assert result["summary"] == "NEW SUMMARY"


@pytest.mark.asyncio
async def test_generate_threat_model_full_pipeline(
    monkeypatch, dummy_config, dummy_asset, dummy_repo, dummy_report
):

    monkeypatch.setattr(
        "core.services.threat_model_services.generate_data_flow",
        AsyncMock(return_value=dummy_report),
    )
    monkeypatch.setattr(
        "core.services.threat_model_services.generate_mitre_attack",
        AsyncMock(return_value=[{"technique": "T999"}]),
    )
    monkeypatch.setattr(
        "core.services.threat_model_services.generate_threats",
        AsyncMock(return_value=[{"name": "X"}]),
    )
    monkeypatch.setattr(
        "core.services.threat_model_services.generate_threat_model_data",
        AsyncMock(return_value={"title": "Pipeline", "summary": "Done"}),
    )

    tm: ThreatModel = await generate_threat_model(
        dummy_asset, [dummy_repo], dummy_config
    )
    assert tm.name == "Pipeline"
    assert tm.summary == "Done"
    assert len(tm.data_flow_reports) == 1
