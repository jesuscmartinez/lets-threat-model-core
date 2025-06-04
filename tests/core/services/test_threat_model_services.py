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

from core.services.threat_model_services import (
    process_local_repository,
    process_remote_repository,
    build_data_flow_report,
    merge_data_flows,
)
from pydantic import SecretStr


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


# Automatically mock generate_dataflow_diagram to return a static diagram string
@pytest.fixture(autouse=True)
def mock_mermaid(monkeypatch):
    monkeypatch.setattr(
        "core.services.threat_model_services.generate_dataflow_diagram",
        lambda *args, **kwargs: "graph TD; A-->B",
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


# --- Additional tests for process/merge/clone/build ---


@pytest.mark.asyncio
async def test_merge_data_flows(monkeypatch, dummy_config):
    # Create two minimal DataFlowReport objects
    import uuid as _uuid

    report1 = DataFlowReport(
        uuid=_uuid.uuid4(),
        repository_uuid=_uuid.uuid4(),
        overview="O1",
        external_entities=[],
        processes=[],
        data_stores=[],
        trust_boundaries=[],
    )
    report1.should_review = ["file1"]
    report1.reviewed = ["file2"]
    report1.could_review = []
    report1.should_not_review = []
    report1.could_not_review = []

    report2 = DataFlowReport(
        uuid=_uuid.uuid4(),
        repository_uuid=_uuid.uuid4(),
        overview="O2",
        external_entities=[],
        processes=[],
        data_stores=[],
        trust_boundaries=[],
    )
    report2.should_review = ["file3"]
    report2.reviewed = ["file4"]
    report2.could_review = []
    report2.should_not_review = []
    report2.could_not_review = []

    # Stub out MergeDataFlowAgent to return a merged state
    fake_agent = MagicMock()
    fake_wf = fake_agent.get_workflow.return_value
    fake_wf.ainvoke = AsyncMock(
        return_value={
            "merged_data_flow_report": {
                "overview": "OM",
                "external_entities": [],
                "processes": [],
                "data_stores": [],
                "trust_boundaries": [],
            },
            "justification": "Merged",
        }
    )
    monkeypatch.setattr(
        "core.services.threat_model_services.MergeDataFlowAgent",
        lambda model: fake_agent,
    )

    merged = await merge_data_flows([report1, report2], dummy_config)
    assert isinstance(merged, DataFlowReport)
    assert merged.overview == "OM"
    # Check that fields from both reports are aggregated
    assert "file1" in merged.should_review and "file3" in merged.should_review
    assert merged.reviewed == ["file2", "file4"]


def test_clone_repository_success(tmp_path, monkeypatch):
    from pydantic import SecretStr as _SecretStr

    # Prepare dummy parameters
    dummy_url = "example.com/repo.git"
    username = "user"
    pat = _SecretStr("token")
    temp_dir = str(tmp_path)

    # Dummy repo with head attributes
    class DummyHead:
        reference = type("R", (), {"name": "main"})()
        commit = type("C", (), {"hexsha": "abc123"})()

    class DummyRepo:
        head = DummyHead()

    # Stub GitRepo.clone_from
    monkeypatch.setattr(
        "core.services.threat_model_services.GitRepo.clone_from",
        lambda auth_url, dir: DummyRepo(),
    )

    repo = clone_repository(username, pat, dummy_url, temp_dir)
    assert isinstance(repo, DummyRepo)


def test_clone_repository_failure(monkeypatch):
    from pydantic import SecretStr as _SecretStr

    username = "user"
    pat = _SecretStr("token")
    temp_dir = "nonexistent"

    # Stub clone_from to raise
    def fake_clone(auth_url, dir):
        raise Exception("clone error")

    monkeypatch.setattr(
        "core.services.threat_model_services.GitRepo.clone_from",
        fake_clone,
    )

    with pytest.raises(Exception):
        clone_repository(username, pat, "example.com/repo.git", temp_dir)


def test_build_data_flow_report(monkeypatch, dummy_config, dummy_repo):
    # Minimal end_state for a data flow report
    end_state = {
        "data_flow_report": {
            "overview": "OV",
            "external_entities": [],
            "processes": [],
            "data_stores": [],
            "trust_boundaries": [],
        }
    }
    # Stub generate_dataflow_diagram
    monkeypatch.setattr(
        "core.services.threat_model_services.generate_dataflow_diagram",
        lambda config, report: "graphTD",
    )

    report = build_data_flow_report(dummy_config, dummy_repo, end_state)
    assert isinstance(report, DataFlowReport)
    assert report.overview == "OV"
    assert report.diagram == "graphTD"
    assert report.repository_uuid == dummy_repo.uuid


@pytest.mark.asyncio
async def test_process_local_repository(
    monkeypatch, tmp_path, dummy_config, dummy_repo
):
    # Create a valid local directory
    repo_dir = tmp_path / "repo_local"
    repo_dir.mkdir()
    dummy_repo.local_path = str(repo_dir)

    # Stub create_data_flow_agent
    fake_agent = MagicMock()
    fake_wf = fake_agent.get_workflow.return_value
    fake_wf.ainvoke = AsyncMock(return_value={"data_flow_report": {}})
    monkeypatch.setattr(
        "core.services.threat_model_services.create_data_flow_agent",
        lambda repository, config, directory: fake_agent,
    )

    state = await process_local_repository(dummy_repo, dummy_config)
    assert "data_flow_report" in state


@pytest.mark.asyncio
async def test_process_local_repository_invalid(dummy_config):
    from uuid import uuid4 as _uuid4

    # Repository with non-existent path
    repo = Repository(
        uuid=_uuid4(),
        name="Invalid",
        local_path="/nonexistent",
        asset_uuid=_uuid4(),
    )
    with pytest.raises(ValueError):
        await process_local_repository(repo, dummy_config)


@pytest.mark.asyncio
async def test_process_remote_repository(
    monkeypatch, tmp_path, dummy_config, dummy_repo
):
    from pydantic import SecretStr as _SecretStr

    # Assign a URL so remote path is used
    dummy_repo.url = "example.com/repo.git"
    # Stub clone_repository to avoid actual git operations
    monkeypatch.setattr(
        "core.services.threat_model_services.clone_repository",
        lambda username, pat, repo_url, temp_dir: True,
    )
    # Stub create_data_flow_agent
    fake_agent = MagicMock()
    fake_wf = fake_agent.get_workflow.return_value
    fake_wf.ainvoke = AsyncMock(return_value={"data_flow_report": {}})
    monkeypatch.setattr(
        "core.services.threat_model_services.create_data_flow_agent",
        lambda repository, config, directory: fake_agent,
    )

    result = await process_remote_repository(dummy_repo, dummy_config)
    assert "data_flow_report" in result
