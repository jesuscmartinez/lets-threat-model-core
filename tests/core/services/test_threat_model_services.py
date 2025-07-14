import asyncio
from uuid import uuid4
import pytest
from pydantic import SecretStr
from git import Repo as GitRepo
from core.models.dtos.DataFlowReport import AgentDataFlowReport, DataFlowReport
from core.models.dtos.MitreAttack import Attack
from core.models.dtos.Threat import Threat
from core.services.threat_model_config import ThreatModelConfig
from core.services.threat_model_services import (
    clone_repository,
    create_data_flow_agent,
    generate_mitre_attack,
    generate_threat_model,
    generate_threat_model_data,
    generate_threats,
    merge_data_flows,
    process_local_repository,
    process_remote_repository,
    generate_dataflow_diagram,
    build_data_flow_report,
    generate_data_flow,
)
from core.agents.repo_data_flow_agent import DataFlowAgent
from core.agents.chat_model_manager import ChatModelManager


# Automatically stub out downstream threat-model post-processing in all tests.
@pytest.fixture()
def stub_threat_model_postprocessors(monkeypatch):
    """Automatically stub out downstream threat-model post-processing in all tests."""

    # Stub MITRE ATT&CK generation to return an empty list
    async def fake_mitre(report, cfg):
        return []

    monkeypatch.setattr(
        "core.services.threat_model_services.generate_mitre_attack",
        fake_mitre,
    )

    # Stub threat generation to return an empty list
    async def fake_threats(asset_arg, report, cfg):
        return []

    monkeypatch.setattr(
        "core.services.threat_model_services.generate_threats",
        fake_threats,
    )

    # Stub threat-model data generation to return fixed title and summary
    async def fake_model_data(tm, cfg):
        return {"title": "TITLE", "summary": "SUMMARY"}

    monkeypatch.setattr(
        "core.services.threat_model_services.generate_threat_model_data",
        fake_model_data,
    )


def test_create_data_flow_agent(monkeypatch, repository, tm_config, tmp_path):

    # Prepare dummy models to be returned by ChatModelManager.get_model
    cat_model = object()
    rev_model = object()
    calls = []

    def fake_get_model(provider, api_key, model):
        calls.append((provider, api_key, model))
        if model == tm_config.categorization_agent_llm:
            return cat_model
        elif model == tm_config.report_agent_llm:
            return rev_model
        return None

    monkeypatch.setattr(ChatModelManager, "get_model", fake_get_model)

    directory = str(tmp_path / "dataflow")
    agent = create_data_flow_agent(repository, tm_config, directory)

    # Validate the returned DataFlowAgent
    assert isinstance(agent, DataFlowAgent)
    assert agent.categorize_model is cat_model
    assert agent.review_model is rev_model
    assert agent.directory == directory
    assert agent.username == tm_config.username
    assert agent.password == tm_config.pat
    assert agent.config is tm_config

    # Ensure get_model was called for both categorization and review models
    assert calls == [
        (tm_config.llm_provider, tm_config.api_key, tm_config.categorization_agent_llm),
        (tm_config.llm_provider, tm_config.api_key, tm_config.report_agent_llm),
    ]


class DummyHead:
    def __init__(self):
        self.reference = type("R", (), {"name": "main"})()
        self.commit = type("C", (), {"hexsha": "abc123"})()


class DummyRepo:
    def __init__(self):
        self.head = DummyHead()


def test_clone_repository_success(tmp_path, monkeypatch):
    username = "user"
    pat = SecretStr("token")
    repo_url = "example.com/repo.git"
    temp_dir = str(tmp_path / "repo_dir")

    captured = {}

    def fake_clone_from(auth_url, directory):
        captured["auth_url"] = auth_url
        captured["directory"] = directory
        return DummyRepo()

    monkeypatch.setattr(GitRepo, "clone_from", fake_clone_from)

    repo = clone_repository(username, pat, repo_url, temp_dir)

    # Ensure we got back our dummy
    assert isinstance(repo, DummyRepo)

    # Make sure the URL was built correctly
    expected = f"https://{username}:{pat.get_secret_value()}@{repo_url}"
    assert captured["auth_url"] == expected
    assert captured["directory"] == temp_dir


def test_clone_repository_failure(monkeypatch):
    username = "user"
    pat = SecretStr("token")
    repo_url = "example.com/repo.git"
    temp_dir = "/invalid/path"

    def fake_clone(auth_url, directory):
        raise Exception("clone error")

    monkeypatch.setattr(GitRepo, "clone_from", fake_clone)

    with pytest.raises(Exception) as excinfo:
        clone_repository(username, pat, repo_url, temp_dir)

    assert "clone error" in str(excinfo.value)


async def test_process_local_repository_success(
    monkeypatch, tm_config, tmp_path, repository
):
    # Prepare a valid local directory
    repo_dir = tmp_path / "local_repo"
    repo_dir.mkdir()
    repository.local_path = str(repo_dir)

    # Create a dummy agent with an async workflow returning a dict
    class DummyAgent:
        def get_workflow(self):
            class WF:
                async def ainvoke(self, input):
                    return {"some": "state"}

            return WF()

    # Stub out create_data_flow_agent
    monkeypatch.setattr(
        "core.services.threat_model_services.create_data_flow_agent",
        lambda repository, config, directory: DummyAgent(),
    )

    result = await process_local_repository(repository, tm_config)
    assert isinstance(result, dict)
    assert result == {"some": "state"}


async def test_process_local_repository_invalid_path(tm_config, repository):
    # Repository with a non-existent path should error
    repo = repository.copy()
    repo.local_path = "/nonexistent/path"

    with pytest.raises(ValueError) as excinfo:
        await process_local_repository(repo, tm_config)
    assert "Local repository path does not exist" in str(excinfo.value)


async def test_process_remote_repository_success(monkeypatch, tm_config, repository):
    # Prepare a repository with a URL
    repo = repository.copy()
    repo.url = "https://example.com/remote.git"

    captured = {}

    # Stub clone_repository to capture arguments
    def fake_clone(username, pat, repo_url, temp_dir):
        captured["username"] = username
        captured["pat"] = pat
        captured["repo_url"] = repo_url
        captured["temp_dir"] = temp_dir

    monkeypatch.setattr(
        "core.services.threat_model_services.clone_repository",
        fake_clone,
    )

    # Dummy agent whose workflow returns a known dict
    class DummyAgent:
        def get_workflow(self):
            class WF:
                async def ainvoke(self, input):
                    return {"key": "value"}

            return WF()

    # Stub create_data_flow_agent to return our dummy agent
    monkeypatch.setattr(
        "core.services.threat_model_services.create_data_flow_agent",
        lambda repository, config, directory: DummyAgent(),
    )

    result = await process_remote_repository(repo, tm_config)

    # Verify clone inputs
    assert captured["username"] == tm_config.username
    assert captured["pat"] == tm_config.pat
    assert captured["repo_url"] == repo.url
    assert isinstance(captured["temp_dir"], str)

    # Verify returned state
    assert result == {"key": "value"}


async def test_process_remote_repository_clone_failure(
    monkeypatch, tm_config, repository
):
    repo = repository.copy()
    repo.url = "https://example.com/remote.git"

    # Stub clone_repository to raise
    def fake_clone(username, pat, repo_url, temp_dir):
        raise RuntimeError("clone failed")

    monkeypatch.setattr(
        "core.services.threat_model_services.clone_repository",
        fake_clone,
    )

    with pytest.raises(RuntimeError) as excinfo:
        await process_remote_repository(repo, tm_config)

    assert "clone failed" in str(excinfo.value)


@pytest.fixture(autouse=True)
def stub_chat_model_get(monkeypatch, tm_config):
    # Capture calls to get_model and return a dummy model object
    dummy_model = object()
    calls = {}

    def fake_get_model(provider, api_key, model):
        calls["provider"] = provider
        calls["api_key"] = api_key
        calls["model"] = model
        return dummy_model

    monkeypatch.setattr(ChatModelManager, "get_model", fake_get_model)
    return calls, dummy_model


@pytest.fixture(autouse=True)
def stub_diagram_agent(monkeypatch):
    # Dummy DiagramAgent whose workflow.invoke returns a fixed diagram
    class DummyDiagramAgent:
        def __init__(self, model):
            self.model = model

        def get_workflow(self):
            class WF:
                def invoke(self, input):
                    return {"mermaid_diagram": "graph LR; A-->B;"}

            return WF()

    monkeypatch.setattr(
        "core.services.threat_model_services.DiagramAgent",
        DummyDiagramAgent,
    )


def test_generate_dataflow_diagram_calls_and_returns(
    tm_config, data_flow_report, stub_chat_model_get
):
    calls, dummy_model = stub_chat_model_get

    # Call the function under test
    diagram = generate_dataflow_diagram(tm_config, data_flow_report)

    # It should return what our dummy workflow provides
    assert diagram == "graph LR; A-->B;"

    # And it should have called ChatModelManager.get_model with report_agent_llm
    assert calls == {
        "provider": tm_config.llm_provider,
        "api_key": tm_config.api_key,
        "model": tm_config.report_agent_llm,
    }


@pytest.fixture
def end_state_minimal():
    # Create minimal AgentDataFlowReport state
    agent_report = AgentDataFlowReport(
        overview="test overview",
        external_entities=[],
        processes=[],
        data_stores=[],
        trust_boundaries=[],
    )
    # Convert to dict as it'd come from the agent
    return {
        "data_flow_report": agent_report.model_dump(exclude_unset=True),
        "reviewed": [{"file_path": "r.txt", "justification": "Reviewed"}],
        "should_review": [{"file_path": "sr.txt", "justification": "Should"}],
        "should_not_review": [{"file_path": "snr.txt", "justification": "Should Not"}],
        "could_review": [{"file_path": "cr.txt", "justification": "Could"}],
        "could_not_review": [{"file_path": "cnr.txt", "justification": "Could Not"}],
    }


def test_build_data_flow_report_minimal(
    monkeypatch, tm_config, repository, end_state_minimal
):
    # Stub the inline diagram generator
    monkeypatch.setattr(
        "core.services.threat_model_services.generate_dataflow_diagram",
        lambda config, report: "MERMAID",
    )

    report: DataFlowReport = build_data_flow_report(
        config=tm_config, repository=repository, end_state=end_state_minimal
    )

    # Verify core fields
    assert isinstance(report, DataFlowReport)
    assert report.overview == "test overview"
    assert report.repository_uuid == repository.uuid
    assert report.diagram == "MERMAID"

    # Validate each file category
    assert len(report.reviewed) == 1
    assert report.reviewed[0].file_path == "r.txt"
    assert report.reviewed[0].justification == "Reviewed"

    assert len(report.should_review) == 1
    assert report.should_review[0].file_path == "sr.txt"
    assert report.should_review[0].justification == "Should"

    assert len(report.should_not_review) == 1
    assert report.should_not_review[0].file_path == "snr.txt"

    assert len(report.could_review) == 1
    assert report.could_review[0].file_path == "cr.txt"

    assert len(report.could_not_review) == 1
    assert report.could_not_review[0].file_path == "cnr.txt"


async def test_generate_data_flow_local(monkeypatch, repository, tm_config):
    # Prepare a repo that looks local
    repo = repository.copy()
    repo.local_path = "/fake/path"
    repo.url = None

    # Stub out process_local_repository
    fake_end = {"data_flow_report": {}}

    async def fake_local(r, cfg):
        assert r is repo
        assert cfg is tm_config
        return fake_end

    monkeypatch.setattr(
        "core.services.threat_model_services.process_local_repository",
        fake_local,
    )

    # Stub out build_data_flow_report
    sentinel = object()
    monkeypatch.setattr(
        "core.services.threat_model_services.build_data_flow_report",
        lambda cfg, r, end: sentinel,
    )

    result = await generate_data_flow(repo, tm_config)
    assert result is sentinel


async def test_generate_data_flow_remote(monkeypatch, repository, tm_config):

    # Prepare a repo that looks remote
    repo = repository.copy()
    repo.local_path = None
    repo.url = "https://example.com/repo.git"

    # Stub out process_remote_repository
    fake_end = {"data_flow_report": {}}

    async def fake_remote(r, cfg):
        assert r is repo
        assert cfg is tm_config
        return fake_end

    monkeypatch.setattr(
        "core.services.threat_model_services.process_remote_repository",
        fake_remote,
    )

    # Stub out build_data_flow_report
    sentinel = object()
    monkeypatch.setattr(
        "core.services.threat_model_services.build_data_flow_report",
        lambda cfg, r, end: sentinel,
    )

    result = await generate_data_flow(repo, tm_config)
    assert result is sentinel


async def test_generate_data_flow_invalid(monkeypatch, repository, tm_config):
    from core.services.threat_model_services import generate_data_flow

    # Repo with neither local_path nor url
    repo = repository.copy()
    repo.local_path = None
    repo.url = None

    with pytest.raises(ValueError) as excinfo:
        await generate_data_flow(repo, tm_config)
    assert "Repository must have either a local_path or a URL." in str(excinfo.value)


async def test_merge_data_flows(monkeypatch, tm_config, make_df):
    from core.models.dtos.File import File

    # Create two sample DataFlowReports with file lists
    report1 = make_df("ov1", uuid4())
    report1.reviewed = [File(file_path="a", justification="x")]
    report1.should_review = [File(file_path="b", justification="y")]
    report2 = make_df("ov2", uuid4())
    report2.reviewed = [File(file_path="c", justification="u")]
    report2.should_not_review = [File(file_path="d", justification="v")]
    report2.could_review = [File(file_path="e", justification="w")]
    report2.could_not_review = [File(file_path="f", justification="z")]

    # Stub ChatModelManager.get_model for MergeDataFlowAgent init
    monkeypatch.setattr(
        ChatModelManager, "get_model", lambda provider, api_key, model: object()
    )

    # Stub MergeDataFlowAgent to return a merged state
    class DummyMergeAgent:
        def __init__(self, model):
            self.model = model

        def get_workflow(self):
            class WF:
                async def ainvoke(self, input):
                    return {
                        "merged_data_flow_report": {
                            "overview": "merged",
                            "external_entities": [],
                            "processes": [],
                            "data_stores": [],
                            "trust_boundaries": [],
                        },
                        "justification": "justified",
                    }

            return WF()

    monkeypatch.setattr(
        "core.services.threat_model_services.MergeDataFlowAgent",
        DummyMergeAgent,
    )

    # Stub generate_dataflow_diagram
    monkeypatch.setattr(
        "core.services.threat_model_services.generate_dataflow_diagram",
        lambda config, report: "DIAGRAM",
    )

    # Execute merge
    merged = await merge_data_flows([report1, report2], tm_config)

    # Assertions
    assert isinstance(merged, DataFlowReport)
    assert merged.overview == "merged"
    assert merged.diagram == "DIAGRAM"
    assert merged.repository_uuid is None

    # Check aggregated files
    assert [f.file_path for f in merged.reviewed] == ["a", "c"]
    assert [f.file_path for f in merged.should_review] == ["b"]
    assert [f.file_path for f in merged.should_not_review] == ["d"]
    assert [f.file_path for f in merged.could_review] == ["e"]
    assert [f.file_path for f in merged.could_not_review] == ["f"]


@pytest.fixture
def dummy_data_flow_report():
    return DataFlowReport.model_validate(
        {
            "uuid": uuid4(),
            "repository_uuid": uuid4(),
            "overview": "overview",
            "external_entities": [],
            "processes": [],
            "data_stores": [],
            "trust_boundaries": [],
            "threats": [],
            "attacks": [],
            "reviewed": [],
            "should_review": [],
            "should_not_review": [],
            "could_review": [],
            "could_not_review": [],
            "diagram": "",
        }
    )


async def test_generate_mitre_attack_empty(
    monkeypatch, dummy_data_flow_report, tm_config
):
    # Stub model lookup
    monkeypatch.setattr(
        ChatModelManager, "get_model", lambda provider, api_key, model: object()
    )

    # Dummy agent with no attacks
    class DummyAgent:
        def get_workflow(self):
            class WF:
                async def ainvoke(self, input):
                    return {"attacks": []}

            return WF()

    monkeypatch.setattr(
        "core.services.threat_model_services.MitreAttackAgent",
        lambda model: DummyAgent(),
    )

    result = await generate_mitre_attack(dummy_data_flow_report, tm_config)
    assert isinstance(result, list)
    assert result == []


async def test_generate_mitre_attack_with_attack(
    monkeypatch, dummy_data_flow_report, tm_config, attack
):
    # Stub model lookup
    monkeypatch.setattr(
        ChatModelManager, "get_model", lambda provider, api_key, model: object()
    )

    # Dummy agent returning that attack
    class DummyAgent:
        def get_workflow(self):
            class WF:
                async def ainvoke(self, input):
                    return {"attacks": [attack.model_dump()]}

            return WF()

    monkeypatch.setattr(
        "core.services.threat_model_services.MitreAttackAgent",
        lambda model: DummyAgent(),
    )

    result = await generate_mitre_attack(dummy_data_flow_report, tm_config)
    assert len(result) == 1
    attack = result[0]
    assert isinstance(attack, Attack)
    # Check several fields
    assert attack.attack_tactic == attack.attack_tactic
    assert attack.technique_id == attack.technique_id
    assert attack.technique_name == attack.technique_name
    assert attack.url == attack.url
    assert attack.component == attack.component
    assert attack.component_uuid == attack.component_uuid
    assert attack.reason_for_relevance == attack.reason_for_relevance
    assert attack.mitigation == attack.mitigation


async def test_generate_threats_empty(
    monkeypatch, asset, dummy_data_flow_report, tm_config
):
    # Stub out ChatModelManager.get_model
    monkeypatch.setattr(
        ChatModelManager, "get_model", lambda provider, api_key, model: object()
    )

    # Dummy agent that returns no threats
    class DummyAgent:
        def __init__(self, model):
            pass

        def get_workflow(self):
            class WF:
                async def ainvoke(self, input):
                    return {"threats": []}

            return WF()

    monkeypatch.setattr(
        "core.services.threat_model_services.ThreatModelAgent",
        lambda model: DummyAgent(model),
    )

    result = await generate_threats(asset, dummy_data_flow_report, tm_config)
    assert isinstance(result, list)
    assert result == []


async def test_generate_threats_with_items(
    monkeypatch, asset, dummy_data_flow_report, tm_config, threat
):
    # Stub out ChatModelManager.get_model
    monkeypatch.setattr(
        ChatModelManager, "get_model", lambda provider, api_key, model: object()
    )

    # Dummy agent that returns one threat
    class DummyAgent:
        def __init__(self, model):
            pass

        def get_workflow(self):
            class WF:
                async def ainvoke(self, input):
                    return {"threats": [threat.model_dump()]}

            return WF()

    monkeypatch.setattr(
        "core.services.threat_model_services.ThreatModelAgent",
        lambda model: DummyAgent(model),
    )

    result = await generate_threats(asset, dummy_data_flow_report, tm_config)
    assert len(result) == 1
    threat_obj = result[0]
    assert isinstance(threat_obj, Threat)
    # Verify fields copied
    assert threat_obj.name == threat.name
    assert threat_obj.stride_category.name == threat.stride_category.name
    assert threat_obj.impact_level.name == threat.impact_level.name
    assert threat_obj.risk_rating.name == threat.risk_rating.name
    assert threat_obj.component_names == threat.component_names
    assert threat_obj.description == threat.description


async def test_generate_threat_model_data_defaults(
    monkeypatch, threat_model, tm_config
):
    # Stub LLM model lookup
    monkeypatch.setattr(
        ChatModelManager, "get_model", lambda provider, api_key, model: object()
    )

    # Dummy ThreatModelDataAgent that returns empty dict
    class DummyAgent:
        def __init__(self, model):
            pass

        def get_workflow(self):
            class WF:
                async def ainvoke(self, input):
                    return {}

            return WF()

    monkeypatch.setattr(
        "core.services.threat_model_services.ThreatModelDataAgent",
        lambda model: DummyAgent(model),
    )

    result = await generate_threat_model_data(threat_model, tm_config)
    assert result == {
        "title": "No title generated.",
        "summary": "No summary generated.",
    }


async def test_generate_threat_model_data_with_values(
    monkeypatch, threat_model, tm_config
):
    # Stub LLM model lookup
    monkeypatch.setattr(
        ChatModelManager, "get_model", lambda provider, api_key, model: object()
    )

    # Dummy agent returning explicit values
    class DummyAgent:
        def __init__(self, model):
            pass

        def get_workflow(self):
            class WF:
                async def ainvoke(self, input):
                    return {"title": "Generated Title", "summary": "Generated Summary"}

            return WF()

    monkeypatch.setattr(
        "core.services.threat_model_services.ThreatModelDataAgent",
        lambda model: DummyAgent(model),
    )

    result = await generate_threat_model_data(threat_model, tm_config)
    assert result["title"] == "Generated Title"
    assert result["summary"] == "Generated Summary"


async def test_skip_data_flow(monkeypatch, tm_config, asset):
    config = tm_config.copy()
    config.generate_data_flow_reports = False

    tm = await generate_threat_model(asset, [], config)
    assert tm.data_flow_reports == []
    assert tm.name == "New Threat Model"
    assert tm.summary == "No summary generated."


async def test_per_repository_strategy(
    monkeypatch, tm_config, asset, repository, make_df
):
    # config that only generates data flow
    config = tm_config.copy()
    config.generate_data_flow_reports = True
    config.categorize_only = True  # skip attacks & threats
    config.generate_mitre_attacks = False
    config.generate_threats = False
    config.data_flow_report_strategy = ThreatModelConfig.STRATEGY_PER_REPOSITORY

    repo1 = repository.copy()
    repo1.uuid = uuid4()

    repo2 = repository.copy()
    repo2.uuid = uuid4()
    repos = [repo1, repo2]

    # Prepare two dummy DFRs
    df1 = make_df("o1", repos[0].uuid)
    df2 = make_df("o2", repos[1].uuid)

    async def fake_gdf(repo, cfg):
        return df1 if repo is repos[0] else df2

    monkeypatch.setattr(
        "core.services.threat_model_services.generate_data_flow",
        fake_gdf,
    )

    tm = await generate_threat_model(asset, repos, config)
    assert tm.data_flow_reports == [df1, df2]


async def test_combined_strategy(
    monkeypatch, asset, repository, tm_config, stub_threat_model_postprocessors, make_df
):
    config = tm_config.copy()
    config.data_flow_report_strategy = ThreatModelConfig.STRATEGY_COMBINED

    repo1 = repository.copy()
    repo1.uuid = uuid4()

    repo2 = repository.copy()
    repo2.uuid = uuid4()
    repos = [repo1, repo2]

    df = make_df("o", repos[0].uuid)

    # Stub both calls
    monkeypatch.setattr(
        "core.services.threat_model_services.generate_data_flow",
        lambda r, c: asyncio.sleep(0, result=df),
    )

    async def fake_merge(dfs, c):
        return df

    monkeypatch.setattr(
        "core.services.threat_model_services.merge_data_flows",
        fake_merge,
    )

    tm = await generate_threat_model(asset, repos, config)
    assert tm.data_flow_reports == [df]


async def test_both_strategy(
    monkeypatch, asset, repository, tm_config, stub_threat_model_postprocessors, make_df
):
    config = tm_config.copy()
    config.data_flow_report_strategy = ThreatModelConfig.STRATEGY_BOTH

    repo1 = repository.copy()
    repo1.uuid = uuid4()

    repo2 = repository.copy()
    repo2.uuid = uuid4()
    repos = [repo1, repo2]

    df1 = make_df("o1", repos[0].uuid)
    df2 = make_df("o2", repos[1].uuid)

    async def fake_gdf(repo, cfg):
        return df1 if repo is repos[0] else df2

    monkeypatch.setattr(
        "core.services.threat_model_services.generate_data_flow",
        fake_gdf,
    )

    async def fake_merge(dfs, c):
        return df1

    monkeypatch.setattr(
        "core.services.threat_model_services.merge_data_flows",
        fake_merge,
    )

    tm = await generate_threat_model(asset, repos, config)
    # combined df1 first, then individual df1 and df2
    assert tm.data_flow_reports == [df1, df1, df2]
