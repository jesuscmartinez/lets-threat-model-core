import yaml
from pathlib import Path
import pytest
import asyncio
from core.services.threat_model_config import ThreatModelConfig

from main import (
    parse_asset,
    build_threat_model_config,
    load_yaml_config,
    parse_repositories,
    main,
)


@pytest.fixture(autouse=True)
def github_env(monkeypatch):
    """Automatically set GitHub env vars for all tests."""
    monkeypatch.setenv("GITHUB_USERNAME", "test_user")
    monkeypatch.setenv("GITHUB_PAT", "test_pat")


@pytest.fixture
def test_asset() -> dict:
    return {
        "name": "Test Asset",
        "description": "Test asset description",
        "internet_facing": True,
        "authn_type": "NONE",
        "data_classification": "PUBLIC",
    }


@pytest.fixture
def test_repositories() -> list[dict]:
    return [
        {
            "name": "Test Repo",
            "description": "A test repository",
            "url": "https://example.com/repo",
        }
    ]


@pytest.fixture
def test_config_data(test_asset, test_repositories) -> dict:
    return {
        "asset": test_asset,
        "repositories": test_repositories,
        "config": {
            "llm_provider": "openai",
            "categorization_agent_llm": "gpt-4o-mini",
            "review_agent_llm": "gpt-4o-mini",
            "threat_model_agent_llm": "gpt-4o-mini",
            "report_agent_llm": "gpt-4o-mini",
            "context_window": 128000,
            "max_output_tokens": 16384,
            "review_max_file_in_batch": 3,
            "review_token_buffer": 0.5,
            "categorize_max_file_in_batch": 30,
            "categorize_token_buffer": 0.5,
            "categorize_only": False,
            "completion_threshold": 0.8,
        },
        "exclude_patterns": [],
    }


@pytest.fixture
def test_config_file(tmp_path, test_config_data) -> Path:
    config_file_path = tmp_path / "config.yaml"
    config_file_path.write_text(yaml.dump(test_config_data))
    return config_file_path


def test_load_yaml_config_reads_yaml_file(test_config_file):
    """Test that a YAML file is read and parsed correctly."""
    config = load_yaml_config(str(test_config_file))
    assert config["asset"]["name"] == "Test Asset"


def test_load_yaml_config_raises_file_not_found(tmp_path):
    """Test that load_yaml_config raises FileNotFoundError for nonexistent file."""
    non_existent_file = tmp_path / "does_not_exist.yaml"
    with pytest.raises(FileNotFoundError) as exc_info:
        load_yaml_config(str(non_existent_file))
    assert "Config file not found" in str(exc_info.value)


def test_asset_parsing(test_asset):
    """Test that the asset parsing function works correctly."""
    asset = parse_asset(test_asset)
    assert asset.name == test_asset["name"]
    assert asset.description == test_asset["description"]
    assert asset.internet_facing == test_asset["internet_facing"]
    assert asset.authn_type.name == test_asset["authn_type"]
    assert asset.data_classification.name == test_asset["data_classification"]


def test_parse_repositories(test_repositories, test_asset):
    """Test that parse_repositories returns Repository objects for valid configs."""
    asset = parse_asset(test_asset)
    repos = parse_repositories(test_repositories, asset.uuid)
    assert len(repos) == 1
    repo = repos[0]
    assert repo.name == "Test Repo"
    assert repo.description == "A test repository"
    assert repo.url == "https://example.com/repo"
    assert repo.local_path is None
    assert repo.asset_uuid == asset.uuid


def test_parse_repositories_raises_error_for_both_url_and_local_path(test_asset):
    """Test that parse_repositories raises ValueError when both url and local_path are provided."""
    asset = parse_asset(test_asset)
    bad_repos = [
        {
            "name": "Bad Repo",
            "url": "https://example.com/repo",
            "local_path": "/tmp/repo",
        }
    ]
    with pytest.raises(ValueError) as exc_info:
        parse_repositories(bad_repos, asset.uuid)
    assert "must have either 'url' or 'local_path'" in str(exc_info.value)


def test_parse_repositories_raises_error_for_neither_url_nor_local_path(test_asset):
    """Test that parse_repositories raises ValueError when neither url nor local_path is provided."""
    asset = parse_asset(test_asset)
    bad_repos = [{"name": "Bad Repo"}]
    with pytest.raises(ValueError) as exc_info:
        parse_repositories(bad_repos, asset.uuid)
    assert "must have either 'url' or 'local_path'" in str(exc_info.value)


def test_build_threat_model_config(test_config_data):
    """Test that build_threat_model_config creates a ThreatModelConfig instance."""
    config = build_threat_model_config(
        test_config_data["config"], test_config_data["exclude_patterns"]
    )
    assert config.llm_provider == "openai"
    assert config.categorization_agent_llm == "gpt-4o-mini"
    assert config.review_agent_llm == "gpt-4o-mini"
    assert config.threat_model_agent_llm == "gpt-4o-mini"
    assert config.report_agent_llm == "gpt-4o-mini"
    assert config.context_window == 128000
    assert config.max_output_tokens == 16384
    assert config.review_max_file_in_batch == 3
    assert config.review_token_buffer == 0.5
    assert config.categorize_max_file_in_batch == 30
    assert config.categorize_token_buffer == 0.5
    assert not config.categorize_only
    assert config.completion_threshold == 0.8
    assert config.username == "test_user"
    assert config.pat.get_secret_value() == "test_pat"


def test_build_threat_model_config_respects_yaml_strategy(test_config_data):
    """Test that data_flow_report_strategy from YAML overrides the default."""
    # Choose a non-default strategy constant
    alternate_strategy = ThreatModelConfig.STRATEGY_COMBINED
    test_config_data["config"]["data_flow_report_strategy"] = alternate_strategy

    config = build_threat_model_config(
        test_config_data["config"], test_config_data["exclude_patterns"]
    )
    assert config.data_flow_report_strategy == alternate_strategy


@pytest.mark.asyncio
async def test_main(tmp_path, test_config_data, monkeypatch):
    """Test the main function to ensure it runs without errors."""

    # Mock external dependencies to avoid real network or file operations
    dummy_threat_model = type(
        "DummyThreatModel", (), {"model_dump_json": lambda self, indent=4: "{}"}
    )()
    future = asyncio.Future()
    future.set_result(dummy_threat_model)
    monkeypatch.setattr(
        "main.generate_threat_model", lambda asset, repositories, config: future
    )
    monkeypatch.setattr(
        "main.generate_threat_model_report",
        lambda threat_model_config, threat_model: "dummy-report",
    )
    monkeypatch.setattr(
        "main.generate_sarif_log_with_om", lambda threat_model: "dummy-sarif-log"
    )
    monkeypatch.setattr("main.sarif_log_to_schema_dict", lambda log: {"runs": []})

    yaml_file = tmp_path / "test_config.yaml"
    yaml_file.write_text(yaml.dump(test_config_data))

    # Call the main function with the test YAML file
    await main(
        str(yaml_file),
        output_file=str(tmp_path / "output.md"),
        json_output_file=str(tmp_path / "output.json"),
        sarif_output_file=str(tmp_path / "output.sarif"),
    )

    # Assert output files created with expected content
    assert (tmp_path / "output.md").read_text() == "dummy-report"
    assert (tmp_path / "output.json").read_text().strip() == "{}"
    assert '"runs": []' in (tmp_path / "output.sarif").read_text()
