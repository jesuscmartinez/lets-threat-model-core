import yaml
import json
import pytest
import asyncio
from pathlib import Path
from pydantic import SecretStr

from core.services.threat_model_config import ThreatModelConfig

from main import (
    parse_asset,
    build_threat_model_config,
    load_yaml_config,
    parse_repositories,
    main,
)
from tests.conftest import tm_config, asset, repository


@pytest.fixture
def config_data(tm_config: ThreatModelConfig) -> dict:

    # model_dump_json gives you a JSON string with secrets unwrapped
    json_str = tm_config.model_dump_json(by_alias=True)
    # load it back to a dict of primitives
    config_dict = json.loads(json_str)

    return config_dict


@pytest.fixture
def test_config_file(tmp_path, config_data) -> Path:
    """Fixture to create a temporary YAML config file for testing."""
    config_file_path = tmp_path / "config.yaml"
    config_file_path.write_text(yaml.dump(config_data))
    return config_file_path


def test_load_yaml_config_reads_yaml_file(test_config_file):
    """Test that a YAML file is read and parsed correctly."""
    config = load_yaml_config(str(test_config_file))
    assert isinstance(config, dict)


def test_load_yaml_config_raises_file_not_found(tmp_path):
    """Test that load_yaml_config raises FileNotFoundError for nonexistent file."""
    non_existent_file = tmp_path / "does_not_exist.yaml"
    with pytest.raises(FileNotFoundError) as exc_info:
        load_yaml_config(str(non_existent_file))
    assert "Config file not found" in str(exc_info.value)


def test_asset_parsing(asset):
    """Test that the asset parsing function works correctly."""
    asset = parse_asset(
        {
            "name": asset.name,
            "description": asset.description,
            "internet_facing": asset.internet_facing,
            "authn_type": asset.authn_type.name,
            "data_classification": asset.data_classification.name,
            "description": asset.description,
            "internet_facing": asset.internet_facing,
            "authn_type": asset.authn_type.name,
            "data_classification": asset.data_classification.name,
            "uuid": asset.uuid,
        }
    )
    assert asset.name == asset.name
    assert asset.description == asset.description
    assert asset.internet_facing == asset.internet_facing
    assert asset.authn_type == asset.authn_type
    assert asset.data_classification == asset.data_classification
    assert asset.description == asset.description
    assert asset.internet_facing == asset.internet_facing
    assert asset.authn_type.name == asset.authn_type.name
    assert asset.data_classification.name == asset.data_classification.name


def test_parse_repositories(repository, asset):
    """Test that parse_repositories returns Repository objects for valid configs."""
    repos = parse_repositories(
        [
            {
                "name": repository.name,
                "description": repository.description,
                "url": repository.url,
                "local_path": repository.local_path,
                "asset_uuid": asset.uuid,
                "uuid": repository.uuid,
            }
        ],
        asset.uuid,
    )
    assert len(repos) == 1
    repo = repos[0]
    assert repo.name == repository.name
    assert repo.description == repository.description
    assert repo.url == repository.url
    assert repo.local_path == repository.local_path
    assert repo.asset_uuid == asset.uuid


def test_parse_repositories_raises_error_for_both_url_and_local_path(asset):
    """Test that parse_repositories raises ValueError when both url and local_path are provided."""
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


def test_parse_repositories_raises_error_for_neither_url_nor_local_path(asset):
    """Test that parse_repositories raises ValueError when neither url nor local_path is provided."""
    bad_repos = [{"name": "Bad Repo"}]
    with pytest.raises(ValueError) as exc_info:
        parse_repositories(bad_repos, asset.uuid)
    assert "must have either 'url' or 'local_path'" in str(exc_info.value)


def test_build_threat_model_config(config_data, monkeypatch):
    """Test that build_threat_model_config creates a ThreatModelConfig instance."""

    monkeypatch.setenv("GITHUB_USERNAME", "test_user")
    monkeypatch.setenv("GITHUB_PAT", "test_pat")
    monkeypatch.setenv("PROVIDER_API_KEY", "test_api_key")

    config_data["base_url"] = "https://example.com/api"
    config_data["data_flow_report_strategy"] = ThreatModelConfig.STRATEGY_BOTH
    config_data["exclude_patterns"] += [
        "exclude_pattern1",
        "exclude_pattern2",
    ]

    config = build_threat_model_config(
        config_data=config_data,
        exclude_patterns=["exclude_pattern1", "exclude_pattern2"],
    )
    # Assert that the config is an instance of ThreatModelConfig
    assert isinstance(config, ThreatModelConfig)

    # Assert that the config has the expected environment variables and values
    assert config.username == "test_user"
    assert config.pat.get_secret_value() == "test_pat"
    assert config.api_key.get_secret_value() == "test_api_key"

    # Assert that the config has the expected values set from config_data values
    assert config.base_url == config_data["base_url"]
    assert config.data_flow_report_strategy == config_data["data_flow_report_strategy"]

    # Assert that the config has the expected extended exclude patterns
    assert config.exclude_patterns == config_data["exclude_patterns"]

    # Assert that the config has the expected default values
    assert config.llm_provider == config_data["llm_provider"]


async def test_main(tmp_path, config_data, monkeypatch):
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
    yaml_file.write_text(yaml.dump(config_data))

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
