import argparse
import asyncio
import json
import json
import logging
import os
from uuid import UUID, uuid4
from pathlib import Path
import yaml
from pydantic import SecretStr
from dotenv import load_dotenv
from typing import Optional
from sarif_om import SarifLog

# Import Models and Services
from core.models.dtos.ThreatModel import ThreatModel
from core.models.enums import AuthnType, DataClassification
from core.models.dtos.Asset import Asset
from core.models.dtos.Repository import Repository
from core.services.sarif_services import (
    generate_sarif_log_with_om,
    sarif_log_to_schema_dict,
)
from core.services.threat_model_config import ThreatModelConfig
from core.services.threat_model_services import generate_threat_model
from core.services.reports import generate_threat_model_report


# Get LOG_LEVEL from env or default to INFO
log_level_str = os.getenv("LOG_LEVEL", "INFO").upper()
log_level = getattr(logging, log_level_str, logging.INFO)

# Setup basic logging
logging.basicConfig(
    level=log_level,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

logger = logging.getLogger(__name__)


def load_yaml_config(file_path: str) -> dict:
    """Loads a YAML configuration file into a dictionary."""
    path = Path(file_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"❌ Config file not found: {path}")

    with path.open("r") as file:
        return yaml.safe_load(file)


def parse_asset(data: dict) -> Asset:
    """Parses asset information from YAML data."""
    return Asset(
        uuid=uuid4(),
        name=data.get("name", "Unnamed Asset"),
        description=data.get("description", "No description provided"),
        internet_facing=data.get("internet_facing", False),
        authn_type=AuthnType[data.get("authn_type", "NONE").upper()],
        data_classification=DataClassification[
            data.get("data_classification", "PUBLIC").upper()
        ],
    )


def parse_repositories(data: list, asset_id: UUID) -> list[Repository]:
    """Parses repository information from YAML data."""
    repositories = []

    for repo in data:
        url = repo.get("url")
        local_path = repo.get("local_path")

        # Validation: Only one should be provided
        if (url and local_path) or (not url and not local_path):
            raise ValueError(
                f"Repository '{repo.get('name', 'Unnamed Repository')}' must have either 'url' or 'local_path', but not both."
            )

        repositories.append(
            Repository(
                uuid=uuid4(),
                name=repo.get("name", "Unnamed Repository"),
                description=repo.get("description"),
                url=url,
                local_path=local_path,
                asset_uuid=asset_id,
            )
        )

    return repositories


def build_threat_model_config(
    config_data: dict, exclude_patterns: list
) -> ThreatModelConfig:
    """Creates a ThreatModelConfig instance from YAML data and environment variables."""

    # Start with all values from config_data
    config_settings = dict(config_data)

    defaults = {
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
        "generate_mitre_attacks": True,
        "generate_threats": True,
        "generate_data_flow_reports": True,
        "data_flow_report_strategy": ThreatModelConfig.STRATEGY_BOTH,
    }

    # Fill in any missing keys with defaults
    for key, default in defaults.items():
        config_settings.setdefault(key, default)

        # Ensure all keys are strings for Pydantic kwargs
        config_settings = {str(k): v for k, v in config_settings.items()}

    # Add secure and required environment-based fields
    config_settings["username"] = os.getenv("GITHUB_USERNAME", "")
    config_settings["pat"] = SecretStr(os.getenv("GITHUB_PAT", ""))
    config_settings["api_key"] = SecretStr(os.getenv("PROVIDER_API_KEY", ""))

    config = ThreatModelConfig(**config_settings)
    config.add_exclude_patterns(exclude_patterns)
    return config


async def main(
    yaml_file: str,
    output_file: str,
    json_output_file: Optional[str] = None,
    sarif_output_file: Optional[str] = None,
):
    load_dotenv()
    """Loads asset and repositories from YAML and generates a threat model report in Markdown format."""
    try:
        config = load_yaml_config(yaml_file)
        asset = parse_asset(config.get("asset", {}))
        repositories = parse_repositories(config.get("repositories", []), asset.uuid)
        threat_model_config = build_threat_model_config(
            config.get("config", {}), config.get("exclude_patterns", [])
        )

        # Generate threat model
        threat_model: ThreatModel = await generate_threat_model(
            asset, repositories, threat_model_config
        )

        logger.debug(
            f"⚙️ Threat Model Configuration:\n{threat_model_config.model_dump_json(indent=4)}"
            f"\n\n📝 Generated Threat Model:\n{threat_model.model_dump_json(indent=4)}"
        )

        # Generate and save the report
        markdown_report = generate_threat_model_report(
            threat_model_config=threat_model_config, threat_model=threat_model
        )

        output_path = Path(output_file).expanduser().resolve(strict=False)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(markdown_report)

        logger.info(f"✅ Threat model report generated and saved to: {output_path}")

        if json_output_file:
            json_output_path = Path(json_output_file).expanduser().resolve(strict=False)
            json_output_path.parent.mkdir(parents=True, exist_ok=True)
            json_output_path.parent.mkdir(parents=True, exist_ok=True)
            json_output_path.write_text(threat_model.model_dump_json(indent=4))
            logger.info(f"✅ Threat model JSON saved to: {json_output_path}")

        if sarif_output_file:
            sarif_output_path = (
                Path(sarif_output_file).expanduser().resolve(strict=False)
            )
            sarif_output_path.parent.mkdir(parents=True, exist_ok=True)
            sarif_log: SarifLog = generate_sarif_log_with_om(threat_model)
            sarif_dict = sarif_log_to_schema_dict(sarif_log)
            sarif_output_path.write_text(json.dumps(sarif_dict, indent=4))
            logger.info(f"✅ Threat model SARIF saved to: {sarif_output_path}")

    except Exception as e:
        logger.error(f"❌ Error generating threat model: {e}", exc_info=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""\
    🛡️  Lets Threat Model Core - Automated Threat Modeling Tool

    Generate a threat model from a YAML configuration file. The tool analyzes your assets and repositories, 
    and outputs a structured threat model report in Markdown. Optionally, you can export the raw threat model data as JSON.
    """
    )

    parser.add_argument(
        "--config-file",
        type=str,
        help="""\
    📄 Path to your YAML configuration file.

    This file should include the asset details, repository information, and tool configuration. 
    Example: `config/my-app-config.yaml`
    """,
    )

    parser.add_argument(
        "--markdown-output",
        type=str,
        default="threat_model_report.md",
        help="""\
    📝 Path to save the generated threat model report in Markdown format.

    Default: `threat_model_report.md`
    """,
    )

    parser.add_argument(
        "--json-output",
        type=str,
        help="""\
    📦 (Optional) Path to save the raw threat model data in JSON format.

    Useful if you want to process the threat model programmatically or integrate with other tools.
    Example: `reports/threat_model.json`
    """,
    )

    parser.add_argument(
        "--sarif-output",
        type=str,
        help="""\
    📄 (Optional) Path to save the SARIF threat model report.

    The report will be generated in SARIF (Static Analysis Results Interchange Format), which is useful for integrating with security analysis tools.
    Example: `reports/threat_model.sarif`
    """,
    )

    args = parser.parse_args()

    asyncio.run(
        main(
            args.config_file, args.markdown_output, args.json_output, args.sarif_output
        )
    )
