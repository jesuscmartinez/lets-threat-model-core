import argparse
import asyncio
import logging
import os
from uuid import uuid4
from pathlib import Path
import yaml
from pydantic import SecretStr
from dotenv import load_dotenv

# Import Models and Services
from core.models.dtos.ThreatModel import ThreatModel
from core.models.enums import AuthnType, DataClassification
from core.models.dtos.Asset import Asset
from core.models.dtos.Repository import Repository
from core.services.threat_model_config import ThreatModelConfig
from core.services.threat_model_services import generate_threat_model
from core.services.reports import generate_threat_model_report

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Load secrets
GITHUB_USERNAME = os.getenv("GITHUB_USERNAME", "")
GITHUB_PAT = SecretStr(os.getenv("GITHUB_PAT", ""))


def safe_join(base_directory: Path, user_path: str) -> Path:
    """
    Safely join a user-provided path with a base directory.
    """
    base_directory = base_directory.resolve()
    combined_path = (base_directory / user_path).resolve()
    if base_directory not in combined_path.parents and combined_path != base_directory:
        raise ValueError(f"Invalid path: {user_path}")
    return combined_path


def load_yaml_config(file_path: str) -> dict:
    """Loads a YAML configuration file into a dictionary."""
    safe_path = safe_join(Path.cwd(), file_path)
    if not safe_path.exists():
        raise FileNotFoundError(f"❌ Config file not found: {safe_path}")

    with safe_path.open("r") as file:
        return yaml.safe_load(file)


def parse_asset(data: dict) -> Asset:
    """Parses asset information from YAML data."""
    return Asset(
        id=uuid4(),
        name=data.get("name", "Unnamed Asset"),
        description=data.get("description", "No description provided"),
        internet_facing=data.get("internet_facing", False),
        authn_type=AuthnType[data.get("authn_type", "NONE").upper()],
        data_classification=DataClassification[
            data.get("data_classification", "PUBLIC").upper()
        ],
    )


def parse_repositories(data: list, asset_id: uuid4) -> list[Repository]:
    """Parses repository information from YAML data."""
    return [
        Repository(
            id=uuid4(),
            name=repo.get("name", "Unnamed Repository"),
            url=repo.get("url", "N/A"),
            asset_id=asset_id,
        )
        for repo in data
    ]


def build_threat_model_config(
    config_data: dict, exclude_patterns: list
) -> ThreatModelConfig:
    """Creates a ThreatModelConfig instance from YAML data and environment variables."""
    config_settings = {
        "llm_provider": config_data.get("llm_provider", "openai"),
        "categorization_agent_llm": config_data.get(
            "categorization_agent_llm", "gpt-4o-mini"
        ),
        "review_agent_llm": config_data.get("review_agent_llm", "gpt-4o-mini"),
        "threat_model_agent_llm": config_data.get(
            "threat_model_agent_llm", "gpt-4o-mini"
        ),
        "report_agent_llm": config_data.get("report_agent_llm", "gpt-4o-mini"),
        "context_window": config_data.get("context_window", 128000),
        "max_output_tokens": config_data.get("max_output_tokens", 16384),
        "review_max_file_in_batch": config_data.get("review_max_file_in_batch", 3),
        "review_token_buffer": config_data.get("review_token_buffer", 0.5),
        "categorize_max_file_in_batch": config_data.get(
            "categorize_max_file_in_batch", 30
        ),
        "categorize_token_buffer": config_data.get("categorize_token_buffer", 0.5),
        "categorize_only": config_data.get("categorize_only", False),
        "completion_threshold": config_data.get("completion_threshold", 0.8),
        "username": GITHUB_USERNAME,
        "pat": GITHUB_PAT,
    }

    # Remove None values
    config_settings = {k: v for k, v in config_settings.items() if v is not None}

    config = ThreatModelConfig(**config_settings)
    config.add_exclude_patterns(exclude_patterns)
    return config


async def main(yaml_file: str, output_file: str):
    """Loads asset and repositories from YAML and generates a threat model report in Markdown format."""
    try:
        config = load_yaml_config(yaml_file)
        asset = parse_asset(config.get("asset", {}))
        repositories = parse_repositories(config.get("repositories", []), asset.id)
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
        markdown_report = generate_threat_model_report(threat_model)

        markdown_report = (
            markdown_report
            + "\n\nDEBUG:\n"
            + f"⚙️ Threat Model Configuration:\n{threat_model_config.model_dump_json(indent=4)}"
            + f"\n\n📝 Generated Threat Model:\n{threat_model.model_dump_json(indent=4)}"
        )

        output_path = Path(output_file)
        output_path.write_text(markdown_report)

        logger.info(f"✅ Threat model report generated and saved to: {output_path}")

    except Exception as e:
        logger.error(f"❌ Error generating threat model: {e}", exc_info=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate a threat model from a YAML file and output as Markdown."
    )
    parser.add_argument(
        "yaml_file",
        type=str,
        help="Path to the YAML file containing asset and repository details.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="threat_model_report.md",
        help="Output Markdown file",
    )
    args = parser.parse_args()

    asyncio.run(main(args.yaml_file, args.output))
