import argparse
import asyncio
import logging
import os
import yaml
from uuid import uuid4
from dotenv import load_dotenv
from core.models.dtos.ThreatModel import ThreatModel
from core.models.enums import AuthnType, DataClassification
from core.models.dtos.Asset import Asset
from core.models.dtos.Repository import Repository
from core.services.threat_model_services import generate_threat_model
from core.services.reports import generate_threat_model_report

# Load environment variables
load_dotenv()

# Configure logging
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=log_level,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def parse_yaml(yaml_file: str):
    """Parses a YAML file and returns asset and repository data."""
    try:
        with open(yaml_file, "r") as file:
            data = yaml.safe_load(file)

        # Extract Asset Data
        asset_data = data.get("asset", {})
        asset = Asset(
            id=uuid4(),
            name=asset_data.get("name", "Unnamed Asset"),
            description=asset_data.get("description", "No description provided"),
            internet_facing=asset_data.get("internet_facing", False),
            authn_type=AuthnType[asset_data.get("authn_type", "NONE").upper()],
            data_classification=DataClassification[
                asset_data.get("data_classification", "PUBLIC").upper()
            ],
        )

        # Extract Repositories Data
        repos = [
            Repository(
                id=uuid4(),
                name=repo.get("name", "Unnamed Repository"),
                url=repo.get("url", "N/A"),
                asset_id=asset.id,
            )
            for repo in data.get("repositories", [])
        ]

        return asset, repos
    except Exception as e:
        logger.error(f"Error parsing YAML file: {e}")
        exit(1)


async def main(yaml_file: str, output_file: str):
    """Loads asset and repositories from YAML and generates a threat model report in Markdown format."""
    asset, repos = parse_yaml(yaml_file)
    threat_model: ThreatModel = await generate_threat_model(asset, repos)

    # Generate report in Markdown format
    markdown_report = generate_threat_model_report(threat_model)

    markdown_report = (
        markdown_report + "\n\n---\n" + threat_model.model_dump_json(indent=4)
    )

    # Save to a Markdown file
    with open(output_file, "w") as md_file:
        md_file.write(markdown_report)

    logger.info(f"✅ Threat model report generated: {output_file}")
    print(f"📄 Report saved to: {output_file}")


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
        help="Output Markdown file (default: threat_model_report.md)",
    )
    args = parser.parse_args()

    asyncio.run(main(args.yaml_file, args.output))
