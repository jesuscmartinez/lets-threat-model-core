from ast import Str
from re import L, S
import unittest
import tempfile

import yaml
from pathlib import Path
from uuid import uuid4, UUID
from unittest.mock import patch, AsyncMock, MagicMock


# Import functions and models from your project.
from core.models.enums import Level, StrideCategory
import main
from main import parse_asset, ThreatModel
from core.models.dtos.DataFlowReport import DataFlowReport
from core.models.dtos.Repository import Repository
from core.models.dtos.Threat import Threat
from core.models.dtos.MitreAttack import Attack

# ----------------------------------------
# Fixtures for testing
# ----------------------------------------


class TestThreatModelGeneration(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # Create a temporary directory for test files.
        self.test_dir = tempfile.TemporaryDirectory()
        self.config_file_path = Path(self.test_dir.name) / "config.yaml"
        self.markdown_output_path = Path(self.test_dir.name) / "output.md"
        self.json_output_path = Path(self.test_dir.name) / "output.json"
        self.sarif_output_path = Path(self.test_dir.name) / "output.sarif"

        # Write a minimal YAML config file.
        config_data = {
            "asset": {
                "name": "Test Asset",
                "description": "Test asset description",
                "internet_facing": True,
                "authn_type": "NONE",
                "data_classification": "PUBLIC",
            },
            "repositories": [
                {
                    "name": "Test Repo",
                    "description": "A test repository",
                    "url": "https://example.com/repo",
                }
            ],
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
        with open(self.config_file_path, "w") as f:
            yaml.dump(config_data, f)

    def tearDown(self):
        self.test_dir.cleanup()

    # Test the main threat model generation and output of Markdown, JSON, and SARIF files.
    @patch("main.generate_threat_model", new_callable=AsyncMock)
    @patch("main.generate_threat_model_report")
    async def test_main_generates_all_reports(
        self,
        mock_generate_threat_model_report,
        mock_generate_threat_model,
    ):
        # Setup a dummy ThreatModel that will be returned by generate_threat_model.
        dummy_asset = parse_asset(
            {
                "name": "Test Asset",
                "description": "Test asset description",
                "internet_facing": True,
                "authn_type": "NONE",
                "data_classification": "PUBLIC",
            }
        )

        dummy_repo = Repository(
            id=uuid4(),
            name="Repo",
            description="desc",
            url="https://repo.com",
            asset_id=dummy_asset.id,
        )
        dummy_data_flow_report = DataFlowReport(
            id=uuid4(),
            repository_id=dummy_repo.id,
            external_entities=[],
            processes=[],
            data_stores=[],
            trust_boundaries=[],
            should_review=[],
            reviewed=[],
            could_review=[],
            should_not_review=[],
            could_not_review=[],
            diagram="graph TD",
        )
        dummy_threat = Threat(
            id=uuid4(),
            data_flow_report_id=dummy_data_flow_report.id,
            name="Dummy Threat",
            description="Threat desc",
            stride_category=StrideCategory.REPUDIATION,
            component_names=["Comp"],
            component_ids=[uuid4()],
            attack_vector="Network",
            impact_level=Level.HIGH,
            risk_rating=Level.MEDIUM,
            mitigations=["Mitigation A"],
        )
        dummy_attack = Attack(
            id=uuid4(),
            component_id=uuid4(),
            attack_tactic="Execution",
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            reason_for_relevance="This technique allows attackers to execute commands on the system.",
            mitigation="Use application whitelisting to block unknown scripts.",
        )
        dummy_threat_model = ThreatModel(
            id=uuid4(),
            name="Dummy Threat Model",
            summary="Dummy summary",
            asset=dummy_asset,
            repos=[dummy_repo],
            data_flow_reports=[dummy_data_flow_report],
            threats=[dummy_threat],
            attacks=[dummy_attack],
        )
        mock_generate_threat_model.return_value = dummy_threat_model

        # Dummy markdown report.
        dummy_markdown = "# Dummy Markdown Report\nContent here..."
        mock_generate_threat_model_report.return_value = dummy_markdown

        # Call main with all output file paths provided.
        await main.main(
            yaml_file=str(self.config_file_path),
            output_file=str(self.markdown_output_path),
            json_output_file=str(self.json_output_path),
            sarif_output_file=str(self.sarif_output_path),
        )

        # Verify Markdown report output.
        self.assertTrue(
            self.markdown_output_path.exists(), "Markdown output file does not exist."
        )
        with open(self.markdown_output_path, "r") as f:
            md_content = f.read()
        self.assertIn("Dummy Markdown Report", md_content)

        # Verify JSON output.
        self.assertTrue(
            self.json_output_path.exists(), "JSON output file does not exist."
        )
        with open(self.json_output_path, "r") as f:
            json_content = f.read()
        self.assertIn("Dummy Threat Model", json_content)

        # Verify SARIF output.
        self.assertTrue(
            self.sarif_output_path.exists(), "SARIF output file does not exist."
        )
        with open(self.sarif_output_path, "r") as f:
            sarif_content = f.read()
        self.assertIn('"version": "2.1.0"', sarif_content)


if __name__ == "__main__":
    unittest.main()
