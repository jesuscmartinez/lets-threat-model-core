from re import L, S
from pydantic import Field, SecretStr
from core.agents import threat_model_agent
from core.agents.repo_data_flow_agent import DataFlowAgent
from core.agents.repo_data_flow_agent_config import RepoDataFlowAgentConfig
from core.agents.threat_model_agent import ThreatModelAgent
from core.models.dtos.Asset import Asset
from core.models.dtos.ThreatModel import ThreatModel
from core.models.dtos.DataFlowReport import DataFlowReport, AgentDataFlowReport
from core.models.dtos.Threat import Threat, AgentThreat
from core.agents.threat_model_data_agent import ThreatModelDataAgent
from core.models.dtos.Repository import Repository
from core.agents.chat_model_manager import ChatModelManager
from core.services.reports import (
    generate_mermaid_from_dataflow,
    generate_mermaid_dataflow_diagram,
)
import logging
import os
import uuid
from tempfile import TemporaryDirectory
from typing import Any, Dict, Optional, Tuple, List
import asyncio

from core.services.threat_model_config import ThreatModelConfig


# Configure logging
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=log_level,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


async def generate_threat_model(
    asset: Asset, repos: List[Repository], config: ThreatModelConfig
) -> ThreatModel:

    # Generate data flow reports concurrently
    data_flow_reports = await asyncio.gather(
        *(generate_data_flow(repo, config) for repo in repos)
    )

    # Generate threats concurrently
    threat_lists = await asyncio.gather(
        *(generate_threats(asset, report, config) for report in data_flow_reports)
    )

    # Flatten the list of threats
    all_threats = [
        threat for report_threats in threat_lists for threat in report_threats
    ]

    diagrams = [generate_mermaid_from_dataflow(report) for report in data_flow_reports]

    # diagrams = diagrams + [
    #     generate_mermaid_dataflow_diagram(report) for report in data_flow_reports
    # ]

    threat_model = ThreatModel(
        id=uuid.uuid4(),
        name="",
        summary="",
        asset=asset,
        repos=repos,
        data_flow_diagrams=diagrams,
        data_flow_reports=data_flow_reports,
        threats=all_threats,
    )

    threat_model_data = await generate_threat_model_data(threat_model, config)
    threat_model.name = threat_model_data["title"]
    threat_model.summary = threat_model_data["summary"]

    return threat_model


async def generate_data_flow(
    repository: Repository, config: ThreatModelConfig
) -> DataFlowReport:
    """Generates a DataFlowReport for a given repository."""
    try:
        logger.info(
            f"🚀 Starting data flow generation for Repository: {repository.name} (ID: {repository.id})"
        )

        with TemporaryDirectory() as temp_dir:
            logger.info(f"📂 Created temporary directory: {temp_dir}")

            data_flow_agent = DataFlowAgent(
                categorization_model=ChatModelManager.get_model(
                    provider=config.llm_provider, model=config.categorization_agent_llm
                ),
                review_model=ChatModelManager.get_model(
                    provider=config.llm_provider, model=config.report_agent_llm
                ),
                repo_url=repository.url,
                directory=temp_dir,
                username=config.username,
                password=config.pat,
                config=config,
            )

            state = {
                "should_review": set(),
                "should_not_review": set(),
                "could_review": set(),
                "could_not_review": set(),
                "reviewed": set(),
                "data_flow_report": AgentDataFlowReport().model_dump(mode="json"),
            }

            end_state = await data_flow_agent.get_workflow().ainvoke(input=state)

            agent_data_flow = AgentDataFlowReport.model_validate(
                end_state["data_flow_report"]
            )

            new_report = DataFlowReport.model_validate(
                obj={
                    "id": uuid.uuid4(),
                    "repository_id": repository.id,
                    **agent_data_flow.model_dump(exclude_unset=True),
                    "could_not_review": list(end_state.get("could_not_review", [])),
                    "could_review": list(end_state.get("could_review", [])),
                    "should_not_review": list(end_state.get("should_not_review", [])),
                    "should_review": list(end_state.get("should_review", [])),
                    "reviewed": list(end_state.get("reviewed", [])),
                }
            )

        logger.info(f"✅ Finished data flow generation repository.")

        return new_report

    except Exception as e:
        logger.exception(f"❌ Error during data flow generation: {str(e)}")
        raise


async def generate_threats(
    asset: Asset, data_flow_report: DataFlowReport, config: ThreatModelConfig
) -> List[Threat]:
    """Generates threats for a given data flow report."""
    logger.info(
        f"🚀 Starting threats generation for Data Flow Report: {data_flow_report.id})"
    )
    try:
        threat_model_agent = ThreatModelAgent(
            model=ChatModelManager.get_model(
                provider=config.llm_provider, model=config.threat_model_agent_llm
            )
        )

        seralized_asset = asset.model_dump(mode="json")

        seralized_report = AgentDataFlowReport(
            overview=data_flow_report.overview,
            external_entities=data_flow_report.external_entities,
            processes=data_flow_report.processes,
            data_stores=data_flow_report.data_stores,
            trust_boundaries=data_flow_report.trust_boundaries,
        ).model_dump(mode="json")

        state = {
            "asset": seralized_asset,
            "data_flow_report": seralized_report,
            "threats": [],
        }
        end_state = await threat_model_agent.get_workflow().ainvoke(input=state)

        new_threats = end_state.get("threats", [])

        logger.info(f"✅ Finished threats generation for data flow report.)")
        return [
            Threat.model_validate(
                {
                    "id": uuid.uuid4(),
                    "data_flow_report_id": data_flow_report.id,
                    **AgentThreat.model_validate(threat).model_dump(exclude_unset=True),
                }
            )
            for threat in new_threats
        ]
    except Exception as e:
        logger.exception(f"❌ Error during threat generation: {str(e)}")
        raise


async def generate_threat_model_data(
    threat_model: ThreatModel, config: ThreatModelConfig
) -> dict:
    logger.info(
        f"🚀 Starting threats model data generation for threat model: {threat_model.id})"
    )
    try:
        threat_model_data_agent = ThreatModelDataAgent(
            model=ChatModelManager.get_model(
                provider=config.llm_provider, model=config.report_agent_llm
            )
        )

        serialized_threat_model = threat_model.model_dump(mode="json")

        state = {
            "threat_model": serialized_threat_model,
        }
        end_state = await threat_model_data_agent.get_workflow().ainvoke(input=state)

        logger.info(f"✅ Finished threat model data generation for threat model.")

        return {
            "title": end_state.get("title", "No title generated."),
            "summary": end_state.get("summary", "No summary generated."),
        }

    except Exception as e:
        logger.exception(f"❌ Error during threat generation: {str(e)}")
        raise
