from pydantic import SecretStr
from core.agents.repo_data_flow_agent import DataFlowAgent, Config
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
from typing import Tuple, List
import asyncio


# Configure logging
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=log_level,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

LLM_PROVIDER = os.getenv("LLM_PROVIDER", "")
CATEGRORIZATION_AGENT_LLM = os.getenv("CATEGRORIZATION_AGENT_LLM", "")
REVIEW_AGENT_LLM = os.getenv("REVIEW_AGENT_LLM", "")
THREAT_MODEL_AGENT_LLM = os.getenv("THREAT_MODEL_AGENT_LLM", "")
REPORT_AGENT_LLM = os.getenv("REPORT_AGENT_LLM", "")

CONTEXT_WINDOW = int(os.getenv("CONTEXT_WINDOW", 0))
USERNAME = os.getenv("USERNAME")
PAT = SecretStr(os.getenv("PAT", ""))


async def generate_threat_model(asset: Asset, repos: List[Repository]) -> ThreatModel:

    # Generate data flow reports concurrently
    data_flow_reports = await asyncio.gather(
        *(generate_data_flow(repo) for repo in repos)
    )

    # # Generate threats concurrently
    # threat_lists = await asyncio.gather(
    #     *(generate_threats(asset, report) for report in data_flow_reports)
    # )

    # # Flatten the list of threats
    # all_threats = [
    #     threat for report_threats in threat_lists for threat in report_threats
    # ]
    all_threats = []

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

    threat_model_data = await generate_threat_model_data(threat_model)
    threat_model.name = threat_model_data["title"]
    threat_model.summary = threat_model_data["summary"]

    return threat_model


async def generate_data_flow(repository: Repository):
    """Generates a DataFlowReport for a given repository."""
    try:
        logger.info(
            f"🚀 Starting data flow generation for Repository: {repository.name} (ID: {repository.id})"
        )

        with TemporaryDirectory() as temp_dir:
            logger.info(f"📂 Created temporary directory: {temp_dir}")

            # Initialize AI-based DataFlowAgent
            data_flow_agent = DataFlowAgent(
                categorization_model=ChatModelManager.get_model(
                    provider=LLM_PROVIDER, model=CATEGRORIZATION_AGENT_LLM
                ),
                review_model=ChatModelManager.get_model(
                    provider=LLM_PROVIDER, model=REVIEW_AGENT_LLM
                ),
                repo_url=repository.url,
                directory=temp_dir,
                config=Config(username=USERNAME, pat=PAT),
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
    asset: Asset, data_flow_report: DataFlowReport
) -> List[Threat]:
    """Generates threats for a given data flow report."""
    logger.info(
        f"🚀 Starting threats generation for Data Flow Report: {data_flow_report.id})"
    )
    try:
        threat_model_agent = ThreatModelAgent(
            model=ChatModelManager.get_model(
                provider=LLM_PROVIDER, model=THREAT_MODEL_AGENT_LLM
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


async def generate_threat_model_data(threat_model: ThreatModel) -> dict:
    logger.info(
        f"🚀 Starting threats model data generation for threat model: {threat_model.id})"
    )
    try:
        threat_model_data_agent = ThreatModelDataAgent(
            model=ChatModelManager.get_model(
                provider=LLM_PROVIDER, model=REPORT_AGENT_LLM
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
