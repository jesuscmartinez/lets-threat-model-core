from pathlib import Path
from pydantic import SecretStr
from core.agents.diagram_agent import DiagramAgent
from core.agents.merge_data_flows_agent import MergeDataFlowAgent
from core.agents.mitre_attack_agent import MitreAttackAgent
from core.agents.repo_data_flow_agent import (
    DataFlowAgent,
    AgentDataFlowReport,
    GraphStateModel,
)
from core.agents.threat_model_agent import ThreatModelAgent
from core.models.dtos.Asset import Asset
from core.models.dtos.MitreAttack import AgentAttack, Attack
from core.models.dtos.ThreatModel import ThreatModel
from core.models.dtos.DataFlowReport import DataFlowReport
from core.models.dtos.Threat import Threat, AgentThreat
from core.agents.threat_model_data_agent import ThreatModelDataAgent
from core.models.dtos.Repository import Repository
from core.agents.chat_model_manager import ChatModelManager
import logging
import uuid
from tempfile import TemporaryDirectory
from typing import Any, Dict, Optional, Tuple, List
import asyncio
from git import Repo as GitRepo


from core.services.threat_model_config import ThreatModelConfig


logger = logging.getLogger(__name__)


async def generate_threat_model(
    asset: Asset, repos: List[Repository], config: ThreatModelConfig
) -> ThreatModel:

    threat_model = ThreatModel(
        uuid=uuid.uuid4(),
        name="New Threat Model",
        summary="No summary generated.",
        asset=asset,
        repos=repos,
        data_flow_reports=[],
    )

    if config.generate_data_flow_reports:
        # Generate data flow reports concurrently
        individual_reports = await asyncio.gather(
            *(generate_data_flow(repo, config) for repo in repos),
            return_exceptions=False,
        )

        strategy = config.data_flow_report_strategy

        # Depending on the strategy, we either keep individual reports,
        # combine them, or keep both combined and individual reports.
        if strategy == ThreatModelConfig.STRATEGY_PER_REPOSITORY:
            threat_model.data_flow_reports = individual_reports
        elif strategy == ThreatModelConfig.STRATEGY_COMBINED:
            combined_report = await merge_data_flows(individual_reports, config)
            threat_model.data_flow_reports = [combined_report]
        elif strategy == ThreatModelConfig.STRATEGY_BOTH:
            combined_report = await merge_data_flows(individual_reports, config)
            threat_model.data_flow_reports = [combined_report, *individual_reports]

        data_flow_reports = threat_model.data_flow_reports

    if not config.categorize_only and threat_model.data_flow_reports:

        if config.generate_mitre_attacks:

            # Generate MITRE ATT&CK attacks concurrently
            attack_results = await asyncio.gather(
                *(generate_mitre_attack(report, config) for report in data_flow_reports)
            )
            for report, attacks in zip(data_flow_reports, attack_results):
                report.attacks = attacks

        if config.generate_threats:
            # Generate threats concurrently
            threat_results = await asyncio.gather(
                *(
                    generate_threats(asset, report, config)
                    for report in data_flow_reports
                )
            )
            for report, threats in zip(data_flow_reports, threat_results):
                report.threats = threats

        threat_model_data = await generate_threat_model_data(threat_model, config)
        threat_model.name = threat_model_data["title"]
        threat_model.summary = threat_model_data["summary"]

    return threat_model


async def generate_data_flow(
    repository: Repository, config: ThreatModelConfig
) -> DataFlowReport:
    """Generates a DataFlowReport for a given repository (local or remote)."""

    logger.info(
        f"🚀 Starting data flow generation for Repository: {repository.name} (ID: {repository.uuid})"
    )

    try:
        if repository.local_path:
            end_state = await process_local_repository(repository, config)

        elif repository.url:
            end_state = await process_remote_repository(repository, config)

        else:
            raise ValueError("Repository must have either a local_path or a URL.")

        report = build_data_flow_report(config, repository, end_state)
        logger.info(
            f"✅ Finished data flow generation for repository: {repository.name}"
        )

        return report

    except Exception as e:
        logger.exception(f"❌ Error during data flow generation: {str(e)}")
        raise


async def generate_mitre_attack(
    data_flow_report: DataFlowReport, config: ThreatModelConfig
) -> List[Attack]:
    """Generates a MITRE ATT&CK for a given data flow report."""
    logger.info(
        f"🚀 Starting MITRE ATT&CK generation for Data Flow Report: {data_flow_report.uuid})"
    )
    try:
        mitre_attack_agent = MitreAttackAgent(
            model=ChatModelManager.get_model(
                provider=config.llm_provider,
                api_key=config.api_key,
                model=config.threat_model_agent_llm,
            )
        )

        serialized_report = DataFlowReport(
            overview=data_flow_report.overview,
            external_entities=data_flow_report.external_entities,
            processes=data_flow_report.processes,
            data_stores=data_flow_report.data_stores,
            trust_boundaries=data_flow_report.trust_boundaries,
            repository_uuid=data_flow_report.repository_uuid,
        ).model_dump(mode="json")

        state = {
            "data_flow_report": serialized_report,
            "attacks": [],
        }
        end_state = await mitre_attack_agent.get_workflow().ainvoke(input=state)

        attacks = end_state.get("attacks", [])

        logger.info(f"✅ Finished MITRE ATT&CK generation for data flow report.)")
        return [
            Attack.model_validate(
                {
                    "uuid": uuid.uuid4(),
                    **AgentAttack.model_validate(attack).model_dump(exclude_unset=True),
                }
            )
            for attack in attacks
        ]
    except Exception as e:
        logger.exception(f"❌ Error during MITRE ATT&CK generation: {str(e)}")
        raise


async def process_local_repository(
    repository: Repository, config: ThreatModelConfig
) -> dict:
    """Process a local repository for data flow generation."""
    repo_path = Path(repository.local_path).resolve()

    if not repo_path.exists() or not repo_path.is_dir():
        raise ValueError(f"Local repository path does not exist: {repo_path}")

    logger.info(f"📂 Using local repository path: {repo_path}")

    data_flow_agent = create_data_flow_agent(
        repository=repository,
        config=config,
        directory=str(repo_path),
    )

    # state = generate_data_flow_state()
    return await data_flow_agent.get_workflow().ainvoke(input=GraphStateModel())


async def process_remote_repository(
    repository: Repository, config: ThreatModelConfig
) -> dict:
    """Clone and process a remote repository for data flow generation."""
    with TemporaryDirectory() as temp_dir:
        logger.info(f"📂 Cloning repository to temporary directory: {temp_dir}")

        # Perform the clone operation
        clone_repository(
            username=config.username,
            pat=config.pat,
            repo_url=repository.url,
            temp_dir=temp_dir,
        )

        data_flow_agent = create_data_flow_agent(
            repository=repository,
            config=config,
            directory=temp_dir,
        )

        # state = generate_data_flow_state()
        return await data_flow_agent.get_workflow().ainvoke(input=GraphStateModel())


def clone_repository(
    username: str, pat: SecretStr, repo_url: str, temp_dir: str
) -> GitRepo:
    """Clone the repository into a temporary directory."""
    try:
        logger.info(
            "🛠️ Initiating repository clone: %s → %s",
            repo_url,
            temp_dir,
        )

        # Use pat.get_secret_value() to retrieve the actual secret string
        auth_repo_url = f"https://{username}:{pat.get_secret_value()}@{repo_url}"

        repo = GitRepo.clone_from(auth_repo_url, temp_dir)
        branch = repo.head.reference.name
        commit = repo.head.commit.hexsha

        logger.info(
            "✅ Successfully cloned repository: %s (Branch: %s | Commit: %s)",
            repo_url,
            branch,
            commit,
        )

        return repo

    except Exception as e:
        logger.error(
            "❌ Failed to clone repository %s: %s",
            repo_url,
            str(e),
            exc_info=True,
        )
        raise e


def create_data_flow_agent(
    repository: Repository,
    config: ThreatModelConfig,
    directory: str,
) -> DataFlowAgent:
    """Creates a DataFlowAgent for the given repository."""
    return DataFlowAgent(
        categorization_model=ChatModelManager.get_model(
            provider=config.llm_provider,
            api_key=config.api_key,
            model=config.categorization_agent_llm,
        ),
        review_model=ChatModelManager.get_model(
            provider=config.llm_provider,
            api_key=config.api_key,
            model=config.report_agent_llm,
        ),
        directory=directory,
        username=config.username,
        password=config.pat,
        config=config,
    )


def generate_dataflow_diagram(
    config: ThreatModelConfig, report: AgentDataFlowReport
) -> Optional[str]:
    # Initialize the diagram agent
    diagram_agent = DiagramAgent(
        model=ChatModelManager.get_model(
            provider=config.llm_provider,
            api_key=config.api_key,
            model=config.report_agent_llm,
        )
    )

    # Example state for the workflow
    state = {"data_flow_report": report}

    return diagram_agent.get_workflow().invoke(input=state)["mermaid_diagram"]


def build_data_flow_report(
    config: ThreatModelConfig, repository: Repository, end_state: dict
) -> DataFlowReport:
    """Builds a DataFlowReport from the final agent end_state."""
    agent_data_flow = AgentDataFlowReport.model_validate(end_state["data_flow_report"])

    diagram = generate_dataflow_diagram(config, agent_data_flow)

    report = DataFlowReport.model_validate(
        obj={
            "uuid": uuid.uuid4(),
            "repository_uuid": repository.uuid,
            **agent_data_flow.model_dump(exclude_unset=True),
            "could_not_review": list(end_state.get("could_not_review", [])),
            "could_review": list(end_state.get("could_review", [])),
            "should_not_review": list(end_state.get("should_not_review", [])),
            "should_review": list(end_state.get("should_review", [])),
            "reviewed": list(end_state.get("reviewed", [])),
            "diagram": diagram if diagram else None,
        }
    )

    return report


async def generate_threats(
    asset: Asset, data_flow_report: DataFlowReport, config: ThreatModelConfig
) -> List[Threat]:
    """Generates threats for a given data flow report."""
    logger.info(
        f"🚀 Starting threats generation for Data Flow Report: {data_flow_report.uuid})"
    )
    try:
        threat_model_agent = ThreatModelAgent(
            model=ChatModelManager.get_model(
                provider=config.llm_provider,
                api_key=config.api_key,
                model=config.threat_model_agent_llm,
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
                    "uuid": uuid.uuid4(),
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
        f"🚀 Starting threats model data generation for threat model: {threat_model.uuid})"
    )
    try:
        threat_model_data_agent = ThreatModelDataAgent(
            model=ChatModelManager.get_model(
                provider=config.llm_provider,
                api_key=config.api_key,
                model=config.report_agent_llm,
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


async def merge_data_flows(
    data_flow_reports: List[DataFlowReport], config: ThreatModelConfig
) -> DataFlowReport:

    logger.info(f"🚀 Starting data flow merger for {len(data_flow_reports)} reports.")
    try:
        merge_agent = MergeDataFlowAgent(
            model=ChatModelManager.get_model(
                provider=config.llm_provider,
                api_key=config.api_key,
                model=config.report_agent_llm,
            )
        )

        state = {
            "data_flow_reports": [
                AgentDataFlowReport.model_validate(r.model_dump()).model_dump(
                    mode="json"
                )
                for r in data_flow_reports
            ],
            "merged_data_flow_report": {},  # empty dict or default structure
            "justification": "",  # placeholder string
        }

        end_state = await merge_agent.get_workflow().ainvoke(input=state)

        agent_data_flow = AgentDataFlowReport.model_validate(
            end_state["merged_data_flow_report"]
        )

        logger.info(
            f"📝 Merge Justification:\n{end_state.get('justification', 'No justification provided.')}"
        )

        diagram = generate_dataflow_diagram(config, agent_data_flow)

        report = DataFlowReport.model_validate(
            obj={
                "uuid": uuid.uuid4(),
                "repository_uuid": None,
                **agent_data_flow.model_dump(exclude_unset=True),
                # Do not set review-related fields here; we'll aggregate them below.
                "diagram": diagram if diagram else None,
            }
        )

        # Collect all categorized files from the input data_flow_report list
        all_should_review = []
        all_reviewed = []
        all_could_review = []
        all_should_not_review = []
        all_could_not_review = []

        for r in data_flow_reports:
            all_should_review.extend(r.should_review)
            all_reviewed.extend(r.reviewed)
            all_could_review.extend(r.could_review)
            all_should_not_review.extend(r.should_not_review)
            all_could_not_review.extend(r.could_not_review)

        report.should_review = all_should_review
        report.reviewed = all_reviewed
        report.could_review = all_could_review
        report.should_not_review = all_should_not_review
        report.could_not_review = all_could_not_review

        logger.info(f"✅ Finished data flow report merger.")

        return report

    except Exception as e:
        logger.exception(f"❌ Error during data flow report merging: {str(e)}")
        raise
