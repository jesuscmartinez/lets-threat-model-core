import logging
import os
import json
from typing import Any, Dict, List

from pydantic import BaseModel, Field

# LangChain / local imports
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.prompts import (
    SystemMessagePromptTemplate,
    HumanMessagePromptTemplate,
    ChatPromptTemplate,
)
from langchain_core.output_parsers import PydanticOutputParser
from core.agents.agent_tools import AgentHelper
from langgraph.graph import StateGraph, START, END


# -----------------------------------------------------------------------------
# Configure logging
# -----------------------------------------------------------------------------
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=log_level,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Pydantic Model for Graph State
# -----------------------------------------------------------------------------
class ThreatModelDataStateModel(BaseModel):
    """State object for threat model data generation."""

    threat_model: Dict[str, Any] = Field(default_factory=dict)
    summary: str = Field("", description="A summary of the threat model.")
    title: str = Field("", description="A generated title for the threat model.")


# -----------------------------------------------------------------------------
# Large Prompt (Constant)
# -----------------------------------------------------------------------------
SYSTEM_GENERATE_PROMPT = """\
Objective:
You are given the following data structures:

1. **Asset** (represents a specific resource or system entity)
2. **List[Repository]** (one or more code repositories associated with the asset)
3. **List[DataFlowReport]** (detailed analyses of data flows within or related to the repositories)
4. **List[Threat]** (list of identified threats associated with the asset and its repositories)

Please perform the following steps:

1. **Title**: Generate a concise, descriptive title that encapsulates the overall context of these data structures (e.g., "System Data Flow and Security Overview").
2. **Summary**: Provide a summary of:
    - The role of the asset and its significance.
    - The purpose of the repositories and their connection to the asset.
    - The presence of data flow reports and why they are important.
    - The existence of potential threats and their impact on the asset.
"""


# -----------------------------------------------------------------------------
# ThreatModelDataAgent
# -----------------------------------------------------------------------------
class ThreatModelDataAgent:
    def __init__(self, model: BaseChatModel):
        self.model = model
        self.agent_helper = AgentHelper()

    def initialize(self, state: ThreatModelDataStateModel) -> ThreatModelDataStateModel:
        """
        Convert the nested data in 'threat_model' from UUID to 'uuid_X' references
        for easier internal handling.
        """
        threat_model = state.threat_model

        # Validate the presence of required fields
        if "asset" not in threat_model or threat_model["asset"] is None:
            raise ValueError("Asset data is missing in threat_model")

        if "repos" not in threat_model or threat_model["repos"] is None:
            raise ValueError("Repo data is missing in threat_model")

        if (
            "data_flow_reports" not in threat_model
            or threat_model["data_flow_reports"] is None
        ):
            raise ValueError("Data flow reports are missing in threat_model")

        if "threats" not in threat_model or threat_model["threats"] is None:
            raise ValueError("Threat data is missing in threat_model")

        # Convert asset
        numbered_asset = self.agent_helper.convert_uuids_to_ids(threat_model["asset"])
        threat_model["asset"] = numbered_asset

        # Convert repos
        repos = threat_model["repos"]
        numbered_repos = [
            self.agent_helper.convert_uuids_to_ids(repo) for repo in repos
        ]
        threat_model["repos"] = numbered_repos

        # Convert data flow reports
        data_flow_reports = threat_model["data_flow_reports"]
        numbered_reports = [
            self.agent_helper.convert_uuids_to_ids(report)
            for report in data_flow_reports
        ]
        threat_model["data_flow_reports"] = numbered_reports

        # Convert threats
        threats = threat_model["threats"]
        numbered_threats = [
            self.agent_helper.convert_uuids_to_ids(threat) for threat in threats
        ]
        threat_model["threats"] = numbered_threats

        # Update state
        state.threat_model = threat_model
        return state

    async def generate(
        self, state: ThreatModelDataStateModel
    ) -> ThreatModelDataStateModel:
        """
        Use the LLM to generate a title and summary for the threat model data.
        """
        logger.info("🔍 Starting threat model data generation...")

        # Pydantic model for LLM results
        class Result(BaseModel):
            """
            Represents the structured output of an LLM-generated threat model result.

            This model provides a title and a summary report for the generated
            threat model, ensuring clear and structured documentation of findings.
            """

            title: str = Field(..., description="Title for the summary.")
            summary: str = Field(
                ..., description="A summary report of the threat model."
            )

        # Prepare system & user prompts
        system_prompt = SystemMessagePromptTemplate.from_template(
            SYSTEM_GENERATE_PROMPT
        )
        user_prompt = HumanMessagePromptTemplate.from_template(
            "Asset:\n{asset}\n\n"
            "Repositories:\n{repos}\n"
            "DataFlowReport:\n{data_flow_reports}\n\n"
            "Threats:\n{threats}\n"
        )
        prompt = ChatPromptTemplate.from_messages([system_prompt, user_prompt])

        # Build chain with structured output
        chain = prompt | self.model.with_structured_output(
            schema=Result.model_json_schema()
        )

        # Prepare inputs
        threat_model = state.threat_model
        asset = threat_model.get("asset", {})
        repos = threat_model.get("repos", [])
        reports = threat_model.get("data_flow_reports", [])
        threats = threat_model.get("threats", [])

        # Invoke chain
        result = await chain.ainvoke(
            {
                "asset": json.dumps(asset),
                "repos": json.dumps(repos),
                "data_flow_reports": json.dumps(reports),
                "threats": json.dumps(threats),
            }
        )

        # Ensure result is a dictionary
        if isinstance(result, dict):
            result = Result(**result)

        state.title = result.title
        state.summary = result.summary

        logger.info("✅ Threat model data generation complete.")
        logger.debug("Generated title: %s", state.title)
        logger.debug("Generated summary: %s", state.summary)

        return state

    def get_workflow(self) -> StateGraph:
        """
        Defines and compiles the workflow for threat model data generation.
        """
        workflow = StateGraph(ThreatModelDataStateModel)

        workflow.add_node("initialize", self.initialize)
        workflow.add_node("generate", self.generate)

        workflow.add_edge(START, "initialize")
        workflow.add_edge("initialize", "generate")
        workflow.add_edge("generate", END)

        return workflow.compile()
