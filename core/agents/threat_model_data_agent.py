from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.prompts import (
    SystemMessagePromptTemplate,
    HumanMessagePromptTemplate,
    ChatPromptTemplate,
)
from langchain_core.output_parsers import PydanticOutputParser
from core.agents.agent_tools import AgentHelper
from langgraph.graph import StateGraph, START, END
import logging
import os
from typing import TypedDict, Dict
from pydantic import BaseModel, Field
import json


# Configure logging
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=log_level,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


class GraphState(TypedDict):
    threat_model: Dict
    summary: str
    title: str


class ThreatModelDataAgent:

    def __init__(self, model: BaseChatModel):
        self.model = model
        self.agent_helper = AgentHelper()

    def initialize(self, state: GraphState) -> GraphState:

        # Convert asset to uuid_X dict
        threat_model = state.get("threat_model")
        if "asset" not in threat_model or threat_model["asset"] is None:
            raise ValueError("Asset data is missing in threat_model")

        numbered_asset = self.agent_helper.convert_uuids_to_numbered_ids(
            threat_model["asset"]
        )
        threat_model["asset"] = numbered_asset

        # Convert repo uuid_X to dict
        if "repos" not in threat_model or threat_model["repos"] is None:
            raise ValueError("Repo data is missing in threat_model")
        repos = threat_model["repos"]
        numbered_repos = [
            self.agent_helper.convert_uuids_to_numbered_ids(repo) for repo in repos
        ]
        threat_model["repos"] = numbered_repos

        # Convert data flow report to uuid_X dict
        if (
            "data_flow_reports" not in threat_model
            or threat_model["data_flow_reports"] is None
        ):
            raise ValueError("Data flow reports is missing in threat_model")
        data_flow_reports = threat_model["data_flow_reports"]
        numbered_reports = [
            self.agent_helper.convert_uuids_to_numbered_ids(data_flow_report)
            for data_flow_report in data_flow_reports
        ]
        threat_model["data_flow_reports"] = numbered_reports

        # Convert threats to uuid_X dict
        if "threats" not in threat_model or threat_model["threats"] is None:
            raise ValueError("Thrat data is missing in threat_model")
        threats = threat_model["threats"]
        numbered_threats = [
            self.agent_helper.convert_uuids_to_numbered_ids(threat)
            for threat in threats
        ]
        threat_model["threat"] = numbered_threats

        state["threat_model"] = threat_model

        return state

    async def generate(self, state: GraphState) -> GraphState:
        logger.info("🔍 Starting threat model data generation...")

        class Result(BaseModel):
            title: str = Field(..., description="Title for the summary.")
            summary: str = Field(
                ..., description="A summary report of the threat model."
            )

        system_prompt = SystemMessagePromptTemplate.from_template(
            """
        Objective:
        You are given the following data structures:

        1. **Asset** (represents a specific resource or system entity)
        2. **List[Repository]** (one or more code repositories associated with the asset)
        4. **List[DataFlowReport]** (detailed analyses of data flows within or related to the repositories)
        5. **List[Threat]** (list of identified threats associated with the asset and its repositories)

        Please perform the following steps:

        1. **Title**: Generate a concise, descriptive title that encapsulates the overall context of these data structures (e.g., "System Data Flow and Security Overview").
        2. **Summary**: Provide a summary of:
        - The role of the asset and its significance.
        - The purpose of the repositories and their connection to the asset.
        - The presence of data flow reports and why they are important.
        - The existence of potential threats and their impact on the asset.
        """
        )

        user_prompt = HumanMessagePromptTemplate.from_template(
            "Asset:\n{asset}\n\nRepositories:\n{repos}\nDataFlowReport:\n{data_flow_reports}\n\n:Threats:{threats}\n"
        )

        prompt = ChatPromptTemplate.from_messages([system_prompt, user_prompt])

        chain = prompt | self.model.with_structured_output(schema=Result)

        threat_model = state.get("threat_model")
        asset = threat_model.get("asset")
        repos = threat_model.get("repos")
        reports = threat_model.get("data_flow_reports")
        threats = threat_model.get("threats")

        result = await chain.ainvoke(
            input={
                "asset": json.dumps(asset),
                "repos": json.dumps(repos),
                "data_flow_reports": json.dumps(reports),
                "threats": json.dumps(threats),
            }
        )

        if isinstance(result, Result):
            state["title"] = result.title
            state["summary"] = result.summary
        else:
            raise TypeError(f"Unexpected result type: {type(result)}")

        return state

    def get_workflow(self):
        """Defines and compiles the workflow for threat model data generation."""
        workflow = StateGraph(GraphState)

        workflow.add_node("initialize", self.initialize)
        workflow.add_node("generate", self.generate)

        workflow.add_edge(START, "initialize")
        workflow.add_edge("initialize", "generate")
        workflow.add_edge("generate", END)

        return workflow.compile()
