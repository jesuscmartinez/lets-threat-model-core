import logging
import json
from typing import Any, Dict, List

from pydantic import BaseModel, Field

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.prompts import (
    SystemMessagePromptTemplate,
    HumanMessagePromptTemplate,
    ChatPromptTemplate,
)
from core.agents.agent_tools import AgentHelper, ainvoke_with_retry
from langgraph.graph import StateGraph, START, END
from trustcall import create_extractor


logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Pydantic Model for Graph State
# -----------------------------------------------------------------------------
class StateModel(BaseModel):
    """State object for merged data flow report generation."""

    data_flow_reports: List[Dict[Any, Any]] = Field(default_factory=list)
    merged_data_flow_report: Dict[Any, Any] = Field(description="")
    justification: str = Field(
        ...,
        description="Explanation of how and why the data flow reports were merged.",
    )


# -----------------------------------------------------------------------------
# Large Prompt (Constant)
# -----------------------------------------------------------------------------
SYSTEM_GENERATE_PROMPT = """\
You are a software security assistant responsible for synthesizing multiple structured data flow reports into a single unified model. Each report represents system components such as external entities, processes, data stores, data flows, and trust boundaries.

Objectives:
	1.	Combine all components into one coherent and consistent data flow report.
	2.	Identify and merge overlapping or duplicate components (e.g., similar processes or external entities), ensuring semantic accuracy and role preservation.
	3.	Retain all distinct data flows and trust boundaries from the original reports.
	4.	Provide a concise justification that explains:
        •	Your strategy for merging components
        •	How overlaps were resolved
        •	How the integrity and intent of the original models were maintained
"""


# -----------------------------------------------------------------------------
# MergeDataFlowAgent
# -----------------------------------------------------------------------------
class MergeDataFlowAgent:
    def __init__(self, model: BaseChatModel):
        self.model = model
        self.agent_helper = AgentHelper()

    def initialize(self, state: StateModel) -> StateModel:
        """Prepare state before we start the rest of the workflow."""
        # Convert data flow reports
        data_flow_reports = state.data_flow_reports
        numbered_reports = [
            self.agent_helper.convert_uuids_to_ids(report)
            for report in data_flow_reports
        ]
        state.data_flow_reports = numbered_reports

        return state

    def finalize(self, state: StateModel) -> StateModel:
        """Convert IDs back to original UUID style at end of workflow."""
        # Convert data flow reports
        converted = self.agent_helper.convert_ids_to_uuids(
            state.merged_data_flow_report
        )
        state.merged_data_flow_report = converted
        return state

    async def merge(self, state: StateModel) -> StateModel:
        """
        Use the LLM to merge multipule data_flows_reports.
        """
        logger.info("🧠 => 🔀 Merging data flow reports with LLM assistance...")

        # Pydantic model for LLM results
        class Result(BaseModel):

            data_flow_report: Dict[str, Any] = Field(
                ...,
                description="The resulting merged data flow report combining multiple individual reports into a single representation.",
            )
            justification: str = Field(
                ...,
                description="Explanation of how and why the data flow reports were merged.",
            )

        # Prepare system & user prompts
        system_prompt = SystemMessagePromptTemplate.from_template(
            SYSTEM_GENERATE_PROMPT
        )
        user_prompt = HumanMessagePromptTemplate.from_template(
            "<data_flow_reports>:\n{data_flow_reports}\n</data_flow_reports>\n"
        )
        prompt = ChatPromptTemplate.from_messages([system_prompt, user_prompt])

        # Build chain with structured output
        chain = prompt | create_extractor(
            self.model,
            tools=[Result],
            tool_choice="Result",
        )

        # Prepare inputs
        reports = state.data_flow_reports

        # Sort reports before serialization for consistent output
        reports = sorted(reports, key=lambda r: r.get("repo_name", ""))

        # Prepare inputs for this iteration
        chain_inputs = {
            "data_flow_reports": json.dumps(reports, sort_keys=True),
        }

        # Invoke the chain with retry logic
        result = await ainvoke_with_retry(chain, chain_inputs)
        result = result["responses"][0]

        state.merged_data_flow_report = result.data_flow_report
        state.justification = result.justification

        logger.info("✅ Data flow reports merger complete.")

        return state

    def get_workflow(self) -> StateGraph:
        """
        Defines and compiles the workflow for threat model data generation.
        """
        workflow = StateGraph(StateModel)

        workflow.add_node("initialize", self.initialize)
        workflow.add_node("finalize", self.finalize)
        workflow.add_node("merge", self.merge)

        workflow.add_edge(START, "initialize")
        workflow.add_edge("initialize", "merge")
        workflow.add_edge("merge", "finalize")
        workflow.add_edge("finalize", END)

        return workflow.compile()
