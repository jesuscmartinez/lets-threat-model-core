import asyncio
import logging
import json
from re import A
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.prompts import (
    SystemMessagePromptTemplate,
    HumanMessagePromptTemplate,
    ChatPromptTemplate,
)
from core.agents.agent_tools import AgentHelper, ainvoke_with_retry, invoke_with_retry
from core.models.dtos.DataFlowReport import DataFlowReport
from langgraph.graph import StateGraph, START, END
from pydantic import BaseModel, Field
from typing import Optional, Any, Dict, List

from core.models.dtos.MitreAttack import AgentAttack, Attack

logger = logging.getLogger(__name__)

SYSTEM_MAP_PROMPT = """
You are a cybersecurity expert skilled in threat modeling and adversary behavior analysis using the MITRE ATT&CK framework.

You will be given a component from a system architecture, along with the complete system description in the form of a `DataFlowReport`. This report includes processes, data stores, external entities, data flows, and trust boundaries that define the architecture and interactions within the system.

Your task is to:
1. Analyze the provided **component** in the context of the full system.
2. Identify the relevant MITRE ATT&CK **tactics** and **techniques** that an adversary could use to compromise this component, move laterally, or exfiltrate data.
3. For each identified technique, include:
   - The **ATT&CK tactic** (e.g., Initial Access, Execution),
   - The **ATT&CK technique ID and name** (e.g., T1078: Valid Accounts),
   - A brief **explanation of why this technique is relevant** to this component.
   - Optionally, suggest **mitigations** based on ATT&CK recommendations.

Focus solely on the current component provided in context, but leverage insights from the full system report as needed.
"""


class AttackGraphStateModel(BaseModel):
    data_flow_report: Dict[str, Any] = Field(default_factory=dict)
    attacks: List[AgentAttack] = Field(default_factory=list)


class Result(BaseModel):
    attacks: list[AgentAttack] = Field(
        default_factory=list,
        description="List of identified attacks based on the MITRE ATT&CK framework.",
    )


class MitreAttackAgent:
    def __init__(self, model: BaseChatModel):
        self.model = model
        self.agent_helper = AgentHelper()

    def initialize(self, state: AttackGraphStateModel) -> AttackGraphStateModel:
        """Initialize the state by converting UUIDs to internal numbered IDs."""
        logger.info("Initializing threat modeling state...")

        state.data_flow_report = self.agent_helper.convert_uuids_to_ids(
            state.data_flow_report
        )

        return state

    def finalize(self, state: AttackGraphStateModel) -> AttackGraphStateModel:
        """Clean up the state by converting internal numbered IDs back to UUIDs."""
        logger.info("Cleaning up threat modeling state...")

        state.attacks = [
            self.agent_helper.convert_ids_to_uuids(threat) for threat in state.attacks
        ]

        return state

    async def _process_component(
        self,
        component: Dict[str, Any],
        report: Dict[str, Any],
        chain: Any,
    ) -> List[AgentAttack]:
        """Helper to process a single component asynchronously."""
        try:
            logger.debug(
                "Processing component: %s",
                component.get("name", "Unknown Component"),
            )

            result = await ainvoke_with_retry(
                chain,
                {
                    "data_flow_report": json.dumps(report, sort_keys=True),
                    "component": json.dumps(component, sort_keys=True),
                },
            )

            attacks = result.attacks if isinstance(result, Result) else []
            logger.debug(
                "Identified %d attacks in component: %s",
                len(attacks),
                component.get("name", "Unknown Component"),
            )

            return attacks

        except Exception as e:
            logger.exception(
                "❌ Error analyzing component '%s': %s",
                component.get("name", "Unknown Component"),
                str(e),
            )
            return []

    def _log_attack_summary(self, attacks: List[AgentAttack]) -> None:
        """Log summary of identified MITRE ATT&CK techniques by tactic."""
        if not attacks:
            logger.warning("No attacks identified.")
            return

        tactic_counts = {}
        technique_counts = {}

        for attack in attacks:
            tactic = getattr(attack, "attack_tactic", "Unknown")
            technique = f"{attack.technique_id}: {attack.technique_name}"

            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
            technique_counts[technique] = technique_counts.get(technique, 0) + 1

        logger.info(
            f"🛡️ MITRE ATT&CK Summary:\n"
            f"  📊 Total Techniques Identified: {len(attacks)}\n"
            f"  🎯 Tactics Breakdown:"
        )
        for tactic, count in sorted(tactic_counts.items(), key=lambda x: x[0]):
            logger.info(f"    - {tactic}: {count}")

        logger.debug("  🧰 Techniques Identified:")
        for technique, count in sorted(
            technique_counts.items(), key=lambda x: x[1], reverse=True
        ):
            logger.debug(f"    - {technique}: {count}")

    async def analyze(self, state: AttackGraphStateModel) -> AttackGraphStateModel:
        report = state.data_flow_report
        if not report:  # Ensure report is not empty
            logger.error("DataFlowReport is empty in generate_attack_map.")
            state.attacks = []
            return state

        system_prompt = SystemMessagePromptTemplate.from_template(SYSTEM_MAP_PROMPT)
        user_prompt = HumanMessagePromptTemplate.from_template(
            """
            DataFlowReport:
            {data_flow_report}

            Component:
            {component}
            """
        )
        prompt = ChatPromptTemplate.from_messages([system_prompt, user_prompt])

        # Build chain with structured output
        chain = prompt | self.model.with_structured_output(schema=Result)

        tasks = [
            self._process_component(component, report, chain)
            for key in (
                "external_entities",
                "processes",
                "data_stores",
                "trust_boundaries",
                "data_flows",
            )
            for component in sorted(
                report.get(key, []), key=lambda c: c.get("name", "")
            )
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        attacks: List[AgentAttack] = []
        for res in results:
            if isinstance(res, Exception):
                logger.error("❌ An error occurred in component analysis", exc_info=res)
                continue
            if isinstance(res, list):
                attacks.extend(res)

        logger.info(
            "✅ Finished MITRE ATT&CK analysis. Total attacks found: %d",
            len(attacks),
        )
        self._log_attack_summary(attacks)

        state.attacks = attacks
        return state

    def get_workflow(self):
        workflow = StateGraph(AttackGraphStateModel)

        workflow.add_node("initialize", self.initialize)
        workflow.add_node("analyze", self.analyze)
        workflow.add_node("finalize", self.finalize)

        workflow.add_edge(START, "initialize")
        workflow.add_edge("initialize", "analyze")
        workflow.add_edge("analyze", "finalize")
        workflow.add_edge("finalize", END)

        return workflow.compile()
