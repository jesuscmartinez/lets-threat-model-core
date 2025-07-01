from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.prompts import (
    SystemMessagePromptTemplate,
    HumanMessagePromptTemplate,
    ChatPromptTemplate,
)
from core.agents.agent_tools import AgentHelper, invoke_with_retry
from langgraph.graph import StateGraph, START, END
from pydantic import BaseModel, Field
from trustcall import create_extractor

SYSTEM_GENERATE_PROMPT = """\
You are a system analysis assistant. Your task is to generate a Mermaid.js-compatible diagram that clearly illustrates the data flows in a software system based on the provided DataFlowReport.

⚠️ Your output must fully conform to the official Mermaid.js flowchart syntax specification:
https://mermaid.js.org/syntax/flowchart.html

Follow these rules:

1. Start the diagram with `graph TD` to represent a top-down flowchart direction.
2. Represent each trust boundary using a `subgraph` block labeled with the trust boundary’s name.
3. Define system components using valid node types:
   - External Entities: `A((External Entity))`
   - Processes: `B[Process]`
   - Data Stores: `C[(Data Store)]`
4. Define directional data flows using the `-->` syntax:
   - Example: `A --> B`
   - If adding a label, use the `|label|` format: `A -->|Data| B`
   - If the label includes parentheses or special characters, wrap the entire label in double quotes: `A -->|"User Input (e.g., credentials)"| B`
5. Node identifiers must follow Mermaid's rules:
   - Use alphanumeric characters, underscores, or camelCase
   - Avoid spaces and special characters in IDs (e.g., use `webServer`, not `Web Server`)
6. Components not belonging to a trust boundary should be placed outside any subgraph.
7. Do not include any explanation or markdown formatting—only output the raw Mermaid.js flowchart code.

Your output must be valid according to the flowchart syntax and render correctly in Mermaid.
"""


class DiagramAgent:
    def __init__(self, model: BaseChatModel):
        self.model = model
        self.agent_helper = AgentHelper()

    def generate_mermaid_dataflow_diagram(self, state: dict) -> dict:
        report = state.get("data_flow_report", None)

        # Pydantic model for LLM results
        class Result(BaseModel):
            mermaid_diagram: str = Field(
                ...,
                description="A Mermaid.js-compatible diagram that visualizes the data flow in the system.",
            )

        system_prompt = SystemMessagePromptTemplate.from_template(
            SYSTEM_GENERATE_PROMPT
        )
        user_prompt = HumanMessagePromptTemplate.from_template(
            "<data_flow_report>\n{data_flow_report}\n</data_flow_report>"
        )
        prompt = ChatPromptTemplate.from_messages([system_prompt, user_prompt])

        # Build chain with structured output
        chain = prompt | create_extractor(
            self.model,
            tools=[Result],
            tool_choice="Result",
        )

        inputs = {
            "data_flow_report": report.model_dump(mode="json") if report else None,
        }

        # Invoke the chain with retry logic
        result = invoke_with_retry(chain, inputs)

        state["mermaid_diagram"] = result["responses"][0].mermaid_diagram

        return state

    def get_workflow(self) -> StateGraph:
        workflow = StateGraph(dict)

        workflow.add_node(
            "generate_mermaid_dataflow_diagram", self.generate_mermaid_dataflow_diagram
        )

        workflow.add_edge(START, "generate_mermaid_dataflow_diagram")
        workflow.add_edge("generate_mermaid_dataflow_diagram", END)

        return workflow.compile()
