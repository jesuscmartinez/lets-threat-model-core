from calendar import c
import json
import pytest
from core.agents.agent_tools import AgentHelper
from core.agents.extractor_agent import ComponentDelta, ExtractorAgent
from core.models.dtos.File import File
from typing import Optional
from pprint import pp, pprint
from core.models.dtos.DataFlowReport import ExternalEntity, Process, TrustBoundary
from langchain.evaluation import load_evaluator
from langchain.evaluation import EvaluatorType
from langchain.evaluation import ScoreStringEvalChain


@pytest.fixture
def expected_component_delta():
    from uuid import UUID
    from core.models.dtos.DataFlowReport import DataFlow

    return ComponentDelta(
        external_entities=[
            ExternalEntity(
                uuid=UUID("1b2c3d4e-5678-90ab-cdef-1234567890ab"),
                name="User",
                description="Human users who interact with the Let's Threat Model tool to generate threat models and reports. They provide input through configuration files and receive output in various formats.",
                data_flows=[
                    DataFlow(
                        uuid=UUID("1b2c3d4e-5678-90ab-cdef-1234567890ac"),
                        name="Configuration Input",
                        description="Users provide configuration details through a YAML file to the system.",
                        destination_uuid=UUID("f3471d37-7621-4979-b23f-e09149828f8e"),
                        data_type="YAML configuration data",
                        direction="incoming",
                    ),
                    DataFlow(
                        uuid=UUID("1b2c3d4e-5678-90ab-cdef-1234567890ad"),
                        name="Report Output",
                        description="Users receive generated threat model reports in Markdown, JSON, or SARIF formats.",
                        destination_uuid=UUID("f3471d37-7621-4979-b23f-e09149828f8e"),
                        data_type="Threat model report",
                        direction="outgoing",
                    ),
                ],
            )
        ],
        data_stores=[],
        processes=[
            Process(
                uuid=UUID("2b3c4d5e-6789-01ab-cdef-2345678901bc"),
                name="Threat Model Generation",
                description="This process analyzes the provided YAML configuration and generates a threat model report based on the repository structure and metadata. It interacts with the LLM provider to categorize and review the repository contents.",
                data_flows=[
                    DataFlow(
                        uuid=UUID("2b3c4d5e-6789-01ab-cdef-2345678901bd"),
                        name="YAML Configuration Analysis",
                        description="The process reads the YAML configuration file to extract asset and repository details.",
                        destination_uuid=UUID("f3471d37-7621-4979-b23f-e09149828f8e"),
                        data_type="YAML configuration data",
                        direction="incoming",
                    ),
                    DataFlow(
                        uuid=UUID("2b3c4d5e-6789-01ab-cdef-2345678901be"),
                        name="Threat Model Report Generation",
                        description="The process outputs the generated threat model report in the specified formats (Markdown, JSON, SARIF).",
                        destination_uuid=UUID("f3471d37-7621-4979-b23f-e09149828f8e"),
                        data_type="Threat model report",
                        direction="outgoing",
                    ),
                ],
                input_data=[],
                output_data=[],
            )
        ],
        trust_boundaries=[
            TrustBoundary(
                uuid=UUID("3c4d5e6f-7890-12ab-cdef-3456789012cd"),
                name="User Interaction Trust Boundary",
                description="This boundary encompasses the interactions between users and the Let's Threat Model tool, ensuring that user inputs and outputs are managed securely.",
                component_uuids=[
                    UUID("1b2c3d4e-5678-90ab-cdef-1234567890ab"),
                    UUID("2b3c4d5e-6789-01ab-cdef-2345678901bc"),
                ],
            )
        ],
    )


@pytest.mark.agent
async def test_extract_per_file(
    temp_test_dir, make_df, llm_model, expected_component_delta
):
    agent = ExtractorAgent(directory=temp_test_dir, model=llm_model)

    file = File(
        file_path="README.md",
        justification="Contains project overview and setup instructions.",
    )

    delta: Optional[ComponentDelta] = await agent.extract_per_file(
        file=file, current_report=make_df()
    )

    expected = expected_component_delta

    assert delta is not None

    pred_json = delta.model_dump_json()
    ref_json = expected.model_dump_json()

    eval_chain = ScoreStringEvalChain.from_llm(llm=llm_model)
    result = await eval_chain.aevaluate_strings(
        prediction=pred_json, reference=ref_json, input=""
    )
    pprint(result)
    assert (
        "better" not in result.lower()
    ), f"LLM judged the generated output inferior: {result}"
