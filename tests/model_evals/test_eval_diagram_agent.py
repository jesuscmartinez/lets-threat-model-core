import pytest
from core.agents.diagram_agent import DiagramAgent
from sentence_transformers import SentenceTransformer, util

pytestmark = pytest.mark.agent


@pytest.fixture
def reference_output():
    return """\
        graph TD
            subgraph Internal Trust Boundary
                B[Threat Modeling Process]
                C[(Threat Model Reports Store)]
                A1((User)) -->|"User Input"| B
                A2((GitHub Repository)) -->|"Repository Data"| B
                B -->|"Threat Model Report Generation"| C
                C -->|"Store Threat Model Report"| B
            end
            subgraph External Trust Boundary
                A1((User))
                A2((GitHub Repository))
            end
        """


async def test_mermaid_generation_regression(
    llm_model, data_flow_report_full, reference_output
):
    agent = DiagramAgent(model=llm_model)
    state = {"data_flow_report": data_flow_report_full}

    result = agent.generate_mermaid_dataflow_diagram(state)
    output = result["mermaid_diagram"]

    print(f"LLM Output:\n{output}")

    print(f"Reference Output:\n{reference_output}")

    # Use CodeBERT locally for structural DSL similarity
    model_emb = SentenceTransformer("microsoft/codebert-base")
    emb_out = model_emb.encode(output, convert_to_tensor=True)
    emb_ref = model_emb.encode(reference_output, convert_to_tensor=True)
    score = util.cos_sim(emb_out, emb_ref).item()

    print(f"Local CodeBERT similarity: {score:.3f}")
    # Assert high similarity between generated and reference diagrams
    assert score >= 0.7, f"CodeBERT similarity too low: {score:.3f}"
