from core.services.sarif_services import (
    get_threat_results,
    get_attack_results,
    generate_sarif_log_with_om,
    sarif_log_to_schema_dict,
)
from sarif_om import SarifLog


def test_get_threat_results(data_flow_report, threat):
    results = get_threat_results(data_flow_report)
    # One result per threat
    assert isinstance(results, list)
    assert len(results) == 1
    result = results[0]
    # Check rule_id uses STRIDE and threat category name
    assert result.rule_id == f"STRIDE-{threat.stride_category.name}"
    # Check message text includes threat name and vector
    text = result.message.text
    assert f"#{threat.name}" in text
    assert threat.attack_vector in text
    # Check properties include id and attack_vector
    props = result.properties
    assert props["id"] == str(threat.uuid)
    assert props["attack_vector"] == threat.attack_vector


def test_get_attack_results(data_flow_report, attack):
    results = get_attack_results(data_flow_report)
    # One result per attack
    assert isinstance(results, list)
    assert len(results) == 1
    result = results[0]
    # Check rule_id is MITRE
    assert result.rule_id == "MITRE"
    # Check message text includes technique and tactic
    text = result.message.text
    assert attack.attack_tactic in text
    assert attack.technique_name in text
    # Check properties include technique_id and mitigation
    props = result.properties
    assert props["technique_id"] == attack.technique_id
    assert props["mitigation"] == attack.mitigation


def test_generate_sarif_log_with_om(threat_model):
    sarif_log = generate_sarif_log_with_om(threat_model)
    assert isinstance(sarif_log, SarifLog)
    # Convert to dict to inspect
    sarif_dict = sarif_log_to_schema_dict(sarif_log)
    assert sarif_dict["version"] == "2.1.0"
    runs = sarif_dict.get("runs", [])
    assert isinstance(runs, list)
    assert len(runs) == 1
    run = runs[0]
    # Check results count equals threats + attacks
    total_issues = sum(
        len(df.threats) + len(df.attacks) for df in threat_model.data_flow_reports
    )
    assert len(run["results"]) == total_issues
    # Check artifacts list exists
    assert "artifacts" in run
    assert isinstance(run["artifacts"], list)


def test_sarif_log_to_schema_dict_basic():
    # Test recursion on list, dict, and scalars
    src = {
        "a": [1, {"b": 2}],
        "c": "string",
    }
    out = sarif_log_to_schema_dict(src)
    assert isinstance(out, dict)
    assert out == src
