from core.services.reports import generate_threat_model_report, process_files
from core.models.dtos.File import File
from tests.conftest import threat_model, tm_config


def test_process_files_no_files():
    title = "Reviewed"
    result = process_files(title, [])
    assert result == f"## {title}\nNo files flagged for {title}.\n\n"


def test_process_files_with_files():
    title = "Should Review"
    files = [
        File(file_path="a.txt", justification="Justification A"),
        File(file_path="b.py", justification="Justification B"),
    ]
    result = process_files(title, files)
    expected = (
        f"## {title}\n"
        "- **a.txt**: Justification A\n"
        "- **b.py**: Justification B\n\n"
    )
    assert result == expected


def test_generate_threat_model_report(tm_config, threat_model):

    report = generate_threat_model_report(tm_config, threat_model)
    assert "## Summary\nFull model summary" in report
    assert "## Asset Information" in report
    assert "## Repository Information" in report
    assert "## Data Flow Reports" in report
    assert "### Report TestRepo" in report
    assert "#### External Entities" in report
    assert "- **External1**: An external entity" in report
    assert "#### Processes" in report
    assert "#### Data Stores" in report
    assert "#### Trust Boundaries" in report
    assert "### ⚠️ ThreatOne" in report
    assert "**🎯 Attack Vector:**\nAttack vector info" in report
    assert "### 🔐 Technique A" in report
    assert "## Reviewed" in report
    assert "- **reviwed.py**: reviewed" in report

    assert "## Should Review" in report
    assert "- **should_review.py**: should be reviewed" in report

    assert "## Should Not Review" in report
    assert "- **should_not_review.py**: should not be reviewed" in report

    assert "## Could Review" in report
    assert "- **could_review.py**: could be reviewed" in report

    assert "## Could Not Review" in report
    assert "- **could_not_review.py**: Could not be reviewed" in report
