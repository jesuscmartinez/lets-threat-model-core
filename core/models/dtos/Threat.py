from pydantic import BaseModel, Field
from uuid import UUID
from core.models.enums import StrideCategory, Level
from typing import List
import uuid


# Input schema for creating
class AgentThreat(BaseModel):
    """
    Represents the input schema for creating a threat.

    This model captures all necessary details to define a security threat,
    including its name, detailed explanation, STRIDE security category, the
    affected components (both names and IDs), the attack vector, the severity
    of the impact, overall risk rating, and recommended mitigations.
    """

    name: str = Field(default="", description="The name of the identified threat.")
    description: str | None = Field(
        default=None, description="Detailed explanation of the threat."
    )
    stride_category: StrideCategory = Field(
        default=StrideCategory.DOS, description="STRIDE security category."
    )
    component_names: List[str] = Field(
        default_factory=list,
        description="The name of the component affected by the threat.",
    )
    component_uuids: List[UUID] = Field(
        default_factory=list,
        description="The UUID of the component affected by the threat.",
    )
    attack_vector: str = Field(default="", description="How the attack is executed.")
    impact_level: Level = Field(
        default=Level.LOW, description="The severity or impact of the attack."
    )
    risk_rating: Level = Field(
        default=Level.LOW, description="The overall risk assessment of the threat."
    )
    mitigations: List[str] = Field(
        default_factory=list,
        description="Recommended controls, countermeasures, or design changes. Where applicable, reference relevant standards or frameworks (e.g., OWASP, NIST, ISO) for implementing recommended controls.",
    )

    def __hash__(self):
        return hash(self.description)

    def __eq__(self, other):
        if not isinstance(other, AgentThreat):
            return False
        return self.description == other.description

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "name": "SQL Injection on Repo Creation",
                "description": "An attacker can inject malicious SQL queries in the 'Repo Name' input field to gain unauthorized access or manipulate database records.",
                "stride_category": "Tampering",
                "component_names": ["Postgres Database"],
                "component_uuids": ["uuid_3"],
                "attack_vector": "User injects SQL commands via a web form input",
                "impact_level": "High",
                "risk_rating": "Critical",
                "mitigations": [
                    "Use parameterized queries, ORM frameworks, and input validation to prevent SQL injection."
                ],
            }
        }


# Output schema for returning data
class Threat(AgentThreat):
    """
    Represents the output schema for a threat.

    This model extends the AgentThreat input schema by adding unique identifiers,
    linking the threat to the specific data flow report where it was detected.
    """

    uuid: UUID = Field(
        default_factory=uuid.uuid4, description="Unique identifier for the threat."
    )

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "uuid": "uuid_1",
                "data_flow_report_uuid": "uuid_1",
                "name": "SQL Injection on Repo Creation",
                "description": "An attacker can inject malicious SQL queries in the 'Repo Name' input field to gain unauthorized access or manipulate database records.",
                "stride_category": "Tampering",
                "component_names": ["Postgres Database"],
                "component_uuid": ["uuid_2"],
                "attack_vector": "User injects SQL commands via a web form input",
                "impact_level": "High",
                "risk_rating": "Critical",
                "mitigations": [
                    "Use parameterized queries, ORM frameworks, and input validation to prevent SQL injection."
                ],
            }
        }
