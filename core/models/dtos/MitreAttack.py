from uuid import UUID
import uuid
from pydantic import BaseModel, Field
from typing import Optional


class AgentAttack(BaseModel):
    component_id: UUID = Field(
        ..., description="The ID of the component affected by the attack."
    )
    attack_tactic: str = Field(
        ..., description="The MITRE ATT&CK tactic relevant to this component."
    )
    technique_id: str = Field(
        ..., description="The MITRE ATT&CK technique ID (e.g., T1078)."
    )
    technique_name: str = Field(
        ..., description="The MITRE ATT&CK technique name (e.g., Valid Accounts)."
    )
    reason_for_relevance: str = Field(
        ...,
        description="Explanation of why this technique is relevant to the component.",
    )
    mitigation: str = Field(..., description="Suggested mitigation for this technique.")

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "component_id": "uuid_1",
                "attack_tactic": "Initial Access",
                "technique_id": "T1078",
                "technique_name": "Valid Accounts",
                "reason_for_relevance": "This technique allows attackers to gain initial access using valid credentials.",
                "mitigation": "Implement multi-factor authentication and monitor for unusual login patterns.",
            }
        }


class Attack(AgentAttack):
    """
    Represents an identified attack based on the MITRE ATT&CK framework.

    This model captures the details of an attack, including the component it affects,
    the relevant MITRE ATT&CK tactic and technique, the reason for its relevance, and
    any suggested mitigations.
    """

    id: UUID = Field(
        default_factory=uuid.uuid4, description="Unique identifier for the attack."
    )

    def __hash__(self):
        return hash(
            (
                self.component_id,
                self.attack_tactic,
                self.technique_id,
                self.technique_name,
            )
        )

    def __eq__(self, other):
        if not isinstance(other, Attack):
            return False
        return (
            self.component_id == other.component_id
            and self.attack_tactic == other.attack_tactic
            and self.technique_id == other.technique_id
            and self.technique_name == other.technique_name
        )

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "component_id": "uuid_1",
                "attack_tactic": "Initial Access",
                "technique_id": "T1078",
                "technique_name": "Valid Accounts",
                "reason_for_relevance": "This technique allows attackers to gain initial access using valid credentials.",
                "mitigation": "Implement multi-factor authentication and monitor for unusual login patterns.",
            }
        }
