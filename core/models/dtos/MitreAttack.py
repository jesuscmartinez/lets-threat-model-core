from uuid import UUID, uuid4
from pydantic import BaseModel, Field
from typing import Optional


class AgentAttack(BaseModel):
    component: str = Field(
        ..., description="The name of the component affected by the attack."
    )

    component_uuid: UUID = Field(
        ...,
        description="The ID of the component affected by the attack.",
    )
    attack_tactic: str = Field(
        default="", description="The MITRE ATT&CK tactic relevant to this component."
    )
    technique_id: str = Field(
        default="", description="The MITRE ATT&CK technique ID (e.g., T1078)."
    )
    technique_name: str = Field(
        default="",
        description="The MITRE ATT&CK technique name (e.g., Valid Accounts).",
    )
    reason_for_relevance: str = Field(
        default="",
        description="Explanation of why this technique is relevant to the component.",
    )
    mitigation: str = Field(
        default="", description="Suggested mitigations for this technique."
    )
    url: Optional[str] = Field(
        default=None, description="Official ATT&CK URL for the technique."
    )
    is_subtechnique: bool = Field(
        default=False, description="True if this entry is a sub‑technique."
    )
    parent_id: Optional[str] = Field(
        default=None, description="ATT&CK ID of the parent technique, if any."
    )
    parent_name: Optional[str] = Field(
        default=None, description="Name of the parent technique, if any."
    )

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "component": "Edge API Gateway",
                "component_uuid": "uuid_1",
                "attack_tactic": "Execution",
                "technique_id": "T1059.003",
                "technique_name": "Windows Command Shell",
                "reason_for_relevance": "Attacker could spawn cmd.exe after uploading a web shell.",
                "mitigation": "Disable interactive shells and monitor command‑line events.",
                "url": "https://attack.mitre.org/techniques/T1059/003/",
                "is_subtechnique": True,
                "parent_id": "T1059",
                "parent_name": "Command and Scripting Interpreter",
            }
        }


class Attack(AgentAttack):
    """
    Represents an identified attack based on the MITRE ATT&CK framework.

    This model captures the details of an attack, including the component it affects,
    the relevant MITRE ATT&CK tactic and technique, the reason for its relevance, and
    any suggested mitigations.
    """

    uuid: UUID = Field(
        default_factory=uuid4, description="Unique identifier for the attack."
    )

    def __hash__(self):
        return hash(
            (
                self.component_uuid,
                self.attack_tactic,
                self.technique_id,
                self.technique_name,
                self.parent_id,
                self.is_subtechnique,
            )
        )

    def __eq__(self, other):
        if not isinstance(other, Attack):
            return False
        return (
            self.component_uuid == other.component_uuid
            and self.attack_tactic == other.attack_tactic
            and self.technique_id == other.technique_id
            and self.technique_name == other.technique_name
            and self.parent_id == other.parent_id
            and self.is_subtechnique == other.is_subtechnique
        )

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "component": "Customer-facing Web Portal",
                "component_uuid": "uuid_1",
                "uuid": "uuid_1",
                "attack_tactic": "Initial Access",
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "reason_for_relevance": "The portal exposes a vulnerable Spring Boot endpoint that can be exploited for RCE.",
                "mitigation": "Apply security patches promptly and deploy a WAF with virtual patching.",
                "url": "https://attack.mitre.org/techniques/T1190/",
                "is_subtechnique": False,
                "parent_id": None,
                "parent_name": None,
            }
        }
