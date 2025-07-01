from pydantic import BaseModel, Field
from uuid import UUID, uuid4
from typing import List

from core.models.dtos.DataFlowReport import DataFlowReport
from core.models.dtos.Asset import Asset
from core.models.dtos.Repository import Repository


class CreateThreatModel(BaseModel):
    """
    Represents the input schema for creating a new threat model.

    This model captures all necessary information to define a threat model,
    including the name, summary, associated assets, repositories,
    data flow reports, and identified threats.
    """

    name: str
    summary: str
    asset: Asset
    repos: List[Repository]
    data_flow_reports: List[DataFlowReport]


# Output schema for returning data
class ThreatModel(CreateThreatModel):
    """
    Represents the output schema for returning a generated threat model.

    This model extends CreateThreatModel by adding a unique identifier (`id`),
    ensuring each generated threat model has a referenceable UUID.
    """

    uuid: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for the threat model.",
    )

    class Config:
        from_attributes = True
