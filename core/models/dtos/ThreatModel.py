from pydantic import BaseModel
from uuid import UUID
from typing import List, Optional, Dict, Any
from core.models.dtos.DataFlowReport import DataFlowReport
from core.models.dtos.Threat import Threat
from core.models.dtos.Asset import Asset
from core.models.dtos.Repository import Repository


class CreateThreatModel(BaseModel):
    name: str
    summary: str
    asset: Asset
    repos: List[Repository]
    data_flow_diagrams: List[str]
    data_flow_reports: List[DataFlowReport]
    threats: List[Threat]


# Output schema for returning data
class ThreatModel(CreateThreatModel):
    id: UUID

    class Config:
        from_attributes = True
