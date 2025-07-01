from typing import Dict, List, Optional
from pydantic import BaseModel


class Message(BaseModel):
    text: str


class ArtifactContent(BaseModel):
    text: Optional[str] = None
    binary: Optional[str] = None
    rendered: Optional[Dict] = None


class ArtifactLocation(BaseModel):
    uri: str
    uriBaseId: Optional[str] = None
    properties: Optional[Dict] = None


class Artifact(BaseModel):
    location: ArtifactLocation
    contents: Optional[ArtifactContent] = None
    encoding: Optional[str] = None
    mimeType: Optional[str] = None


class Region(BaseModel):
    startLine: int
    startColumn: Optional[int] = None


class PhysicalLocation(BaseModel):
    artifactLocation: ArtifactLocation
    region: Region


class Location(BaseModel):
    physicalLocation: PhysicalLocation


class Result(BaseModel):
    ruleId: str
    ruleIndex: int
    level: str
    kind: str
    message: Message
    locations: List[Location]
    properties: Optional[Dict] = None

    def __eq__(self, other):
        if not isinstance(other, Result):
            return NotImplemented
        return (
            self.ruleId == other.ruleId
            and self.message.text == other.message.text
            and self.locations == other.locations
        )

    def __hash__(self):
        return hash(
            (
                self.ruleId,
                self.message.text,
                tuple(
                    tuple(
                        (
                            loc.physicalLocation.artifactLocation.uri,
                            loc.physicalLocation.region.startLine,
                            loc.physicalLocation.region.startColumn,
                        )
                    )
                    for loc in self.locations
                ),
            )
        )


class Rule(BaseModel):
    id: str
    name: str
    shortDescription: Message
    fullDescription: Optional[Message] = None
    helpUri: Optional[str] = None


class ToolDriver(BaseModel):
    name: str
    informationUri: Optional[str] = None
    rules: List[Rule]


class Tool(BaseModel):
    driver: ToolDriver


class Run(BaseModel):
    tool: Tool
    results: List[Result]
    artifacts: Optional[List[Artifact]] = None


class SarifLog(BaseModel):
    version: str = "2.1.0"
    runs: List[Run]
