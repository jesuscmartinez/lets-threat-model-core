from enum import Enum


class AuthnType(Enum):
    NONE = "None"
    PASSWORD = "Password"
    BASIC = "Basic"
    OAUTH = "OAuth"
    OTHER = "Other"

    def to_json(self):
        return self.value


class DataClassification(Enum):
    PUBLIC = "Public"
    INTERNAL = "Internal"
    CONFIDENTIAL = "Confidential"
    HIGHLY_CONFIDENTIAL = "Highly Confidential"

    def to_json(self):
        return self.value


class StrideCategory(Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFO_DISCLOSURE = "Information Disclosure"
    DOS = "Denial of Service"
    ELEVATION_OF_PRIVG = "Elevation of Privilege"

    def to_json(self):
        return self.value


class Level(Enum):
    INFO = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
