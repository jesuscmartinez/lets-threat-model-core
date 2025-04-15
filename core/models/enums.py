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


from enum import Enum


class StrideCategory(Enum):
    """
    STRIDE threat categories used in threat modeling.
    Each category represents a specific type of security threat.
    """

    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFO_DISCLOSURE = "Information Disclosure"
    DOS = "Denial of Service"
    ELEVATION_OF_PRIVG = "Elevation of Privilege"

    def to_json(self):
        return self.value

    @property
    def description(self) -> str:
        """
        Provides a human-readable description for each STRIDE category.
        """
        descriptions = {
            StrideCategory.SPOOFING: (
                "Spoofing refers to impersonating something or someone else. "
                "Attackers can spoof identities, devices, or services to gain unauthorized access."
            ),
            StrideCategory.TAMPERING: (
                "Tampering involves unauthorized modification of data or code. "
                "This can result in corrupted data, malicious behavior, or unauthorized actions."
            ),
            StrideCategory.REPUDIATION: (
                "Repudiation is the ability for users (legitimate or malicious) to deny their actions. "
                "Without proper logging and auditing, it’s difficult to prove actions took place."
            ),
            StrideCategory.INFO_DISCLOSURE: (
                "Information Disclosure is the unintended exposure of information to unauthorized parties. "
                "This can include data leaks, unprotected files, or insecure communication channels."
            ),
            StrideCategory.DOS: (
                "Denial of Service (DoS) makes a system or resource unavailable to its intended users. "
                "This can be due to resource exhaustion or malicious attacks aimed at disrupting service."
            ),
            StrideCategory.ELEVATION_OF_PRIVG: (
                "Elevation of Privilege allows an attacker to gain higher access levels than intended. "
                "This can lead to unauthorized actions, such as gaining administrative control."
            ),
        }
        return descriptions.get(self, "No description available.")

    @property
    def external_resource(self) -> str:
        """
        Provides an external reference link for each STRIDE category.
        These are public, well-documented resources.
        """
        resources = {
            StrideCategory.SPOOFING: (
                "https://owasp.org/www-community/attacks/Authentication_Bypass"
            ),
            StrideCategory.TAMPERING: (
                "https://owasp.org/www-community/attacks/Data_Tampering"
            ),
            StrideCategory.REPUDIATION: (
                "https://owasp.org/www-project-cheat-sheets/cheatsheets/Logging_Cheat_Sheet.html"
            ),
            StrideCategory.INFO_DISCLOSURE: (
                "https://owasp.org/www-community/attacks/Information_Leakage"
            ),
            StrideCategory.DOS: (
                "https://owasp.org/www-community/attacks/Denial_of_Service"
            ),
            StrideCategory.ELEVATION_OF_PRIVG: (
                "https://owasp.org/www-community/attacks/Privilege_Escalation"
            ),
        }
        return resources.get(self, "https://owasp.org/www-community/")

    def to_dict(self):
        """
        Returns a dictionary representation of the STRIDE category, including its description and resource link.
        """
        return {
            "category": self.value,
            "description": self.description,
            "resource": self.external_resource,
        }


class Level(Enum):
    INFO = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    @property
    def score(self) -> float:
        """
        Maps enum value to a representative CVSS-like numeric score for GitHub SARIF.
        """
        mapping = {
            Level.CRITICAL: 9.5,
            Level.HIGH: 8.0,
            Level.MEDIUM: 5.0,
            Level.LOW: 2.0,
            Level.INFO: 0.0,
        }
        return mapping[self]
