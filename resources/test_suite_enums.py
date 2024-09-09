"""Defines Enums for use with the Certificate Management Protocol.
These Enums make the test cases more readable for users of the test suite and facilitate comparisons and switches in the CMP protocol handling code.
"""

from enum import Enum, auto


# The values are as described in RFC 4210 CMP, Section 5.2.3, and RFC 9480 CMP Updates, Appendix A.
class PKIStatus(Enum):
    accepted = 0
    grantedWithMods = 1
    rejection = 2
    waiting = 3
    revocationWarning = 4
    revocationNotification = 5
    keyUpdateWarning = 6


# used for the switch-cases on the PKIMessage ProtectionAlgorithm
class ProtectionAlgorithm(Enum):
    HMAC = auto()
    HMAC_sha256 = auto()
    PBMAC1 = auto()
    PASSWORD_BASED_MAC = auto()
    AES_GMAC = auto()  # default 256
    SIGNATURE = auto()
    DH = auto()
    CERT = auto()

    @classmethod
    def get_names_lowercase(cls):
        """Return the names of all enum members in lowercase."""
        return [member.name.lower() for member in cls]

    @staticmethod
    def get(value: str) -> "ProtectionAlgorithm":
        """Return the ProtectionAlgorithm enum member that matches the provided value.
        The matching is case-insensitive.

        Args:
            value (str): The name of the enum member to get.

        Returns:
            ProtectionAlgorithm: The corresponding enum member.

        Raises:
            ValueError: If the value does not match any enum member.

        """
        value_upper = value.replace("-", "_").upper()

        try:
            return ProtectionAlgorithm[value_upper]
        except KeyError:
            raise ValueError(
                f"'{value}' is not a valid ProtectionAlgorithm. Available values are:"
                f" {', '.join(ProtectionAlgorithm.get_names_lowercase())}."
            )
