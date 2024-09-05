"""
Defines Enums for use with the Certificate Management Protocol.
These Enums make the test cases more readable for users of the test suite and facilitate comparisons and switches in the CMP protocol handling code.
"""

from enum import Enum


# The values are as described in RFC 4210 CMP, Page 32, and RFC 9480 CMP Updates, Pages 35 and 36.
class PKIStatus(Enum):
    accepted = 0
    grantedWithMods = 1
    rejection = 2
    waiting = 3
    revocationWarning = 4
    revocationNotification = 5
    keyUpdateWarning = 6
