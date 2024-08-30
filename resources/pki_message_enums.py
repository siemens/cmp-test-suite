"""
This module creates an enum for the CMP protocol,
making test cases more readable for users of the test suite.
"""

from enum import Enum

class PKIStatus(Enum):
    accepted = 0
    grantedWithMods = 1
    rejection = 2
    waiting = 3
    revocationWarning = 4
    revocationNotification = 5
    keyUpdateWarning = 6