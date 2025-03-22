# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Contains Custom Exceptions for pq_logic."""

from abc import ABC
from typing import List, Optional, Union

from cryptography.exceptions import InvalidSignature
from pyasn1.type import univ
from pyasn1_alt_modules import rfc9480

from resources.oid_mapping import may_return_oid_to_name


class CMPTestSuiteError(Exception, ABC):
    """Base class for CMP Test Suite errors."""

    failinfo: str = "systemFailure"
    error_details: List[str]
    bit_num: int = -1

    def __init__(self, message: str, extra_details: Optional[Union[List[str], str]] = None):
        """Initialize the exception with the message.

        :param message: The message to display.
        :param extra_details: Additional details about the error.
        """
        self.message = message

        if extra_details is not None:
            if isinstance(extra_details, str):
                self.error_details = [extra_details]

        self.error_details = extra_details or []
        super().__init__(message)

    @classmethod
    def get_failinfo(cls) -> str:
        """Return the failinfo."""
        return cls.failinfo

    @classmethod
    def get_error_details(cls) -> List[str]:
        """Return the error details."""
        return cls.error_details


#########################
# CMP Test Suite Errors
##########################


class InvalidKeyCombination(CMPTestSuiteError):
    """Raised when a Hybrid key combination is invalid.

    As an example, a key combination for Chempat or Composite keys is invalid.
    """

    pass


class UnknownOID(CMPTestSuiteError):
    """Raised when an OID is unknown."""

    def __init__(self, oid: univ.ObjectIdentifier, extra_info: str = ""):
        """Initialize the exception with the OID and extra information.

        :param oid: The OID that is unknown.
        :param extra_info: Additional information about the unknown OID.
        """
        oid_name = may_return_oid_to_name(oid)
        self.message = f"Unknown OID: {oid_name}:{oid} {extra_info}"
        self.oid = oid
        super().__init__(self.message)


class AlgorithmProfileError(CMPTestSuiteError):
    """Raised when an algorithm used which is not in RFC9483 or violate the expected algorithm for LwCMP."""

    failinfo = "badAlg"

    def __init__(self, message: str):
        """Initialize the exception with the message.

        :param message: The message to display.
        """
        self.message = message
        super().__init__(message)


class InvalidAltSignature(InvalidSignature):
    """Raised when the alternative signature is invalid."""

    pass


#########################
# CMP Protocol Errors
##########################


class BadAlg(CMPTestSuiteError):
    """Raised when the algorithm is not supported or not allowed to be used."""

    failinfo = "badAlg"
    bit_num = 0


class BadMessageCheck(CMPTestSuiteError):
    """Raised when:

    - `senderKID` is invalid.
    - `PKIProtection` is invalid.
    - Signature protection, and the sender is not the subject of the certificate.
    - Could be used for MAC-protected message, if name not in "directoryName" choice.

    """

    failinfo = "badMessageCheck"
    bit_num = 1


class BadRequest(CMPTestSuiteError):
    """Raised when the request is invalid."""

    failinfo = "badRequest"
    bit_num = 2


class BadDataFormat(CMPTestSuiteError):
    """Raised when the ASN.1 data cannot be decoded."""

    failinfo = "badDataFormat"
    bit_num = 5

    def __init__(self, message: str):
        """Initialize the exception with the message.

        :param message: The message to display.
        """
        self.message = message
        super().__init__(f"Bad data format: {message}")


# This Exception is not in the protocol but would be more accurate.
class BadAsn1Data(CMPTestSuiteError):
    """Raised when the ASN.1 data has a remainder or ASN.1 data is incorrectly populated."""

    failinfo = "badDataFormat"
    bit_num = 5

    def __init__(self, message: str, remainder: Optional[bytes] = None, overwrite: bool = False):
        """Initialize the exception with the message.

        :param message: The message to display or just the structure name.
        :param remainder: The remainder of the ASN.1 data.
        :param overwrite: Raise the exception with the message only.
        """
        self.message = message

        if overwrite:
            super().__init__(message=message)
        else:
            r = "" if remainder is None else remainder.hex()
            super().__init__(f"Decoding the `{message}` structure had a remainder: {r}.")


class BadPOP(CMPTestSuiteError):
    """Raised when the Proof-of-Possession is invalid."""

    failinfo = "badPOP"
    bit_num = 9

    def __init__(self, message: str):
        """Initialize the exception with the message.

        :param message: The message to display.
        """
        self.message = message
        super().__init__(message)


class WrongIntegrity(CMPTestSuiteError):
    """Raised when the integrity of the message is wrong.

    Either expected MAC or signature protection.
    """

    failinfo = "wrongIntegrity"
    bit_num = 12


class BadCertTemplate(CMPTestSuiteError):
    """Raised when the certificate template is invalid."""

    failinfo = "badCertTemplate"
    bit_num = 19
    pass


class TransactionIdInUse(CMPTestSuiteError):
    """Raised when the transaction ID is already in use."""

    failinfo = "transactionIdInUse"
    bit_num = 21
    pass


class NotAuthorized(CMPTestSuiteError):
    """Raised when the user is not authorized to perform the action."""

    failinfo = "notAuthorized"
    bit_num = 23

    def __init__(self, message: str):
        """Initialize the exception with the message.

        :param message: The message to display.
        """
        self.message = message
        super().__init__(message)


def get_pki_error_message_from_exception(pki_message: rfc9480.PKIMessage, exception: CMPTestSuiteError):
    """Return a PKI Error message from the exception.

    Extract the information from the exception and create a error text and the correct failInfo bit.

    :param pki_message: The populated PKIMessage, which just needs the error message.
    :param exception: The exception.
    :return: The PKI error message.
    """
    raise NotImplementedError("Not implemented yet.")
