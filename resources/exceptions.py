# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Contains Custom Exceptions for pq_logic."""

from typing import List, Optional, Union

from cryptography.exceptions import InvalidSignature
from pyasn1.type import univ

from resources.oid_mapping import may_return_oid_to_name


class CMPTestSuiteError(Exception):
    """Base class for CMP Test Suite errors."""

    failinfo: str = "systemFailure"
    error_details: List[str]
    bit_num: int = 26

    def __init__(
        self, message: str, error_details: Optional[Union[List[str], str]] = None, failinfo: Optional[str] = None
    ):
        """Initialize the exception with the message.

        :param message: The message to display.
        :param error_details: Additional details about the error.
        """
        self.message = message
        self._failinfo = failinfo or self.failinfo
        self.error_details = []
        if error_details is not None:
            if isinstance(error_details, str):
                self.error_details = [error_details]

        self.error_details += error_details if error_details is not None else []
        super().__init__(message)

    def get_failinfo(self) -> str:
        """Return the failinfo."""
        return self._failinfo

    def get_error_details(self) -> List[str]:
        """Return the error details."""
        if isinstance(self.error_details, str):
            return [self.error_details]

        return self.error_details


class BadConfig(CMPTestSuiteError):
    """Raised when the configuration is invalid."""


#########################
# CMP Test Suite Errors
##########################


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


#########################
# CMP Protocol Errors
##########################


class BadAlg(CMPTestSuiteError):
    """Raised when the algorithm is not supported or not allowed to be used."""

    failinfo = "badAlg"
    bit_num = 0


class InvalidKeyCombination(BadAlg):
    """Raised when a Hybrid key combination is invalid.

    As an example, a key combination for Chempat or Composite keys is invalid.
    """


class BadMessageCheck(CMPTestSuiteError):
    """Raised when:

    - `senderKID` is invalid.
    - `PKIProtection` is invalid.
    - Signature protection, and the sender is not the subject of the certificate.
    - Could be used for MAC-protected message, if name not in "directoryName" choice.

    """

    failinfo = "badMessageCheck"
    bit_num = 1


class BadMacProtection(BadMessageCheck):
    """Raised when the MAC protection of a PKIMessage is invalid."""


class BadSignatureProtection(BadMessageCheck):
    """Raised when the signature protection of a PKIMessage is invalid."""


class BadRequest(CMPTestSuiteError):
    """Raised when the request is invalid."""

    failinfo = "badRequest"
    bit_num = 2


class BadValueBehavior(BadRequest):
    """Raised if MUST be absent values are set, which are not critical."""


class BadTime(CMPTestSuiteError):
    """Raised when the time is invalid.

    RFC9483 Section 3.6.4: "messageTime was not sufficiently close to the system time,
    as defined by local policy."
    """

    failinfo = "badTime"
    bit_num = 3


class BadCertId(CMPTestSuiteError):
    """Raised when the certificate is not known.

    RFC9483 Section 3.6.4: "A kur, certConf, or rr message references an unknown certificate."
    """

    failinfo = "badCertId"
    bit_num = 4


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


class InvalidKeyData(BadDataFormat):
    """Raised when the key cannot be loaded or decoded."""


# This Exception is not in the protocol but would be more accurate.
class BadAsn1Data(CMPTestSuiteError):
    """Raised when the ASN.1 data has a remainder or ASN.1 data is incorrectly populated."""

    failinfo = "badDataFormat"
    bit_num = 5

    def __init__(
        self,
        message: str,
        remainder: Optional[bytes] = None,
        overwrite: bool = False,
        error_details: Optional[Union[List[str], str]] = None,
        failinfo: str = "badDataFormat",
    ):
        """Initialize the exception with the message.

        :param message: The message to display or just the structure name.
        :param remainder: The remainder of the ASN.1 data.
        :param overwrite: Raise the exception with the message only.
        """
        self.message = message

        if overwrite:
            super().__init__(message=message, error_details=error_details, failinfo=failinfo)
        else:
            r = "" if remainder is None else remainder.hex()
            super().__init__(f"Decoding the `{message}` structure had a remainder: {r}.", error_details=error_details)


class WrongAuthority(CMPTestSuiteError):
    """Raised when the authority indicated in the request is different from the one creating the response token"""

    failinfo = "wrongAuthority"
    bit_num = 6


class BadPOP(CMPTestSuiteError):
    """Raised when the Proof-of-Possession is invalid.

    RFC9483 Section 3.6.4: "An ir/cr/kur/p10cr contains an invalid proof-of-possession."
    """

    failinfo = "badPOP"
    bit_num = 9


class BadAltPOP(CMPTestSuiteError):
    """Raised when the alternative Proof-of-Possession is invalid."""

    failinfo = "badPOP"
    bit_num = 9


class CertRevoked(CMPTestSuiteError):
    """Raised when the certificate is revoked."""

    failinfo = "certRevoked"
    bit_num = 10


class CertConfirmed(CMPTestSuiteError):
    """Raised when the certificate is already confirmed."""

    failinfo = "certConfirmed"
    bit_num = 11


class WrongIntegrity(CMPTestSuiteError):
    """Raised when the integrity of the message is wrong.

    Either expected MAC or signature protection.
    """

    failinfo = "wrongIntegrity"
    bit_num = 12


class BadRecipientNonce(CMPTestSuiteError):
    """Raised when the recipient nonce is invalid, missing or wrong value."""

    failinfo = "badRecipientNonce"
    bit_num = 13


class AddInfoNotAvailable(CMPTestSuiteError):
    """Raised when the additional information is needed to perform the action."""

    failinfo = "addInfoNotAvailable"
    bit_num = 17


class BadSenderNonce(CMPTestSuiteError):
    """Raised when the sender nonce is invalid, missing or wrong value."""

    failinfo = "badSenderNonce"
    bit_num = 18


class BadCertTemplate(CMPTestSuiteError):
    """Raised when the certificate template is invalid."""

    failinfo = "badCertTemplate"
    bit_num = 19


class SignerNotTrusted(CMPTestSuiteError):
    """Raised when the signer is unknown or not trusted."""

    failinfo = "signerNotTrusted"
    bit_num = 20


class TransactionIdInUse(CMPTestSuiteError):
    """Raised when the transaction ID is already in use."""

    failinfo = "transactionIdInUse"
    bit_num = 21


class UnsupportedVersion(CMPTestSuiteError):
    """Raised when the version is not supported."""

    failinfo = "unsupportedVersion"
    bit_num = 22


class NotAuthorized(CMPTestSuiteError):
    """Raised when the user is not authorized to perform the action."""

    failinfo = "notAuthorized"
    bit_num = 23


class DuplicateCertReq(CMPTestSuiteError):
    """Raised when the certificate request was already sent."""

    failinfo = "duplicateCertReq"
    bit_num = 26
