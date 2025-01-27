# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Contains Custom Exceptions for pq_logic."""

from abc import ABC
from typing import List, Optional, Union

from pyasn1.type import univ
from pyasn1_alt_modules import rfc9480

from resources.oid_mapping import may_return_oid_to_name


class CMPTestSuiteError(Exception, ABC):
    """Base class for CMP Test Suite errors."""

    pass


class InvalidKeyCombination(CMPTestSuiteError):
    """Raised when a Hybrid key combination is invalid.

    As an example, a key combination for Chempat or Composite keys is invalid.
    """

    message: str


class UnknownOID(CMPTestSuiteError):
    """Raised when an OID is unknown."""

    def __init__(self, oid: univ.ObjectIdentifier, extra_info: str = ""):
        """Initialize the exception with the OID and extra information.

        :param oid: The OID that is unknown.
        :param extra_info: Additional information about the unknown OID.
        """
        oid = may_return_oid_to_name(oid)
        self.message = f"Unknown OID: {oid} {extra_info}"
        self.oid = oid
        super().__init__(self.message)


#########################
# CMP Protocol Errors
##########################


class BadAlg(CMPTestSuiteError):
    """Raised when the algorithm is not supported or not allowed to be used."""

    failinfo = "badAlg"
    bit_num = 0


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


class BadAsn1Data(CMPTestSuiteError):
    """Raised when the ASN.1 data has a remainder or ASN.1 data is incorrectly populated."""

    def __init__(self, message: str, remainder: Optional[bytes] = None, overwrite: bool = False):
        """Initialize the exception with the message.

        :param message: The message to display.
        """
        self.message = message

        if overwrite:
            super().__init__()
        else:
            r = "" if remainder is None else remainder.hex()
            super().__init__(f"Decoding the `{message}` structure had a remainder: {r}.")


class AlgorithmProfileError(CMPTestSuiteError):
    """Raised when an algorithm used are not in RFC9483 or violate the expected algorithm for LwCMP."""

    def __init__(self, message: str):
        """Initialize the exception with the message.

        :param message: The message to display.
        """
        self.message = message
        super().__init__(message)


class BadAlgError(CMPTestSuiteError):
    """Raised when the algorithm is not supported or not allowed to be used."""

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
