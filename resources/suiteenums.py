# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Enums for use with the Certificate Management Protocol.

These Enums make the test cases more readable for users of the test suite and facilitate
comparisons and switches in the CMP protocol handling code.
"""

import enum
from typing import List, Union

from pyasn1.type import univ
from pyasn1_alt_modules import rfc9480

from pq_logic.tmp_oids import COMPOSITE_SIG03_OID_2_NAME, COMPOSITE_SIG04_OID_2_NAME
from resources.asn1_structures import PKIMessageTMP
from resources.exceptions import UnknownOID
from resources.oidutils import (
    PQ_SIG_OID_2_NAME,
    SYMMETRIC_PROT_ALGO,
    TRAD_SIG_OID_2_NAME,
    id_KemBasedMac,
)


class ProtectionAlgorithm(enum.Enum):
    """Identifiers for ProtectionAlgorithm options used in a PKIMessage."""

    HMAC = enum.auto()  # default sha256
    PBMAC1 = enum.auto()
    PASSWORD_BASED_MAC = enum.auto()
    AES_GMAC = enum.auto()  # default sha256
    SIGNATURE = enum.auto()
    DH = enum.auto()
    RSASSA_PSS = enum.auto()  # default sha256
    KMAC = enum.auto()  # default shake128

    @classmethod
    def get_names_lowercase(cls):
        """Return the names of all enum members in lowercase."""
        return [member.name.lower() for member in cls]

    @staticmethod
    def get(value: str) -> "ProtectionAlgorithm":
        """Return the ProtectionAlgorithm enum member that matches the provided value (case-insensitive).

        Args:
        ----
            value (str): The name of the enum member to get.

        Returns:
        -------
            ProtectionAlgorithm: The corresponding enum member.

        Raises:
        ------
            ValueError: If the value does not match any enum member.

        """
        value_upper = value.replace("-", "_").upper()

        try:
            return ProtectionAlgorithm[value_upper]
        except KeyError as err:
            raise ValueError(
                f"'{value}' is not a valid ProtectionAlgorithm. Available values are:"
                f" {', '.join(ProtectionAlgorithm.get_names_lowercase())}."
            ) from err


class KeyUsageStrictness(enum.Enum):
    """Strictness for the validation for a x509.Certificate."""

    NONE = 0  # no checks.
    LAX = 1  # if present is checked
    STRICT = 2  # has to be present and has to include the provided value.
    ABS_STRICT = 3  # must be equal.

    @staticmethod
    def get(value: Union[str, int]) -> "KeyUsageStrictness":
        """Retrieve the corresponding `KeyUsageStrictness` enum member based on an integer or string input.

        :param value: The strictness level as integer or string (0-3) or matching names ("NONE","LAX",
        "STRICT", "ABS_STRICT").
        :return: The corresponding `KeyUsageStrictness` enum object.
        :raises ValueError: If `value` is not a valid strictness level, an error is raised with
                        the list of allowed values.
        """
        if isinstance(value, str):
            if value.isdigit():
                return KeyUsageStrictness(int(value))

            if value.upper() in KeyUsageStrictness.__members__:
                return KeyUsageStrictness[value.upper()]

        if isinstance(value, int):
            if value in [item.value for item in KeyUsageStrictness]:
                return KeyUsageStrictness(value)

        allowed_values = ", ".join([f"{item.name} ({item.value})" for item in KeyUsageStrictness])
        raise ValueError(
            f"The provided value: {value} is not a valid value for `KeyUsageStrictness`. "
            f"Allowed values are: {allowed_values}."
        )


class NegCertConfTypes(enum.Enum):
    """Negative Patching of the certConf PKIMessage."""

    HASH_VERSION = "hash_version"  # needs to be version 3 if different hash_alg is used.
    MULTIPLE_CERT_STATUS = "multiple_cert_status"
    INVALID_CERT_HASH = "invalid_cert_hash"
    NO_CERT_HASH = "no_cert_hash"
    BAD_HASH_SIZE = "bad_hash_size"
    CERT_REQ_ID = "cert_req_id"
    NEG_STATUS = "neg_status"
    RECIP_NONCE = "recipNonce"
    TRANSACTION_ID = "transactionID"
    IMPLICIT_CONFIRM_VALUE = "ImplicitConfirmValue"
    FAIL_INFO_ACCEPTED_STATUS = "fail_info_accepted_status"
    ACCEPT_EE_REJECTION = "accept_ee_rejection"
    DIFFERENT_TRANSACTION_ID = "different_transactionID"
    DIFFERENT_RECIP_NONCE = "different_recipNonce"
    NO_RECIP_NONCE = "no_recipNonce"
    IMPLICIT_CONFIRM = "implicit_confirm"


class NameCompareTypes(enum.Enum):
    """Identifiers the mode to compare two `pyasn1` names."""

    STRICT = "strict"
    WITHOUT_TAG = "without_tag"
    CONTAINS = "contains"
    CONTAINS_SEQ = "contains_seq"


class GeneralInfoOID(enum.Enum):  #
    """Defines the Support OIDs general messages for the PKIMessage."""

    CA_PROT_ENC_CERT = rfc9480.id_it_caProtEncCert
    SIGN_KEY_PAIR_TYPES = rfc9480.id_it_signKeyPairTypes
    ENC_KEY_PAIR_TYPES = rfc9480.id_it_encKeyPairTypes
    ENC_KEY_AGREEMENT_TYPES = rfc9480.id_it_keyPairParamReq
    PREF_SYM_ALG = rfc9480.id_it_preferredSymmAlg
    CA_CERTS = rfc9480.id_it_caCerts
    CERT_REQ_TEMPLATE = rfc9480.id_it_certReqTemplate
    ROOT_CA_CERT_UPDATE = rfc9480.id_it_rootCaKeyUpdate
    CURRENT_CRL = rfc9480.id_it_currentCRL
    CRL_STATUS_LIST = rfc9480.id_it_crlStatusList
    REV_PASSPHRASE = rfc9480.id_it_revPassphrase
    SUPPORTED_LANG_TAGS = rfc9480.id_it_suppLangTags
    ORIG_PKI_MESSAGE = rfc9480.id_it_origPKIMessage

    @classmethod
    def get_names_lowercase(cls) -> List[str]:
        """Return the names of all enum members in lowercase."""
        return [member.name.lower() for member in cls]

    @classmethod
    def get_oid(cls, name: str) -> univ.ObjectIdentifier:
        """
        Get the ObjectIdentifier for a given stringified name.

        :param name: The stringified name of the OID (e.g., "CA_CERTS").
        :return: The corresponding ObjectIdentifier.
        :raises ValueError: If the name does not match any known OID.
        """
        try:
            return cls[name.upper()].value
        except KeyError:
            raise ValueError(  # pylint: disable=raise-missing-from
                f"Unknown OID name: `{name}` supported are: {', '.join(cls.get_names_lowercase())}"
            )

    @classmethod
    def get_name(cls, oid: univ.ObjectIdentifier) -> str:
        """Get the stringified name for a given ObjectIdentifier.

        :param oid: The ObjectIdentifier to look up.
        :return: The corresponding stringified name.
        :raises ValueError: If the OID does not match any known name.
        """
        for item in cls:
            if item.value == oid:
                return item.name
        raise ValueError(f"Unknown ObjectIdentifier: {oid}")


class ProtectedType(enum.Enum):
    """All possible supported types for the `protectedAlg` field in a PKIMessage."""

    TRAD_SIGNATURE = "trad_sig"
    KEM = "kem_based_mac"
    DH = "dh_based_mac"
    MAC = "mac"
    PQ_SIG = "pq-sig"
    COMPOSITE_SIG = "composite-sig"

    @classmethod
    def get_protection_type(
        cls, value: Union[str, univ.ObjectIdentifier, rfc9480.AlgorithmIdentifier, PKIMessageTMP]
    ) -> "ProtectedType":
        """Retrieve the protection type based on the provided value."""
        if isinstance(value, str):
            if value.lower() in cls.__dict__.values():
                return getattr(cls, value.upper())
            raise ValueError(
                f"'{value}' is not a valid protection type. Available values are: {', '.join(cls.__dict__.values())}."
            )
        elif isinstance(value, rfc9480.AlgorithmIdentifier):
            return cls.get_protection_type(value["algorithm"])

        elif isinstance(value, univ.ObjectIdentifier):
            oid = value
            if oid == id_KemBasedMac:
                return cls.KEM
            if oid == rfc9480.id_DHBasedMac:
                return cls.DH
            if oid in SYMMETRIC_PROT_ALGO:
                return cls.MAC
            if oid in TRAD_SIG_OID_2_NAME:
                return cls.TRAD_SIGNATURE
            if oid in PQ_SIG_OID_2_NAME:
                return cls.PQ_SIG
            if oid in COMPOSITE_SIG04_OID_2_NAME or oid in COMPOSITE_SIG03_OID_2_NAME:
                return cls.COMPOSITE_SIG
            raise UnknownOID(oid, "The OID is not supported, to retrieve the protection type from.")

        elif isinstance(value, PKIMessageTMP):
            if not value["header"]["protectionAlg"].isValue:
                raise ValueError("The `protectedAlg` field is not set in the PKIMessage.")
            return cls.get_protection_type(value["header"]["protectionAlg"]["algorithm"])
        else:
            raise TypeError(f"Unsupported type: {type(value)}")
