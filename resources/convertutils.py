# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Needs extra logic to not make the code to big for typing rules.

So here are ensure types so not everywhere needs to be typing checks.
"""

import datetime
from typing import Any, Optional, Union

from cryptography.hazmat.primitives import serialization
from pq_logic.keys.abstract_composite import AbstractCompositePublicKey
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc4211, rfc5280, rfc9480
from robot.api.deco import not_keyword

from resources.copyasn1utils import copy_subject_public_key_info
from resources.typingutils import PrivateKeySig, PublicKey


@not_keyword
def ensure_is_sign_key(key: Any) -> PrivateKeySig:
    """Ensure provided key is allowed to sign."""
    if not isinstance(key, PrivateKeySig):
        raise ValueError(f"the provided key is not allowed to be used for signing: {type(key)}")
    return key


@not_keyword
def subjectPublicKeyInfo_from_pubkey(
    public_key: PublicKey,
    target: Optional[rfc5280.SubjectPublicKeyInfo] = None,
    use_rsa_pss: bool = False,
    use_pre_hash: bool = False,
) -> rfc5280.SubjectPublicKeyInfo:
    """Convert a `PublicKey` object to a `rfc5280.SubjectPublicKeyInfo` structure.

    This function serializes a `PublicKey` object into DER format and decodes it to produce an
    `rfc5280.SubjectPublicKeyInfo` structure. Optionally, it can copy the decoded data
    into an existing `rfc5280.SubjectPublicKeyInfo` structure.

    :param public_key: The `PublicKey` object to convert.
    :param target: An optional existing `rfc5280.SubjectPublicKeyInfo` object to populate
    with the decoded data. If not provided, a new structure is created.
    :param use_rsa_pss: Whether RSA-PSS-Padding was used for signing. Only relevant for CompositeSigKeys.
    :param use_pre_hash: Whether the public key should be the pre-hash one. Only relevant for CompositeSigKeys.
    :return: An `rfc5280.SubjectPublicKeyInfo` structure containing the public key information.
    """
    if isinstance(public_key, AbstractCompositePublicKey):
        return public_key.to_spki(use_rsa_pss, use_pre_hash)

    der_data = public_key.public_bytes(
        encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    subject_public_key_info, _ = decoder.decode(der_data, asn1Spec=rfc5280.SubjectPublicKeyInfo())
    if target is not None:
        return copy_subject_public_key_info(target, subject_public_key_info)

    return subject_public_key_info


@not_keyword
def pyasn1_time_obj_to_py_datetime(asn1_time: rfc5280.Time) -> datetime.datetime:
    """Convert a `pyasn1` `Time` object into a Python `datetime` object.

    :param asn1_time: A `pyasn1` `Time` object representing either `UTCTime` or `GeneralizedTime`.
    :return: A `datetime.datetime` object representing the corresponding date and time.
    """
    time_obj = asn1_time[asn1_time.getName()].asDateTime
    return time_obj


@not_keyword
def validity_to_optional_validity(validity_obj: rfc5280.Validity) -> rfc4211.OptionalValidity:
    """Prepare the `pyasn1` `OptionalValidity` object from a `Validity` object.

    :param validity_obj: The object to copy the data from.
    :return: The tagged object `OptionalValidity` object
    """
    optional_validity = rfc4211.OptionalValidity().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4)
    )

    before_type = validity_obj["notBefore"].getName()
    after_type = validity_obj["notAfter"].getName()

    not_before_py = pyasn1_time_obj_to_py_datetime(validity_obj["notBefore"])
    not_after_py = pyasn1_time_obj_to_py_datetime(validity_obj["notAfter"])

    not_before = rfc5280.Time().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
    not_before[before_type] = not_before[before_type].fromDateTime(not_before_py)
    optional_validity["notBefore"] = not_before

    not_after = rfc5280.Time().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
    not_after[after_type] = not_after[after_type].fromDateTime(not_after_py)
    optional_validity["notAfter"] = not_after

    return optional_validity


@not_keyword
def copy_asn1_certificate(
    cert: rfc9480.Certificate, target: Optional[rfc9480.Certificate] = None
) -> rfc9480.CMPCertificate:
    """Copy the fields of a pyasn1 certificate structure into a new or provided `CMPCertificate` object.

    :param cert: The source pyasn1 `Certificate` to copy.
    :param target:An optional pyasn1 `CMPCertificate` object to populate with the extracted fields.
    If not provided, a new `CMPCertificate` is created.
    :return: The populated pyasn1 `CMPCertificate` object containing the copied fields.
    """
    tbs_certificate = encoder.encode(cert.getComponentByName("tbsCertificate"))
    signature_algorithm = encoder.encode(cert.getComponentByName("signatureAlgorithm"))
    signature = encoder.encode(cert.getComponentByName("signature"))

    if target is None:
        target = rfc9480.CMPCertificate()

    decoded_signature, _ = decoder.decode(signature, asn1spec=univ.BitString())

    target.setComponentByName("tbsCertificate", decoder.decode(tbs_certificate, asn1Spec=rfc5280.TBSCertificate())[0])
    target.setComponentByName(
        "signatureAlgorithm", decoder.decode(signature_algorithm, asn1Spec=rfc5280.AlgorithmIdentifier())[0]
    )
    target.setComponentByName("signature", decoded_signature)
    return target  # type: ignore


@not_keyword
def str_to_int(value: Union[str, int]) -> int:
    """Convert a given string or integer input to an integer.

    :param value: The value to convert, which can be a string or an integer.
    :return: The converted integer.
    :raises ValueError: If the input is neither a valid integer string nor an integer.
    """
    if isinstance(value, str) and value.replace("-", "", 1).isdigit():
        return int(value)
    if isinstance(value, int):
        return value
    raise ValueError(f"Input must be a valid integer or a string representing an integer. Received: {type(value)}")


@not_keyword
def str_to_bytes(value: Union[str, bytes]) -> bytes:
    """Convert a given string or byte input to bytes.

    :param value: The value to convert:
           - If the input is already bytes, it is returned unchanged.
           - if it starts with "0x" and interpreted as hex and converts it to bytes.
           - Otherwise, encodes the string in UTF-8 format.
    :return: The converted bytes object.
    :raises ValueError: If the input is neither a string nor bytes.
    """
    if isinstance(value, str):
        if value.startswith("0x"):
            return bytes.fromhex(value[2:])
        return value.encode("utf-8")
    if isinstance(value, bytes):
        return value
    raise ValueError(f"Input must be of type 'str' or 'bytes'. Received: {type(value)}")
