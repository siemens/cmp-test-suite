# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Utility to copy pyasn1 object values into another object."""

import copy
from typing import Optional

from pyasn1.codec.der import decoder, encoder
from pyasn1.type import namedtype, tag, univ
from pyasn1_alt_modules import rfc5280, rfc5652, rfc6402
from robot.api.deco import not_keyword


@not_keyword
def copy_subject_public_key_info(
    target: rfc5280.SubjectPublicKeyInfo, filled_sub_pubkey_info: rfc5280.SubjectPublicKeyInfo
) -> rfc5280.SubjectPublicKeyInfo:
    """Copy the contents of one `pyasn1` `SubjectPublicKeyInfo` object into another.

    :param target: The `SubjectPublicKeyInfo` structure to populate.
    :param filled_sub_pubkey_info: The existing `SubjectPublicKeyInfo` object with data to copy.
    :return: The populated `SubjectPublicKeyInfo` structure.
    """
    alg_id, rest1 = decoder.decode(
        encoder.encode(filled_sub_pubkey_info["algorithm"]), asn1Spec=rfc5280.AlgorithmIdentifier()
    )
    sub_pub_key, rest2 = decoder.decode(
        encoder.encode(filled_sub_pubkey_info["subjectPublicKey"]), asn1Spec=univ.BitString()
    )

    if rest1 != b"":
        raise ValueError(
            "The decoding of 'algorithm' field inside the `SubjectPublicKeyInfo` structure had a remainder!"
        )

    if rest2 != b"":
        raise ValueError(
            "The decoding of 'subjectPublicKey' field inside the `SubjectPublicKeyInfo` structure had a remainder!"
        )

    target["algorithm"] = alg_id
    target["subjectPublicKey"] = sub_pub_key
    return target


@not_keyword
def copy_name(target: rfc5280.Name, filled_name: rfc5280.Name) -> rfc5280.Name:
    """Copy the contents of one `pyasn1` `Name` object into another.

    :param target: The `Name` structure to populate.
    :param filled_name: The existing `Name` object with data to copy.
    :return: The populated `Name` structure.
    """
    der_data = encoder.encode(filled_name["rdnSequence"])
    rdn, rest = decoder.decode(der_data, asn1Spec=rfc5280.RDNSequence())

    if rest != b"":
        raise ValueError("The decoding of 'rdnSequence' field inside the `Name` structure had a remainder!")

    target = target.setComponentByName("rdnSequence", rdn)
    return target


@not_keyword
def copy_validity(
    filled_validity: rfc5280.Validity,
    target: Optional[rfc5280.Validity] = None,
) -> rfc5280.Validity:
    """Copy the contents of one `pyasn1` `Validity` object into another.

    :param target: The `Validity` structure to populate.
    :param filled_validity: The existing `Validity` object with data to copy.
    :return: The populated `Validity` structure.
    """
    not_before_type = filled_validity["notBefore"].getName()
    not_before = filled_validity["notBefore"][not_before_type].asDateTime

    not_after_type = filled_validity["notAfter"].getName()
    not_after = filled_validity["notAfter"][not_after_type].asDateTime

    if target is None:
        target = rfc5280.Validity()

    target["notBefore"][not_before_type].fromDateTime(copy.copy(not_before))
    target["notAfter"][not_after_type].fromDateTime(copy.copy(not_after))
    return target


@not_keyword
def copy_csr(
    filled_csr: rfc6402.CertificationRequest, target: Optional[rfc6402.CertificationRequest] = None
) -> rfc6402.CertificationRequest:
    """Copy the contents of one `CertificationRequest` object into another.

    :param target: The `CertificationRequest` structure to populate.
    :param filled_csr: The existing `CertificationRequest` object to copy.
    :return: The populated `CertificationRequest` structure.
    """
    der_data = encoder.encode(filled_csr["certificationRequestInfo"])

    obj = univ.Sequence(
        componentType=namedtype.NamedTypes(
            namedtype.NamedType("version", univ.Integer()),
            namedtype.NamedType("subject", rfc5280.Name()),
            namedtype.NamedType(
                "subjectPublicKeyInfo",
                univ.Sequence(
                    componentType=namedtype.NamedTypes(
                        namedtype.NamedType("algorithm", rfc5280.AlgorithmIdentifier()),
                        namedtype.NamedType("subjectPublicKey", univ.BitString()),
                    )
                ),
            ),
            namedtype.NamedType(
                "attributes",
                univ.SetOf(componentType=rfc5652.Attribute()).subtype(  # type: ignore
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
                ),
            ),
        )
    )
    csr_req_info = decoder.decode(der_data, asn1Spec=obj)[0]

    signature = decoder.decode(encoder.encode(filled_csr["signature"]), asn1Spec=univ.BitString())[0]
    der_data = encoder.encode(filled_csr["signatureAlgorithm"])
    sig_alg_id = decoder.decode(der_data, asn1Spec=rfc5280.AlgorithmIdentifier())[0]

    if target is None:
        target = rfc6402.CertificationRequest()

    target["certificationRequestInfo"] = csr_req_info
    target["signature"] = signature
    target["signatureAlgorithm"] = sig_alg_id

    return target
