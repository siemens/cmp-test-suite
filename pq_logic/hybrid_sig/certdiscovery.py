# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""A Mechanism for X.509 Certificate Discovery.

https://datatracker.ietf.org/doc/draft-lamps-okubo-certdiscovery-05.html.
https://datatracker.ietf.org/doc/draft-lamps-okubo-certdiscovery/
"""

import logging
from typing import List, Optional

import requests
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import char, tag, univ
from pyasn1_alt_modules import rfc5280, rfc9480
from resources import certutils
from resources.certutils import check_is_cert_signer, verify_cert_chain_openssl
from resources.oidutils import CMS_COMPOSITE_OID_2_NAME

from pq_logic.hybrid_structures import OnRelatedCertificateDescriptor, RelatedCertificateDescriptor
from pq_logic.tmp_oids import id_ad_certDiscovery, id_ad_relatedCertificateDescriptor


def prepare_related_certificate_descriptor(
    url: str,
    other_cert: rfc9480.CMPCertificate = None,
    signature_algorithm: rfc5280.AlgorithmIdentifier = None,
    public_key_algorithm: rfc5280.AlgorithmIdentifier = None,
) -> rfc5280.GeneralName:
    """Prepare a `RelatedCertificateDescriptor` wrapped in an `AnotherName` structure.

    :param url: The URI for the secondary certificate.
    :param other_cert: The primary certificate to infer algorithms from.
    :param signature_algorithm: Signature algorithm to use.
    :param public_key_algorithm: Public key algorithm to use.
    :return: The populated `GeneralName` containing the descriptor.
    """
    other_name = OnRelatedCertificateDescriptor().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
    )
    gen_name = rfc5280.GeneralName()
    other_name["type-id"] = id_ad_relatedCertificateDescriptor

    val = RelatedCertificateDescriptor()
    val["uniformResourceIdentifier"] = char.IA5String(url)
    other_name["value"] = val

    if other_cert is not None:
        if signature_algorithm is None:
            signature_algorithm = other_cert["tbsCertificate"]["signature"]

        if public_key_algorithm is None:
            public_key_algorithm = other_cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]

    if signature_algorithm is not None:
        val["signatureAlgorithm"] = signature_algorithm.subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0), cloneValueFlag=True
        )

    if public_key_algorithm is not None:
        val["publicKeyAlgorithm"] = public_key_algorithm.subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1), cloneValueFlag=True
        )

    gen_name["otherName"] = other_name
    return gen_name


def prepare_subject_info_access_syntax_extension(
    url: str = "https://example.com/secondary_certificate.pem",
    critical: bool = False,
    signature_algorithm: Optional[rfc5280.AlgorithmIdentifier] = None,
    public_key_algorithm: Optional[rfc5280.AlgorithmIdentifier] = None,
    other_cert: Optional[rfc9480.CMPCertificate] = None,
) -> rfc5280.Extension:
    """Prepare a SubjectInfoAccessSyntax extension for certDiscovery.

    :param url: The location of the other associated certificate.
    :param critical: Whether the extension is critical.
    :param signature_algorithm: The signature algorithm to be included.
    :param public_key_algorithm: The public key algorithm to be included.
    :param other_cert: Optional. The primary certificate to infer algorithms from.
    :return: The populated `Extension`.
    """
    extension = rfc5280.Extension()

    sia = rfc5280.SubjectInfoAccessSyntax()
    access_description = rfc5280.AccessDescription()

    access_description["accessMethod"] = id_ad_certDiscovery

    access_description["accessLocation"] = prepare_related_certificate_descriptor(
        url=url,
        other_cert=other_cert,
        signature_algorithm=signature_algorithm,
        public_key_algorithm=public_key_algorithm,
    )

    sia.append(access_description)

    extension["extnID"] = rfc5280.id_pe_subjectInfoAccess
    # SHOULD be set to not critical.
    extension["critical"] = univ.Boolean(critical)
    extension["extnValue"] = univ.OctetString(encoder.encode(sia))

    return extension


def extract_sia_extension_for_cert_discovery(
    extension: rfc5280.Extension, index: Optional[int] = None
) -> RelatedCertificateDescriptor:
    """Parse a SubjectInfoAccess (SIA) extension to extract a RelatedCertificateDescriptor for certificate discovery.

    :param extension: An `Extension` object containing the SIA extension to parse.
    :param index: The index of the AccessDescription within the SubjectInfoAccessSyntax. Defaults to None.
    means that all entries are checked.
    :raises ValueError: If the `accessMethod` does not match `id_ad_certDiscovery` or the `type-id` does not
                        match `id_ad_relatedCertificateDescriptor`.
    :return: The extracted `RelatedCertificateDescriptor` object containing details such as
    the `uniformResourceIdentifier`, `signatureAlgorithm`, and `publicKeyAlgorithm`.
    """
    sia, _ = decoder.decode(extension["extnValue"].asOctets(), rfc5280.SubjectInfoAccessSyntax())

    if index is not None:
        access_description = sia[index]
        if access_description["accessMethod"] != id_ad_certDiscovery:
            raise ValueError("accessMethod should match id_ad_certDiscovery.")
    else:
        access_description = next((ad for ad in sia if ad["accessMethod"] == id_ad_certDiscovery), None)
        if access_description is None:
            raise ValueError("No access description with `id_ad_certDiscovery` found.")

    other_name = access_description["accessLocation"]["otherName"]

    if other_name["type-id"] != id_ad_relatedCertificateDescriptor:
        raise ValueError("The `type-id` should match `id_ad_relatedCertificateDescriptor`.")

    obj, _ = decoder.decode(other_name["value"], RelatedCertificateDescriptor())

    return obj


def get_cert_discovery_cert(uri: str) -> rfc9480.CMPCertificate:
    """Get the secondary certificate using the provided URI.

    :param uri: The URI of the secondary certificate.
    :return: The parsed certificate.
    :raise ValueError: If the fetching fails.
    """
    try:
        logging.info(f"Fetching secondary certificate from {uri}")
        response = requests.get(uri)
        response.raise_for_status()
        cert, rest = decoder.decode(response.content, rfc9480.CMPCertificate())
        if rest:
            raise ValueError("The decoding of the fetching certificate had a remainder.")
        return cert

    except requests.RequestException as e:
        raise ValueError(f"Failed to fetch secondary certificate: {e}")


def compare_alg_id_without_tag(first: rfc9480.AlgorithmIdentifier, second: rfc9480.AlgorithmIdentifier) -> bool:
    """Compare `AlgorithmIdentifier` without considering the tag.

    :param first: The first `AlgorithmIdentifier` to compare.
    :param second: The second `AlgorithmIdentifier` to compare.
    :return: `True` if both the OID and parameters match, `False` otherwise.
    """
    oid_first, params_first = first["algorithm"], first["parameters"]
    oid_second, params_second = second["algorithm"], second["parameters"]
    if oid_first != oid_second:
        return False

    if sum([params_first.isValue, params_second.isValue]) in [0, 2]:
        return params_first == params_second
    else:
        return False


def validate_alg_ids(other_cert: rfc9480.CMPCertificate, rel_cert_desc: RelatedCertificateDescriptor) -> None:
    """Validate that the algorithms in the RelatedCertificateDescriptor match those in the Secondary Certificate.

    :param other_cert: The Secondary Certificate as a CMPCertificate.
    :param rel_cert_desc: The RelatedCertificateDescriptor extracted from the Primary Certificate.
    :raises ValueError: If the algorithms do not match.
    """
    if rel_cert_desc["signatureAlgorithm"].isValue:
        if not compare_alg_id_without_tag(
            rel_cert_desc["signatureAlgorithm"], other_cert["tbsCertificate"]["signature"]
        ):
            raise ValueError(
                "The `signatureAlgorithm` in the secondary certificate does not match the "
                "RelatedCertificateDescriptor's one."
            )

    if rel_cert_desc["publicKeyAlgorithm"].isValue:
        if not compare_alg_id_without_tag(
            rel_cert_desc["publicKeyAlgorithm"], other_cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]
        ):
            raise ValueError(
                "The `publicKeyAlgorithm` in the secondary certificate does not "
                "match the RelatedCertificateDescriptor's one."
            )


def validate_cert_discovery(
    primary_cert: rfc9480.CMPCertificate,
    issuer_cert: rfc9480.CMPCertificate,
    cert_chain_secondary: List[rfc9480.CMPCertificate],
):
    """Validate a certificate using the certDiscovery access method.

    :param primary_cert: The primiary certificate.
    :return: True if validation succeeds, False otherwise.
    """
    rel_cert_desc: RelatedCertificateDescriptor = extract_sia_extension_for_cert_discovery(
        primary_cert["tbsCertificate"]["extensions"]
    )
    url = str(rel_cert_desc["uniformResourceIdentifier"])

    other_cert = get_cert_discovery_cert(url)
    validate_alg_ids(other_cert, rel_cert_desc)

    if check_is_cert_signer(cert=other_cert, poss_issuer=issuer_cert):
        raise ValueError("The Signature was correct, with traditional algorithm!")

    if cert_chain_secondary is not None:
        cert_chain = certutils.build_chain_from_list(ee_cert=other_cert, cert_dir=cert_chain_secondary)
        verify_cert_chain_openssl(cert_chain)

    if rel_cert_desc["signatureAlgorithm"] in CMS_COMPOSITE_OID_2_NAME:
        # TODO implement
        raise NotImplementedError("Currently not supported.")
        # verify_cert_hybrid(primary_cert, other_cert, issuer_cert)
