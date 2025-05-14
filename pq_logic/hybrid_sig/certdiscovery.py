# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""A Mechanism for X.509 Certificate Discovery.

https://datatracker.ietf.org/doc/draft-lamps-okubo-certdiscovery-05.html.
https://datatracker.ietf.org/doc/draft-lamps-okubo-certdiscovery/
"""

import logging
from typing import List, Optional, Union

from pyasn1.codec.der import decoder, encoder
from pyasn1.type import char, tag, univ
from pyasn1_alt_modules import rfc5280, rfc9480
from robot.api.deco import keyword, not_keyword

from pq_logic.hybrid_structures import OnRelatedCertificateDescriptor, RelatedCertificateDescriptor
from pq_logic.tmp_oids import id_ad_certDiscovery, id_ad_relatedCertificateDescriptor
from resources import certextractutils, certutils, compareutils, utils


def _prepare_related_certificate_descriptor(
    url: str,
    other_cert: Optional[rfc9480.CMPCertificate] = None,
    signature_algorithm: Optional[rfc5280.AlgorithmIdentifier] = None,
    public_key_algorithm: Optional[rfc5280.AlgorithmIdentifier] = None,
) -> rfc5280.GeneralName:
    """Prepare a `RelatedCertificateDescriptor` wrapped in an `AnotherName` structure.

    :param url: The URI for the secondary certificate.
    :param other_cert: The secondary certificate to extract the algorithms from. Defaults to `None`.
    :param signature_algorithm: The signature algorithm to set for the descriptor. Defaults to `None`.
    :param public_key_algorithm: The public key algorithm to set for the descriptor. Defaults to `None`.
    :return: The `GeneralName` object containing the `RelatedCertificateDescriptor`.
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


@keyword(name="Prepare SubjectInfoAccessSyntax Extension")
def prepare_subject_info_access_syntax_extension(  # noqa D417 undocumented-param
    url: str = "https://example.com/sec_cert.pem",
    critical: bool = False,
    signature_algorithm: Optional[rfc5280.AlgorithmIdentifier] = None,
    public_key_algorithm: Optional[rfc5280.AlgorithmIdentifier] = None,
    other_cert: Optional[rfc9480.CMPCertificate] = None,
) -> rfc5280.Extension:
    """Prepare a SubjectInfoAccessSyntax extension for certDiscovery.

    Arguments:
    ---------
        - url: The location of the other associated certificate. Defaults to `"https://example.com/sec_cert.pem"`.
        - critical: Whether the extension is critical. Defaults to `False`.
        - signature_algorithm: The signature algorithm to be included. Defaults to `None`.
        - public_key_algorithm: The public key algorithm to be included. Defaults to `None`.
        - other_cert: The primary certificate to infer algorithms from. Defaults to `None`.

    Returns:
    -------
        - The populated `Extension`.

    Examples:
    --------
    | ${extn}= | Prepare SubjectInfoAccessSyntax Extension | https://example.com/sec_cert.pem | ${other_cert} |

    """
    extension = rfc5280.Extension()

    sia = rfc5280.SubjectInfoAccessSyntax()
    access_description = rfc5280.AccessDescription()

    access_description["accessMethod"] = id_ad_certDiscovery

    access_description["accessLocation"] = _prepare_related_certificate_descriptor(
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


@keyword(name="Extract RelatedCertificateDescriptor from SIA Extension")
def extract_related_cert_des_from_sis_extension(  # noqa D417 undocumented-param
    extension: rfc5280.Extension, index: Optional[int] = None
) -> RelatedCertificateDescriptor:
    """Parse a SubjectInfoAccessSyntax (SIA) extension to extract a RelatedCertificateDescriptor.

    Used by the cert discovery mechanism, to access the secondary certificate.
    The RelatedCertificateDescriptor contains the URI, signature algorithm, and public key algorithm.

    Arguments:
    ---------
        - extension: An `Extension` object containing the SIA extension to parse.
        - index: The index of the AccessDescription within the SubjectInfoAccessSyntax.
        Defaults to `None` (means that all entries are checked).

    Raises:
    ------
        - ValueError: If the `accessMethod` does not match `id_ad_certDiscovery` or the `type-id` does not
            match `id_ad_relatedCertificateDescriptor`.

    Returns:
    -------
        - The extracted `RelatedCertificateDescriptor` object.

    Examples:
    --------
    | ${rel_cert_desc}= | Extract RelatedCertificateDescriptor from SIA Extension | ${extension} |
    | ${rel_cert_desc}= | Extract RelatedCertificateDescriptor from SIA Extension | ${extension} | ${index} |

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


@not_keyword
def is_cert_discovery_cert(
    cert: rfc9480.CMPCertificate,
) -> bool:
    """Check if the certificate is a certDiscovery certificate.

    :param cert: The certificate to check.
    :return: True if the certificate is a certDiscovery certificate, False otherwise.
    """
    extension = certextractutils.get_extension(cert["tbsCertificate"]["extensions"], rfc5280.id_pe_subjectInfoAccess)

    if extension is None:
        return False

    sia, _ = decoder.decode(extension["extnValue"].asOctets(), rfc5280.SubjectInfoAccessSyntax())
    for access_description in sia:
        if access_description["accessMethod"] == id_ad_certDiscovery:
            return True
    return False


@not_keyword
def get_cert_discovery_cert(cert: rfc9480.CMPCertificate) -> Optional[rfc9480.CMPCertificate]:
    """Get the certDiscovery certificate from the given certificate.

    :param cert: The certificate to check.
    :return: The certDiscovery certificate if found, None otherwise.
    """
    extension = certextractutils.get_extension(cert["tbsCertificate"]["extensions"], rfc5280.id_pe_subjectInfoAccess)

    if extension is None:
        return None

    rel_dis_des = extract_related_cert_des_from_sis_extension(
        extension=extension,
    )
    uri = rel_dis_des["uniformResourceIdentifier"].prettyPrint()
    other_cert = utils.load_certificate_from_uri(uri=uri, load_chain=False)[0]
    return other_cert


@not_keyword
def validate_related_certificate_descriptor_alg_ids(
    other_cert: rfc9480.CMPCertificate, rel_cert_desc: RelatedCertificateDescriptor
) -> None:
    """Validate that the algorithms in the `RelatedCertificateDescriptor` match those in the Secondary Certificate.

    :param other_cert: The Secondary Certificate as a CMPCertificate.
    :param rel_cert_desc: The RelatedCertificateDescriptor extracted from the Primary Certificate.
    :raises ValueError: If the algorithms do not match.
    """
    if rel_cert_desc["signatureAlgorithm"].isValue:
        if not compareutils.compare_alg_id_without_tag(
            rel_cert_desc["signatureAlgorithm"], other_cert["tbsCertificate"]["signature"]
        ):
            raise ValueError(
                "The `signatureAlgorithm` in the secondary certificate does not match the "
                "RelatedCertificateDescriptor's one."
            )

    if rel_cert_desc["publicKeyAlgorithm"].isValue:
        if not compareutils.compare_alg_id_without_tag(
            rel_cert_desc["publicKeyAlgorithm"], other_cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]
        ):
            raise ValueError(
                "The `publicKeyAlgorithm` in the secondary certificate does not "
                "match the RelatedCertificateDescriptor's one."
            )


def validate_cert_discovery_cert(  # noqa: D417 Missing argument descriptions in the docstring
    primary_cert: rfc9480.CMPCertificate,
    issuer_cert: Optional[rfc9480.CMPCertificate] = None,
    cert_chain_secondary: Optional[List[rfc9480.CMPCertificate]] = None,
    verify_openssl: bool = True,
    crl_check: bool = False,
    verbose: bool = True,
    timeout: Union[str, int] = 60,
    fetch_timeout: Union[str, int] = 20,
    certs_dir: Optional[str] = None,
) -> rfc9480.CMPCertificate:
    """Validate a certificate using the certDiscovery access method.

    Arguments:
    ---------
        - `primary_cert`: The primary certificate to validate.
        - `issuer_cert`: The issuer certificate of the secondary certificate. Defaults to `None`.
        - `cert_chain_secondary`: The chain of secondary certificates. Defaults to `None`.
        (If not provided, will OpenSSL verify and build the chain.)
        - `verify_openssl`: Whether to verify the certificate chain using OpenSSL. Defaults to `True`.
        - `crl_check`: Whether to check the CRL. Defaults to `False`.
        - `verbose`: Whether to print verbose output. Defaults to `True`.
        - `timeout`: The timeout for the OpenSSL verification. Defaults to `60` seconds.
        - `fetch_timeout`: The timeout for fetching the secondary certificate. Defaults to `20` seconds.
        - `certs_dir`: The directory to load certificates from, to build the chain. Defaults to `None`.

    Returns:
    -------
        - The validated secondary certificate.

    Raises:
    ------
        - `ValueError`: If the issuer is not a signer of the secondary certificate.
        - `ValueError`: If the OpenSSL verification fails.

    Examples:
    --------
    | ${secondary_cert}= | Validate Cert Discovery | ${primary_cert} | ${cert_chain_secondary} |
    | ${secondary_cert}= | Validate Cert Discovery | ${primary_cert} | ${cert_chain_secondary} | ${issuer_cert} |

    """
    rel_cert_desc: RelatedCertificateDescriptor = extract_related_cert_des_from_sis_extension(
        primary_cert["tbsCertificate"]["extensions"]
    )

    other_cert = utils.load_certificate_from_uri(
        uri=rel_cert_desc["uniformResourceIdentifier"], timeout=fetch_timeout, load_chain=False
    )[0]

    validate_related_certificate_descriptor_alg_ids(other_cert, rel_cert_desc)

    if cert_chain_secondary is None and issuer_cert is None:
        raise ValueError(
            "Either `cert_chain_secondary` or `issuer_cert` must be provided, to verify the secondary certificate."
        )

    if issuer_cert is None:
        issuer_cert = cert_chain_secondary[1]  # type: ignore

    if not certutils.check_is_cert_signer(cert=other_cert, poss_issuer=issuer_cert):
        raise ValueError("The Signature was not correct, with the traditional algorithm!")

    if cert_chain_secondary is not None:
        cert_chain = certutils.build_chain_from_list(ee_cert=other_cert, certs=cert_chain_secondary)

        len_parsed = len(cert_chain_secondary)
        if len(cert_chain) not in [len_parsed + 1, len_parsed]:
            logging.info("The parsed cert chain does not match the built one.")
    else:
        if certs_dir is None:
            raise ValueError("The `certs_dir` must be provided if `cert_chain_secondary` is not set.")

        certs = certutils.load_certificates_from_dir(
            path=certs_dir,
        )
        cert_chain = certutils.build_chain_from_list(ee_cert=other_cert, certs=certs)

    if verify_openssl:
        certutils.verify_cert_chain_openssl(
            cert_chain=cert_chain, crl_check=crl_check, verbose=verbose, timeout=timeout
        )

    return other_cert
