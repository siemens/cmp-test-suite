# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Convertible Forms with Multiple Keys and Signatures For Use In Internet X.509 Certificates.

https://datatracker.ietf.org/doc/draft-sun-lamps-hybrid-scheme/

Based on version:
https://www.ietf.org/archive/id/draft-sun-lamps-hybrid-scheme-00.html


"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import pyasn1
from cryptography.hazmat.primitives import hashes, serialization
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import char, tag, univ
from pyasn1_alt_modules import rfc2986, rfc4211, rfc5280, rfc6402, rfc9480
from robot.api.deco import keyword, not_keyword

import resources.prepare_alg_ids
import resources.protectionutils
from pq_logic.hybrid_structures import AltSignatureExt, AltSubPubKeyExt, UniformResourceIdentifier
from pq_logic.keys.abstract_wrapper_keys import HybridPublicKey
from pq_logic.keys.composite_sig06 import CompositeSig06PublicKey
from pq_logic.tmp_oids import (
    COMPOSITE_SIG06_PREHASH_OID_2_HASH,
    id_altSignatureExt,
    id_altSigValueHashAlgAttr,
    id_altSigValueLocAttr,
    id_altSubPubKeyExt,
    id_altSubPubKeyHashAlgAttr,
    id_altSubPubKeyLocAttr,
)
from resources import certbuildutils, certextractutils, convertutils, cryptoutils, keyutils, oid_mapping, utils
from resources.convertutils import copy_asn1_certificate
from resources.copyasn1utils import copy_subject_public_key_info
from resources.exceptions import BadAsn1Data
from resources.oid_mapping import get_hash_from_oid, sha_alg_name_to_oid
from resources.oidutils import SHA2_NAME_2_OID
from resources.prepare_alg_ids import prepare_sha_alg_id
from resources.typingutils import PublicKey, SignKey


# to avoid import conflicts will be removed in the future.
@not_keyword
def _compute_hash(alg_name: str, data: bytes) -> bytes:
    """Calculate the hash of data using an algorithm given by its name.

    :param alg_name: The Name of algorithm, e.g., 'sha256', see HASH_NAME_OBJ_MAP.
    :param data: The buffer we want to hash.
    :return: The resulting hash.
    """
    hash_class = oid_mapping.hash_name_to_instance(alg_name)
    digest = hashes.Hash(hash_class)
    digest.update(data)
    return digest.finalize()


def _hash_public_key(public_key: PublicKey, hash_alg: str) -> bytes:
    """Hash a public key using the specified hash algorithm.

    :param public_key: The public key to hash.
    :param hash_alg: The hash algorithm name (e.g., "sha256").
    :return: The computed hash as bytes.
    :raises ValueError: If the hash algorithm is invalid.
    """
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return _compute_hash(hash_alg, public_key_der)


##############
# CSR
#############


def _prepare_alt_sub_pub_key_hash_alg_attr(hash_alg: str) -> rfc2986.Attribute:
    """Prepare the alternative subject public key hash algorithm attribute.

    :param hash_alg: The hash algorithm name (e.g., "sha256").
    :return: `Attribute` representing the `altSubPubKeyHashAlgAttr`.
    """
    if not hash_alg:
        raise ValueError("hash_alg must not be None.")

    attr = rfc2986.Attribute()
    attr["type"] = id_altSubPubKeyHashAlgAttr
    attr["values"][0] = prepare_sha_alg_id(hash_alg)
    return attr


def _prepare_alt_sub_pub_key_loc_attr(location: str) -> rfc2986.Attribute:
    """Prepare the Alternative Subject Public Key Location Attribute.

    :param location: URI string representing the location of the alternative public key.
    :return: `Attribute` representing the `altSubPubKeyLocAttr`.
    """
    attr = rfc2986.Attribute()
    attr["type"] = id_altSubPubKeyLocAttr
    attr["values"][0] = encoder.encode(char.IA5String(location))
    return attr


def _prepare_alt_sig_value_hash_alg_attr(hash_alg: str) -> rfc2986.Attribute:
    """Prepare the alternative signature value hash algorithm attribute.

    :param hash_alg: The hash algorithm name (e.g., "sha256").
    :return: `Attribute` representing the `altSigValueHashAlgAttr`.
    """
    if not hash_alg:
        raise ValueError("hash_alg must not be None.")

    attr = rfc2986.Attribute()
    attr["type"] = id_altSigValueHashAlgAttr
    attr["values"][0] = prepare_sha_alg_id(hash_alg)
    return attr


def _prepare_alt_sig_value_loc_attr(location: str) -> rfc2986.Attribute:
    """Prepare the alternative signature value location attribute.

    :param location: URI string representing the location of the alternative signature.
    :return: `Attribute` representing the `altSigValueLocAttr`.
    """
    attr = rfc2986.Attribute()
    attr["type"] = id_altSigValueLocAttr
    attr["values"][0] = char.IA5String(location)
    return attr


def prepare_sun_hybrid_csr_attributes(  # noqa: D417 Missing argument descriptions in the docstring
    pub_key_hash_alg: Optional[str] = None,
    pub_key_location: Optional[str] = None,
    sig_hash_alg: Optional[str] = None,
    sig_value_location: Optional[str] = None,
) -> List[rfc2986.Attribute]:
    """Prepare all alternative public key and signature attributes.

    Arguments:
    ---------
        - `pub_key_hash_alg`: The hash algorithm name to be used to hash the alternative public key.
        Defaults to `None`.
        - `pub_key_location`: The location of the alternative public key. Defaults to `None`.
        - `sig_hash_alg`: The hash algorithm name to be used to hash the alternative signature.
        Defaults to `None`.
        - `sig_value_location`: The location of the alternative signature. Defaults to `None`.

    Returns:
    -------
        - A list of `Attribute` objects representing the alternative public key and signature attributes.

    Examples:
    --------
    | ${attributes}= | Prepare Sun Hybrid CSR Attributes | pub_key_hash_alg=sha256 | https://example.com/pub_key |
    | ${attributes}= | Prepare Sun Hybrid CSR Attributes | pub_key_hash_alg=sha256 \
    | pub_key_location=https://example.com/pub_key |

    """
    attributes = []

    if pub_key_hash_alg is not None:
        attributes.append(_prepare_alt_sub_pub_key_hash_alg_attr(pub_key_hash_alg))

    if pub_key_location is not None:
        attributes.append(_prepare_alt_sub_pub_key_loc_attr(pub_key_location))

    if sig_hash_alg is not None:
        attributes.append(_prepare_alt_sig_value_hash_alg_attr(sig_hash_alg))

    if sig_value_location is not None:
        attributes.append(_prepare_alt_sig_value_loc_attr(sig_value_location))

    return attributes


##############
# X.509
#############


def prepare_sun_hybrid_alt_sub_pub_key_ext(  # noqa: D417 Missing argument descriptions in the docstring
    public_key: PublicKey,
    by_val: bool,
    hash_alg: Optional[str] = None,
    location: Optional[str] = None,
    critical: bool = False,
) -> rfc5280.Extension:
    """Prepare the `AltSubPubKeyExt` as an Extension.

    Arguments:
    ---------
        - `public_key`: The alternative public key.
        - `by_val`: Boolean indicating byVal. If `True`, the public_key contains the actual key value.
                    If `False`, the public_key contains the hash of the alternative public key.
        - `hash_alg`: The hash algorithm name (e.g., "sha256"). Required if by_val is `False`.
        - `location`: Optional URI string representing the location of the alternative public key.
        - `critical`: Whether the extension should be marked as critical. Defaults to `False`.

    Returns:
    -------
        - The populated Extension.

    Raises:
    ------
        - ValueError: If by_val is `False` and hash_alg is not provided.

    Examples:
    --------
    | ${extn}= | Prepare Sun Hybrid Alt Sub Pub Key Ext | public_key=${public_key} | by_val=True |
    | ${extn}= | Prepare Sun Hybrid Alt Sub Pub Key Ext | public_key=${public_key} | by_val=False | hash_alg=sha256 |

    """
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    obj, _ = decoder.decode(public_key_der, rfc5280.SubjectPublicKeyInfo())

    # If byVal is False, calculate the hash of the public key
    if not by_val:
        if not hash_alg:
            raise ValueError("hash_alg must be provided when byVal is False.")
        public_key_der = _compute_hash(alg_name=hash_alg, data=public_key_der)

    alt_sub_pub_key_ext = AltSubPubKeyExt()
    alt_sub_pub_key_ext["byVal"] = by_val
    alt_sub_pub_key_ext["altAlgorithm"] = obj["algorithm"]

    # plainOrHash stores the alternative public key or its hash value. When byVal is FALSE,
    # the plainOrHash field stores the hash value of the alternative public key.
    # When byVal is TRUE, plainOrHash stores the actual value of alternative public key
    alt_sub_pub_key_ext["plainOrHash"] = univ.BitString.fromOctetString(public_key_der)

    if hash_alg:
        alt_sub_pub_key_ext["hashAlg"]["algorithm"] = sha_alg_name_to_oid(hash_alg)

    if location is not None:
        alt_sub_pub_key_ext["location"] = UniformResourceIdentifier(location)

    ext_value = encoder.encode(alt_sub_pub_key_ext)
    extension = rfc5280.Extension()
    extension["extnID"] = id_altSubPubKeyExt
    # MUST be non-critical
    extension["critical"] = critical
    extension["extnValue"] = univ.OctetString(ext_value)
    return extension


def prepare_sun_hybrid_alt_signature_ext(  # noqa: D417 Missing argument descriptions in the docstring
    signature: bytes,
    by_val: bool,
    alt_sig_algorithm: rfc9480.AlgorithmIdentifier,
    hash_alg: Optional[str] = None,
    location: Optional[str] = None,
    critical: bool = False,
) -> rfc5280.Extension:
    """Prepare the `AltSignatureExt` as an Extension.

    Arguments:
    ---------
        - `signature`: Bytes representing the alternative signature.
        - `by_val`: Boolean indicating byVal. If `True`, the signature contains the actual signature value.
                    If `False`, the signature contains the hash of the alternative signature.
        - `alt_sig_algorithm`: AlgorithmIdentifier for the alternative signature algorithm.
        - `hash_alg`: The hash algorithm name (e.g., "sha256"). Required if by_val is `False`. Defaults to `None`.
        - `location`: Optional URI string representing the location of the alternative signature. Defaults to `None`.
        - `critical`: Whether the extension should be marked as critical. Defaults to `False`.

    Returns:
    -------
        - The populated Extension.

    Raises:
    ------
        - ValueError: If the signature is empty or if hash_alg is not provided when by_val is `False`.

    Examples:
    --------
    | ${extn}= | Prepare Sun Hybrid Alt Signature Ext | signature=${sig} | by_val=True \
    | alt_sig_algorithm=${alg_id} |

    """
    # Input validation
    if not signature:
        raise ValueError("signature must not be empty.")
    if not by_val and hash_alg is None:
        raise ValueError("hash_alg must be provided when by_val is False.")

    # If byVal is False, calculate the hash of the signature
    if not by_val:
        if not hash_alg:
            raise ValueError("hash_alg must be provided when byVal is False.")
        signature = _compute_hash(hash_alg, signature)

    alt_signature_ext = AltSignatureExt()
    alt_signature_ext["byVal"] = by_val
    alt_signature_ext["plainOrHash"] = univ.BitString.fromOctetString(signature)
    alt_signature_ext["altSigAlgorithm"] = alt_sig_algorithm

    if hash_alg is not None or not by_val:
        if not hash_alg:
            raise ValueError("hash_alg must be provided when byVal is False.")
        alg_id = prepare_sha_alg_id(hash_alg=hash_alg)
        alt_signature_ext["hashAlg"] = alg_id

    if location is not None:
        alt_signature_ext["location"] = char.IA5String(location)

    ext_value = encoder.encode(alt_signature_ext)

    extension = rfc5280.Extension()
    extension["extnID"] = id_altSignatureExt
    # MUST be non-critical
    extension["critical"] = critical
    extension["extnValue"] = univ.OctetString(ext_value)

    return extension


def _extract_sun_hybrid_attrs_from_csr(csr: rfc6402.CertificationRequest) -> Dict:
    """Extract values of specific attributes from a CSR.

    :param csr: The CSR from which attribute values will be extracted.
    :return: A dictionary with attribute OIDs as keys and their corresponding values.
    """
    attribute_map = {
        id_altSubPubKeyHashAlgAttr: "pub_key_hash_id",
        id_altSubPubKeyLocAttr: "pub_key_loc",
        id_altSigValueHashAlgAttr: "sig_hash_id",
        id_altSigValueLocAttr: "sig_loc",
    }

    extracted_values = {x: None for x in attribute_map.values()}

    for attribute in csr["certificationRequestInfo"]["attributes"]:
        oid = attribute["attrType"]

        if oid in [id_altSubPubKeyHashAlgAttr, id_altSigValueHashAlgAttr]:
            alg_id, _ = decoder.decode(attribute["attrValues"][0].asOctets(), rfc9480.AlgorithmIdentifier())
            key = attribute_map[oid]
            extracted_values[key] = alg_id

        elif oid in attribute_map:
            key = attribute_map[oid]
            extracted_values[key] = decoder.decode(attribute["attrValues"][0].asOctets())[0].prettyPrint()

    return extracted_values


@keyword(name="Sun CSR To Cert")
def sun_csr_to_cert(  # noqa: D417 Missing argument descriptions in the docstring
    csr: rfc6402.CertificationRequest,
    issuer_private_key: SignKey,
    alt_private_key: SignKey,
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
    hash_alg: str = "sha256",
    serial_number: Optional[int] = None,
    extensions: Optional[Sequence[rfc5280.Extension]] = None,
    **kwargs,
) -> Tuple[rfc9480.CMPCertificate, rfc9480.CMPCertificate]:
    """Convert a CSR to a certificate, with the sun hybrid method.

    Arguments:
    ---------
        - `csr`: The CSR to build the certificate from.
        - `issuer_private_key`: The private key of the issuer for signing the certificate.
        - `alt_private_key`: The alternative private key for creating the alternative signature.
        - `issuer_cert`: The issuer's certificate to use for constructing the certificate. Defaults to `None`.
        - `hash_alg`: The hash algorithm to use for signing the certificate (e.g., "sha256"). Defaults to "sha256".
        - `serial_number`: The serial number to use for the certificate. Defaults to `None`.
        - `extensions`: A list of additional extensions to include in the certificate. Defaults to `None`.

    **kwargs:
    ---------
        - `days`: The number of days the certificate is valid for. Defaults to `3650`.

    Returns:
    -------
        - A tuple of the Form4 and Form1 certificates.

    Examples:
    --------
    | ${cert_form4}= | Sun CSR To Cert | csr=${csr} | issuer_private_key=${key} | alt_private_key=${alt_key} |

    """
    public_key = keyutils.load_public_key_from_spki(csr["certificationRequestInfo"]["subjectPublicKeyInfo"])

    if not isinstance(public_key, CompositeSig06PublicKey):
        raise ValueError("The public key must be a CompositeSigCMSPublicKey.")

    oid = csr["signatureAlgorithm"]["algorithm"]
    data: dict = _extract_sun_hybrid_attrs_from_csr(csr)

    if data["pub_key_hash_id"] is None:
        data["pub_key_hash_id"] = SHA2_NAME_2_OID[hash_alg]
    else:
        data["pub_key_hash_id"] = get_hash_from_oid(data["pub_key_hash_id"]["algorithm"])

    if data["sig_hash_id"] is None:
        data["sig_hash_id"] = COMPOSITE_SIG06_PREHASH_OID_2_HASH.get(oid) or hash_alg
    else:
        data["sig_hash_id"] = get_hash_from_oid(data["sig_hash_id"]["algorithm"])

    not_before = datetime.now()
    not_after = datetime.now() + timedelta(days=int(kwargs.get("days", 365 * 10)))
    validity = certbuildutils.prepare_validity(not_before=not_before, not_after=not_after)
    cert_form4, ext_sig, ext_pub = prepare_sun_hybrid_pre_tbs_certificate(
        public_key,
        alt_private_key=alt_private_key,
        serial_number=serial_number,
        issuer_private_key=issuer_private_key,
        csr=csr,
        validity=validity,
        hash_alg=hash_alg,
        issuer_cert=ca_cert,
        extensions=extensions,  # type: ignore
        **data,
    )

    cert_form1 = copy_asn1_certificate(cert_form4)

    # build Form1
    cert_form1["tbsCertificate"]["extensions"] = _patch_extensions(cert_form1["tbsCertificate"]["extensions"], ext_sig)
    cert_form1["tbsCertificate"]["extensions"] = _patch_extensions(cert_form1["tbsCertificate"]["extensions"], ext_pub)

    return cert_form4, cert_form1


def sun_cert_template_to_cert(  # noqa: D417 Missing argument descriptions in the docstring
    cert_template: rfc4211.CertTemplate,
    ca_cert: rfc9480.CMPCertificate,
    ca_key: SignKey,
    alt_private_key: SignKey,
    pub_key_loc: Optional[str],
    sig_loc: Optional[str],
    hash_alg: Optional[str] = None,
    serial_number: Optional[int] = None,
    extensions: Optional[Sequence[rfc5280.Extension]] = None,
    **kwargs,
) -> Tuple[rfc9480.CMPCertificate, rfc9480.CMPCertificate]:
    """Convert a certificate template to a certificate, with the sun hybrid method.

    Arguments:
    ---------
        - `cert_template`: The certificate template, to built the certificate from.
        - `issuer_cert`: The issuer's certificate to use for constructing the certificate.
        - `ca_key`: The private key of the issuer for signing.
        - `alt_private_key`: The alternative private key for creating the alternative signature.
        - `pub_key_loc`: The location of the alternative public key.
        - `sig_loc`: The location of the alternative signature.
        - `hash_alg`: The hash algorithm to use for signing the certificate (e.g., "sha256").
        - `serial_number`: The serial number to use for the certificate. Defaults to `None`.
        - `issuer`: The issuer's name. Defaults to `None`.
        - `extensions`: A list of additional extensions to include in the certificate. Defaults to `None`.
           (as an example for OCSP, CRL, etc.)

    **kwargs:
    ---------
        - `bad_alt_sig`: Boolean indicating whether the alternative signature should be invalid. Defaults to `False`.


    Returns:
    -------
        - A tuple of the Form4 and Form1 certificates.

    Examples:
    --------
    | ${cert_form4} ${cert_form1}= | Sun Cert Template To Cert | cert_template=${cert_template} \
    |issuer_cert=${issuer_cert} | ca_key=${key} | alt_private_key=${alt_key} |

    """
    spki = copy_subject_public_key_info(
        target=rfc5280.SubjectPublicKeyInfo(), filled_sub_pubkey_info=cert_template["publicKey"]
    )
    composite_key = keyutils.load_public_key_from_spki(spki)

    if not isinstance(composite_key, HybridPublicKey):
        raise ValueError("The public key must be a HybridPublicKey, for a Sun Hybrid certificate.")

    spki = convertutils.subject_public_key_info_from_pubkey(composite_key.trad_key)
    tbs_cert = certbuildutils.prepare_tbs_certificate_from_template(
        cert_template=cert_template,
        issuer=ca_cert["tbsCertificate"]["subject"],
        serial_number=serial_number,
        ca_key=ca_key,
        spki=spki,
        use_rsa_pss=False,
    )
    if extensions is not None:
        tbs_cert["extensions"].extend(extensions)

    if not isinstance(composite_key, HybridPublicKey):
        raise ValueError("The public key must be a HybridPublicKey.")
    oid = composite_key.get_oid()
    hash_alg = hash_alg or COMPOSITE_SIG06_PREHASH_OID_2_HASH.get(oid, "sha256")
    extn_alt_pub, extn_alt_pub2 = _prepare_public_key_extensions(composite_key, hash_alg, pub_key_loc)

    tbs_cert["extensions"].append(extn_alt_pub)

    pre_tbs_cert = tbs_cert
    data = encoder.encode(pre_tbs_cert)
    signature = cryptoutils.sign_data(key=alt_private_key, data=data, hash_alg=hash_alg, use_rsa_pss=False)
    sig_alg_id = resources.prepare_alg_ids.prepare_sig_alg_id(
        signing_key=alt_private_key, hash_alg=hash_alg, use_rsa_pss=False
    )

    if kwargs.get("bad_alt_sig", False):
        signature = utils.manipulate_first_byte(signature)

    extn_alt_sig = prepare_sun_hybrid_alt_signature_ext(
        signature=signature, by_val=False, hash_alg=hash_alg, alt_sig_algorithm=sig_alg_id, location=sig_loc
    )

    extn_alt_sig2 = prepare_sun_hybrid_alt_signature_ext(
        signature=signature, by_val=True, hash_alg=hash_alg, alt_sig_algorithm=sig_alg_id, location=sig_loc
    )

    # as of 4.3.2:
    # Sign the preTbsCertificate constructed in Section 4.3.1 with the issuer's
    # alternative private key to obtain the alternative signature.
    pre_tbs_cert["extensions"].append(extn_alt_sig)

    # Sign with the first public key.
    final_tbs_cert_data = encoder.encode(pre_tbs_cert)
    signature = cryptoutils.sign_data(key=ca_key, data=final_tbs_cert_data, hash_alg=hash_alg)
    sig_alg_id = resources.prepare_alg_ids.prepare_sig_alg_id(signing_key=ca_key, hash_alg=hash_alg, use_rsa_pss=False)

    cert_form4 = rfc9480.CMPCertificate()
    cert_form4["tbsCertificate"] = pre_tbs_cert
    cert_form4["signature"] = univ.BitString.fromOctetString(signature)
    cert_form4["signatureAlgorithm"] = sig_alg_id

    cert_form1 = copy_asn1_certificate(cert_form4)

    # build Form1

    cert_form1["tbsCertificate"]["extensions"] = _patch_extensions(
        cert_form1["tbsCertificate"]["extensions"], extn_alt_pub2
    )
    cert_form1["tbsCertificate"]["extensions"] = _patch_extensions(
        cert_form1["tbsCertificate"]["extensions"], extn_alt_sig2
    )

    return cert_form4, cert_form1


def _prepare_public_key_extensions(
    composite_key: HybridPublicKey,
    pub_key_hash_id: str,
    pub_key_loc: Optional[str],
) -> Tuple[rfc5280.Extension, rfc5280.Extension]:
    """Prepare the public key extensions for the Sun-Hybrid certificate.

    :param composite_key: The composite key with set primary and alternative keys.
    :param pub_key_hash_id: The hash algorithm name (e.g., "sha256").
    :param pub_key_loc: The location of the alternative public key.
    :return: THe public key in Form4 and Form1.
    """
    # Compute a hash by hashing pk_2
    extn_alt_pub = prepare_sun_hybrid_alt_sub_pub_key_ext(
        composite_key.pq_key, hash_alg=pub_key_hash_id, by_val=False, location=pub_key_loc
    )
    # Prepare pk_2 for Form1
    extn_alt_pub2 = prepare_sun_hybrid_alt_sub_pub_key_ext(
        public_key=composite_key.pq_key, hash_alg=pub_key_hash_id, by_val=True, location=pub_key_loc
    )
    return extn_alt_pub, extn_alt_pub2


@not_keyword
def prepare_sun_hybrid_pre_tbs_certificate(
    composite_key: HybridPublicKey,
    issuer_private_key,
    alt_private_key,
    issuer_cert: Optional[rfc9480.CMPCertificate],
    csr: rfc6402.CertificationRequest,
    pub_key_hash_id: str,
    sig_hash_id: str,
    validity: rfc5280.Validity,
    hash_alg: str,
    pub_key_loc: Optional[str],
    sig_loc: Optional[str],
    extensions: List[rfc5280.Extension],
    serial_number: Optional[int] = None,
):
    """Prepare a `TBSCertificate` structure with alternative public key and signature extensions.

    :param composite_key: The composite key with set primary and alternative keys.
    :param issuer_private_key: The issuer's private key for signing the certificate.
    :param alt_private_key: The alternative private key used for the alternative signature.
    :param issuer_cert: The issuer's certificate to use for constructing the certificate.
    :param csr: The certificate signing request from which to construct the certificate.
    :param pub_key_hash_id: The hash algorithm name for hashing the alternative public key.
    :param sig_hash_id: The hash algorithm name for hashing the alternative signature.
    :param hash_alg: The hash algorithm used for signing the `TBSCertificate`.
    :param validity: The validity object for the certificate.
    :param pub_key_loc: An optional URI representing the location of the alternative public key.
    :param sig_loc: An optional URI representing the location of the alternative signature.
    :param extensions: Optional list of additional extensions to include in the certificate.
    :param serial_number: The serial number to use for the certificate. Defaults to `None`.
    :return: A fully prepared `TBSCertificate` wrapped in a certificate structure.
    :raises ValueError: If required, parameters are missing or invalid.
    """
    # Compute a hash by hashing pk_1
    extn_alt_pub, extn_alt_pub2 = _prepare_public_key_extensions(composite_key, pub_key_hash_id, pub_key_loc)

    # After creating an AltSubPubKeyExt extension, an issuer constructs a TBSCertificate
    # object from attributes in the given
    # CSR following existing standards, e.g., [RFC2986] and [RFC5280].
    # The constructed TBSCertificate object is the preTbsCertificate field, which MUST
    # include the created AltSubPubKeyExt extension.

    extensions = extensions or []

    subject = utils.get_openssl_name_notation(csr["certificationRequestInfo"]["subject"])
    pre_tbs_cert = certbuildutils.prepare_tbs_certificate(
        subject=subject,
        serial_number=serial_number,
        signing_key=issuer_private_key,
        issuer_cert=issuer_cert,
        public_key=composite_key.trad_key,  # Construct a SubjectPublicKeyInfo object from pk_1
        validity=validity,
        hash_alg=hash_alg,
        extensions=[extn_alt_pub] + extensions,  # type: ignore
        # The constructed TBSCertificate object is the preTbsCertificate
        # field, which MUST include the created `AltSubPubKeyExt` extension.
    )

    data = encoder.encode(pre_tbs_cert)
    signature = cryptoutils.sign_data(key=alt_private_key, data=data, hash_alg=sig_hash_id)
    sig_alg_id = resources.prepare_alg_ids.prepare_sig_alg_id(
        signing_key=alt_private_key, hash_alg=sig_hash_id, use_rsa_pss=False
    )

    extn_alt_sig = prepare_sun_hybrid_alt_signature_ext(
        signature=signature, by_val=False, hash_alg=sig_hash_id, alt_sig_algorithm=sig_alg_id, location=sig_loc
    )

    extn_alt_sig2 = prepare_sun_hybrid_alt_signature_ext(
        signature=signature, by_val=True, hash_alg=sig_hash_id, alt_sig_algorithm=sig_alg_id, location=sig_loc
    )

    # as of 4.3.2:
    # Sign the preTbsCertificate constructed in Section 4.3.1 with the issuer's
    # alternative private key to obtain the alternative signature.
    pre_tbs_cert["extensions"].append(extn_alt_sig)

    # Sign with the first public key.
    final_tbs_cert_data = encoder.encode(pre_tbs_cert)
    signature = cryptoutils.sign_data(key=issuer_private_key, data=final_tbs_cert_data, hash_alg=hash_alg)
    sig_alg_id = resources.prepare_alg_ids.prepare_sig_alg_id(
        signing_key=issuer_private_key, hash_alg=hash_alg, use_rsa_pss=False
    )

    cert = rfc9480.CMPCertificate()
    cert["tbsCertificate"] = pre_tbs_cert
    cert["signature"] = univ.BitString.fromOctetString(signature)
    cert["signatureAlgorithm"] = sig_alg_id

    return cert, extn_alt_sig2, extn_alt_pub2


@keyword("Validate AltSubPubKeyExt")
def validate_alt_pub_key_extn(  # noqa: D417 Missing argument descriptions in the docstring
    cert: rfc9480.CMPCertificate,
) -> PublicKey:
    """Validate the `AltSubPubKeyExt` extension in a certificate.

    Ensures that the AltSubPubKeyExt extension in the certificate is valid
    and that the hash of the alternative public key matches the expected value.

    Arguments:
    ---------
        - `cert`: The certificate to validate the extension inside.

    Raises:
    ------
        - ValueError: If the extension is missing, critical, or invalid.

    Returns:
    -------
        - The alternative public key.

    Examples:
    --------
    | Validate AltSubPubKeyExt | ${cert} |

    """
    decoded_ext = None

    for ext in cert["tbsCertificate"]["extensions"]:
        if ext["extnID"] == id_altSubPubKeyExt:
            decoded_ext, _ = decoder.decode(ext["extnValue"].asOctets(), AltSubPubKeyExt())
            if ext["critical"]:
                raise ValueError("The extension MUST not be critical.")
            break

    if decoded_ext is None:
        raise ValueError("The `AltSubPubKeyExt` was not inside the certificate.")

    if decoded_ext["byVal"]:
        raise ValueError("MUST be in Form 4 for verification.")

    location = decoded_ext["location"]

    if not location.isValue:
        raise ValueError("The location is not a value, the public key can not be fetched.")

    actual_value = utils.fetch_value_from_location(str(location))
    public_key = process_public_key(actual_value)

    hash_alg_oid = decoded_ext["hashAlg"]["algorithm"]
    hash_alg = get_hash_from_oid(hash_alg_oid)
    logging.info("Alt Public key: %s", public_key)
    logging.info("hash alg: %s", hash_alg)

    if not hash_alg:
        raise ValueError("The hash algorithm is not inside the `AltSubPubKeyExt` structure")

    computed_hash = _hash_public_key(public_key, hash_alg=hash_alg)

    if computed_hash != decoded_ext["plainOrHash"].asOctets():
        raise ValueError(
            f"Hash mismatch for ByReference extension:\n"
            f" Found:    {decoded_ext['plainOrHash'].asOctets().hex()}\n"
            f" Computed: {computed_hash.hex()}"
        )

    spki, _ = decoder.decode(actual_value, rfc5280.SubjectPublicKeyInfo())

    if spki["algorithm"] != decoded_ext["altAlgorithm"]:
        raise ValueError("The algorithm is not the same as inside the `AltSubPubKeyExt` structure")

    return keyutils.load_public_key_from_spki(spki)  # type: ignore


@not_keyword
def extract_sun_hybrid_alt_sig(cert: rfc9480.CMPCertificate) -> bytes:
    """Get the alternative signature extension from the certificate.

    Expects the certificate to be in Form 1.

    :param cert: The certificate to extract the alternative signature from.
    :return: The alternative signature.
    :raises ValueError: If the extension is missing or invalid.
    """
    decoded_ext = None
    for x in cert["tbsCertificate"]["extensions"]:
        if x["extnID"] == id_altSignatureExt:
            decoded_ext, _ = decoder.decode(x["extnValue"].asOctets(), AltSignatureExt())

    if not decoded_ext:
        raise ValueError("The `AltSignatureExt` was not inside the certificate.")
    return decoded_ext["plainOrHash"].asOctets()


@keyword("Validate AltSignatureExt")
def validate_alt_sig_extn(  # noqa: D417 Missing argument descriptions in the docstring
    cert: rfc9480.CMPCertificate, alt_pub_key, signature: Optional[bytes] = None
):
    """Validate the `AltSignatureExt` extension in a certificate.

    Verifies the alternative signature in the AltSignatureExt extension
    against the pre-tbsCertificate data.

    Arguments:
    ---------
        - `cert`: The certificate to validate the extension inside.
        - `alt_pub_key`: The alternative public key used to verify the signature.
        - `signature`: The alternative signature which can be cached.

    Raises:
    ------
        - `ValueError`: If the extension is missing, critical, or invalid.
        - `ValueError`: If the fetched signature was invalid.
        - `InvalidSignature`: If the signature verification fails.

    Examples:
    --------
    | Validate AltSignatureExt | ${cert} | ${alt_pub_key} |
    | Validate AltSignatureExt | ${cert} | ${alt_pub_key} | ${signature} |

    """
    old_extensions = cert["tbsCertificate"]["extensions"]

    new_extn = rfc5280.Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))

    decoded_ext = None
    for x in old_extensions:
        if x["extnID"] == id_altSignatureExt:
            decoded_ext, _ = decoder.decode(x["extnValue"].asOctets(), AltSignatureExt())
            if x["critical"]:
                raise ValueError("The extension MUST not be critical.")
            continue

        new_extn.append(x)

    if decoded_ext is None:
        raise ValueError("The `AltSignatureExt` was not inside the certificate.")

    cert["tbsCertificate"]["extensions"] = new_extn

    data = encoder.encode(cert["tbsCertificate"])

    if signature is None:
        signature = (
            utils.fetch_value_from_location(decoded_ext["location"]) if decoded_ext["location"].isValue else None
        )
    sig_alg_id = decoded_ext["altSigAlgorithm"]

    hash_alg = get_hash_from_oid(decoded_ext["hashAlg"]["algorithm"])
    if not hash_alg:
        raise ValueError("The hash algorithm is not inside the `AltSignatureExt` structure")
    hashed_sig = decoded_ext["plainOrHash"].asOctets()

    if signature is None:
        raise ValueError("The signature was not inside the certificateand/or could not be fetched from the location.")

    if hashed_sig != _compute_hash(alg_name=hash_alg, data=signature):
        raise ValueError("The fetched signature was invalid!")

    resources.protectionutils.verify_signature_with_alg_id(
        alg_id=sig_alg_id, public_key=alt_pub_key, data=data, signature=signature
    )


def _patch_extensions(extensions: rfc9480.Extensions, extension: rfc5280.Extension) -> rfc9480.Extensions:
    """Replace or update an extension in the given list of extensions.

    :param extensions: The `Extensions` structure to modify.
    :param extension: The extension to update.
    :return: The update `Extensions` structure.
    :raises ValueError: If the specified extension does not exist in the original structure.
    """
    for i, ext in enumerate(extensions):
        if ext["extnID"] == extension["extnID"]:  # type: ignore
            extensions[i] = extension
            return extensions

    raise ValueError("The extension was not inside the `Extensions` structure.")


def _parse_alt_sig_extension(cert: rfc9480.CMPCertificate, to_by_val: bool) -> rfc9480.CMPCertificate:
    """Parse and convert the `AltSignatureExt` extension in the given certificate.

    Converts the extension to either ByValue or ByReference format as specified.

    :param cert: The certificate containing the `AltSignatureExt`.
    :param to_by_val: Boolean indicating whether to convert to ByValue (True) or ByReference (False).
    :return: The modified certificate with the updated `AltSignatureExt`.
    :raises ValueError: If the `AltSignatureExt` is missing or invalid.
    """
    extensions = cert["tbsCertificate"]["extensions"]
    extension = certextractutils.get_extension(extensions, id_altSignatureExt, must_be_non_crit=True)
    if not extension:
        raise ValueError("AltSignatureExt not found in the provided extensions.")

    decoded_ext, _ = decoder.decode(extension["extnValue"].asOctets(), AltSignatureExt())

    if to_by_val == decoded_ext["byVal"]:
        return cert

    hash_alg = get_hash_from_oid(decoded_ext["hashAlg"]["algorithm"])
    current_signature = decoded_ext["plainOrHash"].asOctets()
    location = str(decoded_ext["location"]) if decoded_ext["location"].isValue else None

    if to_by_val:
        if not location:
            raise ValueError("Location is required to fetch the signature for ByValue conversion.")
        fetched_signature = utils.fetch_value_from_location(location)
        if not fetched_signature:
            raise ValueError(f"Failed to fetch signature from location: {location}")
        new_signature = fetched_signature
    else:
        new_signature = current_signature

    new_extension = prepare_sun_hybrid_alt_signature_ext(
        signature=new_signature,
        by_val=to_by_val,
        alt_sig_algorithm=decoded_ext["altSigAlgorithm"],
        hash_alg=hash_alg,
        location=location,
        critical=extension["critical"],
    )
    cert["tbsCertificate"]["extensions"] = _patch_extensions(extensions, new_extension)

    return cert


def _parse_alt_sub_pub_key_extension(cert: rfc9480.CMPCertificate, to_by_val: bool) -> rfc9480.CMPCertificate:
    """Parse and convert the `AltSubPubKeyExt` extension in the given certificate.

    Converts the extension to either ByValue or ByReference format as specified.

    :param cert: The certificate containing the `AltSubPubKeyExt`.
    :param to_by_val: Boolean indicating whether to convert to ByValue (True) or ByReference (False).
    :return: The modified certificate with the updated `AltSubPubKeyExt`.
    :raises ValueError: If the `AltSubPubKeyExt` is missing or invalid.
    """
    extensions = cert["tbsCertificate"]["extensions"]
    extension = certextractutils.get_extension(extensions, id_altSubPubKeyExt, must_be_non_crit=True)
    if not extension:
        raise ValueError("AltSignatureExt not found in the provided extensions.")

    decoded_ext, _ = decoder.decode(extension["extnValue"].asOctets(), AltSubPubKeyExt())

    if to_by_val == decoded_ext["byVal"]:
        return cert

    hash_alg = get_hash_from_oid(decoded_ext["hashAlg"]["algorithm"])
    public_key = decoded_ext["plainOrHash"].asOctets()
    loc = None if not decoded_ext["location"].isValue else str(decoded_ext["location"])

    if not to_by_val:
        if not loc:
            raise ValueError("Location is required to fetch the public key for ByValue conversion.")

        public_key = process_public_key(public_key)
        logging.info("used hash alg %s", hash_alg)

    else:
        if loc is None:
            raise ValueError("Location is required to fetch the public key for ByReference conversion.")

        public_key = utils.fetch_value_from_location(loc)
        public_key = process_public_key(public_key)

    new_extension = prepare_sun_hybrid_alt_sub_pub_key_ext(
        public_key=public_key,
        by_val=to_by_val,
        hash_alg=hash_alg,
        location=loc,
        critical=extension["critical"],
    )

    cert["tbsCertificate"]["extensions"] = _patch_extensions(extensions, new_extension)

    return cert


def get_sun_hybrid_form(  # noqa: D417 Missing argument descriptions in the docstring
    cert: rfc9480.CMPCertificate,
) -> str:
    """Get the sun-hybrid form name of the certificate.

    Arguments:
    ---------
        - `cert`: The certificate to check.

    Returns:
    -------
        - The form name as a string (Form1, Form2, Form3, Form4).

    Raises:
    ------
        - ValueError: If the certificate is missing required extensions.

    Examples:
    --------
    | ${form}= | Get Sun Hybrid Form | ${cert} |

    """
    extensions = cert["tbsCertificate"]["extensions"]
    alt_sub_pub_key_ext = None
    alt_signature_ext = None

    for ext in extensions:
        if ext["extnID"] == id_altSubPubKeyExt:
            alt_sub_pub_key_ext, _ = decoder.decode(ext["extnValue"].asOctets(), AltSubPubKeyExt())
        elif ext["extnID"] == id_altSignatureExt:
            alt_signature_ext, _ = decoder.decode(ext["extnValue"].asOctets(), AltSignatureExt())

    if not alt_sub_pub_key_ext or not alt_signature_ext:
        raise ValueError("The certificate is missing required extensions.")

    sub_pub_key_by_val = alt_sub_pub_key_ext["byVal"]
    sig_by_val = alt_signature_ext["byVal"]

    if sub_pub_key_by_val and sig_by_val:
        return "Form1"
    if sub_pub_key_by_val and not sig_by_val:
        return "Form2"
    if not sub_pub_key_by_val and sig_by_val:
        return "Form3"

    return "Form4"


def _check_form_1_or_3(cert: rfc9480.CMPCertificate) -> Optional[rfc9480.CMPCertificate]:
    """Check if the certificate is in sun-hybrid form 1 or 3.

    :param cert: The certificate to check.
    :return: The certificate if it is in form 1 or 3, otherwise None.
    """
    extensions = cert["tbsCertificate"]["extensions"]
    for ext in extensions:
        if ext["extnID"] == id_altSignatureExt:
            derived_ext, _ = decoder.decode(ext["extnValue"].asOctets(), AltSignatureExt())
            if derived_ext["byVal"]:
                return cert

    return None


def validate_cert_contains_sun_hybrid_extensions(  # noqa: D417 Missing argument descriptions in the docstring
    cert: rfc9480.CMPCertificate,
) -> None:
    """Validate if the certificate contains the sun-hybrid extensions.

    Arguments:
    ---------
        - `cert`: The certificate to check.

    Raises:
    ------
        - `ValueError`: If the certificate is missing the required extensions.
        - `BadAsn1Data`: If the extensions are incorrectly encoded.
        - `ValueError`: If the extensions are not non-critical.

    Examples:
    --------
    | Check Cert Contains Sun Hybrid Extensions | ${cert} |

    """
    extn = certextractutils.get_extension(
        cert["tbsCertificate"]["extensions"], id_altSubPubKeyExt, must_be_non_crit=True
    )
    if extn is None:
        raise ValueError("The certificate is missing the AltSubPubKeyExt extension.")

    try:
        _, rest = decoder.decode(extn["extnValue"].asOctets(), AltSubPubKeyExt())
        if rest != b"":
            raise BadAsn1Data("Decoding of the AltSubPubKeyExt extension had trailing data.")
    except pyasn1.error.PyAsn1Error:  # type: ignore
        raise BadAsn1Data("The AltSubPubKeyExt extension is invalid.")  # pylint: disable=raise-missing-from

    extn = certextractutils.get_extension(
        cert["tbsCertificate"]["extensions"], id_altSignatureExt, must_be_non_crit=True
    )
    if extn is None:
        raise ValueError("The certificate is missing the AltSignatureExt extension.")

    try:
        _, rest = decoder.decode(extn["extnValue"].asOctets(), AltSignatureExt())
        if rest != b"":
            raise BadAsn1Data("Decoding of the AltSubPubKeyExt extension had trailing data.")
    except pyasn1.error.PyAsn1Error:  # type: ignore
        raise BadAsn1Data("The AltSubPubKeyExt extension is invalid.")  # pylint: disable=raise-missing-from


def contains_sun_hybrid_cert_form_1_or_3(  # noqa: D417 Missing argument descriptions in the docstring
    cert_form4: rfc9480.CMPCertificate, certs: Iterable[rfc9480.CMPCertificate]
):
    """Check if the list of certificates contains the sun-hybrid certificate in form 1 or 3.

    Arguments:
    ---------
        - `cert`: The certificate in form 4 to be expected.
        - `certs`: The list of certificates to check against.

    Returns:
    -------
        - The certificate in form 1 or 3, if found.

    Raises:
    ------
        - `ValueError`: If the certificate is not found.
        - `ValueError`: If the certificate does not match the expected certificate.

    Examples:
    --------
    | ${cert_form1}= | Contains Sun Hybrid Cert Form 1 or 3 | ${cert_form4} | ${certs} |

    """
    found = None
    for cert in certs:
        found = _check_form_1_or_3(cert)
        if found:
            break

    if found is None:
        raise ValueError("The certificate is not found.")

    tmp_form4 = convert_sun_hybrid_cert_to_target_form(found, "Form4")

    if encoder.encode(cert_form4) != encoder.encode(tmp_form4):
        raise ValueError("The certificate did not match the expected certificate.")

    return found


@keyword("Convert Sun-Hybrid Cert to Target Form")
def convert_sun_hybrid_cert_to_target_form(  # noqa: D417 Missing argument descriptions in the docstring
    cert: rfc9480.CMPCertificate, target_form: str
) -> rfc9480.CMPCertificate:
    """Convert the AltSubPubKeyExt and AltSignatureExt extensions inside a certificate to a specified form.

    First updates the alternative subject public key extension and then the alt signature extensions.

    Arguments:
    ---------
        - `cert`: The certificate to modify.
        - `target_form`: Target form, one of: "Form1", "Form2", "Form3", or "Form4".

    Returns:
    -------
        - The modified certificate with updated extensions.

    Raises:
    ------
        - `ValueError`: If the required extensions are missing or invalid.
        - `KeyError`: If the target form is invalid.

    Examples:
    --------
    | ${cert}= | Convert Sun-Hybrid Cert to Target Form | ${cert} | Form1 |

    """
    # -------------------------------------- #
    # AltSubKeyValueExt    AltSignatureExt   #
    # -------------------------------------- #
    # Form 1     ByValue         ByValue     #
    # Form 2     ByValue         ByReference #
    # Form 3     ByReference     ByValue     #
    # Form 4     ByReference     ByReference #
    # -------------------------------------- #
    form_map = {
        "Form1": (True, True),
        "Form2": (True, False),
        "Form3": (False, True),
        "Form4": (False, False),
    }
    # Make a copy of the certificate, so that the original is not modified.
    tmp_cert = copy_asn1_certificate(cert)

    if target_form not in form_map:
        raise ValueError("Invalid target form. Use 'Form1', 'Form2', 'Form3', or 'Form4'.")

    to_by_val_alt_sub_pub, to_by_val_alt_sig = form_map[target_form]

    tmp_cert = _parse_alt_sub_pub_key_extension(tmp_cert, to_by_val_alt_sub_pub)
    tmp_cert = _parse_alt_sig_extension(tmp_cert, to_by_val_alt_sig)

    return tmp_cert


@not_keyword
def process_public_key(data: Optional[bytes]) -> PublicKey:
    """Process the public key from the given bytes, in any sun hybrid form (1-4).

    :param data: The DER encoded public key.
    :return: The loaded public key object.
    """
    if data is None:
        raise ValueError("The public key data is None.")

    obj, rest = decoder.decode(data, rfc5280.SubjectPublicKeyInfo())
    if rest != b"":
        raise ValueError("Decoding of the public key had trailing data.")
    return keyutils.load_public_key_from_spki(obj)


def get_sun_hybrid_alt_pub_key(  # noqa: D417 Missing argument descriptions in the docstring
    extensions: rfc9480.Extensions,
) -> Optional[PublicKey]:
    """Extract the alternative public key from a certificate.

    Arguments:
    ---------
        - `extensions`: The extensions of the certificate.

    Returns:
    -------
        - The alternative public key.

    Raises:
    ------
        - ValueError: If the extension is missing or invalid.

    Examples:
    --------
    | ${pub_key}= | Get Sun Hybrid Alt Pub Key | ${extensions} |

    """
    extn = certextractutils.get_extension(extensions, id_altSubPubKeyExt)

    if extn is None:
        return None

    decoded_ext, _ = decoder.decode(extn["extnValue"].asOctets(), AltSubPubKeyExt())

    if decoded_ext["byVal"]:
        return keyutils.load_public_key_from_spki(decoded_ext["plainOrHash"].asOctets())

    location = decoded_ext["location"]

    if not location.isValue:
        raise ValueError(
            "The location in the AltSubPubKeyExt extension must be a value,to load the public key from the location."
        )

    actual_value = utils.fetch_value_from_location(str(location))

    obj, rest = decoder.decode(actual_value, rfc5280.SubjectPublicKeyInfo())
    if rest != b"":
        raise ValueError("Decoding of the public key had trailing data.")

    return keyutils.load_public_key_from_spki(obj)
