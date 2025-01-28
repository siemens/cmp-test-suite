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
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import char, tag, univ
from pyasn1_alt_modules import rfc2986, rfc4211, rfc5280, rfc6402, rfc9480
from resources import keyutils, utils
from resources.certbuildutils import (
    prepare_sig_alg_id,
    prepare_tbs_certificate,
    prepare_tbs_certificate_from_template,
    prepare_validity,
)
from resources.certextractutils import get_extension
from resources.convertutils import copy_asn1_certificate
from resources.cryptoutils import sign_data
from resources.keyutils import load_public_key_from_spki
from resources.oid_mapping import get_hash_from_oid, sha_alg_name_to_oid
from resources.protectionutils import prepare_sha_alg_id
from resources.typingutils import PublicKey
from robot.api.deco import not_keyword

from pq_logic import pq_compute_utils
from pq_logic.combined_factory import CombinedKeyFactory
from pq_logic.hybrid_structures import AltSignatureExt, AltSubPubKeyExt, UniformResourceIdentifier
from pq_logic.keys.comp_sig_cms03 import (
    CompositeSigCMSPublicKey,
    compute_hash,
)
from pq_logic.pq_utils import fetch_value_from_location
from pq_logic.tmp_oids import (
    CMS_COMPOSITE_OID_2_HASH,
    id_altSignatureExt,
    id_altSigValueHashAlgAttr,
    id_altSigValueLocAttr,
    id_altSubPubKeyExt,
    id_altSubPubKeyHashAlgAttr,
    id_altSubPubKeyLocAttr,
)


def _hash_public_key(public_key, hash_alg: str) -> bytes:
    """Hash a public key using the specified hash algorithm.

    :param public_key: The public key to hash.
    :param hash_alg: The hash algorithm name (e.g., "sha256").
    :return: The computed hash as bytes.
    :raises ValueError: If the hash algorithm is invalid.
    """
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return compute_hash(hash_alg, public_key_der)


##############
# CSR
#############


def prepare_alt_sub_pub_key_hash_alg_attr(hash_alg: str) -> rfc2986.Attribute:
    """Prepare the Alternative Subject Public Key Hash Algorithm Attribute.

    :param hash_alg: The hash algorithm name (e.g., "sha256").
    :return: `Attribute` representing the altSubPubKeyHashAlgAttr.
    """
    if not hash_alg:
        raise ValueError("hash_alg must not be None.")

    attr = rfc2986.Attribute()
    attr["type"] = id_altSubPubKeyHashAlgAttr
    attr["values"][0] = prepare_sha_alg_id(hash_alg)
    return attr


def prepare_alt_sub_pub_key_loc_attr(location: str) -> rfc2986.Attribute:
    """Prepare the Alternative Subject Public Key Location Attribute.

    :param location: URI string representing the location of the alternative public key.
    :return: `Attribute` representing the altSubPubKeyLocAttr.
    """
    attr = rfc2986.Attribute()
    attr["type"] = id_altSubPubKeyLocAttr
    attr["values"][0] = encoder.encode(char.IA5String(location))
    return attr


def prepare_alt_sig_value_hash_alg_attr(hash_alg: str) -> rfc2986.Attribute:
    """Prepare the Alternative Signature Value Hash Algorithm Attribute.

    :param hash_alg: The hash algorithm name (e.g., "sha256").
    :return: `Attribute` representing the altSigValueHashAlgAttr.
    """
    if not hash_alg:
        raise ValueError("hash_alg must not be None.")

    attr = rfc2986.Attribute()
    attr["type"] = id_altSigValueHashAlgAttr
    attr["values"][0] = prepare_sha_alg_id(hash_alg)
    return attr


def prepare_alt_sig_value_loc_attr(location: str) -> rfc2986.Attribute:
    """Prepare the Alternative Signature Value Location Attribute.

    :param location: URI string representing the location of the alternative signature.
    :return: `Attribute` representing the altSigValueLocAttr.
    """
    attr = rfc2986.Attribute()
    attr["type"] = id_altSigValueLocAttr
    attr["values"][0] = char.IA5String(location)
    return attr


def prepare_sun_hybrid_csr_attributes(
    pub_key_hash_alg: Optional[str] = None,
    pub_key_location: Optional[str] = None,
    sig_hash_alg: Optional[str] = None,
    sig_value_location: Optional[str] = None,
) -> List[rfc2986.Attribute]:
    """Prepare all alternative public key and signature attributes.

    :param pub_key_hash_alg: AlgorithmIdentifier for the public key hash algorithm (optional).
    :param pub_key_location: URI string for the alternative public key location (optional).
    :param sig_hash_alg: AlgorithmIdentifier for the signature hash algorithm (optional).
    :param sig_value_location: URI string for the alternative signature location (optional).
    :return: List of rfc2986.Attribute objects.
    """
    attributes = []

    if pub_key_hash_alg is not None:
        attributes.append(prepare_alt_sub_pub_key_hash_alg_attr(pub_key_hash_alg))

    if pub_key_location is not None:
        attributes.append(prepare_alt_sub_pub_key_loc_attr(pub_key_location))

    if sig_hash_alg is not None:
        attributes.append(prepare_alt_sig_value_hash_alg_attr(sig_hash_alg))

    if sig_value_location is not None:
        attributes.append(prepare_alt_sig_value_loc_attr(sig_value_location))

    return attributes


##############
# X.509
#############


def prepare_sun_hybrid_alt_sub_pub_key_ext(
    public_key: rsa.RSAPublicKey,
    by_val: bool,
    hash_alg: Optional[str] = None,
    location: Optional[str] = None,
    critical: bool = False,
) -> rfc5280.Extension:
    """Prepare the `AltSubPubKeyExt` as an rfc5280.Extension.

    :param public_key: Cryptography RSA public key representing the alternative public key or its hash value.
    :param by_val: Boolean indicating byVal. If True, the public_key contains the actual key value.
                    If False, the public_key contains the hash of the alternative public key.
    :param hash_alg: The hash algorithm name (e.g., "sha256"). Required if by_val is False.
    :param location: Optional URI string representing the location of the alternative public key.
    :return: `Extension` instance representing the AltSubPubKeyExt.
    :raises ValueError: If inputs are invalid (e.g., missing required fields).
    """
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    obj, _ = decoder.decode(public_key_der, rfc5280.SubjectPublicKeyInfo())

    # If byVal is False, calculate the hash of the public key
    if not by_val:
        if not hash_alg:
            raise ValueError("hash_alg must be provided when byVal is False.")
        public_key_der = compute_hash(alg_name=hash_alg, data=public_key_der)

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


def prepare_sun_hybrid_alt_signature_ext(
    signature: bytes,
    by_val: bool,
    alt_sig_algorithm: rfc9480.AlgorithmIdentifier,
    hash_alg: Optional[str] = None,
    location: Optional[str] = None,
    critical: bool = False,
) -> rfc5280.Extension:
    """
    Prepare the `AltSignatureExt` as an rfc5280.Extension.

    :param signature: Bytes representing the alternative signature or its hash value.
    :param by_val: Boolean indicating byVal. If True, the signature contains the actual signature value.
                   If False, the signature contains the hash of the alternative signature.
    :param alt_sig_algorithm: AlgorithmIdentifier for the alternative signature algorithm.
    :param hash_alg: The hash algorithm name (e.g., "sha256"). Required if by_val is False.
    :param location: Optional URI string representing the location of the alternative signature.
    :param critical: Whether the extension is critical.
    :return: rfc5280.Extension instance representing the AltSignatureExt.
    :raises ValueError: If inputs are invalid (e.g., missing required fields).
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
        signature = compute_hash(hash_alg, signature)

    alt_signature_ext = AltSignatureExt()
    alt_signature_ext["byVal"] = by_val
    alt_signature_ext["plainOrHash"] = univ.BitString.fromOctetString(signature)
    alt_signature_ext["altSigAlgorithm"] = alt_sig_algorithm

    if hash_alg is not None or not by_val:
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

        if oid == id_altSubPubKeyHashAlgAttr or oid == id_altSigValueHashAlgAttr:
            alg_id, _ = decoder.decode(attribute["attrValues"][0].asOctets(), rfc9480.AlgorithmIdentifier())
            key = attribute_map[oid]
            extracted_values[key] = alg_id

        elif oid in attribute_map:
            key = attribute_map[oid]
            extracted_values[key] = decoder.decode(attribute["attrValues"][0].asOctets())[0].prettyPrint()

    return extracted_values


def sun_csr_to_cert(
    csr: rfc6402.CertificationRequest,
    issuer_private_key,
    alt_private_key,
    issuer_cert: Optional[rfc9480.CMPCertificate] = None,
    hash_alg: str = "sha256",
    extensions: Optional[List[rfc5280.Extension]] = None,
) -> Tuple[rfc9480.CMPCertificate, rfc9480.CMPCertificate]:
    """Convert a CSR to a certificate, with the sun hybrid methode.

    :param csr: The CSR to convert.
    :param issuer_cert:
    :param issuer_private_key: The private key of the issuer for signing.
    :param alt_private_key: The certificate of the issuer.Optional alternative private key for creating AltSignatureExt.
    :param hash_alg: Hash algorithm for signing the certificate (e.g., "sha256").
    :param extensions: Optional list of additional extensions to include in the certificate.
    :return: A tuple of the Form4 and Form1 certificates.
    """
    public_key = CompositeSigCMSPublicKey.from_spki(csr["certificationRequestInfo"]["subjectPublicKeyInfo"])
    oid = csr["signatureAlgorithm"]["algorithm"]
    data: dict = _extract_sun_hybrid_attrs_from_csr(csr)

    if data["pub_key_hash_id"] is None:
        data["pub_key_hash_id"] = CMS_COMPOSITE_OID_2_HASH[oid] or hash_alg
    else:
        data["pub_key_hash_id"] = get_hash_from_oid(data["pub_key_hash_id"]["algorithm"])

    if data["sig_hash_id"] is None:
        data["sig_hash_id"] = CMS_COMPOSITE_OID_2_HASH[oid] or hash_alg
    else:
        data["sig_hash_id"] = get_hash_from_oid(data["sig_hash_id"]["algorithm"])

    not_before = datetime.now()
    not_after = datetime.now() + timedelta(days=365 * 10)
    validity = prepare_validity(not_before=not_before, not_after=not_after)
    cert_form4, ext_sig, ext_pub = prepare_sun_hybrid_pre_tbs_certificate(
        public_key,
        alt_private_key=alt_private_key,
        issuer_private_key=issuer_private_key,
        csr=csr,
        validity=validity,
        hash_alg=hash_alg,
        issuer_cert=issuer_cert,
        extensions=extensions,
        **data,
    )

    cert_form1 = copy_asn1_certificate(cert_form4)

    # build Form1
    cert_form1["tbsCertificate"]["extensions"] = _patch_extensions(cert_form1["tbsCertificate"]["extensions"], ext_sig)
    cert_form1["tbsCertificate"]["extensions"] = _patch_extensions(cert_form1["tbsCertificate"]["extensions"], ext_pub)

    return cert_form4, cert_form1


def sun_cert_template_to_cert(
    cert_template: rfc4211.CertTemplate,
    issuer_cert: rfc9480.CMPCertificate,
    issuer_private_key,
    alt_private_key,
    pub_key_loc: Optional[str],
    sig_loc: Optional[str],
    hash_alg: Optional[str] = None,
) -> Tuple[rfc9480.CMPCertificate, rfc9480.CMPCertificate]:
    """Convert a certificate template to a certificate, with the sun hybrid method.


    :param cert_template: The certificate template, to built the certificate from.
    :param issuer_cert: The issuer's certificate to use for constructing the certificate.
    :param issuer_private_key: The private key of the issuer for signing.
    :param alt_private_key: The alternative private key for creating the alternative signature.
    :param pub_key_loc: The location of the alternative public key.
    :param sig_loc: The location of the alternative signature.
    :param hash_alg: The hash algorithm to use for signing the certificate (e.g., "sha256").
    :return: A tuple of the Form4 and Form1 certificates.
    """
    tbs_cert = prepare_tbs_certificate_from_template(
        cert_template=cert_template,
        issuer_cert=issuer_cert["tbsCertificate"]["subject"],
    )

    composite_key = load_public_key_from_spki(tbs_cert["subjectPublicKeyInfo"])
    oid = composite_key.get_oid()
    hash_alg = CMS_COMPOSITE_OID_2_HASH[oid] or hash_alg or "sha256"
    extn_alt_pub, extn_alt_pub2 = _prepare_public_key_extensions(composite_key, hash_alg, pub_key_loc)

    tbs_cert["extensions"].append(extn_alt_pub)

    pre_tbs_cert = tbs_cert
    data = encoder.encode(pre_tbs_cert)
    signature = sign_data(key=alt_private_key, data=data, hash_alg=hash_alg)
    sig_alg_id = prepare_sig_alg_id(signing_key=alt_private_key, hash_alg=hash_alg, use_rsa_pss=False)

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
    signature = sign_data(key=issuer_private_key, data=final_tbs_cert_data, hash_alg=hash_alg)
    sig_alg_id = prepare_sig_alg_id(signing_key=issuer_private_key, hash_alg=hash_alg, use_rsa_pss=False)

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
    composite_key: CompositeSigCMSPublicKey,
    pub_key_hash_id: str,
    pub_key_loc: Optional[str],
) -> Tuple[rfc5280.Extension, rfc5280.Extension]:
    """Prepare the public key extensions for the Sun-Hybrid certificate.

    :param composite_key: The composite key containing both the primary and alternative keys.
    :param pub_key_hash_id: The hash algorithm identifier for hashing the alternative public key.
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
    composite_key: CompositeSigCMSPublicKey,
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
):
    """Prepare a `TBSCertificate` structure with alternative public key and signature extensions.

    :param composite_key: The composite key containing both the primary and alternative keys.
    :param issuer_private_key: The issuer's private key for signing the certificate.
    :param alt_private_key: The alternative private key used for the alternative signature.
    :param issuer_cert: The issuer's certificate to use for constructing the certificate.
    :param csr: The certificate signing request from which to construct the certificate.
    :param pub_key_hash_id: The hash algorithm identifier for hashing the alternative public key.
    :param sig_hash_id: The hash algorithm identifier for hashing the alternative signature.
    :param hash_alg: The hash algorithm used for signing the TBSCertificate.
    :param validity: The validity object for the certificate.
    :param pub_key_loc: An optional URI representing the location of the alternative public key.
    :param sig_loc: An optional URI representing the location of the alternative signature.
    :return: A fully prepared TBSCertificate wrapped in a certificate structure.
    :raises ValueError: If required parameters are missing or invalid.
    """
    # Compute a hash by hashing pk_1
    extn_alt_pub, extn_alt_pub2 = _prepare_public_key_extensions(composite_key, pub_key_hash_id, pub_key_loc)

    # After creating an AltSubPubKeyExt extension, an issuer constructs a TBSCertificate
    # object from attributes in the given
    # CSR following existing standards, e.g., [RFC2986] and [RFC5280].
    # The constructed TBSCertificate object is the preTbsCertificate field, which MUST
    # inlude the created AltSubPubKeyExt extension.

    subject = utils.get_openssl_name_notation(csr["certificationRequestInfo"]["subject"])
    pre_tbs_cert = prepare_tbs_certificate(
        subject=subject,
        signing_key=issuer_private_key,
        issuer_cert=issuer_cert,
        public_key=composite_key.trad_key,  # Construct a SubjectPublicKeyInfo object from pk_1
        validity=validity,
        hash_alg=hash_alg,
        extensions=[extn_alt_pub] + []
        if not extensions
        else extensions,  # The constructed TBSCertificate object is the preTbsCertificate
        # field, which MUST include the created `AltSubPubKeyExt` extension.
    )

    data = encoder.encode(pre_tbs_cert)
    signature = sign_data(key=alt_private_key, data=data, hash_alg=sig_hash_id)
    sig_alg_id = prepare_sig_alg_id(signing_key=alt_private_key, hash_alg=sig_hash_id, use_rsa_pss=False)

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
    signature = sign_data(key=issuer_private_key, data=final_tbs_cert_data, hash_alg=hash_alg)
    sig_alg_id = prepare_sig_alg_id(signing_key=issuer_private_key, hash_alg=hash_alg, use_rsa_pss=False)

    cert = rfc9480.CMPCertificate()
    cert["tbsCertificate"] = pre_tbs_cert
    cert["signature"] = univ.BitString.fromOctetString(signature)
    cert["signatureAlgorithm"] = sig_alg_id

    return cert, extn_alt_sig2, extn_alt_pub2


def validate_alt_pub_key_extn(cert: rfc9480.CMPCertificate):
    """Validate the `AltSubPubKeyExt` extension in a certificate.

    Ensures that the AltSubPubKeyExt extension in the certificate is valid
    and that the hash of the alternative public key matches the expected value.

    :param cert: The certificate to validate.
    :return: The loaded alternative public key if the extension is valid.
    :raises ValueError: If the extension is missing, critical, or invalid.
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

    actual_value = fetch_value_from_location(str(location))
    public_key = process_public_key(actual_value)

    hash_alg_oid = decoded_ext["hashAlg"]["algorithm"]
    hash_alg = get_hash_from_oid(hash_alg_oid)
    logging.info(f"Alt Public key: {public_key}")
    logging.info(f"hash alg: {hash_alg}")

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

    return CombinedKeyFactory.load_public_key_from_spki(spki)


def validate_alt_sig_extn(cert: rfc9480.CMPCertificate, alt_pub_key, signature: Optional[bytes] = None):
    """Validate the `AltSignatureExt` extension in a certificate.

    Verifies the alternative signature in the AltSignatureExt extension
    against the pre-tbsCertificate data.

    :param cert: The certificate to validate.
    :param alt_pub_key: The alternative public key used to verify the signature.
    :param signature: The alternative signature which can be cached.
    :raises ValueError: If the extension is missing, critical, or invalid.
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
        else:
            new_extn.append(x)

    cert["tbsCertificate"]["extensions"] = new_extn

    data = encoder.encode(cert["tbsCertificate"])

    if signature is None:
        signature = fetch_value_from_location(decoded_ext["location"]) if decoded_ext["location"].isValue else None
    sig_alg_id = decoded_ext["altSigAlgorithm"]

    hash_alg = get_hash_from_oid(decoded_ext["hashAlg"]["algorithm"])
    hashed_sig = decoded_ext["plainOrHash"].asOctets()
    if hashed_sig != compute_hash(alg_name=hash_alg, data=signature):
        raise ValueError("The fetched signature was invalid!")

    pq_compute_utils.verify_signature_with_alg_id(
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
        if ext["extnID"] == extension["extnID"]:
            extensions[i] = extension
            return extensions

    raise ValueError("The extension was not inside the `Extensions` structure.")


def parse_alt_sig_extension(cert: rfc9480.CMPCertificate, to_by_val: bool) -> rfc9480.CMPCertificate:
    """Parse and convert the AltSignatureExt extension in the given certificate.

    Converts the extension to either ByValue or ByReference format as specified.

    :param cert: The certificate containing the AltSignatureExt.
    :param to_by_val: Boolean indicating whether to convert to ByValue (True) or ByReference (False).
    :return: The modified certificate with the updated AltSignatureExt.
    :raises ValueError: If the AltSignatureExt is missing or invalid.
    """
    extensions = cert["tbsCertificate"]["extensions"]
    extension = get_extension(extensions, id_altSignatureExt, must_be_non_crit=True)
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
        fetched_signature = fetch_value_from_location(location)
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


def parse_alt_sub_pub_key_extension(cert: rfc9480.CMPCertificate, to_by_val: bool) -> rfc9480.CMPCertificate:
    """Parse and convert the AltSubPubKeyExt extension in the given certificate.

    Converts the extension to either ByValue or ByReference format as specified.

    :param cert: The certificate containing the AltSubPubKeyExt.
    :param to_by_val: Boolean indicating whether to convert to ByValue (True) or ByReference (False).
    :return: The modified certificate with the updated AltSubPubKeyExt.
    :raises ValueError: If the AltSubPubKeyExt is missing or invalid.
    """
    extensions = cert["tbsCertificate"]["extensions"]
    extension = get_extension(extensions, id_altSubPubKeyExt, must_be_non_crit=True)
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
        public_key = fetch_value_from_location(loc)
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


def convert_cert_to_target_form(cert, target_form: str):
    """Convert the AltSubPubKeyExt and AltSignatureExt extensions inside a certificate to a specified form.

    First updates the alternative subject public key extension and then the alt signature extensions.

    :param cert: The certificate to modify.
    :param target_form: Target form, one of: "Form1", "Form2", "Form3", or "Form4".
    :return: The modified certificate with updated extensions.
    :raises ValueError: If the target form is invalid or the required extensions are missing.
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

    if target_form not in form_map:
        raise ValueError("Invalid target form. Use 'Form1', 'Form2', 'Form3', or 'Form4'.")

    to_by_val_alt_sub_pub, to_by_val_alt_sig = form_map[target_form]

    cert = parse_alt_sub_pub_key_extension(cert, to_by_val_alt_sub_pub)
    cert = parse_alt_sig_extension(cert, to_by_val_alt_sig)

    return cert


def process_public_key(data: bytes):
    """Process the public key from the given bytes, in any sun hybrid form (1-4).

    :param data: The DER encoded public key.
    :return: The loaded public key object.
    """
    obj, rest = decoder.decode(data, rfc5280.SubjectPublicKeyInfo())
    if rest != b"":
        raise ValueError("Decoding of the public key had trailing data.")
    return load_public_key_from_spki(obj)


def get_sun_hybrid_alt_pub_key(extensions: rfc9480.Extensions) -> Optional[PublicKey]:
    """Extract the alternative public key from a certificate.

    :param extensions: The extensions of the certificate.
    :return: The alternative public key.
    """
    extn = get_extension(extensions, id_altSubPubKeyExt)

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

    actual_value = fetch_value_from_location(str(location))

    obj, rest = decoder.decode(actual_value, rfc5280.SubjectPublicKeyInfo())
    if rest != b"":
        raise ValueError("Decoding of the public key had trailing data.")

    return keyutils.load_public_key_from_spki(obj)
