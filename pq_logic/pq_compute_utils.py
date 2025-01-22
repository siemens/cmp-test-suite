# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Utility functions for verifying hybrid signatures."""

import logging
from typing import List, Optional, Sequence, Union

from pyasn1.codec.der import encoder
from pyasn1_alt_modules import rfc5280, rfc6402, rfc9480
from resources.certextractutils import get_extension
from resources.certutils import load_public_key_from_cert
from resources.cryptoutils import sign_data
from resources.exceptions import BadAsn1Data, UnknownOID
from resources.keyutils import load_public_key_from_spki
from resources.oid_mapping import get_hash_from_oid
from resources.oidutils import CMS_COMPOSITE_OID_2_NAME, MSG_SIG_ALG, PQ_OID_2_NAME, RSASSA_PSS_OID_2_NAME
from resources.typingutils import PublicKeySig
from robot.api.deco import not_keyword

from pq_logic.hybrid_sig.catalyst_logic import SubjectAltPublicKeyInfoExt, id_ce_subjectAltPublicKeyInfo
from pq_logic.hybrid_sig.certdiscovery import (
    extract_sia_extension_for_cert_discovery,
    get_secondary_certificate,
    validate_alg_ids,
)
from pq_logic.hybrid_sig.sun_lamps_hybrid_scheme_00 import validate_alt_pub_key_extn, validate_alt_sig_extn
from pq_logic.keys.abstract_pq import PQSignaturePrivateKey, PQSignaturePublicKey
from pq_logic.keys.comp_sig_cms03 import CompositeSigCMSPrivateKey, CompositeSigCMSPublicKey
from pq_logic.pq_key_factory import PQKeyFactory
from pq_logic.py_verify_logic import verify_signature_with_alg_id
from pq_logic.tmp_oids import id_relatedCert


def sign_data_with_alg_id(key, alg_id: rfc9480.AlgorithmIdentifier, data: bytes) -> bytes:
    """Sign the provided data using the given algorithm identifier.

    :param key: The private key object used to sign the data.
    :param alg_id: The algorithm identifier specifying the algorithm and any associated parameters for signing.
    :param data: The data to sign, as a byte string.
    :return: The digital signature as a byte string.
    """
    oid = alg_id["algorithm"]

    if isinstance(key, CompositeSigCMSPrivateKey) or oid in CMS_COMPOSITE_OID_2_NAME:
        name: str = CMS_COMPOSITE_OID_2_NAME[oid]
        use_pss = name.endswith("-pss")
        pre_hash = name.startswith("hash-")
        key: CompositeSigCMSPrivateKey
        return key.sign(data=data, use_pss=use_pss, pre_hash=pre_hash)

    elif oid in PQ_OID_2_NAME or oid in MSG_SIG_ALG:
        hash_alg = get_hash_from_oid(oid, only_hash=True)
        use_pss = oid in RSASSA_PSS_OID_2_NAME
        return sign_data(key=key, data=data, hash_alg=hash_alg, use_rsa_pss=use_pss)
    else:
        raise ValueError(f"Unsupported public key type: {type(key).__name__}.")


# TODO fix parse catalyst directly.
def verify_cert_hybrid_signature(
    ee_cert: rfc9480.CMPCertificate,
    issuer_cert: rfc9480.CMPCertificate,
    other_cert: rfc9480.CMPCertificate,
    catalyst_key: PQSignaturePrivateKey = None,
) -> None:
    """Verify the hybrid signature of an end-entity (EE) certificate using the appropriate composite method.

    :param ee_cert: The end-entity certificate (`CMPCertificate`) to be verified. This certificate
                    contains the hybrid signature and its algorithm identifier.
    :param issuer_cert: The issuer certificate providing the traditional public key or composite signature key.
    :param other_cert: The secondary certificate containing the
                       post-quantum public key (e.g., ML-DSA or another PQ signature algorithm)
                       used in the composite signature. (as an example, use-case for cert discovery)
    :param catalyst_key: Optional. A post-quantum private key (`PQSignaturePrivateKey`) used for creating
                         a composite key dynamically when `other_cert` is not provided.

    :raises ValueError:
        - If the OID in the `ee_cert` is unsupported or invalid.
        - If neither `other_cert` nor `catalyst_key` is provided when required.
    :raises NotImplementedError: If the signature algorithm OID is not supported for verification.
    :raises InvalidSignature: If the signature verification fails.
    """
    oid = ee_cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]
    alg_id = ee_cert["tbsCertificate"]["signature"]
    spki = other_cert["tbsCertificate"]["subjectPublicKeyInfo"]
    if oid in CMS_COMPOSITE_OID_2_NAME:
        if other_cert is None and catalyst_key is None:
            composite_key = PQKeyFactory.load_public_key_from_spki(spki)
            if not isinstance(composite_key, CompositeSigCMSPublicKey):
                raise ValueError()
        elif other_cert is not None:
            trad_key = load_public_key_from_spki(issuer_cert["tbsCertificate"]["subjectPublicKeyInfo"])
            pq_key = PQKeyFactory.load_public_key_from_spki(other_cert["tbsCertificate"]["subjectPublicKeyInfo"])
            composite_key = CompositeSigCMSPublicKey(pq_key, trad_key=trad_key)

        else:
            trad_key = load_public_key_from_spki(issuer_cert["tbsCertificate"]["subjectPublicKeyInfo"])
            composite_key = CompositeSigCMSPublicKey(catalyst_key, trad_key=trad_key)

        data = encoder.encode(ee_cert["tbsCertificate"])
        signature = ee_cert["signature"].asOctets()
        CompositeSigCMSPrivateKey.validate_oid(oid, composite_key)
        verify_signature_with_alg_id(composite_key, alg_id=alg_id, signature=signature, data=data)

    else:
        raise NotImplementedError(f"Unsupported algorithm OID: {oid}. Verification not implemented.")


@not_keyword
def verify_csr_signature(csr: rfc6402.CertificationRequest) -> None:
    """Verify a certification request (CSR) signature using the appropriate algorithm.

    :param csr: THe certification request (`CertificationRequest`) to be verified.
    :raises ValueError: If the algorithm OID in the CSR is unsupported or invalid.
    :raises InvalidSignature: If the signature verification fails.
    """
    alg_id = csr["signatureAlgorithm"]
    spki = csr["certificationRequestInfo"]["subjectPublicKeyInfo"]

    if alg_id["algorithm"] in PQ_OID_2_NAME:
        public_key = PQKeyFactory.load_public_key_from_spki(spki=spki)
    elif alg_id["algorithm"] in CMS_COMPOSITE_OID_2_NAME:
        public_key = CompositeSigCMSPublicKey.from_spki(spki)
        CompositeSigCMSPublicKey.validate_oid(alg_id["algorithm"], public_key)
    else:
        public_key = load_public_key_from_spki(spki)

    signature = csr["signature"].asOctets()
    alg_id = csr["signatureAlgorithm"]
    data = encoder.encode(csr["certificationRequestInfo"])
    verify_signature_with_alg_id(public_key=public_key, alg_id=alg_id, signature=signature, data=data)


CertOrCerts = Union[rfc9480.CMPCertificate, Sequence[rfc9480.CMPCertificate]]


def _verify_signature_with_other_cert(
    cert: rfc9480.CMPCertificate,
    sig_alg: rfc9480.AlgorithmIdentifier,
    data: bytes,
    signature: bytes,
    other_certs: Optional[CertOrCerts] = None,
) -> None:
    """Verify a Composite Signature Certificate using two certificates.

    :param cert: The certificate to verify.
    :param sig_alg: The signature algorithm identifier.
    :param data: The data to verify.
    :param signature: The signature to verify.
    :param other_certs: A single certificate or a sequence of certificates to extract
    the related certificate.
    :raises ValueError: If the related certificate is not provided.
    :raises UnknownOID: If the signature algorithm OID is not supported.
    :raises InvalidSignature: If the signature verification fails.
    """
    sig_alg_oid = sig_alg["algorithm"]

    if sig_alg_oid not in CMS_COMPOSITE_OID_2_NAME:
        raise ValueError("The signature algorithm is not a composite signature one.")

    if other_certs is not None:
        other_certs = other_certs if not isinstance(other_certs, rfc9480.CMPCertificate) else [other_certs]

    pq_key = may_extract_alt_key_from_cert(cert=cert, other_certs=other_certs)
    if pq_key is None:
        raise ValueError("No alternative issuer key found.")

    trad_key = load_public_key_from_spki(cert["tbsCertificate"]["subjectPublicKeyInfo"])

    if not isinstance(pq_key, PQSignaturePublicKey):
        trad_key, pq_key = pq_key, trad_key

    if sig_alg_oid in CMS_COMPOSITE_OID_2_NAME:
        public_key = CompositeSigCMSPublicKey(pq_key=pq_key, trad_key=trad_key)
        CompositeSigCMSPublicKey.validate_oid(sig_alg_oid, public_key)

    else:
        raise UnknownOID(sig_alg_oid, extra_info="Composite signature can not be verified, with 2-certs.")

    verify_signature_with_alg_id(public_key, sig_alg, data, signature)


def verify_signature_with_hybrid_cert(
    data: bytes,
    signature: bytes,
    sig_alg: rfc9480.AlgorithmIdentifier,
    cert: rfc9480.CMPCertificate,
    other_certs: Optional[CertOrCerts] = None,
) -> None:
    """Verify a signature using a hybrid certificate.

    Expected to either get a composite signature certificate or a certificate with a related certificate extension.
    or a certificate with a cert discovery extension. So that the second certificate can be extracted.

    :param data: The data to verify.
    :param signature: The signature to verify against the data.
    :param sig_alg: The signature algorithm identifier.
    :param cert: The certificate may contain a composite signature key or a single key.
    :param other_certs: A single certificate or a sequence of certificates to extract
    the related certificate from.
    :raises ValueError: If the alternative key cannot be obtained.
    :raises UnknownOID: If the signature algorithm OID is not supported.
    :raises InvalidSignature: If the signature verification fails.
    :raises ValueError: If the `cert` contains a PQ signature algorithm.
    It Should be a traditional algorithm for migration strategy.
    """
    if sig_alg["algorithm"] not in CMS_COMPOSITE_OID_2_NAME:
        raise ValueError("The signature algorithm is not a composite signature.")

    cert_sig_alg = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]
    if cert_sig_alg in MSG_SIG_ALG:
        logging.info("The certificate contains a traditional signature algorithm.")
        _verify_signature_with_other_cert(cert, sig_alg, data, signature, other_certs=other_certs)
        return

    elif cert_sig_alg in PQ_OID_2_NAME:
        raise ValueError(
            "The certificate contains a post-quantum signature algorithm."
            "please use traditional signature algorithm"
            "because the migration should test use case of "
            "having the certificate with traditional signature algorithm."
        )

    elif cert_sig_alg in CMS_COMPOSITE_OID_2_NAME:
        logging.info("The certificate contains a composite signature algorithm.")
        public_key = CompositeSigCMSPublicKey.from_spki(cert["tbsCertificate"]["subjectPublicKeyInfo"])
        CompositeSigCMSPublicKey.validate_oid(cert_sig_alg, public_key)
        verify_signature_with_alg_id(public_key, sig_alg, data, signature)

    else:
        raise UnknownOID(sig_alg["algorithm"], extra_info="Composite signature can not be verified.")


def may_extract_alt_key_from_cert(
    cert: rfc9480.CMPCertificate, other_certs: Optional[List[rfc9480.CMPCertificate]] = None
) -> Optional[PQSignaturePublicKey]:
    """May extract the alternative public key from a certificate.

    Either extracts the alternative public key from the issuer's certificate or from the certificate discovery extension.
    Alternative extracts the pq_key of the related certificate from the issuer's certificate or
    if the issuer's certificate is a composite signature certificate, extracts the pq_key from the composite signature
    keys.

    :param cert: The certificate from which to extract the alternative public key.
    :param other_certs: A list of other certificates to search for the related certificate.
    :return: The extracted alternative public key or None if not found.
    """
    extensions = cert["tbsCertificate"]["extensions"]
    extn_rel_cert = get_extension(extensions, id_relatedCert)
    extn_sia = get_extension(extensions, rfc5280.id_pe_subjectInfoAccess)
    extn_alt_spki = get_extension(extensions, id_ce_subjectAltPublicKeyInfo)

    try:
        rel_cert_desc = extract_sia_extension_for_cert_discovery(extn_sia)
    except ValueError:
        rel_cert_desc = None

    # TODO fix try to validate both.

    spki = cert["tbsCertificate"]["subjectPublicKeyInfo"]
    oid = spki["algorithm"]["algorithm"]

    if extn_rel_cert is not None and other_certs is not None:
        logging.info("Validate signature with related certificate.")
        related_cert = get_related_cert_from_list(other_certs, cert)  # type: ignore
        pq_key = load_public_key_from_spki(related_cert["tbsCertificate"]["subjectPublicKeyInfo"])
        return pq_key

    if extn_rel_cert is not None and other_certs is None:
        logging.warning("Related certificate extension found but no other certificates provided.")

    if extn_alt_spki is not None:
        logging.info("Validate signature with alternative public key.")
        spki, rest = decoder.decode(extn_alt_spki["extnValue"].asOctets(), SubjectAltPublicKeyInfoExt())
        if rest:
            raise BadAsn1Data("The alternative public key extension contains remainder data.", overwrite=True)
        alt_issuer_key = load_public_key_from_spki(spki)
        return alt_issuer_key

    if rel_cert_desc is not None:
        logging.info("Validate signature with cert discovery.")
        uri = str(rel_cert_desc["uniformResourceIdentifier"])
        other_cert = get_secondary_certificate(uri)
        validate_alg_ids(other_cert, rel_cert_desc=rel_cert_desc)
        pq_key = load_public_key_from_spki(other_cert["tbsCertificate"]["subjectPublicKeyInfo"])
        return pq_key

    if oid in CMS_COMPOSITE_OID_2_NAME:
        public_key = CompositeSigCMSPublicKey.from_spki(spki)
        CompositeSigCMSPublicKey.validate_oid(oid, public_key)
        return CompositeSigCMSPublicKey.pq_key

    return None


def verify_sun_hybrid_cert(
    cert: rfc9480.CMPCertificate,
    issuer_cert: rfc9480.CMPCertificate,
    alt_issuer_key: Optional[PublicKeySig] = None,
    check_alt_sig: bool = True,
    other_certs: Optional[List[rfc9480.CMPCertificate]] = None,
):
    """Verify a Sun hybrid certificate.

    Validates the primary and alternative signatures in a certificate.
    The main signature is verified using the issuer's tradition key inside the certificate public key.
    And the alternative signature is verified using the issuer's alternative key.

    :param cert: The SUN hybrid certificate to verify.
    :param issuer_cert: The issuer's certificate for verifying the main signature.
    :param check_alt_sig: Whether to validate the alternative signature (default: True).
    :param alt_issuer_key: The issuer's public key for verifying the alternative signature.
    Otherwise, will need to get the public key from the issuer's certificate.
    :param other_certs: A list of other certificates to search for the related certificate.
    :raises ValueError: If validation fails for the certificate or its extensions.
    :raises ValueError: If the alternative issuer key is not found.
    :raises BadAsn1Data: If the AlternativePublicKeyInfo extension contains remainder data.
    """
    if alt_issuer_key is None:
        alt_issuer_key = may_extract_alt_key_from_cert(issuer_cert, other_certs=other_certs)
        if alt_issuer_key is None:
            raise ValueError("No alternative issuer key found.")

    alt_pub_key = validate_alt_pub_key_extn(cert)
    if check_alt_sig:
        validate_alt_sig_extn(cert, alt_pub_key, alt_issuer_key)

    public_key = load_public_key_from_cert(issuer_cert)
    data = encoder.encode(cert["tbsCertificate"])
    alg_id = cert["tbsCertificate"]["signature"]
    signature = cert["signature"].asOctets()
    verify_signature_with_alg_id(public_key=public_key, data=data, signature=signature, alg_id=alg_id)
