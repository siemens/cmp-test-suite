# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Utility functions for verifying hybrid signatures."""

import logging
from typing import List, Optional, Tuple, Union

from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc5280, rfc6402, rfc9480

from pq_logic.hybrid_sig import chameleon_logic
from resources import utils
from resources.certbuildutils import prepare_sig_alg_id
from resources.certextractutils import get_extension
from resources.convertutils import subjectPublicKeyInfo_from_pubkey
from resources.cryptoutils import sign_data, verify_signature
from resources.exceptions import BadAsn1Data
from resources.keyutils import load_public_key_from_spki
from resources.oid_mapping import get_hash_from_oid, may_return_oid_to_name
from resources.oidutils import CMS_COMPOSITE_OID_2_NAME, MSG_SIG_ALG, PQ_OID_2_NAME, RSASSA_PSS_OID_2_NAME
from resources.protectionutils import (
    patch_sender_and_sender_kid,
    prepare_pki_protection_field,
    verify_rsassa_pss_from_alg_id,
)
from resources.typingutils import PrivateKeySig, PublicKeySig
from robot.api.deco import not_keyword

import pq_logic.hybrid_sig.sun_lamps_hybrid_scheme_00
from pq_logic.hybrid_sig.catalyst_logic import (
    id_ce_altSignatureAlgorithm,
    id_ce_altSignatureValue,
    id_ce_subjectAltPublicKeyInfo,
)
from pq_logic.hybrid_structures import SubjectAltPublicKeyInfoExt
from pq_logic.hybrid_sig.cert_binding_for_multi_auth import get_related_cert_from_list
from pq_logic.hybrid_sig.certdiscovery import (
    extract_sia_extension_for_cert_discovery,
    get_cert_discovery_cert,
    validate_alg_ids,
)
from pq_logic.keys.abstract_pq import PQSignaturePrivateKey, PQSignaturePublicKey
from pq_logic.keys.comp_sig_cms03 import CompositeSigCMSPrivateKey, CompositeSigCMSPublicKey
from pq_logic.pq_key_factory import PQKeyFactory
from pq_logic.tmp_oids import id_altSubPubKeyExt, id_relatedCert, id_ce_deltaCertificateDescriptor


def sign_data_with_alg_id(key, alg_id: rfc9480.AlgorithmIdentifier, data: bytes) -> bytes:
    """Sign the provided data using the given algorithm identifier.

    :param key: The private key used to sign the data.
    :param alg_id: The algorithm identifier specifying the algorithm and any associated parameters for signing.
    :param data: The data to sign.
    :return: The digital signature.
    """
    oid = alg_id["algorithm"]

    if isinstance(key, CompositeSigCMSPrivateKey):
        name: str = CMS_COMPOSITE_OID_2_NAME[oid]
        use_pss = name.endswith("-pss")
        pre_hash = name.startswith("hash-")
        key: CompositeSigCMSPrivateKey
        return key.sign(data=data, use_pss=use_pss, pre_hash=pre_hash)

    elif oid in PQ_OID_2_NAME or oid in MSG_SIG_ALG or oid in RSASSA_PSS_OID_2_NAME or str(oid) in PQ_OID_2_NAME:
        hash_alg = get_hash_from_oid(oid, only_hash=True)
        use_pss = oid in RSASSA_PSS_OID_2_NAME
        return sign_data(key=key, data=data, hash_alg=hash_alg, use_rsa_pss=use_pss)
    else:
        raise ValueError(f"Unsupported private key type: {type(key).__name__} oid:{may_return_oid_to_name(oid)}")


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


def may_extract_alt_key_from_cert(
    cert: rfc9480.CMPCertificate, other_certs: Optional[List[rfc9480.CMPCertificate]] = None
) -> Optional[PQSignaturePublicKey]:
    """May extract the alternative public key from a certificate.

    Either extracts the alternative public key from the issuer's certificate or from the certificate discovery
    extension. Alternative extracts the pq_key of the related certificate from the issuer's certificate or
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
