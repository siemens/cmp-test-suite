# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Utility functions for verifying hybrid signatures."""

import logging
from typing import List, Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc5280, rfc6402, rfc9480
from resources import certbuildutils, cryptoutils, utils
from resources.certextractutils import get_extension
from resources.convertutils import subjectPublicKeyInfo_from_pubkey
from resources.exceptions import BadAsn1Data, BadPOP
from resources.keyutils import load_public_key_from_spki
from resources.oid_mapping import get_hash_from_oid, may_return_oid_to_name
from resources.oidutils import (
    CMS_COMPOSITE_OID_2_NAME,
    MSG_SIG_ALG,
    PQ_OID_2_NAME,
    RSASSA_PSS_OID_2_NAME,
    id_ce_altSignatureAlgorithm,
    id_ce_altSignatureValue,
    id_ce_subjectAltPublicKeyInfo,
)
from resources.protectionutils import (
    patch_sender_and_sender_kid,
    prepare_pki_protection_field,
    verify_rsassa_pss_from_alg_id,
)
from resources.typingutils import PrivateKeySig, PublicKeySig
from robot.api.deco import not_keyword

import pq_logic.hybrid_sig.sun_lamps_hybrid_scheme_00
from pq_logic.hybrid_sig import chameleon_logic
from pq_logic.hybrid_sig.cert_binding_for_multi_auth import get_related_cert_from_list
from pq_logic.hybrid_sig.certdiscovery import (
    extract_sia_extension_for_cert_discovery,
    get_cert_discovery_cert,
    validate_related_certificate_descriptor_alg_ids,
)
from pq_logic.hybrid_structures import SubjectAltPublicKeyInfoExt
from pq_logic.keys.abstract_pq import PQSignaturePrivateKey, PQSignaturePublicKey
from pq_logic.keys.comp_sig_cms03 import CompositeSigCMSPrivateKey, CompositeSigCMSPublicKey
from pq_logic.pq_key_factory import PQKeyFactory
from pq_logic.tmp_oids import id_altSubPubKeyExt, id_ce_deltaCertificateDescriptor, id_relatedCert


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
        return cryptoutils.sign_data(key=key, data=data, hash_alg=hash_alg, use_rsa_pss=use_pss)
    else:
        raise ValueError(f"Unsupported private key type: {type(key).__name__} oid:{may_return_oid_to_name(oid)}")


@not_keyword
def verify_csr_signature(csr: rfc6402.CertificationRequest) -> None:
    """Verify a certification request (CSR) signature using the appropriate algorithm.

    :param csr: THe certification request (`CertificationRequest`) to be verified.
    :raises ValueError: If the algorithm OID in the CSR is unsupported or invalid.
    :raises BadPOP: If the signature verification fails.
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
    try:
        verify_signature_with_alg_id(public_key=public_key, alg_id=alg_id, signature=signature, data=data)
    except InvalidSignature as e:
        raise BadPOP("The signature verification failed.") from e


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
    extn_chameleon = get_extension(extensions, id_ce_deltaCertificateDescriptor)
    extn_sun_hybrid = get_extension(extensions, id_altSubPubKeyExt)

    rel_cert_desc = None
    if extn_sia is not None:
        try:
            # it could be that the SIA extension is present, but does not
            # contain the cert discovery entry.
            rel_cert_desc = extract_sia_extension_for_cert_discovery(extn_sia)
        except ValueError:
            pass

    # TODO fix try to validate both.

    spki = cert["tbsCertificate"]["subjectPublicKeyInfo"]
    oid = spki["algorithm"]["algorithm"]

    if extn_sun_hybrid is not None:
        public_key = pq_logic.hybrid_sig.sun_lamps_hybrid_scheme_00.get_sun_hybrid_alt_pub_key(
            cert["tbsCertificate"]["extensions"]
        )
        if public_key is not None:
            return public_key
        raise ValueError("Could not extract the Sun-Hybrid alternative public key.")

    if extn_rel_cert is not None and other_certs is not None:
        logging.info("Validate signature with related certificate.")
        related_cert = get_related_cert_from_list(other_certs, cert)
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
        other_cert = get_cert_discovery_cert(uri)
        validate_related_certificate_descriptor_alg_ids(other_cert, rel_cert_desc=rel_cert_desc)
        pq_key = load_public_key_from_spki(other_cert["tbsCertificate"]["subjectPublicKeyInfo"])
        return pq_key

    if extn_chameleon is not None:
        spki = chameleon_logic.get_chameleon_delta_public_key(cert)
        return load_public_key_from_spki(spki)

    if oid in CMS_COMPOSITE_OID_2_NAME:
        public_key = CompositeSigCMSPublicKey.from_spki(spki)
        CompositeSigCMSPublicKey.validate_oid(oid, public_key)
        return CompositeSigCMSPublicKey.pq_key

    return None


@not_keyword
def verify_signature_with_alg_id(public_key, alg_id: rfc9480.AlgorithmIdentifier, data: bytes, signature: bytes):
    """Verify the provided data and signature using the given algorithm identifier.

    Supports traditional-, pq- and composite signature algorithm.

    :param public_key: The public key object used to verify the signature.
    :param alg_id: An `AlgorithmIdentifier` specifying the algorithm and any
                   associated parameters for signature verification.
    :param data: The original message or data whose signature needs verification,
                 as a byte string.
    :param signature: The digital signature to verify, as a byte string.

    :raises ValueError: If the algorithm identifier is unsupported or invalid.
    :raises InvalidSignature: If the signature does not match the provided data
                              under the given algorithm and public key.
    """
    oid = alg_id["algorithm"]

    if oid in CMS_COMPOSITE_OID_2_NAME:
        name: str = CMS_COMPOSITE_OID_2_NAME[oid]
        use_pss = name.endswith("-pss")
        pre_hash = name.startswith("hash-")
        public_key: CompositeSigCMSPublicKey
        public_key.verify(data=data, signature=signature, use_pss=use_pss, pre_hash=pre_hash)

    elif oid in RSASSA_PSS_OID_2_NAME:
        return verify_rsassa_pss_from_alg_id(public_key=public_key, data=data, signature=signature, alg_id=alg_id)

    elif oid in PQ_OID_2_NAME or str(oid) in PQ_OID_2_NAME or oid in MSG_SIG_ALG:
        hash_alg = get_hash_from_oid(oid, only_hash=True)
        cryptoutils.verify_signature(public_key=public_key, signature=signature, data=data, hash_alg=hash_alg)
    else:
        raise ValueError(f"Unsupported public key type: {type(public_key).__name__}.")


def _prepare_catalyst_info_vals(
    prot_alg_id: rfc9480.AlgorithmIdentifier, public_key: Optional[PublicKeySig]
) -> Tuple[rfc9480.InfoTypeAndValue, Optional[rfc9480.InfoTypeAndValue]]:
    """Prepare the InfoTypeAndValue objects for the catalyst protection scheme.

    :param prot_alg_id: The protection algorithm identifier.
    :param public_key: The alternative public key to include in the message.
    :return: The InfoTypeAndValue objects.
    """
    info_val_type_pub_key = None

    info_val_type = rfc9480.InfoTypeAndValue()
    info_val_type["infoType"] = id_ce_altSignatureAlgorithm
    info_val_type["infoValue"] = encoder.encode(prot_alg_id)

    if public_key is not None:
        info_val_type_pub_key = rfc9480.InfoTypeAndValue()
        info_val_type_pub_key["infoType"] = id_ce_subjectAltPublicKeyInfo
        spki = subjectPublicKeyInfo_from_pubkey(public_key)
        info_val_type_pub_key["infoValue"] = encoder.encode(spki)

    return info_val_type, info_val_type_pub_key


def _compute_protection(
    signing_key: PrivateKeySig,
    pki_message: rfc9480.PKIMessage,
    hash_alg: str = "sha256",
    use_rsa_pss: bool = True,
    use_pre_hash: bool = False,
    bad_message_check: bool = False,
) -> rfc9480.PKIMessage:
    """Compute the protection for a PKIMessage.

    :param signing_key: The private key used for signing.
    :param pki_message: The PKIMessage to protect.
    :param hash_alg: The hash algorithm to use for signing.
    :param use_rsa_pss: Whether to use RSA-PSS padding for signing.
    :param use_pre_hash: Whether to use pre-hashing for signing.
    :return: The protected PKIMessage.
    """
    prot_alg_id = certbuildutils.prepare_sig_alg_id(
        signing_key=signing_key,
        hash_alg=hash_alg,
        use_rsa_pss=use_rsa_pss,
        use_pre_hash=use_pre_hash,
    )
    prot_alg_id = prot_alg_id.subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1), cloneValueFlag=True
    )
    pki_message["header"]["protectionAlg"] = prot_alg_id

    der_data = encoder.encode(pki_message["header"]) + encoder.encode(pki_message["body"])
    signature = sign_data_with_alg_id(
        alg_id=pki_message["header"]["protectionAlg"],
        data=der_data,
        key=signing_key,
    )

    if bad_message_check:
        if isinstance(signing_key, CompositeSigCMSPrivateKey):
            signature = utils.manipulate_composite_sig(signature)
        else:
            signature = utils.manipulate_first_byte(signature)

    pki_message["protection"] = prepare_pki_protection_field(signature)
    return pki_message


def protect_hybrid_pkimessage(
    pki_message: rfc9480.PKIMessage,
    private_key: Union[PrivateKeySig, CompositeSigCMSPrivateKey, PQSignaturePrivateKey],
    protection: str = "signature",
    do_patch: bool = True,
    alt_signing_key: Optional[Union[PrivateKeySig, PQSignaturePrivateKey]] = None,
    include_alt_pub_key: bool = False,
    bad_message_check: bool = False,
    **params,
):
    """Protect a PKIMessage with a hybrid protection scheme.

    :param pki_message: The PKIMessage to protect.
    :param protection: The protection type to use.
    :param private_key: The private key used for the primary signature.
    :param do_patch: Whether to patch the sender and senderKID fields.
    :param alt_signing_key: The alternative signing key to use for composite protection,
    or the catalyst signature.
    :param include_alt_pub_key: Whether to include the alternative public key in the message.
    :param bad_message_check: Whether to manipulate the message signature. Defaults to `False`.
    :return: The protected `PKIMessage`.
    """
    pki_message = patch_sender_and_sender_kid(
        do_patch=do_patch,
        pki_message=pki_message,
        cert=params.get("cert"),
    )

    if protection not in ["signature", "composite", "catalyst"]:
        raise ValueError("Only 'signature', 'composite', and 'catalyst' protection types are supported.")

    if protection == "signature":
        return _compute_protection(
            signing_key=private_key,
            pki_message=pki_message,
            hash_alg=params.get("hash_alg", "sha256"),
            use_rsa_pss=params.get("use_rsa_pss", True),
            use_pre_hash=params.get("use_pre_hash", False),
            bad_message_check=bad_message_check,
        )

    if protection == "composite":
        if alt_signing_key is not None:
            if isinstance(alt_signing_key, PQSignaturePrivateKey):
                private_key, alt_signing_key = alt_signing_key, private_key

            private_key = CompositeSigCMSPrivateKey(
                pq_key=private_key,
                trad_key=alt_signing_key,
            )

        return _compute_protection(
            signing_key=private_key,
            pki_message=pki_message,
            hash_alg=params.get("hash_alg", "sha256"),
            use_rsa_pss=params.get("use_rsa_pss", True),
            use_pre_hash=params.get("use_pre_hash", False),
            bad_message_check=bad_message_check,
        )

    else:
        alt_prot_alg_id = certbuildutils.prepare_sig_alg_id(
            signing_key=alt_signing_key,
            hash_alg=params.get("hash_alg", "sha256"),
            use_rsa_pss=params.get("use_rsa_pss", True),
            use_pre_hash=params.get("use_pre_hash", False),
        )
        prot_alg_id = certbuildutils.prepare_sig_alg_id(
            signing_key=private_key,
            hash_alg=params.get("hash_alg", "sha256"),
            use_rsa_pss=params.get("use_rsa_pss", True),
            use_pre_hash=params.get("use_pre_hash", False),
        )

        prot_alg_id = prot_alg_id.subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1), cloneValueFlag=True
        )
        pki_message["header"]["protectionAlg"] = prot_alg_id

        info_val_type, info_val_type_pub_key = _prepare_catalyst_info_vals(
            prot_alg_id=alt_prot_alg_id,
            public_key=alt_signing_key.public_key() if include_alt_pub_key else None,
        )
        pki_message["header"]["generalInfo"].append(info_val_type)
        if info_val_type_pub_key is not None:
            pki_message["header"]["generalInfo"].append(info_val_type_pub_key)

        der_data = encoder.encode(pki_message["header"]) + encoder.encode(pki_message["body"])

        signature = sign_data_with_alg_id(
            alg_id=alt_prot_alg_id,
            data=der_data,
            key=alt_signing_key,
        )

        if bad_message_check:
            signature = utils.manipulate_first_byte(signature)

        info_val_type_sig = rfc9480.InfoTypeAndValue()
        info_val_type_sig["infoType"] = id_ce_altSignatureValue
        info_val_type_sig["infoValue"] = encoder.encode(univ.BitString.fromOctetString(signature))
        pki_message["header"]["generalInfo"].append(info_val_type_sig)

        der_data = encoder.encode(pki_message["header"]) + encoder.encode(pki_message["body"])

        signature = sign_data_with_alg_id(
            alg_id=prot_alg_id,
            data=der_data,
            key=private_key,
        )
        pki_message["protection"] = prepare_pki_protection_field(signature)

    return pki_message
