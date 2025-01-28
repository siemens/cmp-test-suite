# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Allows issuing certificates with hybrid keys/and mechanisms.

##############################################################################

Warning:
-------
This does not official ideas how to issue certificates with hybrid keys,
like Catalyst. Some are just Ideas how someone could use the newly developed
mechanisms to issue a certificate.
##############################################################################

"""

from typing import Optional, Sequence, Tuple, Union

from cryptography.exceptions import InvalidSignature
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc4211, rfc5280, rfc9480
from resources.ca_ra_utils import (
    build_cp_from_p10cr,
    build_ip_cmp_message,
    get_cert_req_msg_from_pkimessage,
    get_correct_ca_body_name,
    get_public_key_from_cert_req_msg,
    prepare_cert_response,
    prepare_encr_cert_for_request,
    verify_sig_pop_for_pki_request,
)
from resources.certbuildutils import (
    build_cert_from_cert_template,
    build_cert_from_csr,
    prepare_cert_template,
    prepare_sig_alg_id,
    prepare_tbs_certificate_from_template,
    sign_cert,
)
from resources.certextractutils import extract_extension_from_csr, get_extension
from resources.cmputils import (
    patch_pkimessage_header_with_other_message,
    prepare_popo,
    prepare_popo_challenge_for_non_signing_key,
)
from resources.convertutils import copy_asn1_certificate
from resources.exceptions import BadAlg, BadAsn1Data, InvalidKeyCombination, UnknownOID, InvalidAltSignature
from resources.keyutils import generate_key, generate_key_based_on_alg_id
from resources.oidutils import CMS_COMPOSITE_OID_2_NAME, PQ_SIG_PRE_HASH_OID_2_NAME, id_ce_altSignatureAlgorithm, \
    id_ce_altSignatureValue
from resources.protectionutils import protect_pkimessage
from resources.typingutils import PrivateKey, TradSigPrivKey
from resources.utils import manipulate_composite_sig, manipulate_first_byte
from robot.api.deco import keyword, not_keyword
from unit_tests.prepare_ca_response import build_ca_pki_message

from pq_logic.hybrid_sig.catalyst_logic import (
    load_catalyst_public_key,
    prepare_alt_sig_alg_id_extn,
    prepare_alt_signature_value_extn,
    prepare_subject_alt_public_key_info_extn,
    sign_cert_catalyst,
)
from pq_logic.hybrid_structures import AltSignatureValueExt
from pq_logic.hybrid_sig.chameleon_logic import \
    build_chameleon_cert_from_paired_csr
from pq_logic.hybrid_sig.sun_lamps_hybrid_scheme_00 import sun_cert_template_to_cert, sun_csr_to_cert
from pq_logic.keys.abstract_composite import AbstractCompositeSigPrivateKey, AbstractCompositeSigPublicKey
from pq_logic.keys.abstract_pq import PQKEMPrivateKey, PQKEMPublicKey, PQSignaturePrivateKey, PQSignaturePublicKey
from pq_logic.keys.comp_sig_cms03 import CompositeSigCMSPrivateKey, CompositeSigCMSPublicKey
from pq_logic.migration_typing import HybridKEMPrivateKey, HybridKEMPublicKey
from pq_logic.pq_compute_utils import sign_data_with_alg_id, verify_csr_signature, verify_signature_with_alg_id
from pq_logic.trad_typing import ECDHPrivateKey, CA_RESPONSE, CA_CERT_RESPONSE, CA_CERT_RESPONSES


def build_sun_hybrid_cert_from_request(
        request: rfc9480.PKIMessage,
        signing_key: AbstractCompositeSigPrivateKey,
        protection_key: PrivateKey,
        pub_key_loc: str,
        sig_loc: str,
        protection: str = "password_based_mac",
        password: Optional[str] = None,
        issuer_cert: Optional[rfc9480.CMPCertificate] = None,
        cert_chain: Optional[Sequence[rfc9480.CMPCertificate]] = None,
        cert_index: Optional[int] = None,
) -> rfc9480.PKIMessage:
    """Build a Sun-Hybrid certificate from a request.

    The certificate in form 1 is at the second position in the `extraCerts` list.

    Arguments:
    --------
       - `request`: The PKIMessage request.
       - `signing_key`: The key to sign the certificate with.
       - `protection_key`: The key to protect the certificate with.
       - `pub_key_loc`: The location of the public key.
       - `sig_loc`: The location of the signature.
       - `protection`: The protection to use. Defaults to "password_based_mac".
       - `password`: The password to use for protection. Defaults to `None`.
       - `issuer_cert`: The issuer certificate. Defaults to `None`.
       - `cert_chain`: The certificate chain. Defaults to `None`.
       - `cert_index`: The certificate index. Defaults to `None`.

    Returns:
    -------
       - The PKIMessage with the certificate response.

    """
    if issuer_cert is None:
        issuer_cert = cert_chain[0]

    if request["body"].getName() == "p10cr":
        verify_csr_signature(csr=request["body"]["p10cr"])
        cert4, cert1 = sun_csr_to_cert(
            csr=request["body"]["p10cr"],
            issuer_private_key=signing_key.trad_key,
            alt_private_key=signing_key.pq_key,
            issuer_cert=issuer_cert,
        )
        pki_message = build_cp_from_p10cr(request=request, cert=cert4, cert_req_id=-1)

    elif request["body"].getName() in ["ir", "cr"]:
        cert_index = cert_index if cert_index is not None else 0
        cert_req_msg: rfc4211.CertReqMsg = request["body"]["ir"][cert_index]
        public_key = get_public_key_from_cert_req_msg(cert_req_msg)
        if isinstance(public_key, AbstractCompositeSigPublicKey):
            verify_sig_pop_for_pki_request(request, cert_index)
            cert4, cert1 = sun_cert_template_to_cert(
                cert_template=cert_req_msg["certReq"]["certTemplate"],
                issuer_cert=issuer_cert,
                issuer_private_key=signing_key.trad_key,
                alt_private_key=signing_key.pq_key,
                pub_key_loc=pub_key_loc,
                sig_loc=sig_loc,
            )

            pki_message, _ = build_ip_cmp_message(
                cert=cert4,
                request=request,
                cert_req_id=cert_req_msg or cert_req_msg["certReq"]["certReqId"],
            )

        elif isinstance(public_key, HybridKEMPublicKey):
            cert4, cert1 = sun_cert_template_to_cert(
                cert_template=cert_req_msg["certReq"]["certTemplate"],
                issuer_cert=issuer_cert,
                issuer_private_key=signing_key.trad_key,
                alt_private_key=signing_key.pq_key,
                pub_key_loc=pub_key_loc,
                sig_loc=sig_loc,
            )

            pki_message = build_enc_cert_response(
                new_ee_cert=cert4,
                ca_cert=issuer_cert,
                request=request,
            )
        else:
            raise ValueError(f"Invalid key type: {type(public_key).__name__}")

    else:
        raise ValueError(f"Invalid request type: {request['body'].getName()}")

    if password is not None:
        pki_message = protect_pkimessage(pki_message, password, protection=protection)
        pki_message["extraCerts"].append(cert4)
    else:
        pki_message = protect_pkimessage(
            pki_message=pki_message,
            private_key=protection_key,
            protection=protection,
            cert=cert_chain[0],
            exclude_cert=True,
        )
        pki_message["extraCerts"].append(cert_chain[0])
        pki_message["extraCerts"].append(cert4)
        if cert_chain is not None:
            pki_message["extraCerts"].extend(cert_chain[:1])

    return pki_message

@not_keyword
def build_enc_cert_response(
        request: rfc9480.PKIMessage,
        ca_cert: rfc9480.CMPCertificate,
        signing_key: Optional[PrivateKey] = None,
        new_ee_cert: Optional[rfc9480.CMPCertificate] = None,
        hash_alg: str = "sha256",
        cert_index: Optional[int] = None,
        cert_req_id: Optional[int] = None,
        hybrid_kem_key: Optional[Union[HybridKEMPrivateKey, ECDHPrivateKey]] = None,
        client_pub_key: Optional[PQKEMPublicKey] = None,
) -> rfc9480.PKIMessage:
    """Build an encrypted certificate response.

    :param request: The certificate request.
    :param new_ee_cert: The newly created end-entity certificate.
    :param ca_cert: The CA certificate.
    :param signing_key: The key to sign the certificate with.
    :param hash_alg: The hash algorithm to use for signing the certificate. Defaults to "sha256".
    :param cert_index: The index of the certificate request to use. Defaults to 0.
    :param cert_req_id: The certificate request ID. Defaults to the ID inside the request.
    :param hybrid_kem_key: The optional hybrid key, to use for the HybridKEM key encapsulation.
    :param client_pub_key: The optional client public key, to use for the HybridKEM key encapsulation.
    (only needed for the proposed catalyst approach.)
    :return: PKIMessage with the encrypted certificate response.
    """
    if request["body"].getName() == "p10cr":
        raise ValueError("Only IR or CR is supported to build a encrypted certificate response.")

    cert_index = cert_index if cert_index is not None else 0

    if cert_index is None:
        # Should be updated to handle multiple request.
        # TODO fix for multiple request.
        pass

    cert_req_msg: rfc4211.CertReqMsg = request["body"]["ir"][cert_index]
    cert_req_id = cert_req_id or cert_req_msg["certReq"]["certReqId"]

    enc_cert = prepare_encr_cert_for_request(
        cert_req_msg=cert_req_msg,
        signing_key=signing_key,
        hash_alg=hash_alg,
        ca_cert=ca_cert,
        new_ee_cert=new_ee_cert,
        hybrid_kem_key=hybrid_kem_key,
        client_pub_key=client_pub_key,
    )

    cert_response = prepare_cert_response(
        request=request,
        enc_cert=enc_cert,
        cert_req_id=cert_req_id,
        text="Issued encrypted certificate please verify with `CertConf`",
    )

    if request["body"].getName() == "ir":
        body_name = "ip"
    else:
        body_name = "cp"

    pki_message = build_ca_pki_message(body_type=body_name, responses=[cert_response])
    pki_message = patch_pkimessage_header_with_other_message(
        target=pki_message, other_message=request, for_exchange=True
    )
    return pki_message


def build_cert_from_catalyst_request(
        request: rfc9480.PKIMessage,
        ca_cert: rfc9480.CMPCertificate,
        ca_key: PrivateKey,
        cert_index: Union[str, int] = 0,
        hash_alg: str = "sha256",
        use_rsa_pss: bool = True,
        bad_sig: bool = False,
) -> Tuple[rfc9480.PKIMessage, rfc9480.CMPCertificate]:
    """Build a certificate from a Catalyst request.

    This is an experimental approach to show how to build a certificate from a Catalyst request.

    This includes three different methods.
    - First sign an additional signature
    - Second use composite.
    - Third use hybrid KEMs, by making use of the Traditional Key as signing key.
     (the first key will be chosen based on the Key in the `CertTemplate` structure.)

     Arguments:
     ---------
         - `request`: The PKIMessage request.
         - `ca_cert`: The CA certificate.
         - `ca_key`: The CA key.
         - `cert_index`: The index of the certificate request to use. Defaults to 0.
         - `hash_alg`: The hash algorithm to use for signing. Defaults to "sha256".
         - `use_rsa_pss`: Whether to use RSA-PSS for signing. Defaults to `True`.
         - `use_composite_sig`: Whether to use composite signature keys. Defaults to `False`.
         - `bad_sig`: Whether to manipulate the POP. Defaults to `False`.

     Returns:
     -------
            - The PKIMessage with the certificate response.
            - The issued certificate.
    """
    if request["body"].getName() == "p10cr":
        raise ValueError("Only IR or CR is supported to build a encrypted certificate response.")

    cert_req_msg = get_cert_req_msg_from_pkimessage(
        pki_message=request,
        index=cert_index,
    )

    popo: rfc4211.ProofOfPossession = cert_req_msg["popo"]

    if cert_req_msg["certReq"]["certTemplate"]["publicKey"]["algorithm"]["algorithm"] in CMS_COMPOSITE_OID_2_NAME:
        raise ValueError("Composite keys are not supported for Catalyst certificates.")

    cert_template = cert_req_msg["certReq"]["certTemplate"]
    second_key = load_catalyst_public_key(cert_template["extensions"])

    verify_sig_popo_catalyst_cert_req_msg(
        cert_req_msg=cert_req_msg,
    )
    tbs_certs = prepare_tbs_certificate_from_template(
        cert_template=cert_template,
        issuer=ca_cert["tbsCertificate"]["subject"],
        ca_key=ca_key,
        hash_alg=hash_alg,
        use_rsa_pss=use_rsa_pss,
        use_pre_hash=False,
    )

    alt_spki_extn = prepare_subject_alt_public_key_info_extn(public_key=second_key, critical=False)

    tbs_certs["extensions"].append(alt_spki_extn)
    cert = rfc9480.CMPCertificate()
    cert["tbsCertificate"] = tbs_certs
    cert = sign_cert(
        cert=cert,
        signing_key=ca_key,
        hash_alg=hash_alg,
        use_rsa_pss=use_rsa_pss,
        bad_sig=bad_sig,
    )
    issued_cert = copy_asn1_certificate(cert=cert)
    if popo.getName() == "keyEncipherment" or isinstance(second_key, PQKEMPublicKey):
        if isinstance(second_key, PQKEMPublicKey):
            public_key = second_key
        else:
            public_key = None

        pki_message = build_enc_cert_response(
            new_ee_cert=cert,
            ca_cert=ca_cert,
            signing_key=ca_key,
            request=request,
            cert_index=cert_index,
            hash_alg=hash_alg,
            client_pub_key=public_key,
        )
    else:
        pki_message, _ = build_ip_cmp_message(
            cert=cert,
            request=request,
            cert_req_id=int(cert_req_msg["certReq"]["certReqId"]),
        )

    return pki_message, issued_cert


def _prepare_sig_popo(signing_key, data, hash_alg: str, use_rsa_pss: bool) -> rfc4211.ProofOfPossession:
    """Prepare a signature proof of possession.

    :param signing_key: The key to sign the data with.
    :param data: The data to sign.
    :param hash_alg: The hash algorithm to use for signing.
    :param use_rsa_pss: Whether to use RSA-PSS for signing.
    :return: The populated `ProofOfPossession` structure.
    """
    popo: rfc4211.ProofOfPossession
    sig_alg = prepare_sig_alg_id(signing_key=signing_key, use_rsa_pss=use_rsa_pss, hash_alg=hash_alg)
    sig = sign_data_with_alg_id(key=signing_key, alg_id=sig_alg, data=data)
    popo = prepare_popo(signature=sig, signing_key=signing_key)
    popo["signature"]["signature"] = univ.BitString.fromOctetString(sig)
    return popo


def _compute_second_pop_catalyst(
        alt_key: Union[PQSignaturePrivateKey, TradSigPrivKey],
        cert_request: rfc4211.CertRequest,
        hash_alg: str,
        use_rsa_pss: bool,
        bad_alt_pop: bool,
) -> rfc4211.CertRequest:
    """Compute the second `POP` for a Catalyst request.

    :param alt_key: The key to sign the data with.
    :param cert_request: The certificate request.
    :param hash_alg: The hash algorithm to use for signing.
    :param use_rsa_pss: Whether to use RSA-PSS for signing.
    :param bad_alt_pop: Whether to manipulate the first byte of the POP.
    :return: The updated `CertRequest`.
    """
    sig_alg = prepare_sig_alg_id(signing_key=alt_key, use_rsa_pss=use_rsa_pss, hash_alg=hash_alg)
    alt_sig_id_extn = prepare_alt_sig_alg_id_extn(alg_id=sig_alg, critical=False)
    alt_spki = prepare_subject_alt_public_key_info_extn(alt_key.public_key(), critical=False)
    cert_request["certTemplate"]["extensions"].append(alt_sig_id_extn)
    cert_request["certTemplate"]["extensions"].append(alt_spki)

    data = encoder.encode(cert_request)
    sig = sign_data_with_alg_id(key=alt_key, alg_id=sig_alg, data=data)
    if bad_alt_pop:
        sig = manipulate_first_byte(sig)
    extn = prepare_alt_signature_value_extn(signature=sig, critical=False)
    cert_request["certTemplate"]["extensions"].append(extn)
    return cert_request


def _verify_alt_sig_for_pop(
        alt_pub_key: Union[PQSignaturePublicKey],
        cert_req_msg: rfc4211.CertReqMsg,
        alt_sig_alg_id: rfc5280.Extension,
        alt_sig: rfc5280.Extension,
) -> None:
    """Verify the alternative signature for the `POP`.

    :param alt_pub_key: The alternative public key to use for verification.
    :param cert_req_msg: The certificate request message.
    :param alt_sig_alg_id: The alternative signature algorithm identifier.
    :param alt_sig: The alternative signature value.
    :raises InvalidSignature: If the signature is invalid.
    :raises ValueError: If the alternative signature or algorithm is missing.
    """
    if alt_sig_alg_id is None or alt_sig is None:
        raise ValueError(
            "AltSignatureAlgorithm and AltSignatureValue must not present, "
            "if the public key inside the `CertTemplate` is a KEM key."
        )

    cert_template = cert_req_msg["certReq"]["certTemplate"]
    extension = rfc5280.Extensions().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 9))

    for x in cert_template["extensions"]:
        if x["extnID"] != id_ce_altSignatureValue:
            extension.append(x)

    cert_req_msg["certReq"]["certTemplate"]["extensions"] = extension

    alt_signature_algorithm = decoder.decode(alt_sig_alg_id["extnValue"], asn1Spec=rfc5280.AlgorithmIdentifier())[0]
    alt_signature_value, _ = decoder.decode(alt_sig["extnValue"], asn1Spec=AltSignatureValueExt())
    try:
        verify_signature_with_alg_id(
            public_key=alt_pub_key,
            signature=alt_signature_value.asOctets(),
            alg_id=alt_signature_algorithm,
            data=encoder.encode(cert_req_msg["certReq"]),
        )
    except InvalidSignature as e:
        raise InvalidAltSignature("Invalid signature for the alternative `POP`.") from e


@keyword(name="Verify Catalyst CertReqMsg")
def verify_sig_popo_catalyst_cert_req_msg(cert_req_msg: rfc4211.CertReqMsg) -> None:
    """Verify a `Catalyst` certificate request message.


    Arguments:
    ---------
        - `cert_req_msg`: The certificate request message.

    Raises:
    -------
        - `InvalidSignature`: If the signature is invalid.
        - `ValueError`: If the alternative signature or algorithm is missing.
        - `InvalidAltSignature`: If the alternative signature is invalid.

    """
    cert_template = cert_req_msg["certReq"]["certTemplate"]
    alt_pub_key = load_catalyst_public_key(cert_template["extensions"])
    alt_sig_alg_id = get_extension(cert_template["extensions"], id_ce_altSignatureAlgorithm)
    alt_sig = get_extension(cert_template["extensions"], id_ce_altSignatureValue)

    first_key = get_public_key_from_cert_req_msg(cert_req_msg)

    if cert_req_msg["popo"].getName() == "keyEncipherment":
        _verify_alt_sig_for_pop(
            alt_pub_key=alt_pub_key,
            cert_req_msg=cert_req_msg,
            alt_sig_alg_id=alt_sig_alg_id,
            alt_sig=alt_sig,
        )
        return

    sig_alg_oid = cert_req_msg["popo"]["signature"]["algorithmIdentifier"]
    oid = sig_alg_oid["algorithm"]
    if oid in CMS_COMPOSITE_OID_2_NAME or str(oid) in CMS_COMPOSITE_OID_2_NAME:
        if not isinstance(first_key, PQSignaturePublicKey):
            first_key, alt_pub_key = alt_pub_key, first_key

        public_key = CompositeSigCMSPublicKey(pq_key=first_key, trad_key=alt_pub_key)
        CompositeSigCMSPublicKey.validate_oid(oid, public_key)
        verify_signature_with_alg_id(
            public_key=public_key,
            alg_id=sig_alg_oid,
            data=encoder.encode(cert_req_msg["certReq"]),
            signature=cert_req_msg["popo"]["signature"]["signature"].asOctets(),
        )
        return

    elif isinstance(alt_pub_key, PQKEMPublicKey):
        alg_id = cert_req_msg["popo"]["signature"]["algorithmIdentifier"]
        data = encoder.encode(cert_req_msg["certReq"])
        verify_signature_with_alg_id(
            public_key=first_key,
            alg_id=alg_id,
            data=data,
            signature=cert_req_msg["popo"]["signature"]["signature"].asOctets(),
        )
    else:
        alg_id = cert_req_msg["popo"]["signature"]["algorithmIdentifier"]

        try:
            verify_signature_with_alg_id(
                public_key=first_key,
                signature=cert_req_msg["popo"]["signature"]["signature"].asOctets(),
                alg_id=alg_id,
                data=encoder.encode(cert_req_msg["certReq"]),
            )
        except InvalidSignature as e:
            raise InvalidSignature("Invalid signature for the `POP`.") from e

        _verify_alt_sig_for_pop(
            alt_pub_key=alt_pub_key,
            cert_req_msg=cert_req_msg,
            alt_sig_alg_id=alt_sig_alg_id,
            alt_sig=alt_sig,
        )


@keyword(name="Prepare Catalyst CertReqMsg Approach")
def prepare_catalyst_cert_req_msg_approach(
        first_key,
        alt_key,
        cert_req_id: Union[int, str] = 0,
        hash_alg: str = "sha256",
        subject: str = "CN=CMP Catalyst Test",
        use_rsa_pss: bool = True,
        use_composite_sig: bool = False,
        bad_pop: bool = False,
        bad_alt_pop: bool = False,
) -> rfc4211.CertReqMsg:
    """Prepare a `Catalyst` approach for a certificate request message.

    :param first_key: The first key to use for the request.
    :param alt_key: The alternative key to use for the request.
    :param cert_req_id: The certificate request ID. Defaults to `0`.
    :param hash_alg: The hash algorithm to use for signing. Defaults to "sha256".
    :param subject: The subject to use for the certificate. Defaults to "CN=CMP Catalyst Test".
    :param use_rsa_pss: Whether to use RSA-PSS for signing. Defaults to `True`.
    :param use_composite_sig: Whether to use composite signature keys. Defaults to `False`.
    :param bad_pop: Whether to manipulate the POP. Defaults to `False`.
    :param bad_alt_pop: Whether to manipulate the alternative POP. Defaults to `False`.
    :return: The populated `CertReqMsg` structure.
    """
    cert_req_msg = rfc4211.CertReqMsg()
    cert_req = rfc4211.CertRequest()
    cert_req["certReqId"] = int(cert_req_id)

    cert_template = prepare_cert_template(key=first_key, subject=subject)
    cert_req["certTemplate"] = cert_template

    if use_composite_sig:
        if not isinstance(first_key, PQSignaturePrivateKey):
            first_key, alt_key = alt_key, first_key

        comp_key = CompositeSigCMSPrivateKey(first_key, alt_key)
        extn = prepare_subject_alt_public_key_info_extn(alt_key.public_key(), critical=False)
        cert_req["certTemplate"]["extensions"].append(extn)
        data = encoder.encode(cert_req)
        sig_alg = prepare_sig_alg_id(signing_key=comp_key, use_rsa_pss=True, hash_alg=hash_alg) # type: ignore
        sig = sign_data_with_alg_id(key=comp_key, alg_id=sig_alg, data=data)

        if bad_pop:
            sig = manipulate_composite_sig(sig)

        popo = prepare_popo(signature=sig, alg_oid=sig_alg["algorithm"])

    elif isinstance(first_key, PQKEMPrivateKey) and isinstance(alt_key, TradSigPrivKey):
        popo = prepare_popo_challenge_for_non_signing_key(use_encr_cert=True)
        cert_req = _compute_second_pop_catalyst(
            alt_key=alt_key,
            cert_request=cert_req,
            hash_alg=hash_alg,
            use_rsa_pss=use_rsa_pss,
            bad_alt_pop=bad_alt_pop,
        )

    elif isinstance(alt_key, (PQSignaturePrivateKey, TradSigPrivKey)) and isinstance(
            first_key, (PQSignaturePrivateKey, TradSigPrivKey)
    ):
        # means that both are signature keys.
        cert_req = _compute_second_pop_catalyst(
            alt_key=alt_key, cert_request=cert_req, hash_alg=hash_alg, use_rsa_pss=use_rsa_pss, bad_alt_pop=bad_alt_pop
        )

        data = encoder.encode(cert_req)
        sig_alg = prepare_sig_alg_id(signing_key=first_key, use_rsa_pss=use_rsa_pss, hash_alg=hash_alg)
        sig = sign_data_with_alg_id(key=first_key, alg_id=sig_alg, data=data)
        popo = prepare_popo(signature=sig, signing_key=first_key, alg_oid=sig_alg["algorithm"])

    elif isinstance(alt_key, PQKEMPrivateKey) and isinstance(first_key, TradSigPrivKey):
        extn = prepare_subject_alt_public_key_info_extn(alt_key.public_key(), critical=False) # type: ignore
        cert_template["extensions"].append(extn)
        cert_req["certTemplate"] = cert_template

        data = encoder.encode(cert_req)
        sig_alg = prepare_sig_alg_id(signing_key=first_key, use_rsa_pss=True, hash_alg=hash_alg)
        sig = sign_data_with_alg_id(key=first_key, alg_id=sig_alg, data=data)

        if bad_pop:
            sig = manipulate_first_byte(sig)

        popo = prepare_popo(signature=sig, signing_key=first_key, alg_oid=sig_alg["algorithm"])

    else:
        raise InvalidKeyCombination(
            "Invalid key combination for `Catalyst` request."
            "Allowed are PQKEMPublicKey<->TradSigPrivKey, "
            "PQSignaturePrivateKey<->TradSigPrivKey."
            f"Got: {first_key} and {alt_key}"
        )

    cert_req_msg["certReq"] = cert_req
    cert_req_msg["popo"] = popo
    return cert_req_msg


def _generate_catalyst_alt_sig_key(
        alt_sig_alg: Optional[rfc5280.Extension],
        alt_key: Optional[Union[PQSignaturePrivateKey, TradSigPrivKey]],
        allow_chosen_sig_alg: bool,
        extensions: Optional[rfc9480.Extensions] = None,
):
    """Generate an alternative key for the Catalyst signed certificate.

    :param alt_sig_alg: The alternative signature algorithm.
    :param alt_key: The alternative key to use for signing.
    :param allow_chosen_sig_alg: Whether to allow the chosen signature algorithm.
    :return: The alternative key and the optional alternative hash algorithm.
    :raises BadAsn1Data: If the ASN.1 data is invalid.
    :raises BadAlg: If the algorithm is not supported.
    """
    if extensions is not None:
        alt_sig_alg = get_extension(extensions, id_ce_altSignatureAlgorithm)

    pq_hash_alg = None
    if alt_sig_alg is not None and allow_chosen_sig_alg:
        alt_sig_alg, rest = decoder.decode(alt_sig_alg["extnValue"], asn1Spec=rfc5280.AlgorithmIdentifier())
        if rest:
            raise BadAsn1Data("AltSignatureAlgorithm")
        try:
            alt_key = generate_key_based_on_alg_id(alt_sig_alg)
        except NotImplementedError as e:
            raise BadAlg("The provided signature algorithm is not supported.", extra_details=str(e)) from e
        except UnknownOID as e:
            raise BadAlg("The provided signature algorithm is not supported.", extra_details=e.message) from e

        if alt_sig_alg["algorithm"] in PQ_SIG_PRE_HASH_OID_2_NAME:
            pq_hash_alg = PQ_SIG_PRE_HASH_OID_2_NAME[alt_sig_alg["algorithm"]].split("-")[-1]

    elif alt_key is None:
        alt_key = generate_key("ml-dsa-65")

    return alt_key, pq_hash_alg


def _process_single_catalyst_request(
        cert_req_msg: rfc4211.CertReqMsg,
        ca_cert: rfc9480.CMPCertificate,
        ca_key: PrivateKey,
        alt_key: Union[PQSignaturePrivateKey, TradSigPrivKey] = None,
        allow_chosen_sig_alg: bool = True,
        hash_alg: str = "sha256",
        use_rsa_pss: bool = True,
        cert_req_id: Optional[Union[int, str]] = None,
        hybrid_kem_key: Optional[Union[HybridKEMPrivateKey, ECDHPrivateKey]] = None,
) -> CA_CERT_RESPONSE:
    """Process a single Catalyst request.

    :param cert_req_msg: The certificate request message.
    :param ca_cert: The CA certificate matching the CA key.
    :param ca_key: The CA key to sign the certificate with.
    :param alt_key: The alternative key to use for Catalyst signature.
    :param allow_chosen_sig_alg: Whether to allow the client to choose the signature algorithm.
    Defaults to `True`.
    :param hash_alg: The hash algorithm to use for signing. Defaults to "sha256".
    :param use_rsa_pss: Whether to use RSA-PSS for signing. Defaults to `True`.
    :param cert_req_id: The certificate request ID. Defaults to `None`.
    :param hybrid_kem_key: The optional hybrid key to use for the HybridKEM key encapsulation.
    :return: The certificate response and the issued certificate.
    """
    cert_template = cert_req_msg["certReq"]["certTemplate"]

    alt_key, pq_hash_alg = _generate_catalyst_alt_sig_key(
        alt_sig_alg=None,
        alt_key=alt_key,
        allow_chosen_sig_alg=allow_chosen_sig_alg,
        extensions=cert_template["extensions"],
    )

    new_ee_cert = build_cert_from_cert_template(
        cert_template=cert_template,
        ca_cert=ca_cert,
        ca_key=ca_key,
        hash_alg=hash_alg,
        use_rsa_pss=use_rsa_pss,
        use_pre_hash=False,
    )
    new_ee_cert = sign_cert_catalyst(
        cert=new_ee_cert,
        trad_key=ca_key,
        pq_key=alt_key,
        use_rsa_pss=use_rsa_pss,
        hash_alg=hash_alg,
        pq_hash_alg=pq_hash_alg,
    )

    if cert_req_id is None:
        cert_req_id = 0

    enc_cert = None
    if cert_req_msg["popo"].getName() == "keyEncipherment":
        enc_cert = prepare_encr_cert_for_request(
            cert_req_msg=cert_req_msg,
            signing_key=ca_key,
            hash_alg=hash_alg,
            ca_cert=ca_cert,
            new_ee_cert=new_ee_cert,
            hybrid_kem_key=hybrid_kem_key,
            client_pub_key=None,
        )

    cert_response = prepare_cert_response(
        cert=new_ee_cert,
        cert_req_id=int(cert_req_id),
        enc_cert=enc_cert,
    )

    return cert_response, new_ee_cert


def _process_catalyst_requests(
        requests: rfc9480.PKIMessage,
        ca_cert: rfc9480.CMPCertificate,
        ca_key: PrivateKey,
        alt_key: Union[PQSignaturePrivateKey, TradSigPrivKey] = None,
        allow_chosen_sig_alg: bool = True,
        hash_alg: str = "sha256",
        use_rsa_pss: bool = True,
        hybrid_kem_key: Optional[Union[HybridKEMPrivateKey, ECDHPrivateKey]] = None,
) -> CA_CERT_RESPONSES:
    """Process multiple Catalyst requests.

    :param requests: The PKIMessage with the requests.
    :param ca_cert: The CA certificate matching the CA key.
    :param ca_key: The CA key to sign the certificate with.
    :param alt_key: The alternative key to use for Catalyst signature.
    :param allow_chosen_sig_alg: Whether to allow the client to choose the signature algorithm.
    Defaults to `True`.
    :param hash_alg: The hash algorithm to use for signing. Defaults to "sha256".
    :param use_rsa_pss: Whether to use RSA-PSS for signing. Defaults to `True`.
    :param hybrid_kem_key: The optional hybrid key to use for the HybridKEM key encapsulation.
    (when build an encrypted certificate response.)
    :return: A list of certificate responses and a list of issued certificates.
    """
    responses = []
    certs = []

    body_name = requests["body"].getName()
    for idx, cert_req_ms in enumerate(requests["body"][body_name]):
        verify_sig_pop_for_pki_request(
            pki_message=requests,
            cert_index=idx,
        )
        cert_response, cert = _process_single_catalyst_request(
            cert_req_msg=cert_req_ms,
            ca_cert=ca_cert,
            ca_key=ca_key,
            alt_key=alt_key,
            allow_chosen_sig_alg=allow_chosen_sig_alg,
            hash_alg=hash_alg,
            use_rsa_pss=use_rsa_pss,
            cert_req_id=None,
            hybrid_kem_key=hybrid_kem_key,
        )
        responses.append(cert_response)
        certs.append(cert)

    return responses, certs


def build_chameleon_from_p10cr(
        request: rfc9480.PKIMessage,
        ca_cert: rfc9480.CMPCertificate,
        ca_key: PrivateKey,
        cmp_protection_cert: Optional[rfc9480.CMPCertificate] = None,
        **kwargs,
) -> Tuple[rfc9480.PKIMessage, rfc9480.CMPCertificate, rfc9480.CMPCertificate]:
    """Build a Chameleon certificate from a `p10cr` request.


    Arguments:
    ----------
        - `request`: The PKIMessage request.
        - `ca_cert`: The CA certificate matching the CA key.
        - `ca_key`: The CA key to sign the certificate with.
        - `cmp_protection_cert`: The CMP protection certificate. Defaults to `None`.
        (to ensure that the certificate is at the second position)
        - `kwargs`: Additional keyword arguments.

    Returns:
    -------
        - The PKIMessage with the certificate response.
        - The issued paired certificate.
        - The delta certificate.

    Raises:
    -------
        - ValueError: If the request type is not `p10cr`.
        - ValueError: If the key type is invalid.
        - BadAsn1Data: If the ASN.1 data is invalid.
        - BadPOP: If the POP is invalid.

    """
    cert, delta_cert = build_chameleon_cert_from_paired_csr(
        csr=request["body"]["p10cr"],
        ca_cert=ca_cert,
        ca_key=ca_key,
    )
    pki_message, cert = build_cp_from_p10cr(cert=cert, request=request, **kwargs)
    if cmp_protection_cert is None:
        pki_message["extraCerts"].append(cmp_protection_cert)

    pki_message["extraCerts"].append(delta_cert)
    return pki_message, cert, delta_cert
