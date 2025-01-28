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
