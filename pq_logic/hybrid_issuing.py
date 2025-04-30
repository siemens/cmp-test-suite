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

from typing import Any, Optional, Sequence, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc4211, rfc5280, rfc6402, rfc9480
from robot.api.deco import keyword, not_keyword

from pq_logic.hybrid_sig import (
    catalyst_logic,
    cert_binding_for_multi_auth,
    certdiscovery,
    chameleon_logic,
    sun_lamps_hybrid_scheme_00,
)
from pq_logic.hybrid_sig.cert_binding_for_multi_auth import (
    prepare_related_cert_extension,
    validate_multi_auth_binding_csr,
)
from pq_logic.hybrid_sig.certdiscovery import prepare_subject_info_access_syntax_extension
from pq_logic.hybrid_structures import AltSignatureValueExt
from pq_logic.keys.abstract_pq import PQKEMPrivateKey, PQKEMPublicKey, PQSignaturePrivateKey, PQSignaturePublicKey
from pq_logic.keys.abstract_wrapper_keys import HybridKEMPrivateKey, HybridKEMPublicKey, KEMPublicKey
from pq_logic.keys.composite_sig03 import CompositeSig03PrivateKey, CompositeSig03PublicKey
from pq_logic.keys.composite_sig04 import CompositeSig04PrivateKey
from pq_logic.keys.sig_keys import MLDSAPrivateKey
from pq_logic.tmp_oids import (
    COMPOSITE_SIG04_OID_2_NAME,
    id_altSignatureExt,
    id_ce_deltaCertificateDescriptor,
    id_relatedCert,
)
from resources import (
    ca_ra_utils,
    certbuildutils,
    certextractutils,
    certutils,
    cmputils,
    keyutils,
    prepare_alg_ids,
    protectionutils,
    utils,
)
from resources.asn1_structures import PKIMessageTMP
from resources.ca_ra_utils import build_ca_message
from resources.certbuildutils import build_cert_from_csr
from resources.certextractutils import extract_extensions_from_csr, get_extension
from resources.convertutils import (
    copy_asn1_certificate,
    ensure_is_single_sign_key,
    ensure_is_single_verify_key,
    ensure_is_verify_key,
)
from resources.exceptions import BadAlg, BadAsn1Data, InvalidAltSignature, InvalidKeyCombination, UnknownOID
from resources.oidutils import (
    CMS_COMPOSITE03_OID_2_NAME,
    PQ_SIG_PRE_HASH_OID_2_NAME,
    id_ce_altSignatureAlgorithm,
    id_ce_altSignatureValue,
    id_ce_subjectAltPublicKeyInfo,
)
from resources.typingutils import (
    CACertResponse,
    CACertResponses,
    CAResponse,
    ECDHPrivateKey,
    ECSignKey,
    SignKey,
    Strint,
    TradSignKey,
    TradVerifyKey,
)


def build_sun_hybrid_cert_from_request(  # noqa: D417 Missing argument descriptions in the docstring
    request: PKIMessageTMP,
    ca_key: CompositeSig03PrivateKey,
    pub_key_loc: str,
    sig_loc: str,
    serial_number: Optional[int] = None,
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
    cert_chain: Optional[Sequence[rfc9480.CMPCertificate]] = None,
    cert_index: Optional[int] = None,
    **kwargs,
) -> Tuple[PKIMessageTMP, rfc9480.CMPCertificate, rfc9480.CMPCertificate]:
    """Build a Sun-Hybrid certificate from a request.

    The certificate in form 1 is at the second position in the `extraCerts` list.

    Arguments:
    ---------
       - `request`: The PKIMessage request.
       - `ca_key`: The key to sign the certificate with.
       - `protection_key`: The key to protect the certificate with.
       - `pub_key_loc`: The location of the public key.
       - `sig_loc`: The location of the signature.
       - `protection`: The protection to use. Defaults to "password_based_mac".
       - `password`: The password to use for protection. Defaults to `None`.
       - `issuer_cert`: The issuer certificate. Defaults to `None`.
       - `cert_chain`: The certificate chain. Defaults to `None`.
       - `cert_index`: The certificate index. Defaults to `None`.

    **kwargs:
    --------
         - `extensions`: The extensions to use for the certificate.
         (as an example for OCSP, CRL or etc.)
         - `bad_alt_sig`: Whether to manipulate the alternative signature. Defaults to `False`.

    Returns:
    -------
       - The PKIMessage with the certificate response.

    Raises:
    ------
         - `ValueError`: If the CA certificate or the certificate chain is missing.

    Examples:
    --------
    | ${response} ${cert4} ${cert1}= | Build Sun Hybrid Cert From Request | ${request} | ${signing_key} | ${ca_cert} |

    """
    if ca_cert is None and cert_chain is None:
        raise ValueError("Either ca_cert or cert_chain must be provided.")

    if ca_cert is None:
        ca_cert = cert_chain[0]  # type: ignore

    if request["body"].getName() == "p10cr":
        certutils.verify_csr_signature(csr=request["body"]["p10cr"])
        cert4, cert1 = sun_lamps_hybrid_scheme_00.sun_csr_to_cert(
            csr=request["body"]["p10cr"],
            issuer_private_key=ca_key.trad_key,  # type: ignore
            alt_private_key=ca_key.pq_key,  # type: ignore
            serial_number=serial_number,
            ca_cert=ca_cert,
            extensions=kwargs.get("extensions"),
            bad_alt_sig=kwargs.get("bad_alt_sig", False),
        )
        pki_message, _ = ca_ra_utils.build_cp_from_p10cr(request=request, cert=cert4, cert_req_id=-1)

    elif request["body"].getName() in ["ir", "cr", "kur", "crr"]:
        cert_index = cert_index if cert_index is not None else 0
        cert_req_msg: rfc4211.CertReqMsg = request["body"]["ir"][cert_index]
        public_key = ca_ra_utils.get_public_key_from_cert_req_msg(cert_req_msg)
        if isinstance(public_key, CompositeSig03PublicKey):
            ca_ra_utils.verify_sig_pop_for_pki_request(request, cert_index)
            cert4, cert1 = sun_lamps_hybrid_scheme_00.sun_cert_template_to_cert(
                cert_template=cert_req_msg["certReq"]["certTemplate"],
                ca_cert=ca_cert,
                ca_key=ca_key.trad_key,
                serial_number=serial_number,
                alt_private_key=ca_key.pq_key,
                pub_key_loc=pub_key_loc,
                sig_loc=sig_loc,
                extensions=kwargs.get("extensions"),
                bad_alt_sig=kwargs.get("bad_alt_sig", False),
            )

            pki_message, _ = ca_ra_utils.build_ip_cmp_message(
                cert=cert4,
                request=request,
                cert_req_id=int(cert_req_msg["certReq"]["certReqId"]),
            )

        elif isinstance(public_key, HybridKEMPublicKey):
            cert4, cert1 = sun_lamps_hybrid_scheme_00.sun_cert_template_to_cert(
                cert_template=cert_req_msg["certReq"]["certTemplate"],
                ca_cert=ca_cert,
                serial_number=serial_number,
                ca_key=ca_key.trad_key,
                alt_private_key=ca_key.pq_key,
                pub_key_loc=pub_key_loc,
                sig_loc=sig_loc,
                extensions=kwargs.get("extensions"),
            )

            pki_message = build_enc_cert_response(
                new_ee_cert=cert4,
                ca_cert=ca_cert,
                request=request,
                client_pub_key=public_key,
            )
        else:
            raise ValueError(f"Invalid key type: {type(public_key).__name__}")

    else:
        raise ValueError(f"Invalid request type: {request['body'].getName()}")

    return pki_message, cert4, cert1


@not_keyword
def build_enc_cert_response(
    request: PKIMessageTMP,
    ca_cert: rfc9480.CMPCertificate,
    ca_key: Optional[SignKey] = None,
    new_ee_cert: Optional[rfc9480.CMPCertificate] = None,
    hash_alg: str = "sha256",
    cert_index: Optional[Strint] = None,
    cert_req_id: Optional[Strint] = None,
    hybrid_kem_key: Optional[Union[HybridKEMPrivateKey, ECDHPrivateKey]] = None,
    client_pub_key: Optional[KEMPublicKey] = None,
) -> PKIMessageTMP:
    """Build an encrypted certificate response.

    :param request: The certificate request.
    :param new_ee_cert: The newly created end-entity certificate.
    :param ca_cert: The CA certificate.
    :param ca_key: The key to sign the certificate with.
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

    cert_req_msg: rfc4211.CertReqMsg = request["body"]["ir"][int(cert_index)]
    cert_req_id = cert_req_id or cert_req_msg["certReq"]["certReqId"]
    cert_req_id = int(cert_req_id)

    enc_cert = ca_ra_utils.prepare_encr_cert_from_request(
        cert_req_msg=cert_req_msg,
        ca_key=ca_key,
        hash_alg=hash_alg,
        ca_cert=ca_cert,
        new_ee_cert=new_ee_cert,
        hybrid_kem_key=hybrid_kem_key,
        client_pub_key=client_pub_key,
    )

    cert_response = ca_ra_utils.prepare_cert_response(
        enc_cert=enc_cert,
        cert_req_id=cert_req_id,
        text="Issued encrypted certificate please verify with `CertConf`",
    )

    pki_message = build_ca_message(
        request=request,
        responses=[cert_response],
        transaction_id=request["header"]["transactionID"].asOctets(),
        recip_nonce=request["header"]["senderNonce"].asOctets(),
    )

    return pki_message


def build_cert_from_catalyst_request(  # noqa: D417 Missing argument descriptions in the docstring
    request: PKIMessageTMP,
    ca_cert: rfc9480.CMPCertificate,
    ca_key: SignKey,
    cert_index: Union[str, int] = 0,
    hash_alg: str = "sha256",
    use_rsa_pss: bool = True,
    bad_sig: bool = False,
    **kwargs,
) -> Tuple[PKIMessageTMP, rfc9480.CMPCertificate]:
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

    Examples:
    --------
    | ${response} ${cert}= | Build Cert From Catalyst Request | ${request} | ${ca_cert} | ${ca_key} |
    | ${response} ${cert}= | Build Cert From Catalyst Request | ${request} | ${ca_cert} | ${ca_key} | ${cert_index}=1 |

    """
    if request["body"].getName() == "p10cr":
        raise ValueError("Only IR or CR is supported to build a encrypted certificate response.")

    cert_req_msg = ca_ra_utils.get_cert_req_msg_from_pkimessage(
        pki_message=request,
        index=cert_index,
    )

    popo: rfc4211.ProofOfPossession = cert_req_msg["popo"]

    if cert_req_msg["certReq"]["certTemplate"]["publicKey"]["algorithm"]["algorithm"] in CMS_COMPOSITE03_OID_2_NAME:
        raise ValueError("Composite keys are not supported for Catalyst certificates.")

    cert_template = cert_req_msg["certReq"]["certTemplate"]
    second_key = catalyst_logic.load_catalyst_public_key(cert_template["extensions"])

    verify_sig_popo_catalyst_cert_req_msg(
        cert_req_msg=cert_req_msg,
    )
    tbs_certs = certbuildutils.prepare_tbs_certificate_from_template(
        cert_template=cert_template,
        issuer=ca_cert["tbsCertificate"]["subject"],
        ca_key=ca_key,
        hash_alg=hash_alg,
        use_rsa_pss=use_rsa_pss,
        use_pre_hash=False,
        include_extensions=False,
    )
    if kwargs.get("extensions"):
        tbs_certs["extensions"].extend(kwargs.get("extensions"))

    alt_spki_extn = catalyst_logic.prepare_subject_alt_public_key_info_extn(key=second_key, critical=False)

    tbs_certs["extensions"].append(alt_spki_extn)
    cert = rfc9480.CMPCertificate()
    cert["tbsCertificate"] = tbs_certs
    cert = certbuildutils.sign_cert(
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
            ca_key=ca_key,
            request=request,
            cert_index=int(cert_index),
            hash_alg=hash_alg,
            client_pub_key=public_key,
        )
    else:
        pki_message, _ = ca_ra_utils.build_ip_cmp_message(
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
    sig_alg = prepare_alg_ids.prepare_sig_alg_id(signing_key=signing_key, use_rsa_pss=use_rsa_pss, hash_alg=hash_alg)
    sig = protectionutils.sign_data_with_alg_id(key=signing_key, alg_id=sig_alg, data=data)
    popo = cmputils.prepare_popo(signature=sig, signing_key=signing_key)
    popo["signature"]["signature"] = univ.BitString.fromOctetString(sig)
    return popo


def _compute_second_pop_catalyst(
    alt_key: Union[PQSignaturePrivateKey, TradSignKey],
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
    sig_alg = prepare_alg_ids.prepare_sig_alg_id(signing_key=alt_key, use_rsa_pss=use_rsa_pss, hash_alg=hash_alg)
    alt_sig_id_extn = catalyst_logic.prepare_alt_sig_alg_id_extn(alg_id=sig_alg, critical=False)
    alt_spki = catalyst_logic.prepare_subject_alt_public_key_info_extn(
        alt_key.public_key(),  # type: ignore
        critical=False,
    )
    cert_request["certTemplate"]["extensions"].append(alt_sig_id_extn)
    cert_request["certTemplate"]["extensions"].append(alt_spki)

    data = encoder.encode(cert_request)
    sig = protectionutils.sign_data_with_alg_id(key=alt_key, alg_id=sig_alg, data=data)
    if bad_alt_pop:
        sig = utils.manipulate_first_byte(sig)
    extn = catalyst_logic.prepare_alt_signature_value_extn(signature=sig, critical=False)
    cert_request["certTemplate"]["extensions"].append(extn)
    return cert_request


def _verify_alt_sig_for_pop(
    alt_pub_key: Union[PQSignaturePublicKey, TradVerifyKey],
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
        protectionutils.verify_signature_with_alg_id(
            public_key=alt_pub_key,
            signature=alt_signature_value.asOctets(),
            alg_id=alt_signature_algorithm,
            data=encoder.encode(cert_req_msg["certReq"]),
        )
    except InvalidSignature as e:
        raise InvalidAltSignature("Invalid signature for the alternative `POP`.") from e


@keyword(name="Verify Catalyst CertReqMsg")
def verify_sig_popo_catalyst_cert_req_msg(  # noqa: D417 Missing argument descriptions in the docstring
    cert_req_msg: rfc4211.CertReqMsg,
) -> None:
    """Verify a `Catalyst` certificate request message.

    Arguments:
    ---------
        - `cert_req_msg`: The certificate request message.

    Raises:
    ------
        - `InvalidSignature`: If the signature is invalid.
        - `ValueError`: If the alternative signature or algorithm is missing.
        - `InvalidAltSignature`: If the alternative signature is invalid.

    Examples:
    --------
    | Verify Catalyst CertReqMsg | ${cert_req_msg} |

    """
    cert_template = cert_req_msg["certReq"]["certTemplate"]
    alt_pub_key = catalyst_logic.load_catalyst_public_key(cert_template["extensions"])
    alt_sig_alg_id = get_extension(cert_template["extensions"], id_ce_altSignatureAlgorithm)
    alt_sig = get_extension(cert_template["extensions"], id_ce_altSignatureValue)

    first_key = ca_ra_utils.get_public_key_from_cert_req_msg(cert_req_msg)

    if cert_req_msg["popo"].getName() == "keyEncipherment":
        if alt_sig is None:
            raise ValueError(
                "Alternative signature is missing, if the public key inside the `CertTemplate` is a KEM key."
            )
        alt_pub_key = ensure_is_single_verify_key(alt_pub_key)

        if alt_sig_alg_id is None:
            raise ValueError(
                "Alternative signature algorithm is missing, if the public key inside the `CertTemplate` is a KEM key."
            )

        _verify_alt_sig_for_pop(
            alt_pub_key=alt_pub_key,
            cert_req_msg=cert_req_msg,
            alt_sig_alg_id=alt_sig_alg_id,
            alt_sig=alt_sig,
        )
        return

    sig_alg_oid = cert_req_msg["popo"]["signature"]["algorithmIdentifier"]
    oid = sig_alg_oid["algorithm"]

    if oid in CMS_COMPOSITE03_OID_2_NAME or oid in COMPOSITE_SIG04_OID_2_NAME:
        if not isinstance(first_key, PQSignaturePublicKey):
            first_key, alt_pub_key = alt_pub_key, first_key

        signature = cert_req_msg["popo"]["signature"]["signature"].asOctets()
        protectionutils.verify_composite_signature_with_keys(
            data=encoder.encode(cert_req_msg["certReq"]),
            signature=signature,
            first_key=first_key,
            second_key=alt_pub_key,
            alg_id=sig_alg_oid,
        )
        return

    if isinstance(alt_pub_key, PQKEMPublicKey):
        alg_id = cert_req_msg["popo"]["signature"]["algorithmIdentifier"]
        data = encoder.encode(cert_req_msg["certReq"])
        first_key = ensure_is_verify_key(first_key)
        protectionutils.verify_signature_with_alg_id(
            public_key=first_key,
            alg_id=alg_id,
            data=data,
            signature=cert_req_msg["popo"]["signature"]["signature"].asOctets(),
        )
    else:
        alg_id = cert_req_msg["popo"]["signature"]["algorithmIdentifier"]
        first_key = ensure_is_verify_key(first_key)
        try:
            protectionutils.verify_signature_with_alg_id(
                public_key=first_key,
                signature=cert_req_msg["popo"]["signature"]["signature"].asOctets(),
                alg_id=alg_id,
                data=encoder.encode(cert_req_msg["certReq"]),
            )
        except InvalidSignature as e:
            raise InvalidSignature("Invalid signature for the `POP`.") from e

        if alt_sig is None:
            raise ValueError(
                "Alternative signature is present, if the public key inside the `CertTemplate` is a KEM key."
            )

        if alt_sig_alg_id is None:
            raise ValueError(
                "Alternative signature algorithm is present, if the public key inside the `CertTemplate` is a KEM key."
            )

        _verify_alt_sig_for_pop(
            alt_pub_key=alt_pub_key,  # type: ignore
            cert_req_msg=cert_req_msg,
            alt_sig_alg_id=alt_sig_alg_id,
            alt_sig=alt_sig,
        )


def _cast_to_composite_sig_private_key(
    first_key: Any,
    alt_key: Any,
) -> CompositeSig04PrivateKey:
    """Cast the keys to a composite key.

    :param first_key: The first key to cast.
    :param alt_key: The second key to cast.
    :return: The composite key and public key.
    """
    if not isinstance(first_key, PQSignaturePrivateKey):
        first_key, alt_key = alt_key, first_key

    if not isinstance(first_key, MLDSAPrivateKey):
        raise InvalidKeyCombination("The Composite signature pq-key is not a MLDSA key.")

    if not isinstance(alt_key, (ECSignKey, RSAPrivateKey)):
        raise InvalidKeyCombination("The Composite signature trad-key is not a EC or RSA key.")

    return CompositeSig04PrivateKey(first_key, alt_key)


@keyword(name="Prepare Catalyst CertReqMsg Approach")
def prepare_catalyst_cert_req_msg_approach(  # noqa: D417 Missing argument descriptions in the docstring
    first_key: Union[PQKEMPrivateKey, TradSignKey, PQSignaturePrivateKey],
    alt_key: Union[PQSignaturePrivateKey, TradSignKey, PQKEMPrivateKey],
    cert_req_id: Union[int, str] = 0,
    hash_alg: str = "sha256",
    subject: str = "CN=CMP Catalyst Test",
    use_rsa_pss: bool = True,
    use_composite_sig: bool = False,
    bad_pop: bool = False,
    bad_alt_pop: bool = False,
) -> rfc4211.CertReqMsg:
    """Prepare a `Catalyst` approach for a certificate request message.

    Arguments:
    ---------
        - `first_key`: The first key to use for the request.
        - `alt_key`: The alternative key to use for the request.
        - `cert_req_id`: The certificate request ID. Defaults to `0`.
        - `hash_alg`: The hash algorithm to use for signing. Defaults to "sha256".
        - `subject`: The subject to use for the certificate. Defaults to "CN=CMP Catalyst Test".
        - `use_rsa_pss`: Whether to use RSA-PSS for signing. Defaults to `True`.
        - `use_composite_sig`: Whether to use composite signature keys. Defaults to `False`.
        - `bad_pop`: Whether to manipulate the POP. Defaults to `False`.
        - `bad_alt_pop`: Whether to manipulate the alternative POP. Defaults to `False`.

    Returns:
    -------
        - The populated `CertReqMsg` structure.

    Examples:
    --------
    | ${cert_req_msg}= | Prepare Catalyst CertReqMsg Approach | ${first_key} | ${alt_key} |
    | ${cert_req_msg}= | Prepare Catalyst CertReqMsg Approach | ${first_key} | ${alt_key} | ${cert_req_id}=1 |

    """
    cert_req_msg = rfc4211.CertReqMsg()
    cert_req = rfc4211.CertRequest()
    cert_req["certReqId"] = int(cert_req_id)

    cert_template = certbuildutils.prepare_cert_template(key=first_key, subject=subject)
    cert_req["certTemplate"] = cert_template

    if use_composite_sig:
        comp_key = _cast_to_composite_sig_private_key(first_key, alt_key)
        extn = catalyst_logic.prepare_subject_alt_public_key_info_extn(
            alt_key.public_key(),
            critical=False,
        )
        cert_req["certTemplate"]["extensions"].append(extn)
        data = encoder.encode(cert_req)
        sig_alg = prepare_alg_ids.prepare_sig_alg_id(
            signing_key=comp_key,  # type: ignore
            use_rsa_pss=True,
            hash_alg=hash_alg,
        )
        sig = protectionutils.sign_data_with_alg_id(key=comp_key, alg_id=sig_alg, data=data)

        if bad_pop:
            sig = utils.manipulate_bytes_based_on_key(sig, comp_key)

        popo = cmputils.prepare_popo(signature=sig, alg_oid=sig_alg["algorithm"])

    elif isinstance(first_key, PQKEMPrivateKey) and isinstance(alt_key, TradSignKey):
        popo = cmputils.prepare_popo_challenge_for_non_signing_key(use_encr_cert=True)
        cert_req = _compute_second_pop_catalyst(
            alt_key=alt_key,
            cert_request=cert_req,
            hash_alg=hash_alg,
            use_rsa_pss=use_rsa_pss,
            bad_alt_pop=bad_alt_pop,
        )

    elif isinstance(alt_key, (PQSignaturePrivateKey, TradSignKey)) and isinstance(
        first_key, (PQSignaturePrivateKey, TradSignKey)
    ):
        # means that both are signature keys.
        alt_key = ensure_is_single_sign_key(alt_key)
        signing_key = ensure_is_single_sign_key(first_key)
        cert_req = _compute_second_pop_catalyst(
            alt_key=alt_key, cert_request=cert_req, hash_alg=hash_alg, use_rsa_pss=use_rsa_pss, bad_alt_pop=bad_alt_pop
        )

        data = encoder.encode(cert_req)

        sig_alg = prepare_alg_ids.prepare_sig_alg_id(
            signing_key=signing_key, use_rsa_pss=use_rsa_pss, hash_alg=hash_alg
        )
        sig = protectionutils.sign_data_with_alg_id(key=signing_key, alg_id=sig_alg, data=data)
        popo = cmputils.prepare_popo(signature=sig, signing_key=signing_key, alg_oid=sig_alg["algorithm"])

    elif isinstance(alt_key, PQKEMPrivateKey) and isinstance(first_key, TradSignKey):
        extn = catalyst_logic.prepare_subject_alt_public_key_info_extn(
            alt_key.public_key(),  # type: ignore
            critical=False,
        )
        cert_template["extensions"].append(extn)
        cert_req["certTemplate"] = cert_template

        data = encoder.encode(cert_req)
        sig_alg = prepare_alg_ids.prepare_sig_alg_id(signing_key=first_key, use_rsa_pss=True, hash_alg=hash_alg)
        sig = protectionutils.sign_data_with_alg_id(key=first_key, alg_id=sig_alg, data=data)

        if bad_pop:
            sig = utils.manipulate_first_byte(sig)

        popo = cmputils.prepare_popo(signature=sig, signing_key=first_key, alg_oid=sig_alg["algorithm"])

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
    alt_key: Optional[Union[PQSignaturePrivateKey, TradSignKey]],
    allow_chosen_sig_alg: bool,
    extensions: Optional[rfc9480.Extensions] = None,
) -> Tuple[PQSignaturePrivateKey, Optional[str]]:
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
        alt_sig_alg_id, rest = decoder.decode(alt_sig_alg["extnValue"], asn1Spec=rfc5280.AlgorithmIdentifier())
        if rest:
            raise BadAsn1Data("AltSignatureAlgorithm")
        try:
            alt_key = keyutils.generate_key_based_on_alg_id(alt_sig_alg_id)  # type: ignore
        except NotImplementedError as e:
            raise BadAlg("The provided signature algorithm is not supported.", error_details=str(e)) from e
        except UnknownOID as e:
            raise BadAlg("The provided signature algorithm is not supported.", error_details=e.message) from e

        if alt_sig_alg_id["algorithm"] in PQ_SIG_PRE_HASH_OID_2_NAME:
            pq_hash_alg = PQ_SIG_PRE_HASH_OID_2_NAME[alt_sig_alg_id["algorithm"]].split("-")[-1]

    elif alt_key is None:
        alt_key = keyutils.generate_key("ml-dsa-65")  # type: ignore

    if not isinstance(alt_key, PQSignaturePrivateKey):
        raise BadAlg(
            "The provided signature algorithm is not supported."
            f"Got: {type(alt_key).__name__} instead of PQSignaturePrivateKey."
        )

    return alt_key, pq_hash_alg


@not_keyword
def build_catalyst_signed_cert_from_p10cr(
    request: PKIMessageTMP,
    ca_key: SignKey,
    ca_cert: rfc9480.CMPCertificate,
    alt_key: Optional[Union[PQSignaturePrivateKey, TradSignKey]] = None,
    hash_alg: str = "sha256",
    use_rsa_pss: bool = True,
    cert_req_id: Optional[Union[int, str]] = None,
    allow_chosen_sig_alg: bool = True,
) -> Tuple[PKIMessageTMP, rfc9480.CMPCertificate]:
    """Build a certificate from a request, which want to be signed with an alternative key.

    :param request: The `p10cr` request.
    :param ca_key: The CA key to use for signing the certificate.
    :param ca_cert: The CA certificate matching the CA key.
    :param alt_key: The alternative key to use for signing. Defaults to
    either the chosen key from the `AltSignatureAlgorithm` extension or a `ml-dsa-65` key.
    :param hash_alg: The hash algorithm to use for signing. Defaults to "sha256".
    :param use_rsa_pss: Whether to use RSA-PSS for signing. Defaults to `True`.
    :param cert_req_id: The certificate request ID. Defaults to `None`.
    :param allow_chosen_sig_alg: Whether to allow the chosen signature algorithm. Defaults to `True`.
    (indicated by the `AltSignatureAlgorithm` extension.)
    :return:
    """
    certutils.verify_csr_signature(csr=request["body"]["p10cr"])
    crs_extensions = extract_extensions_from_csr(request["body"]["p10cr"])

    alt_sig_alg = None
    if crs_extensions is not None:
        alt_sig_alg = get_extension(crs_extensions, id_ce_altSignatureAlgorithm)

    alt_key, pq_hash_alg = _generate_catalyst_alt_sig_key(
        alt_sig_alg=alt_sig_alg, alt_key=alt_key, allow_chosen_sig_alg=allow_chosen_sig_alg
    )

    cert = certbuildutils.build_cert_from_csr(
        csr=request["body"]["p10cr"],
        ca_key=ca_key,
        ca_cert=ca_cert,
        hash_alg=hash_alg,
        use_rsa_pss=use_rsa_pss,
        include_csr_extensions=False,
    )

    if not isinstance(ca_key, TradSignKey):
        raise ValueError("The CA key must be a traditional signing key.")

    cert = catalyst_logic.sign_cert_catalyst(
        cert=cert, trad_key=ca_key, pq_key=alt_key, use_rsa_pss=use_rsa_pss, hash_alg=hash_alg, pq_hash_alg=pq_hash_alg
    )

    if cert_req_id is None:
        cert_req_id = -1

    return ca_ra_utils.build_cp_from_p10cr(cert=cert, request=request, cert_req_id=int(cert_req_id))


def _process_single_catalyst_request(
    cert_req_msg: rfc4211.CertReqMsg,
    ca_cert: rfc9480.CMPCertificate,
    ca_key: SignKey,
    alt_key: Optional[Union[PQSignaturePrivateKey, TradSignKey]] = None,
    allow_chosen_sig_alg: bool = True,
    hash_alg: str = "sha256",
    use_rsa_pss: bool = True,
    cert_req_id: Optional[Union[int, str]] = None,
    hybrid_kem_key: Optional[Union[HybridKEMPrivateKey, ECDHPrivateKey]] = None,
    extensions: Optional[rfc9480.Extensions] = None,
) -> CACertResponse:
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
    :param extensions: The optional extensions to use for the certificate. Defaults to `None`.
    :return: The certificate response and the issued certificate.
    """
    cert_template = cert_req_msg["certReq"]["certTemplate"]

    alt_key, pq_hash_alg = _generate_catalyst_alt_sig_key(
        alt_sig_alg=None,
        alt_key=alt_key,
        allow_chosen_sig_alg=allow_chosen_sig_alg,
        extensions=cert_template["extensions"],
    )

    new_ee_cert = certbuildutils.build_cert_from_cert_template(
        cert_template=cert_template,
        ca_cert=ca_cert,
        ca_key=ca_key,
        hash_alg=hash_alg,
        use_rsa_pss=use_rsa_pss,
        use_pre_hash=False,
        extensions=extensions,
    )
    new_ee_cert = catalyst_logic.sign_cert_catalyst(
        cert=new_ee_cert,
        trad_key=ca_key,  # type: ignore
        pq_key=alt_key,
        use_rsa_pss=use_rsa_pss,
        hash_alg=hash_alg,
        pq_hash_alg=pq_hash_alg,
    )

    if cert_req_id is None:
        cert_req_id = 0

    enc_cert = None
    if cert_req_msg["popo"].getName() == "keyEncipherment":
        enc_cert = ca_ra_utils.prepare_encr_cert_from_request(
            cert_req_msg=cert_req_msg,
            ca_key=ca_key,
            hash_alg=hash_alg,
            ca_cert=ca_cert,
            new_ee_cert=new_ee_cert,
            hybrid_kem_key=hybrid_kem_key,
            client_pub_key=None,
        )

    cert_response = ca_ra_utils.prepare_cert_response(
        cert=new_ee_cert,
        cert_req_id=int(cert_req_id),
        enc_cert=enc_cert,
    )

    return cert_response, new_ee_cert


def _process_catalyst_requests(
    requests: PKIMessageTMP,
    ca_cert: rfc9480.CMPCertificate,
    ca_key: SignKey,
    alt_key: Optional[Union[PQSignaturePrivateKey, TradSignKey]] = None,
    allow_chosen_sig_alg: bool = True,
    hash_alg: str = "sha256",
    use_rsa_pss: bool = True,
    hybrid_kem_key: Optional[Union[HybridKEMPrivateKey, ECDHPrivateKey]] = None,
    extensions: Optional[rfc9480.Extensions] = None,
) -> CACertResponses:
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
    :param extensions: The optional extensions to use for the certificate. Defaults to `None`.
    :return: A list of certificate responses and a list of issued certificates.
    """
    responses = []
    certs = []

    body_name = requests["body"].getName()
    for idx, cert_req_ms in enumerate(requests["body"][body_name]):
        ca_ra_utils.verify_sig_pop_for_pki_request(
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
            extensions=extensions,
        )
        responses.append(cert_response)
        certs.append(cert)

    return responses, certs


def build_catalyst_signed_cert_from_req(  # noqa: D417 Missing argument descriptions in the docstring
    request: PKIMessageTMP,
    ca_cert: rfc9480.CMPCertificate,
    ca_key: SignKey,
    alt_key: Optional[Union[PQSignaturePrivateKey, TradSignKey]] = None,
    cert_index: Optional[Union[str, int]] = None,
    hash_alg: str = "sha256",
    use_rsa_pss: bool = True,
    allow_chosen_sig_alg: bool = True,
    hybrid_kem_key: Optional[Union[HybridKEMPrivateKey, ECDHPrivateKey]] = None,
    **kwargs,  # pylint: disable=unused-argument
) -> CAResponse:
    """Build a certificate from a Catalyst request.

    Arguments:
    ---------
        - `request`: The PKIMessage request.
        - `ca_cert`: The CA certificate matching the CA key.
        - `ca_key`: The CA key to sign the certificate with.
        - `alt_key`: The alternative key to use for Catalyst signature.
        - `cert_index`: The index of the certificate request to use. Defaults to `None`.
        - `hash_alg`: The hash algorithm to use for signing. Defaults to "sha256".
        - `use_rsa_pss`: Whether to use RSA-PSS for signing. Defaults to `True`.
        - `allow_chosen_sig_alg`: Whether to allow the client to choose the signature algorithm. Defaults to `True`.
        - `hybrid_kem_key`: The optional hybrid key to use for the HybridKEM key encapsulation.
        (when build an encrypted certificate response.)

    Returns:
    -------
        - The PKIMessage with the certificate response.
        - The issued certificates.

    Examples:
    --------
    | ${response} ${cert}= | Build Catalyst Signed Cert From Req | ${request} | ${ca_cert} | ${ca_key} |
    | ${response} ${cert}= | Build Catalyst Signed Cert From Req | ${request} | ${ca_cert} \
    | ${ca_key} | ${cert_index}=0 |

    """
    if request["body"].getName() == "p10cr":
        responses, cert = build_catalyst_signed_cert_from_p10cr(
            request=request,
            ca_cert=ca_cert,
            ca_key=ca_key,
            alt_key=alt_key,
            hash_alg=hash_alg,
            use_rsa_pss=use_rsa_pss,
        )
        certs = [cert]
        return responses, certs

    if request["body"].getName() in ["ir", "cr", "kur", "ccr"]:
        if cert_index is not None:
            cert_req_msg = ca_ra_utils.get_cert_req_msg_from_pkimessage(
                pki_message=request,
                index=int(cert_index),
            )
            cert_responses, cert = _process_single_catalyst_request(
                cert_req_msg=cert_req_msg,
                ca_cert=ca_cert,
                ca_key=ca_key,
                alt_key=alt_key,
                allow_chosen_sig_alg=allow_chosen_sig_alg,
                hash_alg=hash_alg,
                use_rsa_pss=use_rsa_pss,
                cert_req_id=cert_index,
                hybrid_kem_key=hybrid_kem_key,
            )
            certs = [cert]

        else:
            cert_responses, certs = _process_catalyst_requests(
                requests=request,
                ca_cert=ca_cert,
                ca_key=ca_key,
                alt_key=alt_key,
                hash_alg=hash_alg,
                use_rsa_pss=use_rsa_pss,
                hybrid_kem_key=hybrid_kem_key,
            )

    else:
        raise ValueError(
            f"Body type needs to be either `p10cr` or `ir` or `cr` or `kur` or `crr`.Got: {request['body'].getName()}"
        )

    pki_message = build_ca_message(request=request, responses=cert_responses)
    return pki_message, certs


def build_chameleon_from_p10cr(  # noqa: D417 Missing argument descriptions in the docstring
    request: PKIMessageTMP,
    ca_cert: rfc9480.CMPCertificate,
    ca_key: SignKey,
    **kwargs,
) -> Tuple[PKIMessageTMP, rfc9480.CMPCertificate, rfc9480.CMPCertificate]:
    """Build a Chameleon certificate from a `p10cr` request.

    Arguments:
    ---------
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
    ------
        - ValueError: If the request type is not `p10cr`.
        - ValueError: If the key type is invalid.
        - BadAsn1Data: If the ASN.1 data is invalid.
        - BadPOP: If the POP is invalid.

    Examples:
    --------
    | ${ca_cert}= | Build Chameleon From P10cr | ${request} | ${ca_cert} | ${ca_key} |
    | ${ca_cert}= | Build Chameleon From P10cr | ${request} | ${ca_cert} | ${ca_key} \
    | cmp_protection_cert=${cmp_protection_cert} |

    """
    cert, delta_cert = chameleon_logic.build_chameleon_cert_from_paired_csr(
        csr=request["body"]["p10cr"],
        ca_cert=ca_cert,
        ca_key=ca_key,
    )
    pki_message, cert = ca_ra_utils.build_cp_from_p10cr(cert=cert, request=request, **kwargs)
    return pki_message, cert, delta_cert


def build_cert_discovery_cert_from_p10cr(  # noqa: D417 Missing argument descriptions in the docstring
    request: PKIMessageTMP,
    ca_cert: rfc9480.CMPCertificate,
    ca_key: SignKey,
    url: str,
    serial_number: Union[int, str],
    max_freshness_seconds: Union[int, str] = 500,
    load_chain: bool = False,
    set_other_cert_vals: bool = True,
    **kwargs,
):
    """Build a certificate discovery certificate from a CSR.

    Arguments:
    ---------
        - `request`: The PKIMessage request.
        - `ca_cert`: The CA certificate matching the CA key.
        - `ca_key`: The CA key to sign the certificate with.
        - `url`: The URL to use for the certificate discovery.
        - `serial_number`: The serial number to use for the certificate.
        - `max_freshness_seconds`: The maximum freshness in seconds. Defaults to 500.
        - `load_chain`: Whether to load the chain or just the second certificate. Defaults to `False`.
        - `set_other_cert_vals`: Whether to set other certificate values. Defaults to `True`.
        (signature and public key algorithm inside the SIA entry)

    **kwargs:
    --------
        - `cert_req_id`: The certificate request ID. Defaults to `None`.
        - `hash_alg`: The hash algorithm to use for signing. Defaults to "sha256".
        - `use_rsa_pss`: Whether to use RSA-PSS for signing. Defaults to `True`.

    Returns:
    -------
        - The PKIMessage with the certificate response.
        - The issued certificate.

    Examples:
    --------
    | ${response} ${cert}= | Build Cert Discovery Cert From CSR | ${request} | ${ca_cert} | ${ca_key} | ${url} \
    | ${serial_number} |

    """
    certs = cert_binding_for_multi_auth.validate_related_cert_pop(
        csr=request["body"]["p10cr"],
        max_freshness_seconds=max_freshness_seconds,
        load_chain=load_chain,
    )

    extn = prepare_subject_info_access_syntax_extension(
        url=url,
        critical=False,
        other_cert=certs[0] if set_other_cert_vals else None,
    )

    extn = [extn]
    if kwargs.get("extensions"):
        extn.extend(kwargs.get("extensions"))  # type: ignore

    cert = certbuildutils.build_cert_from_csr(
        csr=request["body"]["p10cr"],
        ca_key=ca_key,
        ca_cert=ca_cert,
        hash_alg=kwargs.get("hash_alg", "sha256"),
        use_rsa_pss=kwargs.get("use_rsa_pss", True),
        extensions=extn,
        serial_number=serial_number,
    )

    return ca_ra_utils.build_cp_from_p10cr(cert=cert, request=request, **kwargs)


@keyword(name="Build Related Cert From CSR")
def build_related_cert_from_csr(  # noqa: D417 Missing argument descriptions in the docstring
    csr: rfc6402.CertificationRequest,
    ca_key: SignKey,
    ca_cert: rfc9480.CMPCertificate,
    related_cert: Optional[rfc9480.CMPCertificate] = None,
    critical: bool = False,
    **kwargs,
) -> rfc9480.CMPCertificate:
    """Build the related certificate from a CSR.

    Arguments:
    ---------
       - `csr`: The CSR from which to build the related certificate.
       - `ca_key`: The private key of the CA.
       - `ca_cert`: The CA certificate matching the private key.
       - `related_cert`: The related certificate. Defaults to `None`.
       - `critical`: Whether the extension should be critical. Defaults to `False`.

    **kwargs:
    ---------
       - `trustanchors`: The directory containing the trust anchors. Defaults to `./data/trustanchors`.
       - `allow_os_store`: Whether to allow the OS trust store. Defaults to `False`.
       - `crl_check`: Whether to check the CRL. Defaults to `False`.
       - `max_freshness_seconds`: How fresh the `BinaryTime` must be. Defaults to `500`.
       - `load_chain`: Whether to load a chain or a single certificate, from the URI. Defaults to `False`.

    Returns:
    -------
       - The related certificate.

    Raises:
    ------
       - ValueError: If the `BinaryTime` is not fresh or the certificate chain is invalid.
       - InvalidSignature: If the POP of the related certificate is invalid.
       - ValueError: If the last certificate in the chain is not a trust anchor.
       - ValueError: If the certificate chain is not valid.

    Examples:
    --------
    | ${cert}= | Build Related Certificate | ${csr} | ${ca_key} | ${ca_cert} |

    """
    if related_cert is None:
        related_cert = validate_multi_auth_binding_csr(
            csr,
            load_chain=kwargs.get("load_chain", False),
            trustanchors=kwargs.get("trustanchors", "./data/trustanchors"),
            allow_os_store=kwargs.get("allow_os_store", False),
            crl_check=kwargs.get("crl_check", False),
            max_freshness_seconds=kwargs.get("max_freshness_seconds", 500),
        )

    extn = prepare_related_cert_extension(related_cert, critical=critical)

    extn = [extn]
    if kwargs.get("extensions"):
        extn.extend(kwargs.get("extensions"))  # type: ignore

    # build the certificate
    cert = build_cert_from_csr(
        csr=csr,
        ca_key=ca_key,
        ca_cert=ca_cert,
        extensions=extn,
    )

    return cert

@not_keyword
def is_hybrid_cert(cert: rfc9480.CMPCertificate) -> Optional[str]:
    """Check if the certificate is a hybrid certificate.

    :param cert: The certificate to check.
    :return: The hybrid key type if the certificate is a hybrid certificate, otherwise `None`.
    """
    alg_oid = cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"]

    if alg_oid in COMPOSITE_SIG04_OID_2_NAME:
        return "composite-sig-04"
    if alg_oid in CMS_COMPOSITE03_OID_2_NAME:
        return "composite-sig-03"

    dcd = certextractutils.get_extension(cert["tbsCertificate"]["extensions"], id_ce_deltaCertificateDescriptor)
    if dcd is not None:
        return "chameleon"

    extn = certextractutils.get_extension(cert["tbsCertificate"]["extensions"], id_altSignatureExt)
    if extn is not None:
        return "sun-hybrid"

    extn = certextractutils.get_extension(
        cert["tbsCertificate"]["extensions"],
        id_ce_altSignatureValue,
    )

    extn2 = certextractutils.get_extension(
        cert["tbsCertificate"]["extensions"],
        id_ce_subjectAltPublicKeyInfo,
    )

    if extn is not None or extn2 is not None:
        return "catalyst"

    if certdiscovery.is_cert_discovery_cert(
        cert=cert,
    ):
        return "cert-discovery"

    extn = certextractutils.get_extension(cert["tbsCertificate"]["extensions"], id_relatedCert)
    if extn is not None:
        return "related-cert"

    return None
