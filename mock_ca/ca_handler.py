# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Contains the CA Handler for the Mock CA."""

import argparse
import logging
import os
import sys
from typing import Any, List, Optional, Sequence, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import ocsp

# needs to be here to import the correct modules
# so that this file can be run from the root directory with:
# python ./mock_ca/ca_handler.py
sys.path.append(".")
from cryptography import x509
from flask import Flask, Response, request
from pyasn1_alt_modules import rfc5280, rfc9480, rfc9481

from mock_ca.cert_conf_handler import CertConfHandler
from mock_ca.cert_req_handler import CertReqHandler
from mock_ca.challenge_handler import ChallengeHandler
from mock_ca.db_config_vars import CertConfConfigVars, VerifyState
from mock_ca.general_msg_handler import GeneralMessageHandler
from mock_ca.hybrid_handler import HybridIssuingHandler, SunHybridHandler
from mock_ca.mock_fun import BaseURLData, KeySecurityChecker, MockCAState
from mock_ca.nested_handler import NestedHandler
from mock_ca.operation_dbs import MockCAOPCertsAndKeys, StatefulSigState
from mock_ca.prot_handler import ProtectionHandler
from mock_ca.rev_handler import RevocationHandler
from mock_ca.stfl_validator import STFLPKIMessageValidator
from pq_logic.hybrid_issuing import (
    build_catalyst_signed_cert_from_req,
    build_cert_discovery_cert_from_p10cr,
    build_cert_from_catalyst_request,
    build_chameleon_from_p10cr,
    build_related_cert_from_csr,
    is_hybrid_cert,
)
from pq_logic.hybrid_sig.cert_binding_for_multi_auth import validate_multi_auth_binding_csr
from pq_logic.hybrid_sig.sun_lamps_hybrid_scheme_00 import extract_sun_hybrid_alt_sig, sun_cert_template_to_cert
from pq_logic.keys.abstract_pq import PQSignaturePrivateKey
from pq_logic.keys.abstract_wrapper_keys import HybridKEMPrivateKey
from pq_logic.keys.composite_sig13 import CompositeSig13PrivateKey
from pq_logic.pq_verify_logic import verify_hybrid_pkimessage_protection
from pq_logic.tmp_oids import id_it_KemCiphertextInfo
from resources import asn1utils
from resources.asn1_structures import PKIMessageTMP
from resources.ca_ra_utils import (
    build_cp_cmp_message,
    build_ip_cmp_message,
    get_popo_from_pkimessage,
    validate_cert_req_id_nums,
)
from resources.certbuildutils import (
    build_certificate,
    prepare_authority_key_identifier_extension,
    prepare_cert_template,
    prepare_crl_distribution_point_extension,
    prepare_distribution_point,
    prepare_issuing_distribution_point,
    prepare_issuing_distribution_point_extension,
    prepare_ocsp_extension,
)
from resources.certutils import load_public_key_from_cert, parse_certificate
from resources.checkutils import (
    check_is_protection_present,
)
from resources.cmputils import (
    build_cmp_error_message,
    find_oid_in_general_info,
    get_cmp_message_type,
    parse_pkimessage,
    patch_extra_certs,
    patch_sender,
    patch_senderkid,
)
from resources.compareutils import compare_pyasn1_names
from resources.convertutils import ensure_is_sign_key, ensure_is_verify_key
from resources.exceptions import (
    BadAlg,
    BadAsn1Data,
    BadCertTemplate,
    BadConfig,
    BadKeyUsage,
    BadMessageCheck,
    BadRequest,
    BodyRelevantError,
    CertRevoked,
    CMPTestSuiteError,
    InvalidAltSignature,
    InvalidKeyData,
    NotAuthorized,
    UnknownOID,
)
from resources.general_msg_utils import build_genp_kem_ct_info_from_genm
from resources.keyutils import generate_key, load_private_key_from_file, load_public_key_from_spki
from resources.oid_mapping import may_return_oid_to_name
from resources.oidutils import (
    HYBRID_SIG_OID_2_NAME,
    PQ_SIG_OID_2_NAME,
    PQ_STATEFUL_HASH_SIG_OID_2_NAME,
    SUPPORTED_MAC_OID_2_NAME,
    TRAD_SIG_OID_2_NAME,
)
from resources.protectionutils import (
    protect_hybrid_pkimessage,
    protect_pkimessage,
    protect_pkimessage_kem_based_mac,
    validate_orig_pkimessage,
)
from resources.suiteenums import ProtectedType
from resources.typingutils import ECDHPrivateKey, EnvDataPrivateKey, PublicKey, SignKey, VerifyKey
from resources.utils import load_and_decode_pem_file
from unit_tests.utils_for_test import load_ca_cert_and_key, load_env_data_certs


def _build_error_from_exception(e: CMPTestSuiteError, request_msg: Optional[PKIMessageTMP] = None) -> PKIMessageTMP:
    """Build an error response from an exception.

    :param e: The exception.
    :param request_msg: The PKIMessage request.
    :return: The build error response.
    """
    exclude_fields = []
    if request_msg is not None:
        if not request_msg["header"]["senderNonce"].isValue:
            recip_nonce = None
            exclude_fields.append("recipNonce")
        else:
            recip_nonce = request_msg["header"]["senderNonce"].asOctets()

        if not request_msg["header"]["transactionID"].isValue:
            tx_id = None
            exclude_fields.append("transactionID")
        else:
            tx_id = request_msg["header"]["transactionID"].asOctets()
    else:
        recip_nonce = None
        tx_id = None

    msg = build_cmp_error_message(
        failinfo=e.get_failinfo(),
        texts=e.message,
        status="rejection",
        error_texts=e.get_error_details(),
        recip_nonce=recip_nonce,
        transaction_id=tx_id,
        exclude_fields=", ".join(exclude_fields) if exclude_fields else None,
    )
    return msg


def _contains_challenge(request_msg: PKIMessageTMP) -> bool:
    """Check if the request contains a challenge.

    :param request_msg: The PKIMessage request.
    :return: `True` if the request is made for a challenge, otherwise `False`.
    """
    if request_msg["body"].getName() in ["ir", "cr"]:
        popo = get_popo_from_pkimessage(request_msg)
        if not popo.isValue:
            return False

        if popo.getName() not in ["keyAgreement", "keyEncipherment"]:
            return False

        _name = popo.getName()

        popo_type = popo[_name].getName()

        if not popo[_name].isValue:
            return False

        if popo_type != "subsequentMessage":
            return False

        if not popo[_name]["subsequentMessage"].isValue:
            return False

        if popo[_name]["subsequentMessage"].prettyPrint() == "challengeResp":
            return True

    return False


class CAHandler:
    """A simple class to handle the CA operations."""

    def _prepare_extensions(
        self,
        ca_cert: rfc9480.CMPCertificate,
        base_url: str = "http://localhost",
        cfg_extensions: Optional[Sequence[rfc5280.Extension]] = None,
        port_num: int = 5000,
    ) -> rfc9480.Extensions:
        """Prepare the extensions for the CA.

        Prepares the authority key identifier, OCSP, and CRL distribution point extensions.

        :param base_url: The base URL for the CA, so that the OCSP and CRL URLs can be generated.
        :param ca_cert: The CA issuer certificate.
        :param cfg_extensions: Additional extensions to add.
        :param port_num: The port number for the CA.
        :return: The list of extensions.
        """
        ca_pub_key = load_public_key_from_cert(ca_cert)

        if not isinstance(ca_pub_key, VerifyKey):
            raise BadConfig(f"The CA public key is not a `VerifyKey`. Got: {type(ca_pub_key)}")

        url_data = BaseURLData(base_url=base_url, port_num=port_num)

        aki_extn = prepare_authority_key_identifier_extension(ca_pub_key, critical=False)
        crl_url = url_data.crl_url
        self.ocsp_extn = prepare_ocsp_extension(ocsp_url=url_data.ocsp_url, critical=False)
        dis_point = prepare_distribution_point(
            full_name=crl_url,
            reason_flags="all",
        )

        self.crl_extn = prepare_crl_distribution_point_extension(
            dis_point,
            crl_issuers=ca_cert["tbsCertificate"]["subject"],
            critical=False,
        )

        idp = prepare_issuing_distribution_point(
            full_name=crl_url,
            only_some_reasons=None,
            only_contains_user_certs=False,
            only_contains_ca_certs=False,
            only_contains_attribute_certs=False,
            indirect_crl=False,
        )

        idp_extn = prepare_issuing_distribution_point_extension(
            iss_dis_point=idp,
            critical=False,
        )

        extensions = rfc9480.Extensions()
        extensions.extend([aki_extn, self.ocsp_extn, self.crl_extn, idp_extn])
        if cfg_extensions is not None:
            extensions.extend(cfg_extensions)
        return extensions

    def __init__(
        self,
        ca_cert: Optional[rfc9480.CMPCertificate] = None,
        ca_key: Optional[SignKey] = None,
        config: Optional[dict] = None,
        pre_shared_secret: bytes = b"SiemensIT",
        ca_alt_key: Optional[PQSignaturePrivateKey] = None,
        mock_ca_state: Optional[MockCAState] = None,
        port: int = 5000,
        use_openssl: bool = False,
        base_url: str = "http://127.0.0.1",
        enforce_rfc9481: bool = False,
        trusted_ras_dir: str = "./data/trusted_ras",
    ):
        """Initialize the CA Handler.

        :param ca_cert: The CA issuer certificate. Defaults to `load_ca_cert_and_key()`.
        :param ca_key: The CA issuer key.  Defaults to `load_ca_cert_and_key()`.
        :param ca_alt_key: The CA alternative catalyst sign key. Defaults to `None`.
        :param pre_shared_secret: The pre-shared secret for the CA. Defaults to b"SiemensIT".
        :param mock_ca_state: The state of the CA, creates a fresh state if not provided. Defaults to `None`.
        :param port: The port for the CA, used for the Extensions preparation. Defaults to `5000`.
        :param use_openssl: If OpenSSL should be used for verification. Defaults to `False`.
        :param config: The configuration for the CA Handler.
        :param base_url: The base URL for the CA ONLY used to prepare the extensions (CRL-DP, OCSP, IDP, Sun-Hybrid).
        Defaults to `http://localhost`.
        :param enforce_rfc9481: Whether to enforce the RFC 9481 algorithm profile,
        for MAC and traditional protected PKIMessages. Defaults to `False`.
        :param trusted_ras_dir: The directory for the trusted RAs. Defaults to `./data/trusted_ras`.
        :raises BadConfig: If the CA certificate and key are not provided.
        """
        if ca_cert is None and ca_key is None:
            ca_cert, ca_key = load_ca_cert_and_key()

        if ca_cert is None or ca_key is None:
            raise BadConfig("CA certificate and key must be provided.")

        self.url_data = BaseURLData(base_url=base_url, port_num=port)

        config = config or {"ca_alt_key": ca_alt_key}

        for key, item in load_env_data_certs().items():
            if key not in config:
                config[key] = item

        config["ca_cert"] = ca_cert
        config["ca_key"] = ca_key
        self.ca_cert = ca_cert
        self.ca_key = ca_key
        self.ca_cert_chain = config.get("ca_cert_chain", [ca_cert])
        self.operation_state = MockCAOPCertsAndKeys(**config)

        self.config = config

        self.extensions = self._prepare_extensions(
            self.ca_cert, self.url_data.base_url, config.get("extensions"), port_num=self.url_data.port_num
        )

        self.comp_key = generate_key("composite-sig")
        self.comp_cert = build_certificate(private_key=self.comp_key, is_ca=True, common_name="CN=Test CA")[0]
        self.sun_hybrid_key = generate_key("composite-sig")  # type: ignore
        self.sun_hybrid_key: CompositeSig13PrivateKey
        cert_template = prepare_cert_template(
            self.sun_hybrid_key,
            subject="CN=Hans the Tester",
        )
        self.sun_hybrid_cert, cert1 = sun_cert_template_to_cert(
            cert_template=cert_template,
            ca_cert=ca_cert,
            ca_key=self.sun_hybrid_key.trad_key,  # type: ignore
            alt_private_key=self.sun_hybrid_key.pq_key,  # type: ignore
            pub_key_loc=self.url_data.get_pubkey_url(1),
            sig_loc=self.url_data.get_sig_url(1),
            serial_number=1,
            extensions=[self.ocsp_extn, self.crl_extn],
        )

        self.sender = "CN=Mock CA"
        self.ca_alt_key = ca_alt_key
        self.state = mock_ca_state or MockCAState()
        self.pre_shared_secret = pre_shared_secret
        self.cert_chain = [self.ca_cert, self.comp_cert, self.sun_hybrid_cert, cert1]

        alt_sig = extract_sun_hybrid_alt_sig(cert1)
        self.state.sun_hybrid_state.sun_hybrid_certs[1] = self.sun_hybrid_cert
        self.state.sun_hybrid_state.sun_hybrid_pub_keys[1] = self.sun_hybrid_key.pq_key.public_key()
        self.state.sun_hybrid_state.sun_hybrid_signatures[1] = alt_sig

        if config.get("hybrid_kem_path"):
            self.hybrid_kem = load_private_key_from_file(config["hybrid_kem_path"])

            if config.get("hybrid_cert_path"):
                self.hybrid_cert = parse_certificate(load_and_decode_pem_file(config["hybrid_cert_path"]))
            else:
                self.hybrid_cert, _ = build_certificate(
                    private_key=self.hybrid_kem,
                    hash_alg="sha256",
                    is_ca=True,
                    common_name="CN=Hans the Tester",
                )

        else:
            self.xwing_cert = parse_certificate(load_and_decode_pem_file("data/unittest/hybrid_cert_xwing.pem"))
            self.xwing_key = load_private_key_from_file("data/keys/private-key-xwing-seed.pem")

        if self.xwing_key is not None:
            if not isinstance(self.xwing_key, HybridKEMPrivateKey):
                raise BadConfig(
                    f"The hybrid kem private key is not a `HybridKEMPrivateKey`.Got: {type(self.xwing_key)}"
                )

        self.rev_handler = RevocationHandler(self.state.certificate_db)
        self.cert_conf_handler = CertConfHandler(self.state)

        extensions = self.extensions

        self.verify_state = VerifyState(
            allow_only_authorized_certs=True,
            use_openssl=use_openssl,
        )

        kga_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        kga_cert = parse_certificate(load_and_decode_pem_file("data/unittest/ra_kga_cert_ecdsa.pem"))

        self.kga_cert_chain = [kga_cert, ca_cert]
        self.kga_cert = kga_cert
        self.kga_key = ensure_is_sign_key(kga_key)

        # Just to save all the certificates which are used by the Mock-CA,
        # to issued certs.
        self.own_certs = [
            self.ca_cert,
            self.kga_cert,
            self.comp_cert,
            self.sun_hybrid_cert,
        ]

        if self.xwing_cert is not None:
            self.own_certs.append(self.xwing_cert)

        self.pq_stateful_sig_state = StatefulSigState()

        self.protection_handler = ProtectionHandler(
            cmp_protection_cert=self.ca_cert,
            cmp_prot_key=self.ca_key,
            kem_ss_list=self.state.kem_mac_based,
            pre_shared_secret=self.pre_shared_secret,
            use_openssl=True,
            def_mac_alg="password_based_mac",
            enforce_rfc9481=enforce_rfc9481,
            trusted_ras_dir=trusted_ras_dir,
            pq_stateful_sig_state=self.pq_stateful_sig_state,
        )

        self.cert_req_handler = CertReqHandler(
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            state=self.state,
            cert_conf_handler=self.cert_conf_handler,
            extensions=extensions,
            shared_secrets=self.pre_shared_secret,
            xwing_key=self.xwing_key,
            kga_key=self.kga_key,
            kga_cert_chain=self.kga_cert_chain,
            cmp_protection_cert=self.protection_handler.protection_cert,
            pq_stateful_sig_state=self.pq_stateful_sig_state,
            ca_cert_chain=self.ca_cert_chain,
        )

        self.stfl_validator = STFLPKIMessageValidator(
            stfl_config=None,
            stfl_state=self.pq_stateful_sig_state,
        )

        self.cert_req_handler.stfl_validator = self.stfl_validator
        self.cert_conf_handler.stfl_validator = self.stfl_validator

        self.nested_handler = NestedHandler(
            cert_req_handler=self.cert_req_handler,
            cert_conf_handler=self.cert_conf_handler,
            allow_inner_unprotected=True,
        )
        self.challenge_handler = ChallengeHandler(
            ca_key=self.ca_key,
            ca_cert=self.ca_cert,
            extensions=extensions,
            operation_state=self.operation_state,
            cmp_protection_cert=self.protection_handler.protection_cert,
        )

        prot_enc_cert = parse_certificate(load_and_decode_pem_file("data/unittest/ca_encr_cert_rsa.pem"))
        prot_enc_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)

        if not isinstance(prot_enc_key, EnvDataPrivateKey):
            raise BadConfig(f"The protection encryption key is not a `EnvDataPrivateKey`.Got: {type(prot_enc_key)}")

        self.genm_handler = GeneralMessageHandler(
            root_ca_cert=self.ca_cert,
            root_ca_key=self.ca_key,
            rev_handler=self.rev_handler,
            password=self.pre_shared_secret,
            enforce_lwcmp=True,
            prot_enc_cert=prot_enc_cert,
            prot_enc_key=prot_enc_key,
            crl_url=self.url_data.crl_url,
        )

        self.hybrid_handler = HybridIssuingHandler(
            ca_cert=ca_cert,
            ca_key=ca_key,
            revocation_handler=self.rev_handler,
            cmp_protection_cert=self.protection_handler.protection_cert,
            sender=self.sender,
            extensions=extensions,
        )

        if not isinstance(self.sun_hybrid_key, CompositeSig13PrivateKey):
            raise BadConfig(f"The Sun Hybrid key is not a `CompositeSig03PrivateKey`.Got: {type(self.sun_hybrid_key)}")

        self.sun_hybrid_handler = SunHybridHandler(
            ca_cert=self.sun_hybrid_cert,
            ca_key=self.sun_hybrid_key,
            sun_hybrid_state=self.state.sun_hybrid_state,
            cert_chain=None,
            pre_shared_secret=self.pre_shared_secret,
        )

        self.alg_profile = {}
        self.alg_profile.update(TRAD_SIG_OID_2_NAME)
        self.alg_profile.update(SUPPORTED_MAC_OID_2_NAME)
        self.alg_profile.update(PQ_SIG_OID_2_NAME)
        self.alg_profile.update(PQ_STATEFUL_HASH_SIG_OID_2_NAME)
        self.alg_profile.update(HYBRID_SIG_OID_2_NAME)

        # The default algorithm for the CA, just to correctly build the error message.
        self.default_algorithms = rfc9481.ecdsa_with_SHA512

    def get_cc_certs(self) -> List[rfc9480.CMPCertificate]:
        """Return the issued cross-signed CA certificates.

        :return: The list of CA certificates.
        """
        return self.cert_req_handler.get_cross_signed_certs()

    def add_cert_to_issued_certs(self, cert: Union[rfc9480.CMPCertificate, List[rfc9480.CMPCertificate]]) -> None:
        """Add a certificate to the issued certificates.

        :param cert: The certificate(s) to add.
        """
        if isinstance(cert, rfc9480.CMPCertificate):
            cert = [cert]

        self.state.add_certs(cert, was_confirmed=True)

    def _build_body_relevant_error(self, e: BodyRelevantError) -> PKIMessageTMP:
        """Build a body relevant error from a BadRelevantError exception.

        :param e: The BadRelevantError exception.
        :return: The relevant error body.
        """
        request_msg = e.pki_message
        body_name = get_cmp_message_type(request_msg)

        if body_name == "rr":
            response = self.rev_handler.build_rp_error_response(request_msg, e)
        elif body_name in ["ir", "cr", "kur", "ccr", "p10cr"]:
            response = self.cert_req_handler.build_cert_resp_error_response(e, request_msg)
        else:
            return self.build_error_from_exception(e, request_msg=request_msg)

        return self.protection_handler.protect_pkimessage(
            response=response,
            request=request_msg,
        )

    def build_error_from_exception(
        self, e: CMPTestSuiteError, request_msg: Optional[PKIMessageTMP] = None
    ) -> PKIMessageTMP:
        """Build an error response from an exception.

        :param e: The exception.
        :param request_msg: The PKIMessage request.
        :return: The protected error response.
        """
        response = _build_error_from_exception(e, request_msg)

        if request_msg is None:
            request_msg = PKIMessageTMP()
            request_msg["header"]["protectionAlg"]["algorithm"] = self.default_algorithms

        if not request_msg["header"]["protectionAlg"].isValue:
            request_msg["header"]["protectionAlg"]["algorithm"] = self.default_algorithms

        try:
            # checks for an unknown OID, to replace it with the default one.
            ProtectedType.get_protection_type(request_msg)
        except UnknownOID:
            request_msg["header"]["protectionAlg"]["algorithm"] = self.default_algorithms

        return self.protection_handler.protect_pkimessage(response=response, request=request_msg)

    def verify_protection(self, request_msg: PKIMessageTMP, must_be_protected: bool = True) -> None:
        """Verify the protection of the request."""
        if request_msg["header"]["protectionAlg"].isValue:
            oid = request_msg["header"]["protectionAlg"]["algorithm"]
            if oid not in self.alg_profile:
                _name = may_return_oid_to_name(oid)
                raise BadAlg(f"The parsed protection algorithm is not supported Got: {str(_name)}")

        if not check_is_protection_present(request_msg, must_be_protected=must_be_protected):
            return

        if not request_msg["protection"].isValue:
            raise BadMessageCheck("Protection not provided for request.")

        if not request_msg["header"]["protectionAlg"].isValue:
            raise BadMessageCheck("Protection algorithm not provided for request.")

        self.stfl_validator.validate_pq_stateful_pki_message(request_msg)
        prot_type = ProtectedType.get_protection_type(request_msg)

        if prot_type == ProtectedType.KEM:
            logging.debug("KEM-based MAC protection is present.")
            self.state.kem_mac_based.verify_pkimessage_protection(request=request_msg)
            return

        self.protection_handler.validate_protection(
            request_msg, cc_certs=self.get_cc_certs(), exclude_stateful_sig_check=True
        )

    def _sign_nested_response(self, response: PKIMessageTMP, request_msg: PKIMessageTMP) -> PKIMessageTMP:
        """Sign the nested response."""
        if response["body"].getName() != "nested":
            if request_msg["body"]["nested"][0]["header"]["protectionAlg"].isValue:
                prot_type = ProtectedType.get_protection_type(request_msg)
                if prot_type == ProtectedType.MAC:
                    prot_type = self.protection_handler.get_same_mac_protection(
                        request_msg["header"]["protectionAlg"],
                    )
                    return protect_pkimessage(
                        pki_message=response,
                        password=self.pre_shared_secret,
                        protection=prot_type,
                    )

                if prot_type == ProtectedType.KEM:
                    # KEM-based MAC protection
                    ss = self.protection_handler.kem_shared_secret.get_shared_secret(request_msg)
                    if ss is not None:
                        response = patch_sender(response, sender_name=self.sender)
                        response = patch_senderkid(response, self.sender.encode("utf-8"))
                        response = protect_pkimessage_kem_based_mac(
                            pki_message=response,
                            shared_secret=self.pre_shared_secret,
                        )
                        return response
                if prot_type == ProtectedType.DH:
                    # DH-based MAC protection
                    ca_ecc_cert, ss = self.protection_handler.get_dh_cert_and_ss(request_msg["extraCerts"][0])
                    cert_chain = [ca_ecc_cert, self.ca_cert, self.ca_cert_chain]
                    response = protect_pkimessage(
                        pki_message=response,
                        shared_secret=ss,
                        protection="dh",
                        exclude_certs=True,
                    )
                    response = patch_extra_certs(
                        pki_message=response,
                        certs=cert_chain,
                    )
                    return response

        return protect_hybrid_pkimessage(
            pki_message=response,
            private_key=self.protection_handler.protection_key,
            protection="signature",
            cert=self.protection_handler.protection_cert,
        )

    def sign_response(
        self,
        response: PKIMessageTMP,
        request_msg: PKIMessageTMP,
        secondary_cert: Optional[rfc9480.CMPCertificate] = None,
    ) -> PKIMessageTMP:
        """Sign the response.

        :param response: The PKI message to sign.
        :param request_msg: The request message.
        :param secondary_cert: An optional secondary certificate to include in the response. Defaults to `None`.
        :return: The signed PKI message.
        """
        if request_msg["body"].getName() == "nested":
            return self._sign_nested_response(response, request_msg)

        if not request_msg["header"]["protectionAlg"].isValue:
            protected = protect_hybrid_pkimessage(
                pki_message=response,
                private_key=self.protection_handler.protection_key,
                protection="signature",
                cert=self.protection_handler.protection_cert,
            )
            return protected

        return self.protection_handler.protect_pkimessage(
            response=response,
            request=request_msg,
            secondary_cert=secondary_cert,
            add_certs=self.cert_chain,
        )

    def _check_is_not_confirmed(self, pki_message: PKIMessageTMP) -> None:
        """Check if the certificate is not confirmed, but used for a certificate request."""
        if not pki_message["extraCerts"].isValue:
            return

        if not pki_message["header"]["protectionAlg"].isValue:
            return

        prot_type = ProtectedType.get_protection_type(pki_message)
        if prot_type == ProtectedType.MAC:
            return

        body_name = pki_message["body"].getName()

        if body_name in ["certConf", "error"]:
            return

        for i, cert in enumerate(pki_message["extraCerts"]):
            result = self.cert_conf_handler.is_not_confirmed(cert=cert)
            if result:
                raise NotAuthorized(
                    "The certificate is not authorized to be used to "
                    "start a certificate request."
                    "The certificate must first be confirmed.",
                    error_details=[f"The certificate at index {i} is not confirmed."],
                )

    def process_cert_request(self, pki_message: PKIMessageTMP) -> PKIMessageTMP:
        """Process the normal request.

        :return: The PKI message containing the response.
        """
        try:
            response = self.cert_req_handler.process_cert_request(pki_message)
        except CMPTestSuiteError as e:
            logging.info("An error occurred: %s", str(e.message))
            return self.build_error_from_exception(e, pki_message)
        return self.sign_response(response=response, request_msg=pki_message)

    def process_normal_request(self, pki_message: PKIMessageTMP) -> PKIMessageTMP:
        """Process the normal request.

        :return: The PKI message containing the response.
        """
        logging.debug("Processing request with body: %s", pki_message["body"].getName())
        try:
            if pki_message["extraCerts"].isValue:
                self.rev_handler.is_not_allowed_to_request(
                    pki_message,
                    issued_certs=self.state.issued_certs,
                )
                logging.warning("The certificate was not revoked or for revocation request.")

            if pki_message["body"].getName() not in ["rr", "genm"]:
                self.verify_protection(pki_message)

            if pki_message["body"].getName() in ["ir", "cr", "p10cr", "crr", "kur", "rr"]:
                self._check_for_compromised_key(pki_message)

            if pki_message["body"].getName() not in ["certConf", "error"]:
                self._check_is_not_confirmed(pki_message)

            if pki_message["body"].getName() in ["ir", "cr"]:
                if _contains_challenge(pki_message):
                    response, ecc_key = self.challenge_handler.handle_challenge(pki_message)  # type: ignore
                    response: PKIMessageTMP
                    ecc_key: ECDHPrivateKey
                    cert = self.operation_state.get_ecc_cert(ecc_key)
                    return self.sign_response(
                        response=response,
                        request_msg=pki_message,
                        secondary_cert=cert,
                    )
            if pki_message["body"].getName() == "popdecr":
                response, certs = self.challenge_handler.handle_challenge(pki_message)  # type: ignore
                response: PKIMessageTMP
                certs: List[rfc9480.CMPCertificate]
                self.state.add_certs(certs=certs)
            elif pki_message["body"].getName() == "nested":
                return self.process_nested_request(pki_message)
            elif pki_message["body"].getName() in ["ir", "cr", "p10cr", "kur", "ccr"]:
                self.protection_handler.validate_protection(
                    pki_message=pki_message, cc_certs=self.get_cc_certs(), exclude_stateful_sig_check=True
                )
                self.stfl_validator.add_pq_stateful_pki_message(pki_message=pki_message)
                response = self.cert_req_handler.process_cert_request(pki_message)
            elif pki_message["body"].getName() == "rr":
                try:
                    self.cert_req_handler.validate_header(pki_message, must_be_protected=True)
                    response = self.process_rr(pki_message)
                except (BadMessageCheck, BadKeyUsage, BodyRelevantError) as e:
                    response = self.rev_handler.build_rp_error_response(request=pki_message, exception=e)

            elif pki_message["body"].getName() == "certConf":
                response = self.process_cert_conf(pki_message)
            elif pki_message["body"].getName() == "genm":
                self.cert_req_handler.validate_header(pki_message, must_be_protected=False)
                response, should_protect = self.process_genm(pki_message)
                if should_protect:
                    # Whether the PKIMessage should be protected, must not
                    # be protected for KEMCiphertextInfo.
                    response = self.sign_response(response=response, request_msg=pki_message)
                return self.genm_handler.patch_genp_message_for_extra_certs(pki_message=response)

            else:
                raise NotImplementedError(
                    f"Method not implemented, to handle the provided message: {pki_message['body'].getName()}."
                )

        except BodyRelevantError as e:
            logging.info("An error occurred: %s", str(e.message), exc_info=True)
            return self._build_body_relevant_error(e)

        except CMPTestSuiteError as e:
            logging.info("An error occurred: %s", str(e.message))
            return self.build_error_from_exception(e, request_msg=pki_message)

        except (InvalidSignature, InvalidAltSignature):
            e = BadMessageCheck(message="Invalid signature protection.")
            return self.build_error_from_exception(e, request_msg=pki_message)

        except Exception as e:  # pylint: disable=broad-except
            logging.info("An error occurred while processing the request: %s", str(e))
            logging.exception("An error occurred")
            logging.warning("An error occurred", exc_info=True)
            app.logger.error(e, exc_info=True)
            return self.build_error_from_exception(
                CMPTestSuiteError(
                    f"An error occurred while processing the request: {type(e)} {str(e)}", failinfo="systemFailure"
                ),
                request_msg=pki_message,
            )
        self.state.kem_mac_based.may_update_state(request=pki_message)
        return self.sign_response(response=response, request_msg=pki_message)

    def _is_allowed_to_make_a_request(
        self,
        pki_message: PKIMessageTMP,
    ) -> None:
        """Check if the request is allowed to be made.

        :param pki_message: The PKIMessage request.
        :raises NotAuthorized: If the request is not allowed.
        """
        self.rev_handler.is_not_allowed_to_request(
            pki_message,
            issued_certs=self.state.issued_certs,
        )

    def process_genm(self, pki_message: PKIMessageTMP) -> Tuple[PKIMessageTMP, bool]:
        """Process the GenM message.

        :param pki_message: The GenM message.
        :return: The PKI message containing the response.
        """
        if len(pki_message["body"]["genm"]) == 0:
            raise BadRequest("The general message does not contain any messages.")

        if pki_message["header"]["protectionAlg"].isValue:
            self.protection_handler.validate_protection(pki_message, self.get_cc_certs())

        if pki_message["body"]["genm"][0]["infoType"] == id_it_KemCiphertextInfo:
            if pki_message["header"]["protectionAlg"].isValue:
                raise BadRequest("Protection algorithm was set for KEMCiphertextInfo.")

            if not pki_message["extraCerts"].isValue:
                raise BadRequest("The extraCerts field was not set for KEMCiphertextInfo.")

            ss, genp = build_genp_kem_ct_info_from_genm(
                genm=pki_message,
            )

            self._check_is_not_confirmed(pki_message)
            self._is_allowed_to_make_a_request(pki_message)

            logging.warning("The certificate was not revoked or for revocation request.")

            self.state.add_kem_mac_shared_secret(pki_message=pki_message, shared_secret=ss)
            return genp, False

        return self.genm_handler.process_general_msg(pki_message), True

    def process_nested_request(self, request_msg: PKIMessageTMP) -> PKIMessageTMP:
        """Process the nested request.

        :param request_msg: The nested request.
        :return: The PKI message containing the response.
        """
        return self.nested_handler.process_nested_request(
            request_msg,
            prot_handler=self.protection_handler,
            pq_stateful_state=self.pq_stateful_sig_state,
        )

    def process_rr(self, pki_message: PKIMessageTMP) -> PKIMessageTMP:
        """Process the RR message.

        :param pki_message: The RR message.
        :return: The PKI message containing the response.
        """
        response, _ = self.rev_handler.process_revocation_request(
            pki_message=pki_message,
            issued_certs=self.state.issued_certs,
            shared_secret=self.state.get_kem_mac_shared_secret(pki_message=pki_message),
        )
        return response

    def process_cert_conf(self, pki_message: PKIMessageTMP) -> PKIMessageTMP:
        """Process the CertConf message.

        :param pki_message: The CertConf message.
        :return: The PKIMessage containing the response.
        """
        response, ccp_cert = self.cert_conf_handler.process_cert_conf(pki_message)
        if ccp_cert is not None:
            self.cert_req_handler.get_cross_signed_certs().append(ccp_cert)
        return response

    def _check_for_compromised_key(self, pki_message: PKIMessageTMP) -> None:
        """Check the request for a compromised key.

        :param pki_message: The PKIMessage request.
        :raises BadCertTemplate: If the certificate template is invalid.
        """
        try:
            result = self.state.cert_state_db.check_request_for_compromised_key(pki_message)
            if result:
                raise BadCertTemplate("The certificate template contained a compromised key.")
        except (InvalidKeyData, BadAsn1Data, BadAlg) as e:
            raise BodyRelevantError(
                e.message,
                pki_message=pki_message,
                failinfo="badCertTemplate",
                error_details=e.get_error_details(),
            )

    def process_ir(
        self,
        pki_message: PKIMessageTMP,
        must_be_protected: bool = True,
        verify_ra_verified: bool = True,
    ) -> PKIMessageTMP:
        """Process the IR message.

        :param pki_message: The IR message.
        :param must_be_protected: If `True`, the message must be protected.
        :param verify_ra_verified: Whether to verify the RA verified flag, or let it pass. Defaults to `True`.
        :return: The PKI message containing the response.
        """
        if pki_message["extraCerts"].isValue:
            logging.warning("IR Checking for revoked certificates")
            if self.rev_handler.is_revoked(pki_message["extraCerts"][0]):
                raise CertRevoked("The certificate was already revoked.")
            if self.rev_handler.is_updated(pki_message["extraCerts"][0]):
                raise CertRevoked("The certificate was already updated")

        logging.debug("Processing IR message")
        logging.debug("CA Key: %s", self.ca_key)
        logging.debug("Verify RA verified `process_ir`: %s", verify_ra_verified)

        if not pki_message["header"]["protectionAlg"].isValue and must_be_protected:
            raise BadMessageCheck("Protection algorithm was not set.")

        validate_orig_pkimessage(pki_message)

        confirm_ = find_oid_in_general_info(pki_message, rfc9480.id_it_implicitConfirm)
        response, certs = build_ip_cmp_message(
            request=pki_message,
            sender=self.sender,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            implicit_confirm=confirm_,
            extensions=[self.ocsp_extn, self.crl_extn],
            verify_ra_verified=verify_ra_verified,
        )

        if confirm_:
            self.state.add_certs(certs=certs)

        self.cert_conf_handler.add_response(
            pki_message=response,
            certs=certs,
        )

        logging.debug("RESPONSE: %s", pki_message.prettyPrint())
        self.state.store_transaction_certificate(
            pki_message=pki_message,
            certs=certs,
        )
        return response

    def process_chameleon(self, pki_message: PKIMessageTMP) -> PKIMessageTMP:
        """Process the Chameleon message.

        :param pki_message: The Chameleon message.
        :return: The PKI message containing the response.
        """
        if pki_message["body"].getName() == "p10cr":
            try:
                self.stfl_validator.validate_pq_stateful_pki_message(pki_message)

                if pki_message["extraCerts"].isValue:
                    self.hybrid_handler.is_revoked_for_issuing(request=pki_message, used_both_certs=False)

                self.hybrid_handler.chameleon_handler.is_delta_key_revoked(request=pki_message)

                validate_cert_req_id_nums(pki_message)
                response, paired_cert, delta_cert = build_chameleon_from_p10cr(
                    request=pki_message,
                    ca_cert=self.ca_cert,
                    ca_key=self.ca_key,
                    extensions=self.cert_req_handler.extensions,
                )
                self.state.store_transaction_certificate(
                    pki_message=pki_message,
                    certs=[paired_cert, delta_cert],
                )
                result = find_oid_in_general_info(pki_message, str(rfc9480.id_it_implicitConfirm))
                self.state.add_certs(certs=[paired_cert, delta_cert], was_confirmed=result)

                self.stfl_validator.process_stfl_after_request(
                    request=pki_message, certs=[paired_cert, delta_cert], chameleon=True
                )
                return self.sign_response(
                    response=response,
                    request_msg=pki_message,
                    secondary_cert=delta_cert,
                )
            except CMPTestSuiteError as e:
                logging.info("An error occurred: %s", str(e.message))
                return self.build_error_from_exception(e)
            except Exception as e:
                logging.info("An error occurred: %s", str(e))
                return self.build_error_from_exception(
                    CMPTestSuiteError(
                        f"An error occurred while processing the request: {type(e)} {str(e)}",
                        failinfo="systemFailure",
                    ),
                    request_msg=pki_message,
                )

        raise NotImplementedError(
            f"Not implemented to handle a chameleon request with body: {pki_message['body'].getName()}"
        )

    def _get_serial_number(self) -> int:
        """Get a unique serial number."""
        serial_number = None
        for _ in range(100):
            serial_number = x509.random_serial_number()
            if serial_number not in self.state.sun_hybrid_state.sun_hybrid_certs:
                break
        if serial_number is None:
            raise Exception("Could not generate a unique serial number.")
        return serial_number

    def _after_request(
        self,
        request_msg: PKIMessageTMP,
        response: PKIMessageTMP,
        certs: List[rfc9480.CMPCertificate],
        confirmed: bool = False,
    ) -> None:
        """Perform actions after the request is processed.

        :param request_msg: The PKI message request.
        :param response: The PKI message response.
        :param certs: The list of certificates.
        """
        if not confirmed:
            self.state.add_certs(certs=certs, was_confirmed=False)
            self.state.store_transaction_certificate(
                pki_message=request_msg,
                certs=certs,
            )
            self.cert_req_handler.add_request_for_cert_conf(request=request_msg, response=response, certs=certs)
        else:
            self.state.add_certs(certs=certs)

    def process_sun_hybrid(
        self,
        pki_message: PKIMessageTMP,
        bad_alt_sig: bool = False,
    ) -> PKIMessageTMP:
        """Process the Sun Hybrid message.

        :param pki_message: The Sun Hybrid message.
        :param bad_alt_sig: If `True`, the alternative signature will be invalid.
        :return: The PKI message containing the response.
        """
        if is_hybrid_cert(pki_message["extraCerts"][0]):
            logging.info("Processing hybrid cert")

        prot_type = ProtectedType.get_protection_type(pki_message)
        if prot_type != ProtectedType.MAC:
            try:
                self.hybrid_handler.is_revoked_for_issuing(request=pki_message, used_both_certs=False)
            except CertRevoked as e:
                return self.build_error_from_exception(e, request_msg=pki_message)

        if pki_message["body"].getName() == "certConf":
            response = self.process_cert_conf(pki_message)
            return self.sun_hybrid_handler.sign_response(
                response=response,
                request=pki_message,
                protection_config=self.protection_handler.prot_handler_config,
            )

        if pki_message["body"].getName() == "rr":
            pki_message = self.sun_hybrid_handler.validate_for_rev_request(pki_message)
            response = self.process_rr(pki_message)
            return self.sun_hybrid_handler.sign_response(
                response=response, request=pki_message, protection_config=self.protection_handler.prot_handler_config
            )

        serial_number = self._get_serial_number()

        if not isinstance(self.sun_hybrid_key, CompositeSig13PrivateKey):
            raise Exception("The Sun-Hybrid CA key is not a CompositeSig03PrivateKey.")

        try:
            response, issued_cert, to_be_confirmed = self.sun_hybrid_handler.process_request(
                request=pki_message,
                base_url=self.url_data.get_base_url(),
                serial_number=serial_number,
                extensions=self.extensions,
                bad_alt_sig=bad_alt_sig,
                protection_config=self.protection_handler.prot_handler_config,
            )
        except CMPTestSuiteError as e:
            return self.build_error_from_exception(e, pki_message)

        if sum([issued_cert is None, to_be_confirmed is None]) in [0, 2]:
            raise Exception(
                "The newly issued certificate can either be implicit confirmed ormust be confirmed, but not both."
            )

        logging.debug("Issued certs is confined:", issued_cert is not None)

        self._after_request(
            request_msg=pki_message,
            response=response,
            certs=[issued_cert] if issued_cert else [to_be_confirmed],  # type: ignore
            confirmed=issued_cert is not None,
        )

        return response

    def process_multi_auth(self, pki_message: PKIMessageTMP) -> PKIMessageTMP:
        """Process the Multi-Auth message.

        :param pki_message: The PKIMessage which is hybrid protected.
        :return: The PKIMessage containing the response.
        """
        try:
            self.hybrid_handler.is_revoked_for_request(request=pki_message, used_both_certs=True)
        except CMPTestSuiteError as e:
            logging.info("An error occurred: %s", str(e.message))
            return self.build_error_from_exception(e, request_msg=pki_message)

        try:
            verify_hybrid_pkimessage_protection(
                pki_message=pki_message,
            )
            return self.process_normal_request(pki_message)

        except InvalidAltSignature:
            e = BadMessageCheck(message="Invalid alternative signature protection (catalyst).")
            return self.build_error_from_exception(e, request_msg=pki_message)

        except InvalidSignature:
            e = BadMessageCheck(message="Invalid signature protection.")
            return self.build_error_from_exception(e, request_msg=pki_message)

        except CMPTestSuiteError as e:
            logging.info("An error occurred: %s", str(e.message), exc_info=True)
            return self.build_error_from_exception(e, request_msg=pki_message)

    def process_cert_discovery(self, pki_message: PKIMessageTMP) -> PKIMessageTMP:
        """Process the Cert Discovery request message.

        :param pki_message: The Cert Discovery message.
        :return: The PKI message containing the response.
        """
        body_name = get_cmp_message_type(pki_message)

        if body_name == "p10cr":
            pass
        elif body_name == "certConf":
            return self.process_cert_conf(pki_message)
        else:
            raise NotImplementedError(f"Not implemented to handle a cert discovery request with body: {body_name}")

        serial_number = None
        for _ in range(100):
            serial_number = x509.random_serial_number()
            if serial_number not in self.state.sun_hybrid_state.sun_hybrid_certs:
                break
            serial_number = None

        if serial_number is None:
            raise Exception("Could not generate a unique serial number.")

        response, cert = build_cert_discovery_cert_from_p10cr(
            request=pki_message,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            serial_number=serial_number,
            url=self.url_data.get_cert_url(serial_number=serial_number),
            load_chain=False,
            extensions=[self.ocsp_extn, self.crl_extn],
        )

        self.cert_req_handler.process_after_request(
            request=pki_message,
            response=response,
            certs=[cert],
        )
        return self.sign_response(response=response, request_msg=pki_message)

    def validate_p10cr_public_key(
        self,
        pki_message: PKIMessageTMP,
    ) -> None:
        """Validate the public key in the P10CR request message.

        :param pki_message: The `p10cr` request.
        """
        public_key = load_public_key_from_spki(
            pki_message["body"]["p10cr"]["certificationRequestInfo"]["subjectPublicKeyInfo"]
        )
        try:
            public_key = ensure_is_verify_key(public_key)
        except ValueError as e:
            raise BadCertTemplate("The `p10cr` public key is not a valid verify key.") from e

        self._public_key_is_revoked(
            public_key=public_key,
            subject=pki_message["body"]["p10cr"]["certificationRequestInfo"]["subject"],
        )

    def _public_key_is_revoked(
        self,
        public_key: PublicKey,
        subject: rfc9480.Name,
    ) -> None:
        """Check if the public key is revoked.

        :param public_key: The public key.
        :param subject: The subject of the certificate.
        :raises CertRevoked: If the public key is revoked.
        """
        status = KeySecurityChecker(
            revoked_certs=self.rev_handler.rev_db.revoked_certs,
            updated_certs=self.state.certificate_db.updated_certs,
        ).check_cert_status(
            pub_key=public_key,
            sender=subject,
        )
        if status == "revoked":
            raise CertRevoked("The public key is revoked.")
        if status == "updated":
            raise CertRevoked("The public key is updated.")

    def _validate_related_cert(
        self,
        related_cert: rfc9480.CMPCertificate,
    ) -> None:
        """Validate the Related Cert request message.

        :raises BadRequest: If the request is not valid.
        """
        if compare_pyasn1_names(
            related_cert["tbsCertificate"]["issuer"],
            self.ca_cert["tbsCertificate"]["subject"],
        ):
            if self.rev_handler.is_revoked(related_cert):
                raise CertRevoked("The related certificate is revoked.")
            if self.rev_handler.is_updated(related_cert):
                raise CertRevoked("The related certificate is updated.")
        else:
            raise NotImplementedError("The related certificate is not issued by the Mock-CA.")

    def process_related_cert(self, pki_message: PKIMessageTMP) -> PKIMessageTMP:
        """Process the Related Cert request message.

        :param pki_message: The Related Cert message.
        :return: The PKI message containing the response.
        """
        body_name = get_cmp_message_type(pki_message)

        if body_name == "p10cr":
            pass
        elif body_name == "certConf":
            return self.process_cert_conf(pki_message)
        else:
            raise NotImplementedError(f"Only support p10cr for related cert requests. Got body: {body_name}")

        result = find_oid_in_general_info(pki_message, str(rfc9480.id_it_implicitConfirm))

        try:
            validate_cert_req_id_nums(pki_message)
            self.validate_p10cr_public_key(pki_message)
            related_cert = validate_multi_auth_binding_csr(
                pki_message["body"]["p10cr"],
                trustanchors="data/mock_ca/trustanchors",
                allow_os_store=True,
                crl_check=False,
                max_freshness_seconds=500,
                do_openssl_check=False,
            )
            self._validate_related_cert(related_cert)

            cert = build_related_cert_from_csr(
                csr=pki_message["body"]["p10cr"],
                request=pki_message,
                ca_cert=self.ca_cert,
                ca_key=self.ca_key,
                extensions=self.extensions,
                trustanchors="data/mock_ca/trustanchors",
                related_cert=related_cert,
            )

        except IOError as e:
            tmp = CMPTestSuiteError(
                "The URL was invalid could not fetch the related certificate.",
                failinfo="systemFailure,badPOP",
                error_details=str(e),
            )
            return self.build_error_from_exception(tmp, request_msg=pki_message)

        except CMPTestSuiteError as e:
            return self.build_error_from_exception(e, request_msg=pki_message)

        finally:
            if os.path.exists("data/mock_ca/tmp_crl.pem"):
                os.remove("data/mock_ca/tmp_crl.pem")

        response, _ = build_cp_cmp_message(
            cert=cert,
            request=pki_message,
            cert_req_id=-1,
        )

        self._after_request(
            request_msg=pki_message,
            response=response,
            certs=[cert],
            confirmed=result,
        )

        return self.sign_response(response=response, request_msg=pki_message)

    def process_catalyst_sig(self, pki_message: PKIMessageTMP) -> PKIMessageTMP:
        """Process the Catalyst Sig request message.

        :param pki_message: The Catalyst Sig message.
        :return: The PKI message containing the response.
        """
        try:
            body_name = get_cmp_message_type(pki_message)
            if body_name == "certConf":
                return self.process_cert_conf(pki_message)

            validate_cert_req_id_nums(pki_message)

            response, certs = build_catalyst_signed_cert_from_req(
                request=pki_message,
                ca_cert=self.ca_cert,
                ca_key=self.ca_key,
                extensions=[self.ocsp_extn, self.crl_extn],
            )

            self.cert_req_handler.process_after_request(
                request=pki_message,
                response=response,
                certs=certs,
            )

            return self.sign_response(response=response, request_msg=pki_message)
        except CMPTestSuiteError as e:
            logging.info("An error occurred: %s", str(e.message))
            return self.build_error_from_exception(e, request_msg=pki_message)

    def process_catalyst_issuing(self, pki_message: PKIMessageTMP) -> PKIMessageTMP:
        """Process the Catalyst request message.

        :param pki_message: The Catalyst message.
        :return: The PKI message containing the response.
        """
        try:
            body_name = get_cmp_message_type(pki_message)
            if body_name == "certConf":
                return self.process_cert_conf(pki_message)

            validate_cert_req_id_nums(pki_message)
            response, cert = build_cert_from_catalyst_request(
                request=pki_message,
                ca_cert=self.ca_cert,
                ca_key=self.ca_key,
                extensions=[self.ocsp_extn, self.crl_extn],
            )
            self.cert_req_handler.process_after_request(
                request=pki_message,
                response=response,
                certs=[cert],
            )

        except CMPTestSuiteError as e:
            logging.info("An error occurred: %s", str(e.message))
            response = self.build_error_from_exception(e, pki_message)

        return self.sign_response(response=response, request_msg=pki_message)

    def process_ocsp_request(self, data: bytes) -> bytes:
        """Process the OCSP request and return the response."""
        try:
            ocsp_request = ocsp.load_der_ocsp_request(data)
        except ValueError:
            logging.error("Failed to load OCSP request")
            ocsp_response = ocsp.OCSPResponseBuilder.build_unsuccessful(ocsp.OCSPResponseStatus.MALFORMED_REQUEST)
            return ocsp_response.public_bytes(encoding=Encoding.DER)

        response = self.state.certificate_db.get_ocsp_response(
            request=ocsp_request, ca_cert=self.ca_cert, sign_key=self.ca_key, add_certs=self.own_certs
        )

        return response.public_bytes(encoding=Encoding.DER)

    def get_current_crl(self) -> bytes:
        """Process the CRL request and return the response."""
        response = self.state.cert_state_db.get_crl_response(
            ca_cert=self.ca_cert,
            sign_key=self.ca_key,
            hash_alg="sha256",
        )
        return response.public_bytes(encoding=Encoding.DER)

    def get_details(self, options: Optional[str]) -> Any:
        """Get the details of a state object.

        :param options: The options to get.
        :return: The details as dictionary, if options is `None`, otherwise the details as string,
        if the options are not found.
        """
        if options == "issued_certs":
            return self.state.issued_certs

        data = {}
        data.update(self.rev_handler.details())
        data.update(self.cert_conf_handler.details())
        data["kem_ss"] = self.state.kem_mac_based

        if options is None:
            return data

        if len(options.split(",")) == 0:
            return data

        if len(options.split(",")) == 1 and options in data:
            return data[options]

        out = {key: data[key] for key in options.split(",") if key in data}
        if out:
            return out

        return "Supported keys are: " + ", ".join(data.keys())

    def set_config_vars(self, cert_conf_handler: Union[dict, CertConfConfigVars]) -> None:
        """Set the configuration variables.

        :param cert_conf_handler: The configuration variables.
        """
        self.cert_conf_handler.set_config_vars(cert_conf_handler)


app = Flask(__name__)
state = MockCAState()


def _build_response(
    pki_message: Union[PKIMessageTMP, bytes, rfc9480.CMPCertificate],
    status: int = 200,
    for_msg: bool = True,
) -> Response:
    """Build a response from a PKIMessage.

    :param pki_message: The PKIMessage to encode.
    :return: The response.
    """
    if isinstance(pki_message, bytes):
        response_data = pki_message
        content_type = "application/octet-stream"

    elif isinstance(pki_message, PKIMessageTMP):
        response_data = asn1utils.encode_to_der(pki_message)
        content_type = "application/pkixcmp"

    elif isinstance(pki_message, rfc9480.CMPCertificate):
        response_data = asn1utils.encode_to_der(pki_message)
        content_type = "application/pkix-cert"
    else:
        raise TypeError(f"Expected bytes, cert or PKIMessage, got {type(pki_message)}")

    # Update the content type based on the request:
    # https://www.iana.org/assignments/media-types/media-types.xhtml
    if for_msg:
        content_type = "application/pkixcmp"

    return Response(response_data, content_type=content_type, status=status)


@app.route("/ocsp", methods=["POST"])
def handle_ocsp_request():
    """Handle the OCSP request."""
    data = handler.process_ocsp_request(request.get_data())
    return Response(data, content_type="application/ocsp-response")


@app.route("/crl", methods=["GET"])
def handle_crl_request():
    """Handle the CRL request."""
    data = handler.get_current_crl()
    return Response(data, content_type="application/pkix-crl")


@app.route("/cert/<serial_number>", methods=["GET"])
def get_cert(serial_number):
    """Get the Sun-Hybrid certificate for the specified serial number."""
    serial_number = int(serial_number)
    cert = state.get_cert_by_serial_number(serial_number)
    return _build_response(cert)


@app.route("/pubkey/<serial_number>", methods=["GET"])
def get_pubkey(serial_number):
    """Get the Sun-Hybrid public key for the specified serial number."""
    serial_number = int(serial_number)
    logging.debug(state.sun_hybrid_state.sun_hybrid_pub_keys.keys())
    pub_key = state.sun_hybrid_state.sun_hybrid_pub_keys.get(serial_number)

    if pub_key is None:
        raise BadRequest(
            f"Could not find public key with serial number {serial_number}"
            f" in {state.sun_hybrid_state.sun_hybrid_pub_keys.keys()}"
        )

    der_data = pub_key.public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)
    return Response(der_data, content_type="application/octet-stream")


@app.route("/sig/<serial_number>", methods=["GET"])
def get_signature(serial_number):
    """Get the Sun-Hybrid signature for the specified serial number."""
    serial_number = int(serial_number)
    alt_sig = state.sun_hybrid_state.sun_hybrid_signatures.get(serial_number)

    if alt_sig is None:
        raise BadRequest(
            f"Could not find signature with serial number {serial_number}"
            f" in {state.sun_hybrid_state.sun_hybrid_signatures.keys()}"
        )

    return Response(alt_sig, content_type="application/octet-stream")


@app.route("/issuing", methods=["POST"])
def handle_issuing() -> Response:
    """Handle the issuing request.

    :return: The DER-encoded response.
    """
    try:
        data = request.get_data()
        pki_message = parse_pkimessage(data)
    except ValueError:
        e = BadAsn1Data("Error: Could not decode the request", overwrite=True)
        pki_message = handler.build_error_from_exception(e)
        return _build_response(pki_message, status=400)

    try:
        # Access the raw data from the request body
        response = handler.process_normal_request(pki_message)
        return _build_response(response, for_msg=True)
    except Exception as e:  # pylint: disable=broad-except
        # Handle any errors gracefully
        return Response(f"Error: {str(e)}", status=500, content_type="text/plain")


@app.route("/chameleon", methods=["POST"])
def handle_chameleon():
    """Handle the chameleon request.

    :return: The DER-encoded response.
    """
    data = request.get_data()
    pki_message = parse_pkimessage(data)
    pki_message = handler.process_chameleon(
        pki_message=pki_message,
    )
    return _build_response(pki_message)


@app.route("/sun-hybrid", methods=["POST"])
def handle_sun_hybrid():
    """Handle the Sun Hybrid request.

    :return: The DER-encoded response.
    """
    data = request.get_data()
    pki_message = parse_pkimessage(data)
    response = handler.process_sun_hybrid(
        pki_message=pki_message,
    )
    return _build_response(response)


@app.route("/multi-auth", methods=["POST"])
def handle_multi_auth():
    """Handle the multi-auth request.

    :return: The DER-encoded response.
    """
    data = request.get_data()

    pki_message = parse_pkimessage(data)
    pki_message = handler.process_multi_auth(
        pki_message=pki_message,
    )
    return _build_response(pki_message)


@app.route("/cert-discovery", methods=["POST"])
def handle_cert_discovery():
    """Handle the cert discovery request.

    :return: The DER-encoded response.
    """
    data = request.get_data()
    pki_message = parse_pkimessage(data)
    pki_message = handler.process_cert_discovery(pki_message)
    return _build_response(pki_message)


@app.route("/related-cert", methods=["POST"])
def handle_related_cert():
    """Handle the related cert request.

    :return: The DER-encoded response.
    """
    data = request.get_data()
    pki_message = parse_pkimessage(data)
    pki_message = handler.process_related_cert(pki_message)
    return _build_response(pki_message)


@app.route("/catalyst-sig", methods=["POST"])
def handle_catalyst_sig():
    """Handle the catalyst sig request.

    :return: The DER-encoded response.
    """
    data = request.get_data()
    pki_message = parse_pkimessage(data)
    pki_message = handler.process_catalyst_sig(pki_message)
    return _build_response(pki_message)


@app.route("/catalyst-issuing", methods=["POST"])
def handle_catalyst_issuing():
    """Handle the catalyst request.

    :return: The DER-encoded response.
    """
    data = request.get_data()
    pki_message = parse_pkimessage(data)
    pki_message = handler.process_catalyst_issuing(pki_message)
    return _build_response(pki_message)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mock CA server")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="The host address, is set to 0.0.0.0 for docker.")
    parser.add_argument("--port", type=int, default=5000, help="The port to run the server on.")

    args = parser.parse_args()
    handler = CAHandler(ca_cert=None, ca_key=None, config={}, mock_ca_state=state, port=args.port)

    # import ssl
    # DOMAIN = "mydomain.com"
    # CERT_DIR = f"/etc/letsencrypt/live/{DOMAIN}"
    # CERT_FILE = os.path.join(CERT_DIR, "fullchain.pem")
    # KEY_FILE = os.path.join(CERT_DIR, "privkey.pem")
    # context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    # context = "adhoc"
    # app.run(port=5000, debug=True, ssl_context=context)
    app.run(host=args.host, port=args.port, debug=True)
