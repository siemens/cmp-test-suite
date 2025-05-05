# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Handles certificate request messages of type 'ir', 'cr', 'p10cr', and 'kur'."""

import logging
from typing import List, Optional

from pyasn1.codec.der import encoder
from pyasn1_alt_modules import rfc9480, rfc9481

from mock_ca.nestedutils import validate_orig_pkimessage
from mock_ca.operation_dbs import NonSigningKeyCertsAndKeys
from pq_logic.hybrid_sig.chameleon_logic import load_chameleon_csr_delta_key_and_sender
from pq_logic.keys.abstract_wrapper_keys import HybridKEMPrivateKey
from pq_logic.pq_verify_logic import verify_hybrid_pkimessage_protection
from resources import cmputils, keyutils
from resources.asn1_structures import PKIMessageTMP
from resources.ca_ra_utils import (
    build_ccp_from_ccr,
    build_cp_cmp_message,
    build_cp_from_p10cr,
    build_ip_cmp_message,
    build_kup_from_kur,
    prepare_ca_body,
    prepare_cert_response,
    set_ca_header_fields,
)
from resources.certbuildutils import prepare_extensions
from resources.certutils import (
    build_cmp_chain_from_pkimessage,
    check_is_cert_signer,
    validate_key_usage,
)
from resources.checkutils import (
    check_generalinfo_field,
    check_if_response_contains_encrypted_cert,
    check_is_protection_present,
    check_message_time_field,
    check_sender_cmp_protection,
    validate_request_message_nonces_and_tx_id,
    validate_senderkid_for_cmp_protection,
)
from resources.cmputils import build_cmp_error_message, find_oid_in_general_info, patch_generalinfo
from resources.convertutils import ensure_is_verify_key
from resources.copyasn1utils import copy_name
from resources.data_objects import ExtraIssuingData
from resources.exceptions import (
    BadAlg,
    BadCertTemplate,
    BadMessageCheck,
    BadTime,
    CMPTestSuiteError,
    NotAuthorized,
    SignerNotTrusted,
    TransactionIdInUse,
    UnsupportedVersion,
    WrongIntegrity,
)
from resources.keyutils import load_public_key_from_cert_template
from resources.oidutils import id_KemBasedMac
from resources.protectionutils import (
    get_protection_alg_name,
    get_protection_type_from_pkimessage,
    verify_pkimessage_protection,
)
from resources.typingutils import SignKey
from resources.utils import get_openssl_name_notation
from unit_tests.utils_for_test import load_env_data_certs

# (Make sure to import all the required functions and exceptions, for example:
#  build_cp_cmp_message, build_cp_from_p10cr, build_ip_cmp_message, build_kup_from_kur,
#  find_oid_in_general_info, verify_hybrid_pkimessage_protection, verify_pkimessage_protection,
#  BadMessageCheck, etc.)


class CertReqHandler:
    """Handles certificate request messages of type 'ir', 'cr', 'p10cr', and 'kur'."""

    def __init__(
        self,
        ca_cert: rfc9480.CMPCertificate,
        ca_key: SignKey,
        state,
        cert_conf_handler,
        cmp_protection_cert: Optional[rfc9480.CMPCertificate] = None,
        extensions: Optional[rfc9480.Extensions] = None,
        shared_secrets: Optional[bytes] = None,
        xwing_key: Optional[HybridKEMPrivateKey] = None,
        kga_key: Optional[SignKey] = None,
        kga_cert_chain: Optional[List[rfc9480.CMPCertificate]] = None,
        issuing_db: Optional[NonSigningKeyCertsAndKeys] = None,
    ):
        """Initialize the certificate request handler.

        :param ca_cert: The CA certificate.
        :param ca_key: The CA private key.
        :param state: The overall CA state.
        :param cert_conf_handler: The certificate confirmation handler.
        :param extensions: A list of extensions (e.g. OCSP, CRL) to include in responses.
        :param shared_secrets: The shared secret used for MAC protection.
        :param xwing_key: Optional fallback key for verifying password-based protection.
        """
        self.ca_cert = ca_cert
        self.ca_key = ca_key
        self.state = state
        self.cert_conf_handler = cert_conf_handler
        self.extensions = extensions  # Now a unified list of extensions

        if extensions is None:
            ca_pub_key = ensure_is_verify_key(self.ca_key.public_key())
            self.extensions = prepare_extensions(ca_key=ca_pub_key, critical=False)

        self.pre_shared_secret = shared_secrets
        self.xwing_key = xwing_key
        self.must_be_protected = True
        self.check_time = True
        self.allowed_interval = 500
        self.allow_same_key_cert_req = False
        self.allow_same_key_kur = False
        self.sender = "CN=Mock-CA"
        self.kga_key = kga_key
        self.kga_cert_chain = kga_cert_chain
        self.issuing_db = issuing_db

        self.issuing_params = load_env_data_certs()

        self.cmp_protection_cert = cmp_protection_cert
        self.extra_issuing_data = ExtraIssuingData(
            regToken="SuperSecretRegToken",
            authenticator="MaidenName",
        )
        self.issuing_params.update(
            {
                "kga_cert_chain": self.kga_cert_chain,
                "kga_key": self.kga_key,
                "password": self.pre_shared_secret,
                "sender": self.sender,
                "cmp_protection_cert": self.cmp_protection_cert,
                "extensions": self.extensions,
                "ca_cert": self.ca_cert,
                "ca_key": self.ca_key,
                "extra_issuing_data": self.extra_issuing_data,
            }
        )

    @staticmethod
    def is_certificate_in_list(cert_template: rfc9480.CertTemplate, cert_list: List[rfc9480.CMPCertificate]) -> bool:
        """Check if the certificate template is in the list of certificates.

        :param cert_template: The certificate template to check.
        :param cert_list: The list of certificates to check against.
        :return: `True` if the certificate is in the list, `False` otherwise.
        """
        name_obj = copy_name(filled_name=cert_template["subject"], target=rfc9480.Name())
        subject_der = encoder.encode(name_obj)
        public_key = load_public_key_from_cert_template(cert_template, must_be_present=False)
        if public_key is None:
            return False

        for candidate in cert_list:
            candidate_subject_der = encoder.encode(candidate["tbsCertificate"]["subject"])
            if candidate_subject_der == subject_der:
                loaded_pub_key = keyutils.load_public_key_from_spki(candidate["tbsCertificate"]["subjectPublicKeyInfo"])
                if loaded_pub_key == public_key:
                    return True

        return False

    def check_same_key_cert_request(self, pki_message: PKIMessageTMP) -> None:
        """Check if the certificate template is already in the list of certificates."""
        if self.allow_same_key_cert_req and pki_message["body"].getName() in ["ir", "cr", "p10cr", "ccr"]:
            return

        if self.allow_same_key_kur and pki_message["body"].getName() == "kur":
            return

        if pki_message["body"].getName() == "p10cr":
            csr = pki_message["body"]["p10cr"]
            spki = csr["certificationRequestInfo"]["subjectPublicKeyInfo"]

            if spki["subjectPublicKey"].asOctets() == b"":
                return

            loaded_pub_key = keyutils.load_public_key_from_spki(spki)
            if loaded_pub_key is not None:
                if self.state.contains_pub_key(loaded_pub_key, csr["certificationRequestInfo"]["subject"]):
                    raise BadCertTemplate("The public key is already defined for the user.")

            try:
                public_key = load_chameleon_csr_delta_key_and_sender(csr=pki_message["body"]["p10cr"])
                if self.state.contains_pub_key(public_key, csr["certificationRequestInfo"]["subject"]):
                    raise BadCertTemplate("The chameleon delta public key is already defined for the user.")
            except ValueError:
                pass

        else:
            body_name = pki_message["body"].getName()
            for entry in pki_message["body"][body_name]:
                cert_template = entry["certReq"]["certTemplate"]
                if self.is_certificate_in_list(cert_template, self.state.issued_certs):
                    _name = get_openssl_name_notation(cert_template["subject"])
                    raise BadCertTemplate(f"The public key is already defined for the user: {_name}")

                public_key = load_public_key_from_cert_template(cert_template, must_be_present=False)

                if self.state.contains_pub_key(public_key, cert_template["subject"]):
                    raise BadCertTemplate("The public key is already defined for the user.")

    def _get_for_mac(self, request: PKIMessageTMP) -> bool:
        """Determine if the message is for MAC protection."""
        for_mac = False
        if request["header"]["protectionAlg"].isValue:
            prot_type = get_protection_type_from_pkimessage(
                pki_message=request,
            )
            for_mac = prot_type == "mac"
        return for_mac

    def _add_cert_to_state(self, cert: rfc9480.CMPCertificate) -> None:
        """Add a certificate to the state."""
        self.state.add_cert(cert)

    def _add_successful_request(
        self, request: PKIMessageTMP, response: PKIMessageTMP, certs: List[rfc9480.CMPCertificate]
    ) -> None:
        """Add a successful request to the state."""
        self.cert_conf_handler.add_request(pki_message=request)
        self.cert_conf_handler.add_response(pki_message=response, certs=certs)

    def process_after_request(
        self,
        request: PKIMessageTMP,
        response: PKIMessageTMP,
        certs: List[rfc9480.CMPCertificate],
    ) -> PKIMessageTMP:
        """Process the request after it has been handled successfully.

        :param request: The original request.
        :param response: The response to the request.
        :param certs: The list of certificates.
        """
        confirm_ = CertReqHandler.check_if_used(
            request=request,
            response=response,
        )
        self.state.store_transaction_certificate(pki_message=request, certs=certs)
        if confirm_:
            response = patch_generalinfo(
                msg_to_patch=response,
                implicit_confirm=True,
            )
            self.state.add_certs(certs=certs)
            self.cert_conf_handler.add_confirmed_certs(request, certs=certs)
        else:
            self._add_successful_request(request=request, response=response, certs=certs)

        return response

    def process_ir(
        self,
        pki_message: PKIMessageTMP,
        must_be_protected: bool = True,
        verify_ra_verified: bool = True,
    ) -> "PKIMessageTMP":
        """Process an initialization request (IR) message."""
        logging.debug("CertReqHandler: Processing IR message")

        logging.warning("Verify RA verified: %s", verify_ra_verified)

        if not pki_message["header"]["protectionAlg"].isValue and must_be_protected:
            raise BadMessageCheck("Protection algorithm was not set.")

        for_mac = self._get_for_mac(request=pki_message)

        validate_orig_pkimessage(pki_message, must_be_present=False, pre_shared_secret=self.pre_shared_secret)

        response, certs = build_ip_cmp_message(
            request=pki_message,
            implicit_confirm=False,
            verify_ra_verified=verify_ra_verified,
            for_mac=for_mac,
            **self.issuing_params,
        )

        return self.process_after_request(
            request=pki_message,
            response=response,
            certs=certs,
        )

    def process_cr(self, pki_message: PKIMessageTMP):
        """Process a certificate request (CR) message."""
        logging.debug("CertReqHandler: Processing CR message")
        for_mac = self._get_for_mac(request=pki_message)

        if pki_message["header"]["protectionAlg"].isValue:
            prot_type = get_protection_type_from_pkimessage(pki_message)
            alg_name = get_protection_alg_name(pki_message)

            if alg_name == "dh_based_mac" or alg_name == "kem_based_mac":
                result = True
            elif prot_type == "mac":
                result = False
            else:
                result = True

            if pki_message["extraCerts"].isValue and result:
                cert = pki_message["extraCerts"][0]
                if not self.state.contains_cert(cert):
                    raise NotAuthorized(
                        "The certificate was not found in the state. CR messages are only "
                        "allowed for known certificates."
                    )

        response, certs = build_cp_cmp_message(
            request=pki_message,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            implicit_confirm=False,
            extensions=self.extensions,
            sender=self.sender,
            for_mac=for_mac,
        )

        return self.process_after_request(
            request=pki_message,
            response=response,
            certs=certs,
        )

    def process_p10cr(self, pki_message: PKIMessageTMP):
        """Process a `P10CR` message."""
        logging.debug("CertReqHandler: Processing P10CR message")
        self.state.cert_state_db.check_request_for_compromised_key(pki_message)

        for_mac = self._get_for_mac(request=pki_message)

        response, cert = build_cp_from_p10cr(
            request=pki_message,
            set_header_fields=True,
            ca_key=self.ca_key,
            ca_cert=self.ca_cert,
            implicit_confirm=False,
            extensions=self.extensions,
            sender=self.sender,
            for_mac=for_mac,
            include_csr_extensions=False,
        )
        return self.process_after_request(
            request=pki_message,
            response=response,
            certs=[cert],
        )

    def process_kur(self, pki_message: PKIMessageTMP):
        """Process a key update request (KUR) message.

        :param pki_message: The received `PKIMessage`.
        :return: The response `PKIMessage`.
        """
        logging.debug("CertReqHandler: Processing KUR message")

        if not pki_message["header"]["protectionAlg"].isValue:
            raise BadMessageCheck("Protection algorithm was not set.")

        oid = pki_message["header"]["protectionAlg"]["algorithm"]
        if get_protection_type_from_pkimessage(pki_message) == "mac":
            if oid not in [rfc9480.id_DHBasedMac, id_KemBasedMac]:
                raise WrongIntegrity("The key updated request was MAC protected")

        try:
            verify_hybrid_pkimessage_protection(pki_message=pki_message)
        except ValueError:
            verify_pkimessage_protection(
                pki_message=pki_message,
                shared_secret=self.state.get_kem_mac_shared_secret(pki_message=pki_message),
                private_key=self.xwing_key,
                password=self.pre_shared_secret,
            )

        response, certs = build_kup_from_kur(
            request=pki_message,
            implicit_confirm=False,
            allow_same_key=self.allow_same_key_kur,
            **self.issuing_params,
        )

        return self.process_after_request(
            request=pki_message,
            response=response,
            certs=certs,
        )

    def check_message_time(self, pki_message: PKIMessageTMP) -> None:
        """Check if the message time is within the allowed time interval."""
        if self.check_time:
            if not pki_message["header"]["messageTime"].isValue:
                raise BadTime("The message time was not set.")

            check_message_time_field(
                pki_message=pki_message,
                allowed_interval=self.allowed_interval,
            )

    @staticmethod
    def check_if_used(request: PKIMessageTMP, response: PKIMessageTMP) -> bool:
        """Check if the request is automatically confirmed.

        :param request: The request to check if the implicit confirm was set.
        :param response: The response to check if an encrypted certificate is returned.
        :return: `True` if the request is/can be automatically confirmed, `False` otherwise.
        """
        body_name = request["body"].getName()

        if body_name in {"p10cr", "ccr", "krp"}:
            return find_oid_in_general_info(request, str(rfc9480.id_it_implicitConfirm))

        if body_name not in {"ir", "cr", "kur"}:
            return False

        if not find_oid_in_general_info(request, str(rfc9480.id_it_implicitConfirm)):
            return False

        return not check_if_response_contains_encrypted_cert(
            response,
        )

    @staticmethod
    def validate_nonces_and_tx_id(pki_message: PKIMessageTMP) -> None:
        """Validate the nonces and the `transactionID` of a `PKIMessage`."""
        validate_request_message_nonces_and_tx_id(pki_message)

    @staticmethod
    def validate_general_info(pki_message: PKIMessageTMP) -> None:
        """Validate the general info of a PKIMessage."""
        check_generalinfo_field(pki_message=pki_message)

    @staticmethod
    def check_signer(pki_message: PKIMessageTMP) -> None:
        """Check if the signer is trusted."""
        if not pki_message["extraCerts"].isValue:
            raise BadMessageCheck("The extraCerts field was not set.")

        cert_chain = build_cmp_chain_from_pkimessage(
            pki_message=pki_message,
            ee_cert=pki_message["extraCerts"][0],
        )
        if len(cert_chain) == 1:
            raise SignerNotTrusted("The certificate chain was not present.")

        if not check_is_cert_signer(cert_chain[-1], cert_chain[-1]):
            raise SignerNotTrusted("The last certificate in the chain was not a signer.")

        # Verify that the CMP-protection certificate is authorized to sign the message.
        # Allows the CMP protection certificate to have an unset key usage.
        validate_key_usage(cert_chain[0], key_usages="digitalSignature", strictness="LAX")

    def validate_header(self, pki_message: PKIMessageTMP) -> None:
        """Validate the header of a PKIMessage."""
        if int(pki_message["header"]["pvno"]) not in [2, 3]:
            raise UnsupportedVersion("The protocol version number was not 2 or 3.")

        validate_request_message_nonces_and_tx_id(request=pki_message)
        self.validate_general_info(pki_message=pki_message)
        self.check_message_time(pki_message=pki_message)
        check_is_protection_present(pki_message, must_be_protected=self.must_be_protected)
        check_sender_cmp_protection(pki_message, must_be_protected=self.must_be_protected, allow_failure=False)
        validate_senderkid_for_cmp_protection(
            pki_message, must_be_protected=self.must_be_protected, allow_mac_failure=False
        )
        oid = pki_message["header"]["protectionAlg"]["algorithm"]
        prot_name = get_protection_alg_name(pki_message)
        if pki_message["header"]["protectionAlg"].isValue:
            prot_type = get_protection_type_from_pkimessage(pki_message)
            if prot_type != "mac":
                self.check_signer(pki_message)

            elif prot_name in ["dh_based_mac", "kem_based_mac"]:
                logging.debug("The message was MAC protected, with %s.", prot_name)

            else:
                if oid not in [rfc9480.id_PasswordBasedMac, rfc9481.id_PBMAC1]:
                    raise BadAlg("For LwCMP is only `PasswordBasedMac` and `PBMAC1` as protection algorithm allowed.")

    def _build_cert_resp_error_response(self, e: CMPTestSuiteError, request: PKIMessageTMP) -> PKIMessageTMP:
        """Build an error response for an IR message.

        :param e: The exception that caused the error.
        :return: The error response.
        """
        cert_response = prepare_cert_response(
            status="rejection", failinfo=e.failinfo, text=[e.message] + e.get_error_details()
        )

        body_name = request["body"].getName()

        body_to_out_name = {"ir": "ip", "cr": "cp", "p10cr": "cp", "kur": "kup", "ccr": "ccp"}
        out_name = body_to_out_name[body_name]
        kwargs = set_ca_header_fields(request, {})
        body = prepare_ca_body(out_name, responses=cert_response, ca_pubs=None)
        pki_message = cmputils.prepare_pki_message(sender=self.sender, **kwargs)
        pki_message["body"] = body
        return pki_message

    def error_body(self, e: CMPTestSuiteError, request: PKIMessageTMP) -> PKIMessageTMP:
        """Build an error response for an IR message."""
        kwargs = set_ca_header_fields(request, {})
        pki_message = build_cmp_error_message(
            request=request, sender=self.sender, status="rejection", failinfo=e.failinfo, text=[e.message], **kwargs
        )
        return pki_message

    def process_cert_request(self, pki_message: PKIMessageTMP) -> "PKIMessageTMP":
        """Process a certificate request message.

        :param pki_message: The incoming PKI message.
        :return: The processed PKI response.
        :raises NotImplementedError: If the message type is unsupported.
        """
        # raise exception for the error body.
        self.validate_header(pki_message)

        msg_type = pki_message["body"].getName()
        if msg_type not in ["ir", "cr", "p10cr", "kur", "ccr"]:
            raise NotImplementedError(f"Message type '{msg_type}' is not supported by CertReqHandler.")
        try:
            self.check_same_key_cert_request(pki_message=pki_message)
            if msg_type == "ir":
                response = self.process_ir(pki_message)
            elif msg_type == "cr":
                response = self.process_cr(pki_message)
            elif msg_type == "p10cr":
                response = self.process_p10cr(pki_message)
            elif msg_type == "kur":
                response = self.process_kur(pki_message)
                self.state.add_updated_cert(pki_message["extraCerts"][0])
            elif msg_type == "ccr":
                response = self.handle_cross_cert_req(pki_message)
            else:
                raise NotImplementedError(f"Message type '{msg_type}' is not supported by CertReqHandler.")

        except TransactionIdInUse as e:
            if "Transaction ID" in e.message and "already exists" in e.message:
                return self.error_body(e, request=pki_message)

        except CMPTestSuiteError as e:
            return self._build_cert_resp_error_response(e, pki_message)

        return response  # type: ignore

    def handle_cross_cert_req(self, pki_message: PKIMessageTMP) -> PKIMessageTMP:
        """Handle cross-certification requests."""
        # Only MSG-SIG-ALg is allowed for cross-certification requests.
        response, certs = build_ccp_from_ccr(
            request=pki_message,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            extensions=self.extensions,
            for_mac=False,
            implicit_confirm=False,
        )
        return self.process_after_request(
            request=pki_message,
            response=response,
            certs=certs,
        )
