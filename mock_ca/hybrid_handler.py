# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
"""Contains the hybrid issuing handler for the Mock-CA."""

import logging
from typing import List, Optional, Tuple

from pyasn1_alt_modules import rfc9480

from mock_ca.db_config_vars import ProtectionHandlerConfig
from mock_ca.operation_dbs import SunHybridState
from mock_ca.prot_handler import ProtectionHandler
from mock_ca.rev_handler import RevocationHandler
from pq_logic.hybrid_issuing import build_sun_hybrid_cert_from_request, is_hybrid_cert
from pq_logic.hybrid_sig import sun_lamps_hybrid_scheme_00
from pq_logic.hybrid_sig.cert_binding_for_multi_auth import get_related_cert_from_list
from pq_logic.hybrid_sig.certdiscovery import get_cert_discovery_cert
from pq_logic.hybrid_sig.chameleon_logic import (
    build_delta_cert_from_paired_cert,
    load_chameleon_csr_delta_key_and_sender,
)
from pq_logic.hybrid_sig.sun_lamps_hybrid_scheme_00 import (
    convert_sun_hybrid_cert_to_target_form,
    extract_sun_hybrid_alt_sig,
)
from pq_logic.keys.composite_sig07 import CompositeSig07PrivateKey
from pq_logic.pq_verify_logic import build_sun_hybrid_cert_chain, verify_hybrid_pkimessage_protection
from pq_logic.tmp_oids import id_ce_deltaCertificateDescriptor
from resources import certextractutils
from resources.asn1_structures import PKIMessageTMP
from resources.ca_ra_utils import validate_cert_req_id_nums
from resources.certutils import load_public_key_from_cert
from resources.checkutils import check_if_response_contains_encrypted_cert
from resources.cmputils import add_general_info_values, find_oid_in_general_info
from resources.exceptions import BadCertTemplate, BadConfig, BadMessageCheck, CertRevoked
from resources.protectionutils import protect_hybrid_pkimessage, protect_pkimessage
from resources.suiteenums import ProtectedType
from resources.typingutils import PrivateKey


class ChameleonHandler:
    """The handler for chameleon certificates."""

    def __init__(
        self,
        ca_cert: rfc9480.CMPCertificate,
        ca_key: PrivateKey,
        revocation_handler: RevocationHandler,
        cmp_protection_cert: rfc9480.CMPCertificate,
        sender: str = "CN=MOCK-CA",
        extensions: Optional[rfc9480.Extensions] = None,
    ):
        """Initialize the chameleon handler.

        :param ca_cert: The CA certificate.
        :param ca_key: The CA key.
        :param revocation_handler: The revocation handler.
        :param cmp_protection_cert: The CMP protection certificate.
        :param sender: The sender of the PKI message.
        :param extensions: The extensions to use.
        """
        self.ca_cert = ca_cert
        self.ca_key = ca_key
        self.sender = sender
        self.cmp_protection_cert = cmp_protection_cert
        self.extensions = extensions or []
        self.revocation_handler = revocation_handler

    @staticmethod
    def is_chameleon_cert(cert: rfc9480.CMPCertificate) -> bool:
        """Check if the certificate is a chameleon certificate.

        :param cert: The certificate to check.
        :return: True if the certificate is a chameleon certificate, False otherwise.
        """
        dcd = certextractutils.get_extension(cert["tbsCertificate"]["extensions"], id_ce_deltaCertificateDescriptor)
        if dcd is None:
            return False
        return True

    @staticmethod
    def get_delta_cert(
        cert: rfc9480.CMPCertificate,
    ) -> rfc9480.CMPCertificate:
        """Get the chameleon certificate and the delta certificate.

        :param cert: The certificate to check.
        :return: The chameleon certificate and the delta certificate.
        """
        delta_cert = build_delta_cert_from_paired_cert(
            paired_cert=cert,
        )
        return delta_cert

    def is_revoked(
        self,
        request: PKIMessageTMP,
        used_both_certs: bool = True,
    ) -> None:
        """Check if the certificate is revoked.

        :param request: The PKI message request.
        :param used_both_certs: Whether both certificates were used to sign the request,
        so that the Delta certificate must be checked. Defaults to `True`.
        """
        cert = request["extraCerts"][0]
        delta_cert = ChameleonHandler.get_delta_cert(cert)

        if self.revocation_handler.is_revoked(cert):
            raise CertRevoked("The paired chameleon certificate is revoked.")

        if self.revocation_handler.is_updated(cert):
            raise CertRevoked("The paired chameleon certificate is updated.")

        if not used_both_certs:
            return

        if self.revocation_handler.is_revoked(delta_cert):
            raise CertRevoked("The chameleon delta certificate is revoked.")

        if self.revocation_handler.is_updated(delta_cert):
            raise CertRevoked("The chameleon delta certificate is updated.")

    def is_delta_key_revoked(self, request: PKIMessageTMP) -> None:
        """Check if the delta key is revoked.

        :param request: The PKI message request.
        """
        public_key, sender = load_chameleon_csr_delta_key_and_sender(csr=request["body"]["p10cr"])

        if self.revocation_handler.public_key_is_revoked(public_key, sender):
            raise BadCertTemplate("The chameleon delta key is revoked.")


class SunHybridHandler:
    """The handler for the Sun hybrid scheme."""

    def __init__(
        self,
        ca_cert: rfc9480.CMPCertificate,
        ca_key: CompositeSig07PrivateKey,
        sun_hybrid_state: SunHybridState,
        cert_chain: Optional[rfc9480.CMPCertificate] = None,
        pre_shared_secret: bytes = b"SiemensIT",
    ):
        """Initialize the Sun hybrid handler.

        :param ca_cert: The CA certificate.
        :param ca_key: The CA key.
        """
        self.ca_cert = ca_cert
        self.ca_key = ca_key
        self.ca_cert_chain = cert_chain or [self.ca_cert]
        self.pre_shared_secret = pre_shared_secret
        self.sun_hybrid_state = sun_hybrid_state

        pub_key = load_public_key_from_cert(ca_cert)

        if pub_key != self.ca_key.public_key().trad_key:
            raise BadConfig("The Sun Hybrid CA key does not match the CA certificate.")

    def _process_after_request(self, request, response):
        """Process the request after the issuing process."""
        raise NotImplementedError("The process_after_request method is not implemented.")

    def sign_response(
        self,
        response: PKIMessageTMP,
        request: PKIMessageTMP,
        protection_config: ProtectionHandlerConfig,
        use_composite: bool = False,
        second_cert: Optional[rfc9480.CMPCertificate] = None,
    ) -> PKIMessageTMP:
        """Sign the response, based on the request.

        :param request: The PKI message request.
        :param response: The PKI message response.
        :param protection_config: The protection configuration.
        :param use_composite: Whether to use composite signing or just traditional signing.
        :param second_cert: The second certificate to use for signing.
        :return: The signed PKI message.
        """
        protection_handler = ProtectionHandler(
            cmp_protection_cert=self.ca_cert,
            cmp_prot_key=self.ca_key,
        )
        protection_handler.set_config(config=protection_config)

        if not request["header"]["protectionAlg"].isValue:
            use_mac = False
        else:
            use_mac = ProtectedType.get_protection_type(request) == ProtectedType.MAC

        if use_mac:
            mac_alg = protection_handler.get_same_mac_protection(request["header"]["protectionAlg"])
            if second_cert is not None:
                response["extraCerts"].append(second_cert)
            response["extraCerts"].extend(self.ca_cert_chain)
            return protect_pkimessage(
                protection=mac_alg,
                pki_message=response,
                password=self.pre_shared_secret,
            )

        response["extraCerts"].append(self.ca_cert)
        if second_cert is not None:
            response["extraCerts"].append(second_cert)
        response["extraCerts"].extend(self.ca_cert_chain[1:])
        if not use_composite:
            return protect_pkimessage(
                protection="signature",
                pki_message=response,
                private_key=self.ca_key.trad_key,
                cert=self.ca_cert,
                exclude_certs=True,
            )

        return protect_hybrid_pkimessage(
            protection="composite",
            pki_message=response,
            private_key=self.ca_key,
            cert=self.ca_cert,
            exclude_certs=True,
        )

    def _add_to_state(self, serial_number: int, cert1: rfc9480.CMPCertificate) -> None:
        """Add the certificate to the state.

        :param serial_number: The serial number of the certificate.
        :param cert1: The Sun-Hybrid certificate in Form4.
        """
        public_key = sun_lamps_hybrid_scheme_00.get_sun_hybrid_alt_pub_key(cert1["tbsCertificate"]["extensions"])
        alt_sig = extract_sun_hybrid_alt_sig(cert1)
        if public_key is None:
            raise Exception("The Sun-hybrid public key could not be extracted from the certificate.")

        self.sun_hybrid_state.sun_hybrid_certs[serial_number] = cert1
        self.sun_hybrid_state.sun_hybrid_pub_keys[serial_number] = public_key
        self.sun_hybrid_state.sun_hybrid_signatures[serial_number] = alt_sig

    @staticmethod
    def validate_for_rev_request(
        request: PKIMessageTMP,
    ) -> PKIMessageTMP:
        """Validate the request for revocation.

        :param request: The PKI message request.
        """
        verify_hybrid_pkimessage_protection(
            pki_message=request,
        )

        request["extraCerts"][0] = convert_sun_hybrid_cert_to_target_form(
            cert=request["extraCerts"][0], target_form="Form4"
        )
        return request

    @staticmethod
    def get_certs_for_revocated_check(pki_message: PKIMessageTMP) -> List[rfc9480.CMPCertificate]:
        """Get the certificates for the revocation check.

        :return: The certificates for the revocation check.
        """
        return build_sun_hybrid_cert_chain(pki_message["extraCerts"][0], pki_message["extraCerts"])

    def process_request(
        self,
        request: PKIMessageTMP,
        serial_number: int,
        protection_config: ProtectionHandlerConfig,
        base_url: str = "http://localhost:5000",
        bad_alt_sig: bool = False,
        extensions: Optional[rfc9480.Extensions] = None,
    ) -> Tuple[PKIMessageTMP, Optional[rfc9480.CMPCertificate], Optional[rfc9480.CMPCertificate]]:
        """Process the Sun hybrid request.

        :param request: The PKI message request.
        :param serial_number: The serial number of the certificate.
        :param base_url: The base URL for the public key and signature locations.
        :param bad_alt_sig: Whether to use a bad alternative signature.
        :param extensions: The extensions to use.
        :param protection_config: The protection configuration. Defaults to `None`.
        :return: The response, the certificate issued and the certificate not confirmed.
        """
        validate_cert_req_id_nums(request)
        implicit_confirm = find_oid_in_general_info(request, str(rfc9480.id_it_implicitConfirm))

        response, cert4, cert1 = build_sun_hybrid_cert_from_request(
            request=request,
            ca_key=self.ca_key,
            serial_number=serial_number,  # type: ignore
            ca_cert=self.ca_cert,
            pub_key_loc=f"{base_url}/pubkey/{serial_number}",
            sig_loc=f"{base_url}/sig/{serial_number}",
            extensions=extensions,
            bad_alt_sig=bad_alt_sig,
        )
        # TODO: maybe not always add the public key to the state.

        self._add_to_state(serial_number=serial_number, cert1=cert1)
        result = check_if_response_contains_encrypted_cert(response)
        if result:
            # MUST not send the decrypted certificate in the response.
            return (
                self.sign_response(
                    response=response, protection_config=protection_config, request=request, use_composite=False
                ),
                None,
                cert4,
            )

        if not implicit_confirm:
            return (
                self.sign_response(
                    response=response,
                    protection_config=protection_config,
                    request=request,
                    use_composite=False,
                    second_cert=cert1,
                ),
                None,
                cert4,
            )

        response = add_general_info_values(response, implicit_confirm=True)
        return (
            self.sign_response(
                response=response,
                protection_config=protection_config,
                request=request,
                use_composite=False,
                second_cert=cert1,
            ),
            cert4,
            None,
        )


class HybridIssuingHandler:
    """The handler for the hybrid issuing processes."""

    def __init__(
        self,
        ca_cert: rfc9480.CMPCertificate,
        ca_key: PrivateKey,
        revocation_handler: RevocationHandler,
        cmp_protection_cert: rfc9480.CMPCertificate,
        sender: str = "CN=MOCK-CA",
        extensions: Optional[rfc9480.Extensions] = None,
    ):
        """Initialize the hybrid issuing handler.

        :param ca_cert: The CA certificate.
        :param ca_key: The CA key.
        :param revocation_handler: The revocation handler.
        :param cmp_protection_cert: The CMP protection certificate.
        :param sender: The sender of the PKI message.
        :param extensions: The extensions to use.
        """
        self.ca_cert = ca_cert
        self.ca_key = ca_key
        self.sender = sender
        self.cmp_protection_cert = cmp_protection_cert
        self.extensions = extensions

        self.chameleon_handler = ChameleonHandler(
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            revocation_handler=revocation_handler,
            sender=self.sender,
            cmp_protection_cert=self.cmp_protection_cert,
            extensions=self.extensions,
        )
        self.revocation_handler = revocation_handler

    def is_revoked_for_request(
        self,
        request: PKIMessageTMP,
        used_both_certs: bool = True,
    ) -> None:
        """Check if the certificate is revoked.

        :param request: The PKI message request.
        :param used_both_certs: Whether both certificates were used to sign the request.
        """
        # result = is_hybrid_cert(request["extraCerts"][0])
        # if result is None:
        #    raise Exception("The certificate is not a hybrid certificate.")

        if self.chameleon_handler.is_chameleon_cert(request["extraCerts"][0]):
            self.chameleon_handler.is_revoked(request=request, used_both_certs=used_both_certs)

        else:
            logging.error("Not implemented yet, so validate the request.")

    def is_revoked_for_issuing(
        self,
        request: PKIMessageTMP,
        used_both_certs: bool = False,
    ) -> None:
        """Check if the certificate is revoked.

        :param request: The PKI message request.
        :param used_both_certs: Whether both certificates were used to sign the request.
        """
        cert = request["extraCerts"][0]
        result = is_hybrid_cert(cert)
        if result is None:
            return

        if result == "chameleon":
            self.chameleon_handler.is_revoked(request=request)
            public_key, sender = load_chameleon_csr_delta_key_and_sender(csr=request["body"]["p10cr"])

            self.revocation_handler.public_key_is_revoked(public_key, sender)

        elif result == "catalyst":
            pass

        elif result == "sun-hybrid":
            cert = convert_sun_hybrid_cert_to_target_form(cert, "Form4")
            result = self.revocation_handler.is_revoked(cert)
            if result:
                raise CertRevoked("The Sun hybrid certificate is revoked.")

        elif result == "related_cert":
            self.revocation_handler.is_revoked(cert)
            if used_both_certs:
                related_cert = get_related_cert_from_list(cert_a=cert, certs=request["extraCerts"][1:])
                self.revocation_handler.is_revoked(related_cert)
        elif result.startswith("composite-sig"):
            self.revocation_handler.is_revoked(cert)

        elif result == "cert_discovery":
            self.revocation_handler.is_revoked(cert)
            if used_both_certs:
                related_cert = get_cert_discovery_cert(cert)
                if related_cert is None:
                    raise BadMessageCheck("The related certificate is not found, or could not be extracted.")
                self.revocation_handler.is_revoked(related_cert)

        else:
            raise NotImplementedError(f"Unknown hybrid certificate type: {result}")
