# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
"""Contains the hybrid issuing handler for the Mock-CA."""

from typing import Optional

from pyasn1_alt_modules import rfc9480

from mock_ca.rev_handler import RevocationHandler
from pq_logic.hybrid_issuing import is_hybrid_cert
from pq_logic.hybrid_sig.cert_binding_for_multi_auth import get_related_cert_from_list
from pq_logic.hybrid_sig.certdiscovery import get_cert_discovery_cert
from pq_logic.hybrid_sig.chameleon_logic import (
    build_delta_cert_from_paired_cert,
    load_chameleon_csr_delta_key_and_sender,
)
from pq_logic.hybrid_sig.sun_lamps_hybrid_scheme_00 import convert_sun_hybrid_cert_to_target_form
from pq_logic.tmp_oids import id_ce_deltaCertificateDescriptor
from resources import certextractutils
from resources.asn1_structures import PKIMessageTMP
from resources.exceptions import BadCertTemplate, BadMessageCheck, CertRevoked
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
    ) -> None:
        """Check if the certificate is revoked.

        :param request: The PKI message request.
        """
        cert = request["extraCerts"][0]
        delta_cert = ChameleonHandler.get_delta_cert(cert)

        if self.revocation_handler.is_revoked(cert):
            raise CertRevoked("The paired chameleon certificate is revoked.")

        if self.revocation_handler.is_updated(cert):
            raise CertRevoked("The paired chameleon certificate is updated.")

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

    def is_revoked(
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
