# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Revocation handler for the Mock CA."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pyasn1_alt_modules import rfc9480

from mock_ca.mock_fun import (
    CertificateDB,
    CertStateEnum,
    KeySecurityChecker,
    RevokedEntry,
)
from pq_logic.pq_verify_logic import verify_hybrid_pkimessage_protection
from resources import certutils, cmputils
from resources.asn1_structures import PKIMessageTMP
from resources.ca_ra_utils import build_rp_from_rr, set_ca_header_fields, validate_rr_crl_entry_details_reason
from resources.certutils import load_public_key_from_cert
from resources.checkutils import (
    check_sender_cmp_protection,
    validate_request_message_nonces_and_tx_id,
    validate_senderkid_for_cmp_protection,
)
from resources.cmputils import get_pkistatusinfo
from resources.cryptoutils import perform_ecdh
from resources.exceptions import (
    AddInfoNotAvailable,
    BadCertId,
    BadMessageCheck,
    BadRequest,
    CertRevoked,
    CMPTestSuiteError,
    NotAuthorized,
    WrongIntegrity,
)
from resources.protectionutils import (
    verify_kem_based_mac_protection,
    verify_pkimessage_protection,
)
from resources.suiteenums import ProtectedType
from resources.typingutils import ECDHPublicKey, PublicKey, SignKey
from resources.utils import display_pki_status_info


def _build_rp_error_response(
    request: PKIMessageTMP,
    exception: CMPTestSuiteError,
    **kwargs,
) -> PKIMessageTMP:
    """Build a PKIMessage for an error response.

    :param request: The PKIMessage to build the response for.
    :param exception: The exception to build the response for.
    :return: The PKIMessage for the error response.
    """
    kwargs = set_ca_header_fields(request, kwargs)

    logging.warning(exception)
    logging.warning(exception.failinfo)
    body = rfc9480.PKIBody()
    status_info = cmputils.prepare_pkistatusinfo(
        status="rejection",
        failinfo=exception.failinfo,
        texts=exception.message,
    )
    body["rp"]["status"].append(status_info)

    pki_message = cmputils.prepare_pki_message(**kwargs)
    pki_message["body"] = body
    return pki_message


class RevocationHandler:
    """Handler for certificate revocation with improved state management."""

    def __init__(
        self,
        rev_db: Optional[CertificateDB] = None,
        x25519_key: Optional[X25519PrivateKey] = None,
        x448_key: Optional[X448PrivateKey] = None,
        ec_key: Optional[EllipticCurvePrivateKey] = None,
    ):
        """Initialize the revocation handler and state."""
        self.rev_db = rev_db or CertificateDB()
        self.x25519_key = x25519_key
        self.x448_key = x448_key
        self.ec_key = ec_key

    def get_current_crl(self, ca_key: SignKey, ca_cert: rfc9480.CMPCertificate) -> bytes:
        """Get the current CRL as DER-encoded bytes."""
        return self.rev_db.get_current_crl(ca_key=ca_key, ca_cert=ca_cert).public_bytes(serialization.Encoding.DER)

    def public_key_is_revoked(self, public_key: PublicKey, sender: rfc9480.Name) -> bool:
        """Check if a public key is revoked based on its serial number."""
        status = KeySecurityChecker(
            revoked_certs=self.rev_db.revoked_certs,
            updated_certs=self.rev_db.updated_certs,
        ).check_cert_status(
            pub_key=public_key,
            sender=sender,
        )
        return status != "good"

    def is_revoked(self, cert: rfc9480.CMPCertificate) -> bool:
        """Check if a certificate is revoked based on its serial number."""
        cert_state = self.rev_db.get_cert_state(cert)
        result = cert_state == CertStateEnum.REVOKED
        serial_number = int(cert["tbsCertificate"]["serialNumber"])
        logging.debug("Check if serial number %d is revoked: %s", serial_number, str(cert_state))
        return result

    def is_updated(self, cert: rfc9480.CMPCertificate, strict: bool = True, body_name: Optional[str] = None) -> bool:
        """Check if a certificate is updated based on its serial number.

        :param cert: The certificate to check.
        :param strict: If True, consider 'UPDATED_BUT_NOT_CONFIRMED' as updated.
        :param body_name: The name of the body to check against, for logging purposes.
        :return: True if the certificate is updated, False otherwise.
        """
        cert_state = self.rev_db.get_cert_state(cert)
        if cert_state == CertStateEnum.UPDATED:
            result = True
        elif strict and cert_state == CertStateEnum.UPDATED_BUT_NOT_CONFIRMED:
            result = True
        else:
            result = False
        serial_number = int(cert["tbsCertificate"]["serialNumber"])
        logging.warning(
            "Check if serial number %d is updated: %s. For body: %s",
            serial_number,
            cert_state,
            body_name if body_name else "unknown",
        )
        return result

    def validate_is_updated(
        self,
        body_name: str,
        cert: rfc9480.CMPCertificate,
    ) -> None:
        """Validate if a certificate is updated.

        :param body_name: The name of the body to check against.
        :param cert: The certificate to check.
        :raises CertRevoked: If the certificate is updated.
        """
        return self.rev_db.update_state.validate_is_updated(
            body_name=body_name,
            cert=cert,
            allow_timeout=False,
        )

    def is_not_allowed_to_request(
        self,
        request: PKIMessageTMP,
        issued_certs: List[rfc9480.CMPCertificate],
        trusted_rev_certs: Optional[List[rfc9480.CMPCertificate]] = None,
    ) -> None:
        """Check if a certificate is not allowed to request revocation."""
        body_name = cmputils.get_cmp_message_type(request)
        cert = request["extraCerts"][0]
        cert_state = self.rev_db.get_cert_state(cert)

        if body_name != "rr":
            if self.is_revoked(cert):
                raise CertRevoked("The certificate is revoked and cannot be used for new requests.")

            self.validate_is_updated(
                body_name=body_name,
                cert=cert,
            )
        else:
            if cert_state == CertStateEnum.UPDATED_BUT_NOT_CONFIRMED:
                raise BadRequest(
                    "The certificate is updated but not confirmed,"
                    " cannot revoke it. Please confirm the other request first."
                )

            cert = request["extraCerts"][0]
            if not certutils.cert_in_list(cert, issued_certs) or not self.is_revoked(cert):
                if trusted_rev_certs is not None:
                    if not certutils.cert_in_list(cert, trusted_rev_certs):
                        raise NotAuthorized(
                            "The certificate is not trusted and cannot be used for revoking another certificate."
                        )

    def revive_cert(self, cert: rfc9480.CMPCertificate):
        """Check if a certificate is revoked based on its serial number."""
        serial_number = int(cert["tbsCertificate"]["serialNumber"])
        self.rev_db.change_cert_state(
            cert=cert,
            new_state=CertStateEnum.REVIVED,
            error_suffix="Called from `revive_cert`",
        )
        logging.info("Removed certificate %d from revoked list.", serial_number)

    def mark_as_revoked(self, cert: rfc9480.CMPCertificate, reason: str = "unspecified") -> None:
        """Mark a certificate as revoked and update the state."""
        serial_number = int(cert["tbsCertificate"]["serialNumber"])
        revoked_entry = RevokedEntry(reason=reason, cert=cert, revoked_date=datetime.now(timezone.utc))
        self.rev_db.change_cert_state(
            cert=cert,
            new_state=CertStateEnum.REVOKED,
            revoke_entry=revoked_entry,
            error_suffix="Called from `mark_as_revoked`",
        )
        serial_numbers = [int(x["tbsCertificate"]["serialNumber"]) for x in self.rev_db.revoked_certs]
        logging.warning("Revoked certificate %d for reason: %s.", serial_number, reason)
        logging.warning("Current revoked certificates: %s", str(serial_numbers))

    def _process_revive_response(
        self, response: PKIMessageTMP, cert_to_revive: List[rfc9480.CMPCertificate]
    ) -> List[rfc9480.CMPCertificate]:
        """Process the revive response and update the revocation state, if needed.

        :param response: The PKIMessage response from the revive request.
        :param cert_to_revive: The list of certificates to revive.
        """
        certs_revive = []
        logging.info("Revoked certs before revive request: %d", len(self.rev_db.revoked_certs))
        for i, status_info in enumerate(response["body"]["rp"]["status"]):
            if status_info["status"].prettyPrint() == "accepted":
                self.revive_cert(cert_to_revive[i])
                logging.info(
                    "Revived certificate at index: %d with serial number: %d",
                    i,
                    int(cert_to_revive[i]["tbsCertificate"]["serialNumber"]),
                )
                certs_revive.append(cert_to_revive[i])
            else:
                status = display_pki_status_info(status_info)
                logging.info("Revive request failed: %s", status)

        logging.info("Revoked certs after revive request: %d", len(self.rev_db.revoked_certs))
        return certs_revive

    def _handle_self_revive_request(
        self,
        pki_message: PKIMessageTMP,
    ) -> Tuple[PKIMessageTMP, List[rfc9480.CMPCertificate]]:
        """Handle a revive request for the same certificate."""
        cert_entry = self.rev_db.get_cert(
            pki_message["extraCerts"][0],
        )
        if cert_entry is None:
            raise BadCertId("Certificate not found in the revocation database, certificate cannot be revived.")

        cert = cert_entry.cert

        logging.info("Process self-revive request.")
        response, _ = build_rp_from_rr(
            request=pki_message,
            certs=[cert],
            revoked_certs=self.rev_db.revoked_certs,
            verify=False,
        )

        status_info = get_pkistatusinfo(response)
        print("Self Revive Status: ", display_pki_status_info(status_info))

        revive_certs = self._process_revive_response(response, [cert])
        return response, revive_certs

    def _handle_revive_request(
        self,
        pki_message: PKIMessageTMP,
        issued_certs: List[rfc9480.CMPCertificate],
    ) -> Tuple[PKIMessageTMP, List[rfc9480.CMPCertificate]]:
        """Handle a revive request and update the revocation state."""
        try:
            if not pki_message["extraCerts"].isValue:
                raise AddInfoNotAvailable("No extra certificates provided for revive request.")

            cert = pki_message["extraCerts"][0]

            if self.is_revoked(cert):
                # means was issued by the CA
                return self._handle_self_revive_request(pki_message=pki_message)

            response, entry = build_rp_from_rr(
                request=pki_message,
                certs=issued_certs,
                revoked_certs=self.rev_db.revoked_certs,
                verify=False,
            )
            certs = [x["cert"] for x in entry]  # type: ignore
            certs: List[rfc9480.CMPCertificate]
            revive_certs = self._process_revive_response(response, certs)

        except CMPTestSuiteError as e:
            return self.build_rp_error_response(pki_message, e), []
        except (InvalidSignature, ValueError) as e:
            return self.build_rp_error_response(pki_message, BadMessageCheck(message=str(e))), []

        return response, revive_certs

    def _check_is_update_request(
        self,
        cert: rfc9480.CMPCertificate,
    ) -> None:
        """Check if the certificate is an updated or updated but not confirmed.

        :param cert: The certificate to check.
        """
        self.rev_db.update_state.validate_is_updated(
            body_name="rr",
            cert=cert,
            allow_timeout=False,
        )

    def process_revocation_request(
        self,
        pki_message: PKIMessageTMP,
        issued_certs: List[rfc9480.CMPCertificate],
        shared_secret: Optional[bytes] = None,
    ) -> Tuple[PKIMessageTMP, List[rfc9480.CMPCertificate]]:
        """Process a revocation request and update the revocation state."""
        try:
            self.verify_protection(pki_message=pki_message, shared_secret=shared_secret)
            validate_request_message_nonces_and_tx_id(pki_message)
            validate_senderkid_for_cmp_protection(pki_message, must_be_protected=True)
            check_sender_cmp_protection(pki_message, must_be_protected=True, allow_failure=False)

            if not pki_message["extraCerts"].isValue:
                raise BadMessageCheck("No extra certificates provided for revocation request.")

            cert = pki_message["extraCerts"][0]
            serial_number = int(cert["tbsCertificate"]["serialNumber"])

            crl_entry_details = pki_message["body"]["rr"][0]["crlEntryDetails"]

            reason = validate_rr_crl_entry_details_reason(crl_entry_details)
            if self.is_revoked(cert) and reason != "removeFromCRL":
                raise CertRevoked(f"Certificate already revoked. Serial number: {serial_number}")

            self._check_is_update_request(cert)

            if reason == "removeFromCRL" and self.is_revoked(cert):
                logging.info(
                    "Certificate is revoked, but reason is removeFromCRL. Proceeding to remove it from the CRL."
                )
                return self._handle_revive_request(pki_message, issued_certs)

            logging.debug("length revoked certs: %d", len(self.rev_db.revoked_certs))
            logging.debug("Length of issued certs: ", len(issued_certs))
            response, entry = build_rp_from_rr(
                request=pki_message,
                shared_secret=shared_secret,
                certs=issued_certs,
                revoked_certs=self.rev_db.revoked_certs,  # Ensure revoked certs are passed
                verify=False,
            )
            status_info = get_pkistatusinfo(response)
            logging.info("Status: %s", display_pki_status_info(status_info))

            if reason != "removeFromCRL" and status_info["status"].prettyPrint() == "accepted":
                self.mark_as_revoked(entry[0]["cert"], reason)  # type: ignore

            elif reason == "removeFromCRL" and status_info["status"].prettyPrint() == "accepted":
                self.revive_cert(entry[0]["cert"])  # type: ignore

            elif status_info["status"].prettyPrint() != "accepted":
                pass

            else:
                # means an error occurred, and the comparison failed.
                raise ValueError("Unexpected behavior!")

            logging.info("Afterwards length revoked certs: %d", len(self.rev_db.revoked_certs))

        except CMPTestSuiteError as e:
            return self.build_rp_error_response(pki_message, e), []
        except (InvalidSignature, ValueError) as e:
            return self.build_rp_error_response(pki_message, BadMessageCheck(message=str(e))), []

        return response, []

    @staticmethod
    def build_rp_error_response(request: PKIMessageTMP, exception: CMPTestSuiteError) -> PKIMessageTMP:
        """Build an error response for a failed revocation request."""
        logging.debug("Revocation request failed: %s", exception.message)
        return _build_rp_error_response(
            request=request,
            exception=exception,
        )

    def _get_ecdh_shared_secret(self, public_key: PublicKey) -> bytes:
        """Get the private key for a given public key."""
        if not isinstance(public_key, ECDHPublicKey):
            raise ValueError("Provided public key is not an ECDH key.")

        key = None
        if isinstance(public_key, X25519PrivateKey):
            key = self.x25519_key
        elif isinstance(public_key, X448PrivateKey):
            key = self.x448_key
        elif isinstance(public_key, EllipticCurvePrivateKey):
            key = self.ec_key

        if key is None:
            raise ValueError("No private key found for the provided public key.")

        return perform_ecdh(key, public_key)

    def verify_protection(self, pki_message: PKIMessageTMP, shared_secret: Optional[bytes] = None) -> None:
        """Verify the protection of a revocation request."""
        if not pki_message["protection"].isValue:
            raise BadMessageCheck("Protection not provided for revocation request.")

        if not pki_message["header"]["protectionAlg"].isValue:
            raise BadMessageCheck("Protection algorithm not provided for revocation request.")

        prot_type = ProtectedType.get_protection_type(pki_message)

        if prot_type == ProtectedType.KEM:
            if shared_secret is None:
                raise BadRequest("Shared secret MUST be provided for KEM-based protection.")
            verify_kem_based_mac_protection(pki_message=pki_message, shared_secret=shared_secret)

            if not pki_message["extraCerts"].isValue:
                raise BadRequest("The extraCerts field MUST be set for `KEM` revocation messages.")

            return

        if prot_type == ProtectedType.DH:
            cmp_cert = pki_message["extraCerts"][0]
            public_key = load_public_key_from_cert(cmp_cert)
            shared_secret = self._get_ecdh_shared_secret(public_key)

            verify_pkimessage_protection(pki_message=pki_message, shared_secret=shared_secret)

        if prot_type == ProtectedType.MAC:
            raise WrongIntegrity("MAC protection is not supported for revocation requests.")

        try:
            verify_hybrid_pkimessage_protection(pki_message=pki_message)
        except InvalidSignature as e:
            raise BadMessageCheck("Invalid signature protection.") from e
        except ValueError as e:
            raise BadMessageCheck(f"Invalid protection, got error: {e}") from e

    def details(self) -> Dict[str, Any]:
        """Return the details of the revocation handler."""
        return self.rev_db.get_details()
