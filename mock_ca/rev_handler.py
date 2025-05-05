# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Revocation handler for the Mock CA."""

import logging
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pyasn1_alt_modules import rfc9480
from pyasn1_alt_modules.rfc9480 import id_DHBasedMac

from mock_ca.mock_fun import CertRevStateDB, RevokedEntry
from pq_logic.keys.abstract_wrapper_keys import HybridPublicKey
from pq_logic.pq_verify_logic import verify_hybrid_pkimessage_protection
from resources import certutils, cmputils
from resources.asn1_structures import PKIMessageTMP
from resources.asn1utils import encode_to_der
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
    CertRevoked,
    CMPTestSuiteError,
    NotAuthorized,
    WrongIntegrity,
)
from resources.oid_mapping import compute_hash
from resources.oidutils import id_KemBasedMac
from resources.protectionutils import (
    get_protection_type_from_pkimessage,
    verify_kem_based_mac_protection,
    verify_pkimessage_protection,
)
from resources.typingutils import ECDHPublicKey, PublicKey, SignKey
from resources.utils import display_pki_status_info
from unit_tests.utils_for_test import compare_pyasn1_objects


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
        rev_db: Optional[CertRevStateDB] = None,
        x25519_key: Optional[X25519PrivateKey] = None,
        x448_key: Optional[X448PrivateKey] = None,
        ec_key: Optional[EllipticCurvePrivateKey] = None,
    ):
        """Initialize the revocation handler and state."""
        self.rev_db = rev_db or CertRevStateDB()
        self.x25519_key = x25519_key
        self.x448_key = x448_key
        self.ec_key = ec_key
        self.hash_alg = "sha1"

    def add_revoked_cert(self, cert: rfc9480.CMPCertificate, reason: str = "unspecified") -> None:
        """Add a certificate to the revoked list."""
        serial_number = int(cert["tbsCertificate"]["serialNumber"])
        revoked_entry = RevokedEntry(reason=reason, cert=cert)
        self.rev_db.add_rev_entry(revoked_entry)
        logging.warning(f"Added certificate {serial_number} to revoked list.")

    def get_current_crl(self, ca_key: SignKey, ca_cert: rfc9480.CMPCertificate) -> bytes:
        """Get the current CRL as DER-encoded bytes."""
        return self.rev_db.get_crl_response(
            sign_key=ca_key,
            ca_cert=ca_cert,
        ).public_bytes(serialization.Encoding.DER)

    def public_key_is_revoked(self, public_key: PublicKey, sender: rfc9480.Name) -> bool:
        """Check if a public key is revoked based on its serial number."""
        for cert in self.rev_db.revoked_certs + self.rev_db.update_entry_list.certs:
            if not compare_pyasn1_objects(sender, cert["tbsCertificate"]["subject"]):
                continue

            pub_key = load_public_key_from_cert(cert)
            if isinstance(pub_key, HybridPublicKey) and isinstance(public_key, HybridPublicKey):
                if pub_key == public_key:
                    return True
            elif isinstance(pub_key, HybridPublicKey):
                if pub_key.trad_key == public_key or pub_key.pq_key == public_key:
                    return True
            elif isinstance(public_key, HybridPublicKey):
                if public_key.trad_key == pub_key or public_key.pq_key == pub_key:
                    return True
            else:
                if pub_key == public_key:
                    return True

        return False

    def is_revoked(self, cert: rfc9480.CMPCertificate) -> bool:
        """Check if a certificate is revoked based on its serial number."""
        serial_number = int(cert["tbsCertificate"]["serialNumber"])
        hashed_cert = compute_hash(self.hash_alg, encode_to_der(cert))
        print("hashed_cert", hashed_cert.hex())
        result = self.rev_db.is_revoked_by_hash(hashed_cert)
        logging.info(f"Check if serial {serial_number} is revoked: {result}")
        return result

    def is_updated(self, cert: rfc9480.CMPCertificate) -> bool:
        """Check if a certificate is updated based on its serial number."""
        serial_number = int(cert["tbsCertificate"]["serialNumber"])
        hashed_cert = compute_hash(self.hash_alg, encode_to_der(cert))
        result = self.rev_db.is_updated_by_hash(hashed_cert)
        logging.info(f"Check if serial {serial_number} is updated: {result}")
        return result

    def is_not_allowed_to_request(
        self,
        request: PKIMessageTMP,
        issued_certs: List[rfc9480.CMPCertificate],
        trusted_rev_certs: Optional[List[rfc9480.CMPCertificate]] = None,
    ) -> None:
        """Check if a certificate is not allowed to request revocation."""
        body_name = cmputils.get_cmp_message_type(request)
        if body_name != "rr":
            cert = request["extraCerts"][0]
            if self.is_revoked(cert):
                raise CertRevoked("The certificate is revoked and cannot be used for new requests.")

            if self.is_updated(cert):
                raise CertRevoked("The certificate is updated and cannot be used for new requests.")
        else:
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
        hashed_cert = compute_hash(self.hash_alg, encode_to_der(cert))
        self.rev_db.rev_entry_list.remove_by_hash(hashed_cert)
        logging.info(f"Removed certificate {serial_number} from revoked list.")

    def mark_as_revoked(self, cert: rfc9480.CMPCertificate, reason: str = "unspecified") -> None:
        """Mark a certificate as revoked and update the state."""
        serial_number = int(cert["tbsCertificate"]["serialNumber"])
        revoked_entry = RevokedEntry(reason=reason, cert=cert)
        self.rev_db.add_rev_entry(revoked_entry)
        logging.warning(f"Revoked certificate {serial_number} for reason: {reason}.")
        logging.warning(f"Current revoked certificates: {self.rev_db.rev_entry_list.serial_numbers}")

    def _process_revive_response(
        self, response: PKIMessageTMP, cert_to_revive: List[rfc9480.CMPCertificate]
    ) -> List[rfc9480.CMPCertificate]:
        """Process the revive response and update the revocation state, if needed.

        :param response: The PKIMessage response from the revive request.
        :param cert_to_revive: The list of certificates to revive.
        """
        certs_revive = []
        logging.info("Revoked certs before revive request: ", len(self.rev_db.rev_entry_list.serial_numbers))
        for i, status_info in enumerate(response["body"]["rp"]["status"]):
            if status_info["status"].prettyPrint() == "accepted":
                self.revive_cert(cert_to_revive[i])
                logging.info(
                    f"Revived certificate at index: {i} with serial number: "
                    f"{int(cert_to_revive[i]['tbsCertificate']['serialNumber'])}"
                )
                certs_revive.append(cert_to_revive[i])
            else:
                status = display_pki_status_info(status_info)
                logging.info("Revive request failed: ", status)

        logging.info("Revoked certs after revive request: ", len(self.rev_db.rev_entry_list.serial_numbers))
        return certs_revive

    def _handle_self_revive_request(
        self,
        pki_message: PKIMessageTMP,
    ) -> Tuple[PKIMessageTMP, List[rfc9480.CMPCertificate]]:
        """Handle a revive request for the same certificate."""
        cert = self.rev_db.get_by_hash(
            pki_message["extraCerts"][0],
        )
        if cert is None:
            raise BadCertId("Certificate not found in the revocation database, certificate cannot be revived.")

        logging.info("Process self-revive request.")
        response, entry = build_rp_from_rr(
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
            return self._build_error_response(pki_message, e), []
        except (InvalidSignature, ValueError) as e:
            return self._build_error_response(pki_message, BadMessageCheck(message=str(e))), []

        return response, revive_certs

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

            if self.is_updated(cert):
                raise CertRevoked(f"Certificate already updated. Serial number: {serial_number}")

            if reason == "removeFromCRL" and self.is_revoked(cert):
                logging.info(
                    "Certificate is revoked, but reason is removeFromCRL. Proceeding to remove it from the CRL."
                )
                return self._handle_revive_request(pki_message, issued_certs)

            logging.info("length revoked certs: ", len(self.rev_db.revoked_certs))
            response, entry = build_rp_from_rr(
                request=pki_message,
                shared_secret=shared_secret,
                certs=issued_certs,
                revoked_certs=self.rev_db.revoked_certs,  # Ensure revoked certs are passed
                verify=False,
            )
            status_info = get_pkistatusinfo(response)
            logging.info("Status: ", display_pki_status_info(status_info))

            if reason != "removeFromCRL" and status_info["status"].prettyPrint() == "accepted":
                self.mark_as_revoked(cert, reason)

            elif reason == "removeFromCRL" and status_info["status"].prettyPrint() == "accepted":
                self.revive_cert(cert)

            elif status_info["status"].prettyPrint() != "accepted":
                pass

            else:
                # means an error occurred, and the comparison failed.
                raise ValueError("Unexpected behavior!")

            logging.info("Afterwards length revoked certs: ", len(self.rev_db.revoked_certs))

        except CMPTestSuiteError as e:
            return self._build_error_response(pki_message, e), []
        except (InvalidSignature, ValueError) as e:
            return self._build_error_response(pki_message, BadMessageCheck(message=str(e))), []

        return response, []

    def _build_error_response(self, request: PKIMessageTMP, exception: CMPTestSuiteError) -> PKIMessageTMP:
        """Build an error response for a failed revocation request."""
        return _build_rp_error_response(
            request=request,
            exception=exception,
        )
        logging.warning(f"Revocation request failed: {exception.message}")
        return cmputils.prepare_pki_message(
            **set_ca_header_fields(
                request, {"status": "rejection", "failinfo": exception.failinfo, "texts": exception.message}
            )
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

        if pki_message["header"]["protectionAlg"]["algorithm"] == id_KemBasedMac:
            if shared_secret is None:
                raise ValueError("Shared secret MUST be provided for KEM-based protection.")
            verify_kem_based_mac_protection(pki_message=pki_message, shared_secret=shared_secret)
            return

        elif pki_message["header"]["protectionAlg"]["algorithm"] == id_DHBasedMac:
            cmp_cert = pki_message["extraCerts"][0]
            public_key = load_public_key_from_cert(cmp_cert)
            shared_secret = self._get_ecdh_shared_secret(public_key)

            verify_pkimessage_protection(pki_message=pki_message, shared_secret=shared_secret)

        if get_protection_type_from_pkimessage(pki_message=pki_message) == "mac":
            raise WrongIntegrity("MAC protection is not supported for revocation requests.")

        try:
            verify_hybrid_pkimessage_protection(pki_message=pki_message)
        except InvalidSignature as e:
            raise BadMessageCheck("Invalid signature protection.") from e
        except ValueError as e:
            raise BadMessageCheck(f"Invalid protection, got error: {e}") from e

    def details(self) -> Dict[str, Any]:
        """Return the details of the revocation handler."""
        return {
            "revoked_certs": self.rev_db.rev_entry_list.serial_numbers,
            "updated_certs": self.rev_db.update_entry_list.serial_numbers,
            "revocation_state": self.rev_db.rev_entry_list,
        }
