# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Protection handler for PKIMessages."""

import logging
from typing import List, Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from pyasn1_alt_modules import rfc9480, rfc9481

from mock_ca.mock_fun import KEMSharedSecretList
from pq_logic.pq_verify_logic import verify_hybrid_pkimessage_protection
from resources.asn1_structures import PKIMessageTMP
from resources.ca_ra_utils import get_public_key_from_cert_req_msg
from resources.certutils import (
    build_cert_chain_from_dir,
    build_cmp_chain_from_pkimessage,
    certificates_are_trustanchors,
    certificates_must_be_trusted,
    check_is_cert_signer,
    load_public_key_from_cert,
    validate_key_usage,
)
from resources.checkutils import check_if_response_contains_encrypted_cert, check_if_response_contains_private_key
from resources.cryptoutils import perform_ecdh
from resources.exceptions import (
    BadAlg,
    BadConfig,
    BadMessageCheck,
    CMPTestSuiteError,
    InvalidAltSignature,
    NotAuthorized,
    SignerNotTrusted,
)
from resources.oid_mapping import may_return_oid_to_name
from resources.oidutils import id_KemBasedMac
from resources.protectionutils import (
    get_protection_type_from_pkimessage,
    protect_hybrid_pkimessage,
    protect_pkimessage,
    verify_pkimessage_protection,
)
from resources.typingutils import SignKey
from unit_tests.utils_for_test import load_env_data_certs


class ProtectionHandler:
    """Handles the protection of PKIMessages."""

    def __init__(
        self,
        cmp_protection_cert: rfc9480.CMPCertificate,
        cmp_prot_key: SignKey,
        kem_ss_list: KEMSharedSecretList,
        pre_shared_secret: Union[bytes, str] = b"SiemensIT",
        def_mac_alg: str = "password_based_mac",
        use_openssl: bool = True,
        prot_alt_key: Optional[SignKey] = None,
    ) -> None:
        """Initialize the ProtectionHandler with the specified parameters."""
        self.prot_cert = cmp_protection_cert
        self.prot_key = cmp_prot_key
        self.def_mac_alg = def_mac_alg
        self.use_openssl = use_openssl
        self.pre_shared_secret = pre_shared_secret
        self.prot_alt_key = prot_alt_key
        self.mock_ca_trusted_dir = "data/mock_ca/trustanchors"
        self.cmp_cert_chain = build_cert_chain_from_dir(
            ee_cert=self.prot_cert,
            cert_chain_dir="data/unittest",
            root_dir=self.mock_ca_trusted_dir,
        )

        self.kari_data = load_env_data_certs()
        self.kem_shared_secret = kem_ss_list
        self.enforce_lwcmp = False

    @property
    def protection_cert(self) -> rfc9480.CMPCertificate:
        """Get the protection certificate."""
        return self.prot_cert

    @property
    def protection_key(self) -> SignKey:
        """Get the protection key."""
        return self.prot_key

    def verify_kem_based_mac_protection(self, pki_message: PKIMessageTMP) -> None:
        """Verify the KEM-based MAC protection of the PKI message.

        :param pki_message: The PKI message to verify.
        :return: True if the MAC protection is valid, False otherwise.
        """
        self.kem_shared_secret.verify_pkimessage_protection(request=pki_message)

    def verify_dh_based_mac_protection(self, pki_message: PKIMessageTMP) -> None:
        """Verify the DH-based MAC protection of the PKI message.

        :param pki_message: The PKI message to verify.
        :return: True if the MAC protection is valid, False otherwise.
        """
        cert, ss = self.get_dh_cert_and_ss(pki_message["extraCerts"][0])
        try:
            verify_pkimessage_protection(
                pki_message,
                shared_secret=ss,
            )
        except ValueError as e:
            raise BadMessageCheck("The DH-based MAC protection is invalid.") from e

    def get_dh_cert_and_ss(self, cert: rfc9480.CMPCertificate) -> Tuple[rfc9480.CMPCertificate, bytes]:
        """Get the ECDH certificate and shared secret.

        :param cert: The certificate to use for the ECDH.
        :return: The ECDH certificate and shared secret.
        """
        public_key = load_public_key_from_cert(cert)
        if isinstance(public_key, X25519PublicKey):
            kari_cert = self.kari_data["x25519_cert"]
            kari_key = self.kari_data["x25519_key"]
            if not isinstance(kari_key, X25519PrivateKey):
                raise BadConfig("The Mock CA x25519 key is not a X25519 key.")
            ss = perform_ecdh(kari_key, public_key)

        elif isinstance(public_key, X448PublicKey):
            kari_cert = self.kari_data["x448_cert"]
            kari_key = self.kari_data["x448_key"]
            if not isinstance(kari_key, X448PrivateKey):
                raise BadConfig("The Mock CA x448 key is not a X448 key.")
            ss = perform_ecdh(kari_key, public_key)
        elif isinstance(public_key, EllipticCurvePublicKey):
            kari_cert = self.kari_data["ecc_cert"]
            kari_key = self.kari_data["ecc_key"]
            if not isinstance(kari_key, EllipticCurvePrivateKey):
                raise BadConfig("The Mock CA ECC key is not a ECC key.")
            ss = perform_ecdh(kari_key, public_key)
        else:
            raise BadMessageCheck("The client public key is not a ECDH key.")

        return kari_cert, ss

    def get_same_mac_protection(self, alg_id: rfc9480.AlgorithmIdentifier, use_same: bool = True) -> str:
        """Get the same MAC protection algorithm.

        :param alg_id: The algorithm to use.
        :param use_same: Whether to use the same MAC protection algorithm as the request. Defaults to `True`.
        :return: The MAC protection algorithm.
        """
        if alg_id["algorithm"] == rfc9481.id_PBMAC1:
            return "pbmac1" if use_same else "password_based_mac"
        if alg_id["algorithm"] == rfc9481.id_PasswordBasedMac:
            return "password_based_mac" if use_same else "pbmac1"
        return self.def_mac_alg

    def check_if_request_is_for_kari_encr_cert(
        self, request: PKIMessageTMP, response: PKIMessageTMP
    ) -> Optional[rfc9480.CMPCertificate]:
        """Check if the request is for an encrypted X25519 or x448 certificate.

        :param request: The PKI message to check.
        :param response: The PKI message to check.
        :return: The encrypted certificate if present, None otherwise.
        """
        body_name = response["body"].getName()
        if body_name not in ["ip", "cp", "kup"]:
            return None

        if check_if_response_contains_encrypted_cert(response):
            public_key = get_public_key_from_cert_req_msg(request["body"][request["body"].getName()][0])
            if isinstance(public_key, X25519PublicKey):
                return self.kari_data["x25519_cert"]
            if isinstance(public_key, X448PublicKey):
                return self.kari_data["x448_cert"]
            elif isinstance(public_key, EllipticCurvePublicKey):
                return self.kari_data["ecc_cert"]

        return None

    def is_kga_kari_request(self, request: PKIMessageTMP, response: PKIMessageTMP) -> bool:
        """Check if the request is a KGA KARI with ECC to set the correct certificate as CMP protection cert.

        :param request: The PKI message to check.
        :param response: The PKI message to check.
        :return: True if the request is a KGA/KARI request, False otherwise.
        """
        # The CertTemplate is modified so it cannot be checked.

        body_name = response["body"].getName()

        if body_name not in ["cp", "ip", "kup"]:
            return False

        nums = len(response["body"][body_name]["response"])
        found = False
        logging.warning("Checking if the request is a KGA/KARI request.")
        for num in range(nums):
            result = check_if_response_contains_private_key(response, num)
            if result:
                found = True
                break

        if not found:
            return False

        cert = request["extraCerts"][0]
        public_key = load_public_key_from_cert(cert)
        # The other types are supposed to be used with DH-based-MAC.
        logging.warning("Public key type:", type(public_key))
        return isinstance(public_key, EllipticCurvePublicKey)

    def protect_pkimessage(
        self,
        response: PKIMessageTMP,
        request: PKIMessageTMP,
        secondary_cert: Optional[rfc9480.CMPCertificate] = None,
        add_certs: Optional[List[rfc9480.CMPCertificate]] = None,
        bad_protection_type=False,
        bad_message_check=False,
        bad_alt_message_check=False,
    ) -> PKIMessageTMP:
        """Protect the PKI message with the specified protection method.

        :param response: The PKI message to protect.
        :param request: The original PKI message.
        :param secondary_cert: The secondary certificate to add, either the extra Chameleon cert or
        the Sun-hybrid cert in form 1.
        :param add_certs: Additional certificates to add to the PKIMessage.
        :param bad_protection_type: Normal uses the same MAC protection algorithm as the request,
            but this Flag will use the different one. ("pbmac1" or "password_based_mac")
        :param bad_message_check: Whether to invalidate the protection. Defaults to `False`.
        :param bad_alt_message_check: Whether to invalidate the alternative protection. Defaults to `False`.
        :return: The protected PKI message.
        """
        # Implement the protection logic here
        prot_type = get_protection_type_from_pkimessage(request)

        alg_name = may_return_oid_to_name(request["header"]["protectionAlg"]["algorithm"])
        if alg_name == "dh_based_mac":
            cert, ss = self.get_dh_cert_and_ss(cert=request["extraCerts"][0])
            protected_pki_message = protect_pkimessage(
                shared_secret=ss,
                pki_message=response,
                protection="dh",
                bad_message_check=bad_message_check,
                exclude_certs=True,
                cert=cert,
            )
            protected_pki_message["extraCerts"].append(cert)
            if secondary_cert is not None:
                protected_pki_message["extraCerts"].append(secondary_cert)

            cert_chain = build_cert_chain_from_dir(cert, cert_chain_dir="data/unittest", root_dir="data/trustanchors")
            protected_pki_message["extraCerts"].extend(cert_chain[1:])
            if add_certs is not None:
                protected_pki_message["extraCerts"].extend(add_certs)
            return protected_pki_message

        if "mac" == prot_type:
            prot_type = self.get_same_mac_protection(
                request["header"]["protectionAlg"], use_same=not bad_protection_type
            )
            protected_pki_message = protect_pkimessage(
                password=self.pre_shared_secret,
                pki_message=response,
                protection=prot_type,
                bad_message_check=bad_message_check,
                exclude_certs=True,
            )
            if secondary_cert is not None:
                protected_pki_message["extraCerts"].append(secondary_cert)

            if add_certs is not None:
                protected_pki_message["extraCerts"].extend(add_certs)

            return protected_pki_message

        elif self.is_kga_kari_request(request, response):
            protected_pki_message = protect_pkimessage(
                pki_message=response,
                protection="signature",
                private_key=self.kari_data["ecc_key"],
                cert=self.kari_data["ecc_cert"],
                bad_message_check=bad_message_check,
                exclude_certs=True,
            )
            protected_pki_message["extraCerts"].append(self.kari_data["ecc_cert"])
            if secondary_cert is not None:
                protected_pki_message["extraCerts"].append(secondary_cert)

            cert_chain = build_cert_chain_from_dir(
                ee_cert=self.kari_data["ecc_cert"],
                cert_chain_dir="data/unittest",
                root_dir="data/trustanchors",
            )
            protected_pki_message["extraCerts"].extend(cert_chain[1:])
            if add_certs is not None:
                protected_pki_message["extraCerts"].extend(add_certs)
            return protected_pki_message

        enc_cert = self.check_if_request_is_for_kari_encr_cert(request=request, response=response)
        if enc_cert is not None:
            protected_pki_message = protect_hybrid_pkimessage(
                pki_message=response,
                cert=self.prot_cert,
                private_key=self.prot_key,
                bad_message_check=bad_message_check,
                bad_alt_message_check=bad_alt_message_check,
                exclude_certs=True,
                alt_signing_key=self.prot_alt_key,
            )
            protected_pki_message["extraCerts"].append(self.prot_cert)
            logging.warning("added the X-Certificate for the encrypted certificate challenge.")
            protected_pki_message["extraCerts"].append(enc_cert)

            if secondary_cert is not None:
                protected_pki_message["extraCerts"].append(secondary_cert)

            if len(self.cmp_cert_chain) > 1:
                protected_pki_message["extraCerts"].extend(self.cmp_cert_chain[1:])
            if add_certs is not None:
                protected_pki_message["extraCerts"].extend(add_certs)

            return protected_pki_message

        else:
            protected_pki_message = protect_hybrid_pkimessage(
                pki_message=response,
                cert=self.prot_cert,
                private_key=self.prot_key,
                bad_message_check=bad_message_check,
                bad_alt_message_check=bad_alt_message_check,
                exclude_certs=True,
                alt_signing_key=self.prot_alt_key,
            )

        protected_pki_message["extraCerts"].append(self.prot_cert)
        if secondary_cert is not None:
            protected_pki_message["extraCerts"].append(secondary_cert)

        protected_pki_message["extraCerts"].extend(self.cmp_cert_chain[1:])

        if add_certs is not None:
            protected_pki_message["extraCerts"].extend(add_certs)

        return protected_pki_message

    def validate_mac_protection(self, pki_message: PKIMessageTMP):
        """Validate the MAC protection of the PKI message.

        :param pki_message: The PKI message to validate.
        :return: True if the MAC protection is valid, False otherwise.
        """
        try:
            verify_pkimessage_protection(
                pki_message=pki_message,
                password=self.pre_shared_secret,
                enforce_lwcmp=self.enforce_lwcmp,
            )
        except ValueError:
            raise BadMessageCheck(message="Invalid MAC protection.")

    def validate_signature_protection(self, pki_message: PKIMessageTMP):
        """Validate the signature protection of the PKI message.

        :param pki_message: The PKI message to validate.
        :return: True if the signature protection is valid, False otherwise.
        """
        if not pki_message["extraCerts"].isValue:
            raise BadMessageCheck("No extra certificates in PKI message. Cannot validate signature.")

        try:
            verify_hybrid_pkimessage_protection(
                pki_message=pki_message,
            )
        except BadAlg as e:
            raise BadMessageCheck(
                message="Invalid algorithm or combination for signature protection.",
                error_details=[e.message] + e.error_details,
            )

        except (InvalidSignature, InvalidAltSignature, ValueError):
            raise BadMessageCheck(message="Invalid signature protection.")

        # Implement the signature validation logic here
        self.check_signer_is_trusted(pki_message)

    def validate_protection(self, pki_message: PKIMessageTMP):
        """Validate the protection of the PKI message.

        :param pki_message: The PKI message to validate.
        :return: True if the protection is valid, False otherwise.
        """
        # Implement the validation logic here

        if not pki_message["header"]["protectionAlg"].isValue:
            raise BadMessageCheck("The protection algorithm is not set.")

        alg_oid = pki_message["header"]["protectionAlg"]["algorithm"]

        if alg_oid == rfc9480.id_DHBasedMac:
            # Validate DH-based MAC protection
            self.verify_dh_based_mac_protection(pki_message)

        elif alg_oid == id_KemBasedMac:
            # Validate KEM-based MAC protection
            self.verify_kem_based_mac_protection(pki_message)

        elif get_protection_type_from_pkimessage(pki_message) == "mac":
            # Validate MAC protection
            self.validate_mac_protection(pki_message)
        else:
            self.validate_signature_protection(pki_message)

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

    def check_signer_is_trusted(self, pki_message: PKIMessageTMP, for_dh: bool = False) -> None:
        """Check if the signer is trusted.

        Verify the certificate chain and check if the last certificate is trusted.
        Optional uses OpenSSL for signature verification and additional checks.

        :param pki_message: The PKI message to check.
        :param for_dh: If the message is for DH-based MAC protection. Defaults to `False`.
        :return: True if the signer is trusted, False otherwise.
        :raises BadMessageCheck: If the message is invalid.
        :raises SignerNotTrusted: If the signer is not trusted.
        :raises NotAuthorized: If the signer is not authorized.
        """
        logging.debug("Checking if the signer is trusted. use_openssl: %s", self.use_openssl)
        # Implement the logic to check if the signer is trusted
        cert_chain = build_cmp_chain_from_pkimessage(pki_message, for_issued_cert=False)
        logging.info("Certificate chain length: %s", len(cert_chain))
        may_trusted_cert = cert_chain[-1]

        # Temporary fix to avoid errors for Composite signatures and PQ signatures.

        prot_type = get_protection_type_from_pkimessage(pki_message)
        result = prot_type == "pq-sig" or prot_type == "composite-sig"

        if result:
            logging.debug(
                "Skipping OpenSSL cert chain validation check for Composite or PQ signature."
                "Will be checked in the Future."
            )

        if self.use_openssl and not result:
            try:
                certificates_must_be_trusted(
                    cert_chain=cert_chain,
                    # Must contain `digitalSignature` if present.
                    key_usage_strict=1,
                    key_usages="digitalSignature" if not for_dh else "keyAgreement",
                    crl_check=False,
                    trustanchors=self.mock_ca_trusted_dir,
                )
                logging.debug("Certificate chain is trusted")
            except FileNotFoundError:
                raise CMPTestSuiteError("Please do not modify the `certutils.py` file,while running the tests.")
            except ValueError as e:
                raise NotAuthorized(
                    "The certificate `KeyUsage` indicates that the certificate,"
                    "is not authorized to be used for signing."
                ) from e
        else:
            # Check if the certificate is trusted.
            certificates_are_trustanchors(may_trusted_cert, trustanchors=self.mock_ca_trusted_dir)
