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

from mock_ca.db_config_vars import ProtectionHandlerConfig
from mock_ca.mock_fun import KEMSharedSecretList
from pq_logic.pq_verify_logic import verify_hybrid_pkimessage_protection
from resources.asn1_structures import PKIMessageTMP
from resources.ca_ra_utils import get_public_key_from_cert_req_msg
from resources.certbuildutils import validate_private_key_usage_period
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
from resources.cmputils import get_cmp_message_type, patch_sender, patch_senderkid
from resources.cryptoutils import perform_ecdh
from resources.data_objects import KARICertsAndKeys
from resources.exceptions import (
    BadAlg,
    BadAsn1Data,
    BadConfig,
    BadMessageCheck,
    BadSigAlgID,
    CMPTestSuiteError,
    InvalidAltSignature,
    LwCMPViolation,
    NotAuthorized,
    SignerNotTrusted,
    WrongIntegrity,
)
from resources.protectionutils import (
    protect_hybrid_pkimessage,
    protect_pkimessage,
    protect_pkimessage_kem_based_mac,
    verify_pkimessage_protection,
)
from resources.suiteenums import ProtectedType
from resources.typingutils import SignKey
from unit_tests.utils_for_test import load_env_data_certs


class ProtectionHandler:
    """Handles the protection of PKIMessages."""

    def __init__(
        self,
        cmp_protection_cert: rfc9480.CMPCertificate,
        cmp_prot_key: SignKey,
        kem_ss_list: Optional[KEMSharedSecretList] = None,
        pre_shared_secret: Union[bytes, str] = b"SiemensIT",
        def_mac_alg: str = "password_based_mac",
        use_openssl: bool = True,
        prot_alt_key: Optional[SignKey] = None,
    ) -> None:
        """Initialize the ProtectionHandler with the specified parameters."""
        self.prot_cert = cmp_protection_cert
        self.prot_key = cmp_prot_key
        mock_ca_trusted_dir = "data/mock_ca/trustanchors"
        self.cmp_cert_chain = build_cert_chain_from_dir(
            ee_cert=self.prot_cert,
            cert_chain_dir="data/unittest",
            root_dir=mock_ca_trusted_dir,
        )

        self.kari_data = load_env_data_certs()
        if kem_ss_list is None:
            kem_ss_list = KEMSharedSecretList()
        self.kem_shared_secret = kem_ss_list
        self.sender = "CN=Mock CA"

        kari_cert = KARICertsAndKeys.from_kwargs(**load_env_data_certs())

        self._prot_config = ProtectionHandlerConfig(
            pre_shared_secret=pre_shared_secret,
            def_mac_alg=def_mac_alg,
            use_openssl=use_openssl,
            prot_alt_key=prot_alt_key,
            kari_certs=kari_cert,
            mock_ca_trusted_dir=mock_ca_trusted_dir,
            enforce_lwcmp=False,
        )

    def patch_for_mac(self, response: PKIMessageTMP) -> PKIMessageTMP:
        """Patch a PKIMessage for MAC protection, by modifying the sender and senderKid fields."""
        response = patch_sender(response, sender_name=self.sender)
        response = patch_senderkid(response, self.sender.encode("utf-8"))
        return response

    def get_details(self) -> dict:
        """Get the details of the ProtectionHandler."""
        return {
            "protection_cert": self.prot_cert,
            "protection_key": self.prot_key,
            "protection_config": self._prot_config.to_dict(),
            "cmp_cert_chain": self.cmp_cert_chain,
            "kem_shared_secret": self.kem_shared_secret,
        }

    def set_config(self, config: ProtectionHandlerConfig) -> None:
        """Set the configuration for the ProtectionHandler."""
        self._prot_config = config

    @property
    def prot_handler_config(self) -> ProtectionHandlerConfig:
        """Get the protection configuration."""
        return self._prot_config

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

        self.check_signer_is_trusted(pki_message, for_dh=True)

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
        return self._prot_config.def_mac_alg

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
        prot_type = ProtectedType.get_protection_type(request)

        if prot_type == ProtectedType.DH:
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

        if prot_type == ProtectedType.KEM:
            ss = self.kem_shared_secret.get_shared_secret_object(request=request)
            logging.info("Looking for the shared secret object: %s", str(ss is not None))
            if ss is not None:
                response = self.patch_for_mac(response)
                protected_response = protect_pkimessage_kem_based_mac(
                    pki_message=response,
                    shared_secret=ss.shared_secret,
                )
                if secondary_cert is not None:
                    protected_response["extraCerts"].append(secondary_cert)
                if add_certs is not None:
                    protected_response["extraCerts"].extend(add_certs)
                return protected_response

        if prot_type == ProtectedType.MAC:
            prot_type = self.get_same_mac_protection(
                request["header"]["protectionAlg"], use_same=not bad_protection_type
            )
            response = self.patch_for_mac(response)
            protected_pki_message = protect_pkimessage(
                password=self._prot_config.pre_shared_secret,
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
                alt_signing_key=self._prot_config.prot_alt_key,
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
                alt_signing_key=self._prot_config.prot_alt_key,
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
        if get_cmp_message_type(pki_message) == "rr":
            raise WrongIntegrity(
                "A revocation request cannot be protected with a MAC."
                "Must either be protected by the certificate to be revoked or "
                "a trusted certificate."
            )

        try:
            verify_pkimessage_protection(
                pki_message=pki_message,
                password=self._prot_config.pre_shared_secret,
                enforce_lwcmp=self.prot_handler_config.enforce_lwcmp,
            )

        except LwCMPViolation as e:
            raise BadMessageCheck(
                message="The MAC protection is invalid (please check the error details).",
                error_details=[e.message] + e.error_details,
            ) from e
        except ValueError as e:
            raise BadMessageCheck(message="Invalid MAC protection.") from e

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

        except BadSigAlgID as e:
            raise BadMessageCheck(
                message="Invalid signature algorithm and public key type.",
                error_details=[e.message] + e.error_details,
            ) from e

        except BadAlg as e:
            raise BadMessageCheck(
                message="Invalid algorithm or combination for signature protection.",
                error_details=[e.message] + e.error_details,
            ) from e

        except (InvalidSignature, InvalidAltSignature, ValueError) as e:
            raise BadMessageCheck(message="Invalid signature protection.") from e

        # Implement the signature validation logic here
        self.check_signer_is_trusted(pki_message, for_dh=False)

    def validate_protection(self, pki_message: PKIMessageTMP):
        """Validate the protection of the PKI message.

        :param pki_message: The PKI message to validate.
        :return: True if the protection is valid, False otherwise.
        """
        # Implement the validation logic here

        if not pki_message["header"]["protectionAlg"].isValue:
            raise BadMessageCheck("The protection algorithm is not set.")

        alg_oid = pki_message["header"]["protectionAlg"]["algorithm"]

        prot_type = ProtectedType.get_protection_type(alg_oid)

        if prot_type == ProtectedType.DH:
            # Validate DH-based MAC protection
            self.verify_dh_based_mac_protection(pki_message)

        elif prot_type == ProtectedType.KEM:
            # Validate KEM-based MAC protection
            self.verify_kem_based_mac_protection(pki_message)

        elif prot_type == ProtectedType.MAC:
            # Validate MAC protection
            self.validate_mac_protection(pki_message)
        else:
            self.validate_signature_protection(pki_message)

    @staticmethod
    def check_signer_extensions(pki_message: PKIMessageTMP) -> None:
        """Check if the signer extensions are present.

        :param pki_message: The PKI message to check.
        :return: True if the signer extensions are present, False otherwise.
        """
        # Verify that the CMP-protection certificate is authorized to sign the message.
        # Allows the CMP protection certificate to have an unset key usage.

        ee_cert = pki_message["extraCerts"][0]

        cert_chain = build_cmp_chain_from_pkimessage(
            pki_message=pki_message,
            ee_cert=ee_cert,
        )
        try:
            validate_key_usage(cert_chain[0], key_usages="digitalSignature", strictness="LAX")
        except ValueError as e:
            raise NotAuthorized("The CMP protection certificate is not authorized to sign the message.") from e
        except BadAsn1Data:
            raise SignerNotTrusted("The CMP protection certificate did not contain a valid KeyUsage extension.")  # pylint: disable=raise-missing-from

        try:
            validity = cert_chain[0]["tbsCertificate"]["validity"]
            extns = cert_chain[0]["tbsCertificate"]["extensions"]
            validate_private_key_usage_period(extns=extns, validity=validity, must_be_present=False)
        except BadAsn1Data as e:
            raise NotAuthorized(
                "The CMP protection certificate did not contain a valid `PrivateKeyUsagePeriod` extension.",
                error_details=[e.message] + e.error_details,
            ) from e

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
        logging.debug("Checking if the signer is trusted. use_openssl: %s", self._prot_config.use_openssl)
        # Implement the logic to check if the signer is trusted
        cert_chain = build_cmp_chain_from_pkimessage(pki_message, for_issued_cert=False)
        logging.info("Certificate chain length: %s", len(cert_chain))
        may_trusted_cert = cert_chain[-1]

        # Temporary fix to avoid errors for Composite signatures and PQ signatures.

        prot_type = ProtectedType.get_protection_type(pki_message)
        result = prot_type in [ProtectedType.COMPOSITE_SIG, ProtectedType.PQ_SIG]

        if result:
            logging.debug(
                "Skipping OpenSSL cert chain validation check for Composite or PQ signature."
                "Will be checked in the Future."
            )

        if self._prot_config.use_openssl and not result:
            try:
                certificates_must_be_trusted(
                    cert_chain=cert_chain,
                    # Must contain `digitalSignature` if present.
                    key_usage_strict=1,
                    key_usages="digitalSignature" if not for_dh else "keyAgreement",
                    crl_check=False,
                    trustanchors=self._prot_config.mock_ca_trusted_dir,
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
            certificates_are_trustanchors(may_trusted_cert, trustanchors=self._prot_config.mock_ca_trusted_dir)
