# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Contains the CA Handler for the Mock CA."""

import logging
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import ocsp

# needs to be here to import the correct modules
# so that this file can be run from the root directory with:
# python ./mock_ca/ca_handler.py
sys.path.append(".")
from cryptography import x509
from flask import Flask, Response, request
from pyasn1.codec.der import encoder
from pyasn1_alt_modules import rfc9480

from mock_ca.cert_conf_handler import CertConfHandler
from mock_ca.cert_req_handler import CertReqHandler
from mock_ca.challenge_handler import ChallengeHandler
from mock_ca.general_msg_handler import GeneralMessageHandler
from mock_ca.hybrid_handler import HybridIssuingHandler
from mock_ca.mock_fun import CertRevStateDB, KEMSharedSecretList, RevokedEntry
from mock_ca.nested_handler import NestedHandler
from mock_ca.nestedutils import validate_orig_pkimessage
from mock_ca.operation_dbs import MockCAOPCertsAndKeys
from mock_ca.prot_handler import ProtectionHandler
from mock_ca.rev_handler import RevocationHandler
from pq_logic.hybrid_issuing import (
    build_catalyst_signed_cert_from_req,
    build_cert_discovery_cert_from_p10cr,
    build_cert_from_catalyst_request,
    build_chameleon_from_p10cr,
    build_related_cert_from_csr,
    build_sun_hybrid_cert_from_request,
)
from pq_logic.hybrid_sig import sun_lamps_hybrid_scheme_00
from pq_logic.hybrid_sig.sun_lamps_hybrid_scheme_00 import extract_sun_hybrid_alt_sig, sun_cert_template_to_cert
from pq_logic.keys.abstract_pq import PQSignaturePrivateKey
from pq_logic.keys.abstract_wrapper_keys import HybridKEMPrivateKey, HybridPublicKey
from pq_logic.keys.composite_sig03 import CompositeSig03PrivateKey
from pq_logic.keys.composite_sig04 import CompositeSig04PrivateKey
from pq_logic.pq_verify_logic import verify_hybrid_pkimessage_protection
from pq_logic.tmp_oids import id_it_KemCiphertextInfo
from resources.asn1_structures import PKIMessageTMP
from resources.ca_ra_utils import (
    build_cp_cmp_message,
    build_ip_cmp_message,
    get_popo_from_pkimessage,
)
from resources.certbuildutils import (
    build_certificate,
    prepare_authority_key_identifier_extension,
    prepare_cert_template,
    prepare_crl_distribution_point_extension,
    prepare_ocsp_extension,
)
from resources.certutils import load_public_key_from_cert, parse_certificate
from resources.checkutils import (
    check_is_protection_present,
)
from resources.cmputils import (
    build_cmp_error_message,
    find_oid_in_general_info,
    get_cert_response_from_pkimessage,
    get_cmp_message_type,
    parse_pkimessage,
)
from resources.compareutils import compare_pyasn1_names
from resources.convertutils import ensure_is_sign_key, ensure_is_verify_key
from resources.exceptions import (
    BadAlg,
    BadAsn1Data,
    BadCertId,
    BadCertTemplate,
    BadConfig,
    BadMessageCheck,
    BadRequest,
    CertRevoked,
    CMPTestSuiteError,
    InvalidAltSignature,
    NotAuthorized,
    TransactionIdInUse,
)
from resources.general_msg_utils import build_genp_kem_ct_info_from_genm
from resources.keyutils import generate_key, load_private_key_from_file
from resources.oid_mapping import compute_hash, may_return_oid_to_name
from resources.oidutils import MSG_SIG_ALG, SUPPORTED_MAC_OID_2_NAME, id_KemBasedMac
from resources.protectionutils import (
    get_protection_type_from_pkimessage,
    protect_hybrid_pkimessage,
    protect_pkimessage,
    verify_pkimessage_protection,
)
from resources.typingutils import ECDHPrivateKey, EnvDataPrivateKey, PublicKey, SignKey
from resources.utils import load_and_decode_pem_file
from unit_tests.utils_for_test import load_ca_cert_and_key, load_env_data_certs


@dataclass
class SunHybridState:
    """A simple class to store the state of the SunHybridHandler."""

    sun_hybrid_certs: Dict[int, rfc9480.CMPCertificate] = field(default_factory=dict)
    sun_hybrid_pub_keys: Dict[int, PublicKey] = field(default_factory=dict)
    sun_hybrid_signatures: Dict[int, bytes] = field(default_factory=dict)


@dataclass
class MockCAState:
    """A simple class to store the state of the MockCAHandler.

    Attributes:
        currently_used_ids: The currently used IDs.
        issued_certs: The issued certificates.
        kem_mac_based: The KEM-MAC-based shared secrets.
        to_be_confirmed_certs: The certificates to be confirmed.
        challenge_rand_int: The challenge random integers.
        sun_hybrid_state: The state of the Sun Hybrid handler.

    """

    cert_state_db: CertRevStateDB = field(default_factory=CertRevStateDB)
    currently_used_ids: Set[bytes] = field(default_factory=set)
    issued_certs: List[rfc9480.CMPCertificate] = field(default_factory=list)
    # stores the transaction id mapped to the shared secret.
    kem_mac_based: KEMSharedSecretList = field(default_factory=KEMSharedSecretList)
    # stores the (txid, sender_raw) mapped to the certificate.
    to_be_confirmed_certs: Dict[Tuple[bytes, bytes], List[rfc9480.CMPCertificate]] = field(default_factory=dict)
    challenge_rand_int: Dict[bytes, int] = field(default_factory=dict)
    sun_hybrid_state: SunHybridState = field(default_factory=SunHybridState)

    def _compare_pub_keys(self, pub_key: PublicKey, cert: rfc9480.CMPCertificate) -> bool:
        """Compare the public key with the certificate.

        :param pub_key: The public key to compare.
        :param cert: The certificate to compare with.
        :return: `True` if the public key matches the certificate, otherwise `False`.
        """
        loaded_pub_key = load_public_key_from_cert(cert)
        if isinstance(pub_key, HybridPublicKey):
            if not isinstance(loaded_pub_key, HybridPublicKey):
                return pub_key.trad_key == loaded_pub_key or pub_key.pq_key == loaded_pub_key

            if pub_key == loaded_pub_key:
                return True

            if pub_key.trad_key == loaded_pub_key.trad_key:
                return True
            if pub_key.pq_key == loaded_pub_key.pq_key:
                return True

            if pub_key.pq_key == loaded_pub_key.trad_key:
                return True

            return False

        if isinstance(loaded_pub_key, HybridPublicKey):
            if pub_key == loaded_pub_key.trad_key:
                return True
            if pub_key == loaded_pub_key.pq_key:
                return True
            return False

        return pub_key == loaded_pub_key

    def contains_pub_key(self, pub_key: PublicKey, sender: rfc9480.Name) -> bool:
        """Check if the public key is already in use.

        :param pub_key: The public key to check.
        :param sender: The sender of the request.
        :return: `True` if the public key is already in use, otherwise `False`.
        """
        for cert in self.issued_certs:
            if self._compare_pub_keys(pub_key, cert):
                return compare_pyasn1_names(sender, cert["tbsCertificate"]["subject"], "without_tag")

        return False

    def add_tx_id(self, tx_id: bytes) -> None:
        """Store the transaction ID.

        :param tx_id: The transaction ID to store.
        """
        if tx_id in self.currently_used_ids:
            raise TransactionIdInUse(f"Transaction ID {tx_id.hex()} already exists.")
        self.currently_used_ids.add(tx_id)

    def remove_tx_id(self, tx_id: bytes) -> None:
        """Remove the transaction ID.

        :param tx_id: The transaction ID to remove.
        """
        self.currently_used_ids.remove(tx_id)

    @property
    def len_issued_certs(self) -> int:
        """Get the number of issued certificates."""
        return len(self.issued_certs)

    @property
    def len_to_be_confirmed_certs(self) -> int:
        """Get the number of certificates to be confirmed."""
        return len(self.to_be_confirmed_certs)

    def store_transaction_certificate(self, pki_message, certs: List[rfc9480.CMPCertificate]) -> None:
        """Store a transaction certificate.

        :param pki_message: The PKIMessage request.
        :param certs: A list of certificates to store.
        :raises TransactionIdInUse: If the transaction ID is already in use.
        """
        transaction_id = pki_message["header"]["transactionID"].asOctets()
        sender = pki_message["header"]["sender"]

        if transaction_id in self.currently_used_ids:
            raise TransactionIdInUse(f"Transaction ID {transaction_id.hex()} already exists for sender {sender}")

        der_sender = encoder.encode(sender)
        self.to_be_confirmed_certs[(transaction_id, der_sender)] = certs
        self.currently_used_ids.add(transaction_id)

    def add_kem_mac_shared_secret(self, pki_message: PKIMessageTMP, shared_secret: bytes) -> None:
        """Add the shared secret for the KEM-MAC-based protection.

        :param pki_message: The PKIMessage request.
        :param shared_secret: The shared secret.
        """
        self.kem_mac_based.add_shared_secret(request=pki_message, ss=shared_secret)

    def get_kem_mac_shared_secret(self, pki_message: PKIMessageTMP) -> Optional[bytes]:
        """Retrieve the shared secret for the KEM-MAC-based protection.

        :param pki_message: The PKI message containing the request.
        :return: The shared secret.
        """
        return self.kem_mac_based.get_shared_secret(request=pki_message)

    def get_issued_certs(self, pki_message: PKIMessageTMP) -> List[rfc9480.CMPCertificate]:
        """Retrieve the issued certificates.

        :param pki_message: The PKI message containing the request.
        :return: The issued certificates.
        """
        transaction_id = pki_message["header"]["transactionID"].asOctets()
        der_sender = encoder.encode(pki_message["header"]["sender"])
        return self.to_be_confirmed_certs[(transaction_id, der_sender)]

    def get_cert_by_serial_number(self, serial_number: int) -> rfc9480.CMPCertificate:
        """Get the Sun-Hybrid certificate for the specified serial number.

        :param serial_number: The serial number of the certificate.
        :return: The certificate.
        :raises BadRequest: If the certificate could not be found.
        """
        for cert in self.issued_certs:
            if serial_number == int(cert["tbsCertificate"]["serialNumber"]):
                return cert

        raise BadCertId(f"Could not find certificate with serial number {serial_number}")

    def add_certs(self, certs: List[rfc9480.CMPCertificate]) -> None:
        """Add the issued certificates to the state.

        :param certs: The certificates to add.
        """
        self.issued_certs.extend(certs)

    def check_request_for_compromised_key(self, request: PKIMessageTMP) -> bool:
        """Check the request for a compromised key."""
        return self.cert_state_db.check_request_for_compromised_key(request)

    def add_updated_cert(self, cert: rfc9480.CMPCertificate):
        """Add an updated certificate to the state."""
        hashed_cert = compute_hash("sha1", encoder.encode(cert))
        self.cert_state_db.add_update_entry(RevokedEntry("updated", cert, hashed_cert))

    def is_updated(self, cert: rfc9480.CMPCertificate) -> bool:
        """Check if a certificate is updated based on its serial number."""
        hashed_cert = compute_hash("sha1", encoder.encode(cert))
        return self.cert_state_db.is_updated_by_hash(hashed_cert)


def _build_error_from_exception(e: CMPTestSuiteError, request: Optional[PKIMessageTMP] = None) -> PKIMessageTMP:
    """Build an error response from an exception.

    :param e: The exception.
    :return: The error response, as raw bytes.
    """
    msg = build_cmp_error_message(failinfo=e.failinfo, texts=e.message, status="rejection", error_texts=e.error_details)
    return msg


def _is_encrypted_cert(pki_message: PKIMessageTMP) -> bool:
    """Check if the certificate is encrypted.

    :param pki_message: The PKIMessage.
    :return: `True` if the certificate is encrypted, otherwise `False`.
    """
    rep = get_cert_response_from_pkimessage(pki_message, response_index=0)

    # Otherwise, deletes the entries.
    if not rep["certifiedKeyPair"].isValue:
        return False

    if not rep["certifiedKeyPair"]["certOrEncCert"].isValue:
        return False

    return rep["certifiedKeyPair"]["certOrEncCert"]["encryptedCert"].isValue


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


@dataclass
class VerifyState:
    """A simple class to store the verification state.

    Attributes:
        allow_only_authorized_certs: If only authorized certificates are allowed. Defaults to `False`.
        use_openssl: If OpenSSL should be used for verification. Defaults to `False`.
        algorithms: The algorithms to use. Defaults to "ecc+,rsa, pq, hybrid".
        curves: The curves to use. Defaults to "all".
        hash_alg: The hash algorithm to use. Defaults to "all".

    """

    allow_only_authorized_certs: bool = False
    use_openssl: bool = False
    algorithms: str = "ecc+,rsa, pq, hybrid"
    curves: str = "all"
    hash_alg: str = "all"


class CAHandler:
    """A simple class to handle the CA operations."""

    def _prepare_extensions(
        self,
        ca_cert: rfc9480.CMPCertificate,
        base_url: str = "http://localhost:5000",
        cfg_extensions: Optional[Sequence[rfc5280.Extension]] = None,
    ) -> rfc9480.Extensions:
        """Prepare the extensions for the CA.

        Prepares the authority key identifier, OCSP, and CRL distribution point extensions.

        :param base_url: The base URL for the CA, so that the OCSP and CRL URLs can be generated.
        :param ca_cert: The CA issuer certificate.
        :param cfg_extensions: Additional extensions to add.
        :return: The list of extensions.
        """
        ca_pub_key = load_public_key_from_cert(ca_cert)

        if not isinstance(ca_pub_key, VerifyKey):
            raise BadConfig(f"The CA public key is not a `VerifyKey`. Got: {type(ca_pub_key)}")

        aki_extn = prepare_authority_key_identifier_extension(ca_pub_key, critical=False)
        crl_url = f"{base_url}/crl"
        self.ocsp_extn = prepare_ocsp_extension(ocsp_url=f"{base_url}/ocsp")
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
        state: Optional[MockCAState] = None,
        port: int = 5000,
        allow_only_authorized_certs: bool = True,
        use_openssl: bool = False,
        base_url: str = "http://127.0.0.1",
    ):
        """Initialize the CA Handler.

        :param config: The configuration for the CA Handler.
        """
        if ca_cert is None and ca_key is None:
            ca_cert, ca_key = load_ca_cert_and_key()

        if ca_cert is None or ca_key is None:
            raise BadConfig("CA certificate and key must be provided.")

        self.base_url = f"{base_url}:{port}"

        config = config or {"ca_alt_key": ca_alt_key}

        for key, item in load_env_data_certs().items():
            if key not in config:
                config[key] = item

        config["ca_cert"] = ca_cert
        config["ca_key"] = ca_key
        self.ca_cert = ca_cert
        self.ca_key = ca_key
        self.operation_state = MockCAOPCertsAndKeys(**config)

        self.config = config

        self.extensions = self._prepare_extensions(self.ca_cert, self.base_url, config.get("extensions"))

        self.comp_key = generate_key("composite-sig")
        self.comp_cert = build_certificate(private_key=self.comp_key, is_ca=True, common_name="CN=Test CA")[0]
        self.sun_hybrid_key = generate_key("composite-sig")  # type: ignore
        self.sun_hybrid_key: CompositeSig04PrivateKey
        cert_template = prepare_cert_template(
            self.sun_hybrid_key,
            subject="CN=Hans the Tester",
        )
        self.sun_hybrid_cert, cert1 = sun_cert_template_to_cert(
            cert_template=cert_template,
            ca_cert=ca_cert,
            ca_key=self.sun_hybrid_key.trad_key,  # type: ignore
            alt_private_key=self.sun_hybrid_key.pq_key,  # type: ignore
            pub_key_loc=f"{self.base_url}/pubkey/1",
            sig_loc=f"{self.base_url}/sig/1",
            serial_number=1,
            extensions=[self.ocsp_extn, self.crl_extn],
        )

        self.sender = "CN=Mock CA"

        self.ca_alt_key = ca_alt_key
        self.state = state or MockCAState()
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
            self.xwing_key = load_private_key_from_file("data/keys/private-key-xwing.pem")

        if self.xwing_key is not None:
            if not isinstance(self.xwing_key, HybridKEMPrivateKey):
                raise BadConfig(
                    f"The hybrid kem private key is not a `HybridKEMPrivateKey`.Got: {type(self.xwing_key)}"
                )

        # Handler classes
        self.rev_handler = RevocationHandler(self.state.cert_state_db)
        self.cert_conf_handler = CertConfHandler(self.state)

        extensions = self.extensions

        self.verify_state = VerifyState(
            allow_only_authorized_certs=allow_only_authorized_certs,
            use_openssl=use_openssl,
        )

        kga_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        kga_cert = parse_certificate(load_and_decode_pem_file("data/unittest/ra_kga_cert_ecdsa.pem"))

        self.kga_cert_chain = [kga_cert, ca_cert]
        self.kga_cert = kga_cert
        self.kga_key = ensure_is_sign_key(kga_key)

        self.protection_handler = ProtectionHandler(
            cmp_protection_cert=self.ca_cert,
            cmp_prot_key=self.ca_key,
            kem_ss_list=self.state.kem_mac_based,
            pre_shared_secret=self.pre_shared_secret,
            use_openssl=True,
            def_mac_alg="password_based_mac",
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
        )

        self.nested_handler = NestedHandler(ca_handler=self, extensions=extensions)
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
            crl_url=self.base_url + "/crl",
        )

        self.hybrid_handler = HybridIssuingHandler(
            ca_cert=ca_cert,
            ca_key=ca_key,
            revocation_handler=self.rev_handler,
            cmp_protection_cert=self.protection_handler.protection_cert,
            sender=self.sender,
            extensions=extensions,
        )

    def verify_protection(self, request: PKIMessageTMP, must_be_protected: bool = True) -> None:
        """Verify the protection of the request."""
        if request["header"]["protectionAlg"].isValue:
            oid = request["header"]["protectionAlg"]["algorithm"]
            if oid not in MSG_SIG_ALG and oid not in SUPPORTED_MAC_OID_2_NAME:
                _name = may_return_oid_to_name(oid)
                raise BadAlg(f"The parsed protection algorithm is not supported Got: {str(_name)}")

        if not check_is_protection_present(request, must_be_protected=must_be_protected):
            return

        if not request["protection"].isValue:
            raise BadMessageCheck("Protection not provided for request.")

        if not request["header"]["protectionAlg"].isValue:
            raise BadMessageCheck("Protection algorithm not provided for request.")

        if request["header"]["protectionAlg"]["algorithm"] == id_KemBasedMac:
            logging.debug("KEM-based MAC protection is present.")
            self.state.kem_mac_based.verify_pkimessage_protection(request=request)
            return

        if request["header"]["protectionAlg"]["algorithm"] == rfc9480.id_DHBasedMac:
            self.protection_handler.verify_dh_based_mac_protection(
                pki_message=request,
            )
            return

        prot_type = get_protection_type_from_pkimessage(request)
        try:
            if prot_type == "mac":
                verify_pkimessage_protection(pki_message=request, password=self.pre_shared_secret)
            else:
                verify_hybrid_pkimessage_protection(pki_message=request)
        except (InvalidSignature, InvalidAltSignature, ValueError):
            raise BadMessageCheck(message="Invalid signature protection.")

    def _sign_nested_response(self, response: PKIMessageTMP, request_msg: PKIMessageTMP) -> PKIMessageTMP:
        """Sign the nested response."""
        if response["body"].getName() != "nested":
            if request_msg["header"]["protectionAlg"].isValue:
                prot_type = get_protection_type_from_pkimessage(request_msg)
                if prot_type == "mac":
                    prot_type = self.protection_handler.get_same_mac_protection(
                        request_msg["header"]["protectionAlg"],
                    )
                    return protect_pkimessage(
                        pki_message=response,
                        password=self.pre_shared_secret,
                        protection=prot_type,
                    )
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
        if response["body"].getName() == "genp":
            # quick fix for KEMBasedMAC.
            return response

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

        prot_type = get_protection_type_from_pkimessage(pki_message)
        if prot_type == "mac":
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
            logging.info(f"An error occurred: {str(e.message)}")
            return _build_error_from_exception(e)
        return self.sign_response(response=response, request_msg=pki_message)

    def process_normal_request(self, pki_message: PKIMessageTMP) -> PKIMessageTMP:
        """Process the normal request.

        :return: The PKI message containing the response.
        """
        logging.debug("Processing request with body: %s", pki_message["body"].getName())
        try:
            # self._check_is_not_confirmed(pki_message)

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
                    if cert is None:
                        raise BadConfig("The ECC certificate could not be found, to prepare the challenge response.")
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
                self.protection_handler.validate_protection(pki_message=pki_message)
                response = self.cert_req_handler.process_cert_request(pki_message)
            elif pki_message["body"].getName() == "rr":
                response = self.process_rr(pki_message)
            elif pki_message["body"].getName() == "certConf":
                response = self.process_cert_conf(pki_message)
            elif pki_message["body"].getName() == "genm":
                response = self.process_genm(pki_message)
                response = self.sign_response(response=response, request_msg=pki_message)
                return self.genm_handler.patch_genp_message_for_extra_certs(pki_message=response)

            else:
                raise NotImplementedError(
                    f"Method not implemented, to handle the provided message: {pki_message['body'].getName()}."
                )
        except CMPTestSuiteError as e:
            logging.info(f"An error occurred: {str(e.message)}")
            return _build_error_from_exception(e)

        except (InvalidSignature, InvalidAltSignature):
            e = BadMessageCheck(message="Invalid signature protection.")
            return _build_error_from_exception(e)

        except Exception as e:
            logging.info(f"An error occurred while processing the request: {str(e)}")
            logging.exception("An error occurred")
            logging.warning("An error occurred", exc_info=True)
            app.logger.error(e, exc_info=True)
            return _build_error_from_exception(
                CMPTestSuiteError(
                    f"An error occurred while processing the request: {type(e)} {str(e)}", failinfo="systemFailure"
                )
            )
        self.state.kem_mac_based.may_update_state(request=pki_message)
        return self.sign_response(response=response, request_msg=pki_message)

    def process_genm(self, pki_message: PKIMessageTMP) -> PKIMessageTMP:
        """Process the GenM message.

        :param pki_message: The GenM message.
        :return: The PKI message containing the response.
        """
        if len(pki_message["body"]["genm"]) == 0:
            raise BadRequest("The general message does not contain any messages.")

        if pki_message["body"]["genm"][0]["infoType"] == id_it_KemCiphertextInfo:
            ss, genp = build_genp_kem_ct_info_from_genm(
                genm=pki_message,  # type: ignore
            )
            self.state.add_kem_mac_shared_secret(pki_message=pki_message, shared_secret=ss)
            return genp  # type: ignore
        else:
            return self.genm_handler.process_general_msg(pki_message)

    def process_nested_request(self, request: PKIMessageTMP) -> PKIMessageTMP:
        """Process the nested request.

        :param request: The nested request.
        :return: The PKI message containing the response.
        """
        return self.nested_handler.process_nested_request(request)

    def process_rr(self, pki_message: PKIMessageTMP) -> PKIMessageTMP:
        """Process the RR message.

        :param pki_message: The RR message.
        :return: The PKI message containing the response.
        """
        response, certs_to_revive = self.rev_handler.process_revocation_request(
            pki_message=pki_message,
            issued_certs=self.state.issued_certs,
            shared_secret=self.state.get_kem_mac_shared_secret(pki_message=pki_message),
        )

        if certs_to_revive:
            self.state.add_certs(certs=certs_to_revive)
        return response

    def process_cert_conf(self, pki_message: PKIMessageTMP) -> PKIMessageTMP:
        """Process the CertConf message.

        :param pki_message: The CertConf message.
        :return: The PKIMessage containing the response.
        """
        return self.cert_conf_handler.process_cert_conf(pki_message)

    def _check_for_compromised_key(self, pki_message: PKIMessageTMP) -> None:
        """Check the request for a compromised key.

        :param pki_message: The PKIMessage request.
        :raises BadCertTemplate: If the certificate template is invalid.
        """
        result = self.state.cert_state_db.check_request_for_compromised_key(pki_message)
        if result:
            raise BadCertTemplate("The certificate template contained a compromised key.")

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
                if pki_message["extraCerts"].isValue:
                    self.hybrid_handler.is_revoked(request=pki_message, used_both_certs=False)

                self.hybrid_handler.chameleon_handler.is_delta_key_revoked(request=pki_message)

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
                return self.sign_response(
                    response=response,
                    request_msg=pki_message,
                    secondary_cert=delta_cert,
                )
            except CMPTestSuiteError as e:
                logging.info(f"An error occurred: {str(e.message)}")
                return _build_error_from_exception(e)
            except Exception as e:
                logging.info(f"An error occurred: {str(e)}")
                return _build_error_from_exception(
                    CMPTestSuiteError(
                        f"An error occurred while processing the request: {type(e)} {str(e)}",
                        failinfo="systemFailure",
                    )
                )

        raise NotImplementedError(
            f"Not implemented to handle a chameleon request with body: {pki_message['body'].getName()}"
        )

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
        if pki_message["body"].getName() == "certConf":
            return self.process_cert_conf(pki_message)

        serial_number = None
        for _ in range(100):
            serial_number = x509.random_serial_number()
            if serial_number not in self.state.sun_hybrid_state.sun_hybrid_certs:
                break

        if serial_number is None:
            raise Exception("Could not generate a unique serial number.")

        if not isinstance(self.sun_hybrid_key, CompositeSig03PrivateKey):
            raise Exception("The Sun-Hybrid CA key is not a CompositeSig03PrivateKey.")

        response, cert4, cert1 = build_sun_hybrid_cert_from_request(
            request=pki_message,
            ca_key=self.sun_hybrid_key,
            serial_number=serial_number,  # type: ignore
            ca_cert=self.ca_cert,
            pub_key_loc=f"http://localhost:5000/pubkey/{serial_number}",
            sig_loc=f"http://localhost:5000/sig/{serial_number}",
            extensions=[self.ocsp_extn, self.crl_extn],
            bad_alt_sig=bad_alt_sig,
        )

        result = True  # _is_encrypted_cert(response)
        if not result:
            self.state.store_transaction_certificate(
                pki_message=pki_message,
                certs=[cert4],
            )
            return self.sign_response(response=response, request_msg=pki_message)
        else:
            public_key = sun_lamps_hybrid_scheme_00.get_sun_hybrid_alt_pub_key(cert1["tbsCertificate"]["extensions"])
            alt_sig = extract_sun_hybrid_alt_sig(cert1)
            if public_key is None:
                raise Exception("The Sun-hybrid public key could not be extracted from the certificate.")
            self.state.sun_hybrid_state.sun_hybrid_certs[serial_number] = cert4
            self.state.sun_hybrid_state.sun_hybrid_pub_keys[serial_number] = public_key
            self.state.sun_hybrid_state.sun_hybrid_signatures[serial_number] = alt_sig

            self.state.add_certs(certs=[cert4])

        return self.sign_response(
            response=response,
            request_msg=pki_message,
            secondary_cert=cert1,
        )

    def process_multi_auth(self, pki_message: PKIMessageTMP) -> PKIMessageTMP:
        """Process the Multi-Auth message.

        :param pki_message: The PKIMessage which is hybrid protected.
        :return:
        """
        try:
            self.hybrid_handler.is_revoked(request=pki_message, used_both_certs=True)
        except CMPTestSuiteError as e:
            logging.info(f"An error occurred: {str(e.message)}")
            return _build_error_from_exception(e, request=pki_message)

        verify_hybrid_pkimessage_protection(
            pki_message=pki_message,
        )
        return self.process_normal_request(pki_message)

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
            url=f"http://127.0.0.1:5000/cert/{serial_number}",
            load_chain=False,
            extensions=[self.ocsp_extn, self.crl_extn],
        )

        self.cert_req_handler.process_after_request(
            request=pki_message,
            response=response,
            certs=[cert],
        )
        return self.sign_response(response=response, request_msg=pki_message)

    def process_related_cert(self, pki_message: PKIMessageTMP) -> PKIMessageTMP:
        """Process the Related Cert request message.

        :param pki_message: The Related Cert message.
        :return: The PKI message containing the response.
        """
        if pki_message["body"].getName() != "p10cr":
            raise NotImplementedError("Only support p10cr for related cert requests.")

        cert = build_related_cert_from_csr(
            csr=pki_message["body"]["p10cr"],
            request=pki_message,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
        )

        response, _ = build_cp_cmp_message(
            cert=cert,
            request=pki_message,
            cert_req_id=-1,
        )

        return self.sign_response(response=response, request_msg=pki_message)

    def process_catalyst_sig(self, pki_message: PKIMessageTMP) -> PKIMessageTMP:
        """Process the Catalyst Sig request message.

        :param pki_message: The Catalyst Sig message.
        :return: The PKI message containing the response.
        """
        pki_message, certs = build_catalyst_signed_cert_from_req(
            request=pki_message,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            extensions=[self.ocsp_extn, self.crl_extn],
        )
        return self.sign_response(response=pki_message, request_msg=pki_message)

    def process_catalyst_issuing(self, pki_message: PKIMessageTMP) -> PKIMessageTMP:
        """Process the Catalyst request message.

        :param pki_message: The Catalyst message.
        :return: The PKI message containing the response.
        """
        pki_message, cert = build_cert_from_catalyst_request(
            request=pki_message,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            extensions=[self.ocsp_extn, self.crl_extn],
        )
        return self.sign_response(response=pki_message, request_msg=pki_message)

    def process_ocsp_request(self, data: bytes) -> bytes:
        """Process the OCSP request and return the response."""
        ocsp_request = ocsp.load_der_ocsp_request(data)

        response = self.state.cert_state_db.get_ocsp_response(
            request=ocsp_request,
            ca_cert=self.ca_cert,
            sign_key=self.ca_key,
            issued_certs=self.state.issued_certs,
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
        data = {}
        data.update(self.rev_handler.details())
        data["kem_ss"] = self.state.kem_mac_based

        if options is None:
            return data
        else:
            out = {key: data[key] for key in options.split(",") if key in data}
            if out:
                return out

        return "Supported keys are: " + ", ".join(data.keys())


app = Flask(__name__)
state = MockCAState()

ca_cert, ca_key = load_ca_cert_and_key()

handler = CAHandler(ca_cert=ca_cert, ca_key=ca_key, config={}, state=state)


def _build_response(pki_message: PKIMessageTMP, status: int = 200) -> Response:
    """Build a response from a PKIMessage.

    :param pki_message: The PKIMessage to encode.
    :return: The response.
    """
    response_data = encoder.encode(pki_message)
    return Response(response_data, content_type="application/octet-stream", status=status)


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
    return _build_response(cert)  # type: ignore


@app.route("/pubkey/<serial_number>", methods=["GET"])
def get_pubkey(serial_number):
    """Get the Sun-Hybrid public key for the specified serial number."""
    serial_number = int(serial_number)
    print(state.sun_hybrid_state.sun_hybrid_pub_keys.keys())
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
        pki_message = _build_error_from_exception(e)
        return _build_response(pki_message, status=400)

    try:
        # Access the raw data from the request body
        response = handler.process_normal_request(pki_message)
        return _build_response(response)
    except Exception as e:
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
def handle_catalyst():
    """Handle the catalyst request.

    :return: The DER-encoded response.
    """
    data = request.get_data()
    pki_message = parse_pkimessage(data)
    pki_message = handler.process_catalyst_issuing(pki_message)
    return _build_response(pki_message)


if __name__ == "__main__":
    app.run(port=5000, debug=True)
