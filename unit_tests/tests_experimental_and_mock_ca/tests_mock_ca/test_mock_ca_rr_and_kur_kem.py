# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from typing import List

from pyasn1_alt_modules import rfc9480

from mock_ca.ca_handler import CAHandler
from mock_ca.mock_fun import CertStateEnum
from pq_logic.keys.abstract_wrapper_keys import KEMPrivateKey
from resources.asn1_structures import PKIMessageTMP
from resources.certutils import build_cmp_chain_from_pkimessage
from resources.cmputils import build_ir_from_key, get_pkistatusinfo, build_cert_conf, get_cmp_message_type, \
    patch_extra_certs, build_cmp_revoke_request, build_key_update_request
from resources.convertutils import ensure_is_kem_priv_key
from resources.extra_issuing_logic import get_enc_cert_from_pkimessage
from resources.general_msg_utils import build_cmp_general_message, \
    validate_genp_kem_ct_info
from resources.keyutils import generate_key
from resources.protectionutils import protect_pkimessage, prepare_kem_ciphertextinfo, protect_pkimessage_kem_based_mac
from unit_tests.utils_for_test import load_ca_cert_and_key


class TestMockCARRAndKURKEMHandling(unittest.TestCase):

    def setUp(self):
        self.ca_cert, self.ca_key = load_ca_cert_and_key()
        self.pre_shared_secret = b"SiemensIT"
        self.ca_handler = CAHandler(
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            pre_shared_secret=self.pre_shared_secret,
        )
        self.sender = "CN=Test KEM"
        self.tx_id = b"A" * 16

    def _build_cert_conf(self, response: PKIMessageTMP, key: KEMPrivateKey, ss: bytes) -> List[rfc9480.CMPCertificate]:
        """
        Build a certificate configuration from a CMP response.
        Returns the certificate and the KEM algorithm used.
        """
        cert = get_enc_cert_from_pkimessage(
            response,
            ee_private_key=key,
            exclude_rid_check=True,
            expected_recip_type="kemri",
        )
        cert_conf = build_cert_conf(
            cert=cert,
            hash_alg="sha512",
            transaction_id=response["header"]["transactionID"].asOctets(),
            recip_nonce=response["header"]["senderNonce"].asOctets(),
            recip_kid=response["header"]["senderKID"].asOctets(),
            sender=self.sender,
            recipient="CN=Mock CA",
            for_mac=True,
        )
        protected_cert_conf = protect_pkimessage_kem_based_mac(
            cert_conf,
            private_key=key,
            shared_secret=ss,
        )
        response = self.ca_handler.process_normal_request(
            protected_cert_conf,
        )
        self.assertEqual("pkiconf", get_cmp_message_type(response), response["body"].prettyPrint())
        cert_chain = build_cmp_chain_from_pkimessage(
            response,
            ee_cert=cert,
        )
        return cert_chain


    def _establish_kem_cert(self, key: KEMPrivateKey) -> List[rfc9480.CMPCertificate]:
        """Establish a KEM certificate for testing.

        :param key: The KEM private key to use for the certificate.
        :return: A list containing the established KEM certificate chain.
        """

        ir = build_ir_from_key(key,
                               pvno=3,
                               sender=self.sender,
                               recipient="CN=Mock CA",
                               common_name=self.sender,
                               for_mac=True)
        protected_ir = protect_pkimessage(
            ir,
            protection="pbmac1",
            password=self.pre_shared_secret,
        )
        response = self.ca_handler.process_normal_request(
            protected_ir,
        )
        status = get_pkistatusinfo(response)
        self.assertEqual(status["status"].prettyPrint(), "accepted")

        cert = get_enc_cert_from_pkimessage(
            response,
            ee_private_key=key,
            exclude_rid_check=True,
            expected_recip_type="kemri",
        )
        cert_conf = build_cert_conf(
            cert=cert,
            hash_alg="sha512",
            transaction_id=response["header"]["transactionID"].asOctets(),
            recip_nonce=response["header"]["senderNonce"].asOctets(),
            recip_kid=response["header"]["senderKID"].asOctets(),
            sender=self.sender,
            recipient="CN=Mock CA",
            for_mac=True,
        )
        protected_cert_conf = protect_pkimessage(
            cert_conf,
            protection="pbmac1",
            password=self.pre_shared_secret,
        )
        response = self.ca_handler.process_normal_request(
            protected_cert_conf,
        )
        self.assertEqual("pkiconf", get_cmp_message_type(response), response["body"].prettyPrint())
        cert_chain = build_cmp_chain_from_pkimessage(
            response,
            ee_cert=cert,
        )
        return cert_chain

    def _establish_ss(self, key: KEMPrivateKey,
                      cert_chain: List[rfc9480.CMPCertificate]) -> bytes:
        """Establish a shared secret for testing."""
        info_val = prepare_kem_ciphertextinfo(key=key,)
        genm = build_cmp_general_message(info_values=info_val,
                                         transaction_id=self.tx_id,
                                         sender=self.sender, recipient="CN=Mock CA")

        genm = patch_extra_certs(genm, cert_chain)

        genp = self.ca_handler.process_normal_request(
            genm
            )

        return validate_genp_kem_ct_info(
            genp,
            client_private_key=key,
        )

    def test_establish_kem_cert(self):
        """
        GIVEN a KEM private key.
        WHEN a KEM certificate is established.
        THEN the certificate is confirmed and the state is set to CONFIRMED.
        """
        ml_kem_key = generate_key("ml-kem-512")
        if not isinstance(ml_kem_key, KEMPrivateKey):
            raise TypeError("Expected a KEMPrivateKey instance.")
        cert_chain = self._establish_kem_cert(ml_kem_key)
        cert_state = self.ca_handler.state.certificate_db.get_cert_state(cert_chain[0])
        self.assertEqual(cert_state, CertStateEnum.CONFIRMED, "Certificate state should be CONFIRMED.")

    def test_rr_kem_handling(self):
        """
        GIVEN a KEM certificate and a KEM private key.
        WHEN a revocation request is processed.
        THEN the certificate is revoked.
        """
        ml_kem_key = generate_key("ml-kem-512")
        if not isinstance(ml_kem_key, KEMPrivateKey):
            raise TypeError("Expected a KEMPrivateKey instance.")
        cert_chain = self._establish_kem_cert(ml_kem_key)
        ss = self._establish_ss(ml_kem_key, cert_chain)
        rr = build_cmp_revoke_request(
            cert=cert_chain[0],
            reason="keyCompromise",
            transaction_id=self.tx_id,
            sender=self.sender,
            recipient="CN=Mock CA",
            for_mac=True,
            exclude_fields=None,
        )

        rr = patch_extra_certs(rr, cert_chain)

        protected_rr = protect_pkimessage_kem_based_mac(
            rr,
            private_key=ml_kem_key,
            shared_secret=ss,
        )
        response= self.ca_handler.process_normal_request(
            protected_rr,
        )
        self.assertEqual("rp", get_cmp_message_type(response), response["body"].prettyPrint())
        status = get_pkistatusinfo(response)
        self.assertEqual(status["status"].prettyPrint(), "accepted", status.prettyPrint())


    def test_kur_kem_response(self):
        """
        GIVEN a KEM certificate and a KEM private key.
        WHEN a key update request is processed.
        THEN the certificate is updated and the state is correctly set.
        """
        ml_kem_key = generate_key("ml-kem-512")
        if not isinstance(ml_kem_key, KEMPrivateKey):
            raise TypeError("Expected a KEMPrivateKey instance.")
        cert_chain = self._establish_kem_cert(ml_kem_key)
        ss = self._establish_ss(ml_kem_key, cert_chain)
        old_cert = cert_chain[0]

        new_key = generate_key("ml-kem-512")

        kur = build_key_update_request(
            new_key,
            pvno=3,
            transaction_id=self.tx_id,
            sender=self.sender,
            common_name=self.sender,
            recipient="CN=Mock CA",
            for_mac=True,
            exclude_fields=None,
            implicit_confirm=True,
        )
        kur = patch_extra_certs(kur, cert_chain)
        protected_kur = protect_pkimessage_kem_based_mac(
            kur,
            private_key=ml_kem_key,
            shared_secret=ss,
        )
        response = self.ca_handler.process_normal_request(protected_kur)
        self.assertEqual("kup", get_cmp_message_type(response), response["body"].prettyPrint())
        status = get_pkistatusinfo(response)
        self.assertEqual(status["status"].prettyPrint(), "accepted", status.prettyPrint())
        cert_db = self.ca_handler.state.certificate_db
        cert_state = cert_db.get_cert_state(cert_chain[0])
        self.assertEqual(cert_state, CertStateEnum.UPDATED_BUT_NOT_CONFIRMED, "Certificate state should be CONFIRMED.")

        # Build the certificate confirmation.
        new_key = ensure_is_kem_priv_key(new_key)
        cert_chain = self._build_cert_conf(response, new_key, ss)
        cert_db = self.ca_handler.state.certificate_db
        cert_state = cert_db.get_cert_state(cert_chain[0])
        old_cert_state = cert_db.get_cert_state(old_cert)
        self.assertEqual(old_cert_state, CertStateEnum.UPDATED, "Old certificate state should not be CONFIRMED.")
        self.assertEqual(cert_state, CertStateEnum.CONFIRMED, "Certificate state should be CONFIRMED after KUR.")
