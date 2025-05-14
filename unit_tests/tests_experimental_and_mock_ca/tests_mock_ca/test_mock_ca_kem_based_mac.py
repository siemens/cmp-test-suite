# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
import os
import unittest
from typing import Dict

from mock_ca.ca_handler import CAHandler
from mock_ca.db_config_vars import CertConfConfigVars
from mock_ca.mock_fun import KEMSharedSharedState, KEMSharedSecretList

from pq_logic.keys.abstract_wrapper_keys import KEMPrivateKey
from resources.asn1_structures import PKIMessageTMP
from resources.asn1utils import is_bit_set
from resources.certbuildutils import build_certificate
from resources.cmputils import build_ir_from_key, get_cmp_message_type, get_pkistatusinfo, patch_extra_certs, \
    build_cert_conf_from_resp
from resources.general_msg_utils import build_cmp_general_message, validate_genp_kem_ct_info
from resources.keyutils import generate_key
from resources.oidutils import id_KemBasedMac
from resources.protectionutils import protect_pkimessage_kem_based_mac
from resources.utils import display_pki_status_info
from unit_tests.utils_for_test import load_ca_cert_and_key


class TestCMPKEMBasedMAC(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_cert, cls.ca_key = load_ca_cert_and_key()
        cls.mock_ca_obj = CAHandler(
            ca_cert=cls.ca_cert,
            ca_key=cls.ca_key,
        )

        kem_cert, kem_key = build_certificate(
            ca_cert=cls.ca_cert,
            ca_key=cls.ca_key,
            subject="CN=KEM Test",
            private_key="ml-kem-768",
        )

        cls.kem_cert = kem_cert
        cls.kem_key: KEMPrivateKey = kem_key  # type: ignore
        cls.kem_key: KEMPrivateKey

    def _build_genm_request(self, tx_id: bytes) -> PKIMessageTMP:
        """Build a general message request."""

        genm = build_cmp_general_message(
            add_messages="kem_ct_info",
            sender="CN=Hans the Tester",
            recipient="CN=Mock CA",
            transaction_id=tx_id,
        )
        genm = patch_extra_certs(
            genm,
            certs=[self.kem_cert],
        )
        return genm

    @staticmethod
    def _build_ir_request(tx_id: bytes,
                          ss: bytes,
                          bad_message_check: bool = False,
                          implicit_confirm: bool = True,
                          ) -> PKIMessageTMP:
        """Build an IR request."""
        key = generate_key("rsa")
        ir = build_ir_from_key(
            key,
            sender="CN=Hans the Tester",
            recipient="CN=Mock CA",
            transaction_id=tx_id,
            for_mac=True,
            implicit_confirm=implicit_confirm,
        )

        protected_ir = protect_pkimessage_kem_based_mac(
            ir,
            shared_secret=ss,
            bad_message_check=bad_message_check,
        )

        return protected_ir

    def test_kem_ss_exchange(self):
        """
        GIVEN a General Message with a KEM certificate
        WHEN the general response message is processed by the CA,
        THEN is a valid ciphertext returned.
        """
        mock_ca_obj = CAHandler(
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
        )

        tx_id = b"A" * 16
        genm = self._build_genm_request(tx_id)
        genp = mock_ca_obj.process_normal_request(genm)
        shared_secret = validate_genp_kem_ct_info(
            genp,
            client_private_key=self.kem_key,
        )
        data = mock_ca_obj.get_details("kem_ss")["kem_ss"]
        data: KEMSharedSecretList
        self.assertEqual(len(data), 1, "Shared secret exchange failed")
        self.assertEqual(
            data[0].transaction_id,
            tx_id,
            "Transaction ID mismatch",
        )
        self.assertEqual(
            data[0].shared_secret,
            shared_secret,
            "Shared secret mismatch",
        )
        self.assertEqual(
            data[0].was_used_for_issuing,
            False,
            "The shared secret should not be used for issuing yet",
        )

    def test_kem_based_mac_protection(self):
        """
        GIVEN a General Message with a KEM certificate and established shared secret.
        WHEN a new IR request is created with the shared secret,
        THEN is a new PKIMessage with KEMBasedMAC protection returned.
        """
        tx_id = b"C" * 16
        genm = self._build_genm_request(tx_id)

        genp = self.mock_ca_obj.process_normal_request(genm)

        shared_secret = validate_genp_kem_ct_info(
            genp,
            client_private_key=self.kem_key,
        )

        protected_ir = self._build_ir_request(
            tx_id=tx_id,
            ss=shared_secret,
        )

        self.assertEqual(protected_ir["header"]["transactionID"].asOctets(),
                         tx_id, "Transaction ID mismatch")
        self.assertEqual(
            protected_ir["header"]["protectionAlg"]["algorithm"],
            id_KemBasedMac,
            "Protection algorithm is not KEMBasedMAC",
        )

        response = self.mock_ca_obj.process_normal_request(protected_ir)
        self.assertEqual(get_cmp_message_type(response), "ip", f"Unexpected CMP message type: {response.prettyPrint()}")
        pki_status_info = get_pkistatusinfo(response)
        self.assertEqual(
            pki_status_info["status"].prettyPrint(),
            "accepted",
            f"Unexpected PKI status: {pki_status_info.prettyPrint()}",
        )

    def test_invalid_kem_based_mac_protection(self):
        """
        GIVEN a General Message with a KEM certificate
        WHEN the message is processed by the CA
        THEN a valid ciphertext is returned, and a certificate request can be processed.
        """

        tx_id = b"B" * 16
        genm = self._build_genm_request(tx_id)
        genp = self.mock_ca_obj.process_normal_request(genm)

        shared_secret = validate_genp_kem_ct_info(
            genp,
            client_private_key=self.kem_key,
        )

        protected_ir = self._build_ir_request(
            tx_id=tx_id,
            ss=shared_secret,
            bad_message_check=True,
        )

        response = self.mock_ca_obj.process_normal_request(protected_ir)
        pki_status_info = get_pkistatusinfo(response)
        self.assertEqual(
            pki_status_info["status"].prettyPrint(),
            "rejection",
            f"Unexpected PKI status: {display_pki_status_info(pki_status_info)}",
        )
        result = is_bit_set(pki_status_info["failInfo"], "badMessageCheck"
                            )
        self.assertTrue(result)

    def test_use_ss_two_times(self):
        """
        GIVEN a General Message with a KEM certificate and an established shared secret.
        WHEN a second request is created with the same shared secret,
        THEN is an error message with the `PKIStatusInfo` rejection status returned.
        """
        tx_id = b"D" * 16
        genm = self._build_genm_request(tx_id)
        genp = self.mock_ca_obj.process_normal_request(genm)
        shared_secret = validate_genp_kem_ct_info(
            genp,
            client_private_key=self.kem_key,
        )
        protected_ir = self._build_ir_request(
            tx_id=tx_id,
            ss=shared_secret,
        )
        response = self.mock_ca_obj.process_normal_request(protected_ir)
        pki_status_info = get_pkistatusinfo(response)
        self.assertEqual(
            pki_status_info["status"].prettyPrint(),
            "accepted",
            f"Unexpected PKI status: {pki_status_info.prettyPrint()}",
        )
        protected_ir = self._build_ir_request(
            tx_id=tx_id,
            ss=shared_secret,
        )
        response = self.mock_ca_obj.process_normal_request(protected_ir)
        pki_status_info = get_pkistatusinfo(response)
        self.assertEqual(
            pki_status_info["status"].prettyPrint(),
            "rejection",
            f"Expected Mock-CA to delete the ss after it was successfully used.",
        )

    def test_not_established_ss(self):
        """
        GIVEN a General Message with a KEM certificate and a not established shared secret.
        WHEN the message is processed by the CA,
        THEN is an error message with the `PKIStatusInfo` rejection status returned.
        """
        tx_id = b"E" * 16
        tx_id2 = b"F" * 16
        genm = self._build_genm_request(tx_id)
        genp = self.mock_ca_obj.process_normal_request(genm)
        shared_secret = validate_genp_kem_ct_info(
            genp,
            client_private_key=self.kem_key,
        )
        protected_ir = self._build_ir_request(
            tx_id=tx_id2,
            ss=shared_secret,
            bad_message_check=True,
        )
        response = self.mock_ca_obj.process_normal_request(protected_ir)
        pki_status_info = get_pkistatusinfo(response)
        self.assertEqual(
            pki_status_info["status"].prettyPrint(),
            "rejection",
            f"Unexpected PKI status: {pki_status_info.prettyPrint()}",
        )
        result = is_bit_set(pki_status_info["failInfo"], "badMessageCheck")
        self.assertTrue(result, f"Expected badMessageCheck to be set:\n {display_pki_status_info(pki_status_info)}")

    def test_kem_based_mac_issuing_cert_conf(self):
        """
        GIVEN a General Message with a KEM certificate and an established shared secret.
        WHEN the messages are processed by the CA,
        THEN is the certificate confirmation correctly handled.
        """
        mock_ca_obj = CAHandler(
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
        )
        cert_conf_cfg = CertConfConfigVars(must_be_fresh_nonce=True)
        mock_ca_obj.set_config_vars(
            cert_conf_handler=cert_conf_cfg
        )

        tx_id = b"G" * 16
        genm = self._build_genm_request(tx_id)
        genp = mock_ca_obj.process_normal_request(genm)
        shared_secret = validate_genp_kem_ct_info(
            genp,
            client_private_key=self.kem_key,
        )
        ir = self._build_ir_request(
            tx_id=tx_id,
            ss=shared_secret,
            implicit_confirm=False,
        )
        response = mock_ca_obj.process_normal_request(ir)
        pki_status_info = get_pkistatusinfo(response)
        self.assertEqual(
            pki_status_info["status"].prettyPrint(),
            "accepted",
            f"Unexpected PKI status: {display_pki_status_info(pki_status_info)}",
        )

        cert_conf = build_cert_conf_from_resp(
            response,
            sender="CN=Hans the Tester",
            sender_kid=b"CN=Hans the Tester",
            recipient="CN=Mock-CA",
            for_mac=True,
            sender_nonce=os.urandom(16),
        )

        prot_cert_conf = protect_pkimessage_kem_based_mac(
            cert_conf,
            shared_secret=shared_secret,
        )
        response = mock_ca_obj.process_normal_request(prot_cert_conf)
        self.assertEqual(get_cmp_message_type(response), "pkiconf")










if __name__ == "__main__":
    unittest.main()
