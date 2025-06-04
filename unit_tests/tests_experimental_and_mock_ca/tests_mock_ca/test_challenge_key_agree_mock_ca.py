# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from mock_ca.ca_handler import CAHandler

from resources.certutils import load_public_key_from_cert
from resources.checkutils import check_if_response_contains_encrypted_cert
from resources.cmputils import build_ir_from_key, get_pkistatusinfo, prepare_popo_challenge_for_non_signing_key
from resources.extra_issuing_logic import get_enc_cert_from_pkimessage, process_pkimessage_with_popdecc
from resources.keyutils import generate_key
from resources.protectionutils import protect_pkimessage
from unit_tests.utils_for_test import load_ca_cert_and_key, load_env_data_certs


class TestChallengeCAHandler(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Set up the test environment."""
        # Load necessary data and configurations
        cls.kari_certs = load_env_data_certs()
        cls.ca_cert, cls.ca_key = load_ca_cert_and_key()
        cls.handler = CAHandler(cls.ca_cert, cls.ca_key)

    def test_popdecc_popdecr_flow(self):
        """
        GIVEN a x25519 key and a SubsequentMessage challengeResp popo.
        WHEN the key is sent to the CA.
        THEN the CA should return a popdecc message and then issue a correct certificate.
        """
        x25519_key = generate_key("x25519")
        popo = prepare_popo_challenge_for_non_signing_key(use_encr_cert=False, use_key_enc=False)

        ir = build_ir_from_key(
            x25519_key,
            popo=popo,
            pvno=3,
            common_name="CN=Hans the Tester",
            exclude_fields="sender,senderKID",
        )
        prot_ir = protect_pkimessage(
            ir,
            protection="signature",
            cert=self.kari_certs["ecc_cert"],
            private_key=self.kari_certs["ecc_key"],
        )

        response = self.handler.process_normal_request(prot_ir)

        self.assertEqual(
            response["body"].getName(),
            "popdecc",
        )
        response_client = process_pkimessage_with_popdecc(response, ee_key=x25519_key)
        response_client = protect_pkimessage(
            response_client,
            protection="signature",
            cert=self.kari_certs["ecc_cert"],
            private_key=self.kari_certs["ecc_key"],
        )
        self.assertEqual(response_client["body"].getName(), "popdecr")
        ip = self.handler.process_normal_request(response_client)
        self.assertEqual(ip["body"].getName(), "ip", get_pkistatusinfo(ip))

    def test_popdecc_popdecr_flow_ecc(self):
        """
        GIVEN an ECC key and a SubsequentMessage challengeResp popo.
        WHEN the key is sent to the CA.
        THEN the CA should return a popdecc message and then issue a correct certificate.
        """
        ecc_key = generate_key("ecc")
        popo = prepare_popo_challenge_for_non_signing_key(use_encr_cert=False, use_key_enc=False)

        ir = build_ir_from_key(
            ecc_key,
            popo=popo,
            pvno=3,
            common_name="CN=Hans the Tester",
            exclude_fields="sender,senderKID",
        )
        prot_ir = protect_pkimessage(
            ir,
            protection="signature",
            cert=self.kari_certs["ecc_cert"],
            private_key=self.kari_certs["ecc_key"],
        )

        response = self.handler.process_normal_request(prot_ir)

        self.assertEqual(
            response["body"].getName(),
            "popdecc",
        )
        response_client = process_pkimessage_with_popdecc(
            response, ee_key=ecc_key, kari_cert=self.kari_certs["ecc_cert"]
        )
        response_client = protect_pkimessage(
            response_client,
            protection="signature",
            cert=self.kari_certs["ecc_cert"],
            private_key=self.kari_certs["ecc_key"],
        )
        self.assertEqual(response_client["body"].getName(), "popdecr")
        ip = self.handler.process_normal_request(response_client)
        self.assertEqual(ip["body"].getName(), "ip", get_pkistatusinfo(ip))

    def test_encrypted_cert(self):
        """
        GIVEN a x25519 key and a SubsequentMessage encrCert popo.
        WHEN the key is sent to the CA.
        THEN the CA should return a popdecc message and then issue a correct certificate.
        """
        x25519_key = generate_key("x25519")
        popo = prepare_popo_challenge_for_non_signing_key(use_encr_cert=True, use_key_enc=False)
        ir = build_ir_from_key(
            x25519_key,
            popo=popo,
            common_name="CN=Hans the Tester",
            exclude_fields="sender,senderKID",
        )
        prot_ir = protect_pkimessage(
            ir,
            protection="signature",
            cert=self.kari_certs["ecc_cert"],
            private_key=self.kari_certs["ecc_key"],
        )

        response = self.handler.process_normal_request(prot_ir)
        status = get_pkistatusinfo(response)
        self.assertTrue(
            check_if_response_contains_encrypted_cert(response),
            msg=f"PKIStatusInfo: {status}. The cert is not encrypted or missing.",
        )
        cert = get_enc_cert_from_pkimessage(response, ee_private_key=x25519_key)
        loaded_key = load_public_key_from_cert(cert)
        self.assertEqual(x25519_key.public_key(), loaded_key)


if __name__ == "__main__":
    unittest.main()
