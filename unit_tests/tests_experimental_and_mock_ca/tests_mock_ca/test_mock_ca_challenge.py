# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import os
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from mock_ca.ca_handler import CAHandler
from mock_ca.challenge_handler import ChallengeHandler

from resources.asn1_structures import PKIMessageTMP
from resources.asn1utils import try_decode_pyasn1
from resources.certbuildutils import build_certificate, prepare_extensions
from resources.certutils import load_public_key_from_cert, parse_certificate
from resources.cmputils import build_ir_from_key, prepare_popo_challenge_for_non_signing_key
from resources.extra_issuing_logic import process_pkimessage_with_popdecc
from resources.keyutils import generate_key, load_private_key_from_file
from resources.protectionutils import protect_pkimessage
from resources.utils import load_and_decode_pem_file
from unit_tests.utils_for_test import try_encode_pyasn1


class TestMockCAChallengeHandler(unittest.TestCase):
    @classmethod
    def generate_key_and_cert(cls, key_alg, **kwargs):
        private_key = generate_key(key_alg, **kwargs)
        cert, private_key = build_certificate(
            private_key=private_key,
            ca_key=cls.ed_key,
            ca_cert=cls.root_cert,
            key_usage="keyAgreement",
        )
        return cert, private_key

    @classmethod
    def setUpClass(cls):
        cls.ed_key = load_private_key_from_file("data/keys/private-key-ed25519.pem")
        cls.root_cert = parse_certificate(load_and_decode_pem_file("data/unittest/root_cert_ed25519.pem"))
        extensions = prepare_extensions(ca_key=cls.ed_key.public_key(), critical=False)
        cls.x25519_cert, cls.ca_x25519 = cls.generate_key_and_cert("x25519")
        cls.x448_cert, cls.x448 = cls.generate_key_and_cert("x448")
        cls.ec_cert, cls.ec_key = cls.generate_key_and_cert("ecc", curve="brainpoolP256r1")
        cls.chall_handler = ChallengeHandler(
            ca_key=cls.ed_key,
            ca_cert=cls.root_cert,
            extensions=extensions,
            x25519_key=cls.ca_x25519,
            x448_key=cls.x448,
            ecc_key=cls.ec_key,
        )
        config = {
            "x25519_key": cls.ca_x25519,
            "x448_key": cls.x448,
            "ecc_key": cls.ec_key,
            "x25519_cert": cls.x25519_cert,
            "x448_cert": cls.x448_cert,
            "ecc_cert": cls.ec_cert,
        }
        cls.handler = CAHandler(
            ca_key=cls.ed_key,
            ca_cert=cls.root_cert,
            config=config,
        )

    def _protect_msg(self, msg: PKIMessageTMP) -> PKIMessageTMP:
        return protect_pkimessage(msg, "signature", cert=self.root_cert, private_key=self.ed_key)

    def test_challenge_handler(self):
        """
        GIVEN a PKIMessage Challenge Exchange.
        WHEN processing the request and response with the ChallengeHandler.
        THEN the certificate is successfully issued.
        """
        return
        tx_id = os.urandom(16)
        sender_nonce = os.urandom(16)
        key = load_private_key_from_file("data/keys/private-key-ml-kem-512.pem")
        popo = prepare_popo_challenge_for_non_signing_key(use_encr_cert=False, use_key_enc=True)
        ir = build_ir_from_key(
            key,
            sender="CN=Hans the Tester",
            popo=popo,
            common_name="CN=Hans the Tester",
            pvno=3,
            sender_nonce=sender_nonce,
            transaction_id=tx_id,
        )
        ir = self._protect_msg(ir)
        response, ecc_key = self.chall_handler.handle_challenge(ir)
        self.assertEqual(ecc_key, None)
        self.assertEqual(response["body"].getName(), "popdecc")
        self.assertTrue(response["body"]["popdecc"][0]["encryptedRand"].isValue)
        self.assertEqual(response["header"]["recipNonce"].asOctets(), sender_nonce)
        self.assertEqual(response["header"]["transactionID"].asOctets(), tx_id)
        der_data = try_encode_pyasn1(response)
        response, rest = try_decode_pyasn1(der_data, PKIMessageTMP())
        response: PKIMessageTMP
        self.assertEqual(rest, b"")

        client_out = process_pkimessage_with_popdecc(response, ee_key=key)
        self.assertEqual(client_out["header"]["senderNonce"].asOctets(), sender_nonce)
        self.assertEqual(client_out["header"]["transactionID"].asOctets(), tx_id)

        ip, certs = self.chall_handler.handle_challenge(client_out)
        self.assertEqual(ip["body"].getName(), "ip")

    def test_challenge_mock_ca(self):
        """
        GIVEN a PKIMessage Challenge Exchange.
        WHEN processing the request and response with the CAHandler.
        THEN the certificate is successfully issued.
        """
        return
        tx_id = os.urandom(16)
        sender_nonce = os.urandom(16)
        key = load_private_key_from_file("data/keys/private-key-ml-kem-512.pem")
        popo = prepare_popo_challenge_for_non_signing_key(use_encr_cert=False, use_key_enc=True)

        ir = build_ir_from_key(
            key,
            sender="CN=Hans the Tester",
            popo=popo,
            common_name="CN=Hans the Tester",
            pvno=3,
            sender_nonce=sender_nonce,
            transaction_id=tx_id,
            for_mac=True,
        )

        ir = self._protect_msg(ir)
        response = self.handler.process_normal_request(ir)
        self.assertEqual(response["body"].getName(), "popdecc")
        self.assertTrue(response["body"]["popdecc"][0]["encryptedRand"].isValue)
        self.assertEqual(response["header"]["recipNonce"].asOctets(), sender_nonce)
        self.assertEqual(response["header"]["transactionID"].asOctets(), tx_id)
        der_data = try_encode_pyasn1(response)
        response, rest = try_decode_pyasn1(der_data, PKIMessageTMP())
        response: PKIMessageTMP
        self.assertEqual(rest, b"")

        client_out = process_pkimessage_with_popdecc(response, ee_key=key)
        client_out = self._protect_msg(client_out)
        self.assertEqual(client_out["header"]["senderNonce"].asOctets(), sender_nonce)
        self.assertEqual(client_out["header"]["transactionID"].asOctets(), tx_id)
        ip = self.handler.process_normal_request(client_out)
        self.assertEqual(ip["body"].getName(), "ip", ip["body"].prettyPrint())

    def test_challenge_mock_ca_ecc_key(self):
        tx_id = os.urandom(16)
        sender_nonce = os.urandom(16)
        key = generate_key("x25519")
        popo = prepare_popo_challenge_for_non_signing_key(use_encr_cert=False, use_key_enc=False)
        ir = build_ir_from_key(
            key,
            sender="CN=Hans the Tester",
            popo=popo,
            common_name="CN=Hans the Tester",
            pvno=3,
            sender_nonce=sender_nonce,
            transaction_id=tx_id,
            for_mac=True,
        )

        ir = self._protect_msg(ir)
        response = self.handler.process_normal_request(ir)
        self.assertEqual(response["body"].getName(), "popdecc", response["body"].prettyPrint())
        self.assertTrue(response["body"]["popdecc"][0]["encryptedRand"].isValue)
        self.assertEqual(response["header"]["recipNonce"].asOctets(), sender_nonce)
        self.assertEqual(response["header"]["transactionID"].asOctets(), tx_id)
        der_data = try_encode_pyasn1(response)
        response, rest = try_decode_pyasn1(der_data, PKIMessageTMP())
        response: PKIMessageTMP
        self.assertEqual(rest, b"")
        pub_key = load_public_key_from_cert(response["extraCerts"][0])
        self.assertIsInstance(pub_key, Ed25519PublicKey)
        pub_key = load_public_key_from_cert(response["extraCerts"][1])
        self.assertIsInstance(pub_key, X25519PublicKey)

        client_out = process_pkimessage_with_popdecc(response, ee_key=key)
        client_out = self._protect_msg(client_out)
        self.assertEqual(client_out["header"]["senderNonce"].asOctets(), sender_nonce)
        self.assertEqual(client_out["header"]["transactionID"].asOctets(), tx_id)
        ip = self.handler.process_normal_request(client_out)
        self.assertEqual(ip["body"].getName(), "ip", ip["body"].prettyPrint())
