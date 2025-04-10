# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey

from pq_logic.trad_typing import ECDHPrivateKey
from resources.asn1_structures import PKIMessageTMP
from resources.ca_ra_utils import build_ip_cmp_message
from resources.certutils import load_public_key_from_cert
from resources.cmputils import prepare_cert_request, build_ir_from_key
from resources.exceptions import BadPOP
from resources.extra_issuing_logic import prepare_pkmac_popo
from resources.keyutils import generate_key
from unit_tests.utils_for_test import load_kari_certs, load_ca_cert_and_key


class TestBuildIpForAgreeMac(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.kari_certs = load_kari_certs()
        cls.cm = "CN=Hans the Tester"
        cls.ca_cert, cls.ca_key = load_ca_cert_and_key()

    def _build_request(self, key: ECDHPrivateKey, key_name: str, bad_pop: bool = False) -> PKIMessageTMP:
        """Build a certificate request and a proof of possession object."""
        cert_request = prepare_cert_request(key, self.cm)
        popo = prepare_pkmac_popo(
            cert_request, self.kari_certs[f"{key_name}_cert"], key,
            bad_pop=bad_pop,
        )
        return build_ir_from_key(
            key,
            popo=popo,
            cert_request=cert_request,
            common_name=self.cm,
        )

    def test_issuing_x25519_key(self):
        """
        GIVEN a CA x25519 certificate and a client x25519 key.
        WHEN the CA processes the certificate request,
        THEN a valid certificate is issued.
        """
        key = generate_key("x25519")
        ir = self._build_request(key, key_name="x25519")
        response, certs = build_ip_cmp_message(
            ir,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            **self.kari_certs
        )
        self.assertEqual(response["body"].getName(), "ip")
        loaded_key = load_public_key_from_cert(certs[0])
        self.assertIsInstance(loaded_key, X25519PublicKey)
        self.assertEqual(key.public_key(), loaded_key)


    def test_issuing_x25519_key_bad_pop(self):
        """
        GIVEN a CA x25519 certificate and a client x25519 key.
        WHEN the CA processes the certificate request with a bad POP,
        THEN a BadPOP exception is raised.
        """
        key = generate_key("x25519")
        ir = self._build_request(key, key_name="x25519", bad_pop=True)

        with self.assertRaises(BadPOP):
            build_ip_cmp_message(
                ir,
                ca_cert=self.ca_cert,
                ca_key=self.ca_key,
                **self.kari_certs
            )

    def test_issuing_x448_key(self):
        """
        GIVEN a CA X448 certificate and a client x448 key.
        WHEN the CA processes the certificate request,
        THEN a valid certificate is issued.
        """
        key = generate_key("x448")
        ir = self._build_request(key, key_name="x448")
        response, certs = build_ip_cmp_message(
            ir,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            **self.kari_certs
        )
        self.assertEqual(response["body"].getName(), "ip")
        loaded_key = load_public_key_from_cert(certs[0])
        self.assertIsInstance(loaded_key, X448PublicKey)
        self.assertEqual(key.public_key(), loaded_key)


    def test_issuing_ecc_key_agreeMAC(self):
        """
        GIVEN a CA ECC certificate and a client ECC key.
        WHEN the CA processes the certificate request,
        THEN a valid certificate is issued.
        """
        key = generate_key("ecc")
        ir = self._build_request(key, key_name="ecc")
        response, certs = build_ip_cmp_message(
            ir,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            **self.kari_certs
        )
        self.assertEqual(response["body"].getName(), "ip")
        loaded_key = load_public_key_from_cert(certs[0])
        self.assertIsInstance(loaded_key, EllipticCurvePublicKey)
        self.assertEqual(key.public_key(), loaded_key)

