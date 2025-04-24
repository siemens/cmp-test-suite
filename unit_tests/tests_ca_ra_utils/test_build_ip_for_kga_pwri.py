# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from resources.ca_kga_logic import validate_not_local_key_gen
from resources.ca_ra_utils import build_ip_cmp_message
from resources.certutils import parse_certificate
from resources.cmputils import build_ir_from_key
from resources.keyutils import load_private_key_from_file, get_key_name, generate_key
from resources.protectionutils import protect_pkimessage
from resources.utils import load_and_decode_pem_file
from unit_tests.utils_for_test import load_ca_cert_and_key


class TestBuildIpForKgaPWRI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ca_cert, cls.ca_key = load_ca_cert_and_key()
        cls.kga_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        cls.kga_cert = parse_certificate(load_and_decode_pem_file("data/unittest/ra_kga_cert_ecdsa.pem"))
        cls.password = b"SiemensIT"

    def test_default_key_gen(self):
        """
        GIVEN a key generation request
        WHEN the request is validated,
        THEN a key should be generated and exchanged.
        """
        ir = build_ir_from_key(None, for_kga=True)
        prot_ir = protect_pkimessage(ir, "pbmac1", b"SiemensIT")
        ip, _ = build_ip_cmp_message(prot_ir, ca_cert=self.ca_cert, ca_key=self.ca_key,
                                     password=b"SiemensIT",
                                     pvno=3,
                                     kga_cert_chain=[self.kga_cert, self.ca_cert], kga_key=self.kga_key)

        prot_ip = protect_pkimessage(ip, "pbmac1", b"SiemensIT")
        key = validate_not_local_key_gen(prot_ip, expected_type="pwri", password="SiemensIT", trustanchors="data/unittest")
        _ = get_key_name(key)

    def test_key_gen_ed25519(self):
        """
        GIVEN a key generation request for a specific key type.
        WHEN the request is validated,
        THEN the `ed25519` key should be generated and securely exchanged.
        """
        key = generate_key("ed25519")
        ir = build_ir_from_key(key, for_kga=True)
        prot_ir = protect_pkimessage(ir, "pbmac1", b"SiemensIT")
        ip, _ = build_ip_cmp_message(prot_ir, ca_cert=self.ca_cert, ca_key=self.ca_key,
                                     password=b"SiemensIT",
                                     pvno=3,
                                     kga_cert_chain=[self.kga_cert, self.ca_cert], kga_key=self.kga_key)

        prot_ip = protect_pkimessage(ip, "pbmac1", b"SiemensIT")
        key = validate_not_local_key_gen(prot_ip, expected_type="pwri", password="SiemensIT", trustanchors="data/unittest")
        self.assertIsInstance(key, Ed25519PrivateKey)


