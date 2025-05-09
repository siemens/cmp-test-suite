# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import encoder

from resources.ca_ra_utils import validate_enc_key_with_id
from resources.certbuildutils import prepare_cert_template
from resources.exceptions import BadPOP
from resources.extra_issuing_logic import prepare_enc_key_with_id
from resources.keyutils import generate_different_public_key, load_private_key_from_file


class TestValidateEncKeyWithId(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.xwing = load_private_key_from_file("data/keys/private-key-xwing-seed.pem")
        cls.mldsa_key = load_private_key_from_file("data/keys/private-key-ml-dsa-44-seed.pem")
        cls.ecc_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        cls.keys = {"rsa": cls.rsa_key, "x-wing": cls.xwing, "mldsa": cls.mldsa_key, "ecc": cls.ecc_key}

    def test_validate_enc_key_with_id(self):
        """
        GIVEN a private key and an encrypted key with ID.
        WHEN calling validate_enc_key_with_id,
        THEN should the function return True.
        """
        for name, key in self.keys.items():
            with self.subTest(key_type=name):
                cert_template = prepare_cert_template(
                    subject="CN=Hans the Tester",
                    key=key,
                )
                enc_key_with_id = prepare_enc_key_with_id(sender="CN=Hans the Tester", private_key=key)
                der_data = encoder.encode(enc_key_with_id)
                validate_enc_key_with_id(der_data, cert_template)

    def test_mis_matching_enc_key_with_id(self):
        """
        GIVEN an encrypted key with ID that does not match the public key inside the `CertTemplate`.
        WHEN calling validate_enc_key_with_id,
        THEN should the function raise an `BadPOP` exception.
        """
        for name, key in self.keys.items():
            with self.subTest(key_type=name):
                diff_pub_key = generate_different_public_key(key)
                self.assertNotEqual(key.public_key(), diff_pub_key)
                cert_template = prepare_cert_template(
                    subject="CN=Hans the Tester",
                    key=diff_pub_key,
                )
                enc_key_with_id = prepare_enc_key_with_id(sender="CN=Hans the Tester", private_key=key)
                der_data = encoder.encode(enc_key_with_id)
                with self.assertRaises(BadPOP):
                    validate_enc_key_with_id(der_data, cert_template)
