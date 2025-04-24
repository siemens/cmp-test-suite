# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import os
import unittest

from cryptography.hazmat.primitives.serialization import load_der_private_key

from resources.ca_kga_logic import validate_kari_env_data
from resources.certutils import parse_certificate
from resources.utils import load_and_decode_pem_file
from unit_tests.utils_for_test import parse_cms_env_data


class TestKARIEnvelopedDataBC(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir_path = "unit_tests/tests_protocol_related/test_kga_logic/tests_kari_related"
        cert_path = os.path.join(cls.dir_path, "recipient_cert.pem")
        cls.cert = parse_certificate(load_and_decode_pem_file(cert_path))
        key_path = os.path.join(cls.dir_path, "sender_private_key.der")
        der_data = open(key_path, "rb").read()
        cls.sender_key = load_der_private_key(der_data, password=None)

    def test_kari_env_data_dh_static(self):
        fpath = os.path.join(self.dir_path, "cms_ecdh_envelopedData_std_sha256.der")
        with open(fpath, "rb") as f:
            der_data = f.read()
        env_data_loaded = parse_cms_env_data(der_data)

        dec_data = validate_kari_env_data(
            env_data=env_data_loaded,
            recip_private_key=self.sender_key,
            cmp_protection_cert=self.cert,
            expected_raw_data=True,
            for_pop=True,  # To exclude the RID check.
        )
        self.assertEqual(
            dec_data.hex(),
            "Hello World!".encode("utf-8").hex(),
        )

    def test_kari_env_data_dh_static_ukm(self):
        fpath = os.path.join(self.dir_path, "cms_envelopedData_std_sha256_ukm.der")
        with open(fpath, "rb") as f:
            der_data = f.read()
        env_data_loaded = parse_cms_env_data(der_data)

        dec_data = validate_kari_env_data(
            env_data=env_data_loaded,
            recip_private_key=self.sender_key,
            cmp_protection_cert=self.cert,
            expected_raw_data=True,
            for_pop=True,  # To exclude the RID check.
        )
        self.assertEqual(
            dec_data.hex(),
            "Hello World!".encode("utf-8").hex(),
        )

    def test_kari_env_data_dh_cofactor(self):
        # currently makes no sense, because the curve is "secp256r1",
        # which has cofactor 1.
        fpath = os.path.join(self.dir_path, "cms_envelopedData_cofactorDH_sha256.der")
        with open(fpath, "rb") as f:
            der_data = f.read()
        env_data_loaded = parse_cms_env_data(der_data)

        dec_data = validate_kari_env_data(
            env_data=env_data_loaded,
            recip_private_key=self.sender_key,
            cmp_protection_cert=self.cert,
            expected_raw_data=True,
            for_pop=True,  # To exclude the RID check.
        )
        self.assertEqual(
            dec_data.hex(),
            "Hello World!".encode("utf-8").hex(),
        )
