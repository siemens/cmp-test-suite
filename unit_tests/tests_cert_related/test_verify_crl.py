# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.certutils import (
    build_crl_chain_from_list,
    find_crl_signer_cert,
    load_certificates_from_dir,
    load_crl_from_der,
    parse_certificate,
    verify_openssl_crl,
)
from resources.utils import load_and_decode_pem_file

from unit_tests.utils_for_test import compare_pyasn1_objects


class TestCRLSignatureVerification(unittest.TestCase):

    def setUp(self):
        self.crl_path = "data/unittest/test_verify_crl.crl"
        der_data = load_and_decode_pem_file(self.crl_path)
        self.crl_obj = load_crl_from_der(der_data)
        self.crl_signer = parse_certificate(
            load_and_decode_pem_file("data/unittest/crl_sign_cert_ecdsa.pem"))

        self.root_cert = parse_certificate(
            load_and_decode_pem_file("data/unittest/root_cert_ed25519.pem"))

    def test_find_crl(self):
        """
        GIVEN a CRL with a valid signature.
        WHEN a directory containing certificates is provided,
        THEN the CRL signer should be successfully found.
        """
        signer = find_crl_signer_cert(self.crl_obj, ca_cert_dir="data/unittest")
        self.assertTrue(compare_pyasn1_objects(signer, self.crl_signer))

    def test_build_crl_chain(self):
        """
        GIVEN a CRL with a valid signature.
        WHEN the CRL chain is built,
        THEN the CRL chain should be successfully built.
        """
        certs = load_certificates_from_dir("data/unittest")
        crl_chain = build_crl_chain_from_list(self.crl_obj, certs=certs)
        self.assertEqual(len(crl_chain), 3)
        self.assertTrue(compare_pyasn1_objects(crl_chain[0], self.crl_obj))
        self.assertTrue(compare_pyasn1_objects(crl_chain[1], self.crl_signer))
        self.assertTrue(compare_pyasn1_objects(crl_chain[2], self.root_cert))


    def test_crl_signature_verification(self):
        """
        GIVEN a CRL with a valid signature.
        WHEN the CRL is verified using OpenSSL.
        THEN the CRL should be successfully verified.
        """
        certs = load_certificates_from_dir("data/unittest")
        crl_chain = build_crl_chain_from_list(self.crl_obj, certs=certs)
        verify_openssl_crl(crl_chain)



if __name__ == "__main__":
    unittest.main()
