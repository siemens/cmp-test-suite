# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

import cryptography.exceptions
from cryptography import x509

import certutils
import cmputils
from cmputils import encode_to_der, parse_csr, modify_csr_cn
from cryptoutils import generate_signed_csr
from utils import decode_pem_string


class TestUtils(unittest.TestCase):
    def test_csr_signature_verification(self):
        """
        Tests the failure of CSR signature verification when the CSR content is modified.

        This test generates a CSR (Certificate Signing Request), signs it, and then
        intentionally modifies the common name (CN) in the CSR. It then verifies that
        the CSR signature is invalid after modification.

        """

        csr, key = generate_signed_csr(common_name="CN=Hans", key="rsa", pem=False)


        # to check that the signature before was correct.
        csr_signed = x509.load_pem_x509_csr(csr)
        #verify if the certificate is correct
        certutils.verify_csr_signature(csr_signed)

        # Modify the common name (CN) in the CSR to "Hans MusterMann"
        # returns DER Encoded data
        csr = parse_csr(decode_pem_string(csr))
        modified_csr = cmputils.modify_csr_cn(csr, new_cn="Hans MusterMann")

        modified_csr = x509.load_der_x509_csr(encode_to_der(modified_csr))

        self.assertNotEqual(modified_csr, csr_signed)

        # Verify the signature of the modified CSR
        with self.assertRaises(cryptography.exceptions.InvalidSignature):
            certutils.verify_csr_signature(modified_csr)



