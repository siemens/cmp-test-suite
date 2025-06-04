# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
import tempfile
import unittest
from typing import List

from pyasn1_alt_modules import rfc9480
from resources import utils
from resources.certutils import certificates_are_trustanchors, certificates_must_be_trusted, parse_certificate
from resources.exceptions import SignerNotTrusted

from unit_tests.utils_for_test import load_or_generate_cert_chain


class TestCertAndValidateLogic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cert_chain, _ = load_or_generate_cert_chain()
        cls.cert_chain: List[rfc9480.CMPCertificate] = cert_chain
        cls.root_cert = cls.cert_chain[0]
        cls.ca1_cert = cls.cert_chain[1]
        cls.ca2_cert = cls.cert_chain[2]
        # Expects the chain to start from the end-entity
        cls.cert_chain = cert_chain[::-1]
        cls.path_to_anchors = "data/unittest"
        cls.path_to_trust_anchor = "data/unittest/root_cert_ed25519.pem"

    def test_certificates_are_trustanchors(self):
        """
        GIVEN a certificate that is a trust anchor
        WHEN `certificates_are_trustanchors` is called with this certificate and valid trust anchors,
        THEN it should pass without raising any errors
        """
        der_data = utils.load_and_decode_pem_file(self.path_to_trust_anchor)
        ee_cert = parse_certificate(der_data)
        certificates_are_trustanchors(
            [ee_cert],
            allow_os_store=True,
            trustanchors=self.path_to_anchors,
            verbose=True
        )
        certificates_are_trustanchors(
            [ee_cert],
            allow_os_store=False,
            trustanchors=self.path_to_anchors,
            verbose=True
        )

    def test_certificates_are_trustanchors_untrusted_cert(self):
        """
        GIVEN a certificate that is not a trust anchor and no trust anchors are provided
        WHEN `certificates_are_trustanchors` is called with this certificate,
        THEN it should raise a `SignerNotTrusted` indicating the certificate is not a trust anchor
        """
        der_data = utils.load_and_decode_pem_file(self.path_to_trust_anchor)
        untrusted_cert = parse_certificate(der_data)

        with self.assertRaises(SignerNotTrusted):
            certificates_are_trustanchors(
                [untrusted_cert],
                allow_os_store=True,
                trustanchors=None,
                verbose=True
            )

    def test_certificate_must_be_trusted_with_not_anchor_valid_chain(self):
        """
        GIVEN a certificate chain that is not trusted because the trust anchor is not provided
        WHEN `certificates_must_be_trusted` is called with this chain and invalid trust anchors,
        THEN it should raise a `ValueError` indicating the chain is not trusted
        """
        with tempfile.TemporaryDirectory() as temp_trust_dir:
            # Optionally populate temp_trust_dir with dummy trust anchors.
            with self.assertRaises(SignerNotTrusted):
                certificates_must_be_trusted(
                    cert_chain=self.cert_chain,
                    allow_os_store=True,
                    trustanchors=temp_trust_dir,
                    crl_check=False,
                    verbose=False,
                    key_usages="keyCertSign, cRLSign",
                )


    def test_certificate_must_be_trusted_with_anchor_valid_chain(self):
        """
        GIVEN a valid certificate chain with the correct trust anchors provided
        WHEN `certificates_must_be_trusted` is called with this chain,
        THEN it should pass without raising any errors
        """
        certificates_must_be_trusted(
            cert_chain=self.cert_chain,
            allow_os_store=True,
            trustanchors=self.path_to_anchors,
            crl_check=False,
            verbose=False,
            key_usages="keyCertSign, cRLSign",
        )


if __name__ == '__main__':
    unittest.main()
