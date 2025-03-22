# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives.asymmetric import rsa
from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc4211
from resources import cryptoutils
from resources.certbuildutils import prepare_extensions
from resources.cmputils import prepare_cert_req_msg


class TestPrepareCertReqMsg(unittest.TestCase):
    def setUp(self):
        """Set up a sample private key and common name for testing."""
        # Generate an RSA private key for testing
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.common_name = "CN=Hans the Tester"
        self.cert_req_id = 1234
        self.hash_alg = "sha256"

    def test_prepare_certreqmsg_with_valid_popo(self):
        """
        GIVEN a private key, common name, and valid proof of possession.
        WHEN prepare_certreqmsg is called with valid PoP.
        THEN it should return a CertReqMsg structure with certReq and valid PoP.
        """
        cert_req_msg = prepare_cert_req_msg(
            private_key=self.private_key,
            common_name=self.common_name,
            cert_req_id=self.cert_req_id,
            hash_alg=self.hash_alg,
        )

        # Encode the CertReqMsg structure to DER format
        encoded_cert_req_msg = encoder.encode(cert_req_msg)

        # Decode the encoded CertReqMsg structure back
        decoded_cert_req_msg, rest = decoder.decode(encoded_cert_req_msg, asn1Spec=rfc4211.CertReqMsg())

        self.assertEqual(rest, b"", "Decoding did not consume the entire input")
        self.assertTrue(decoded_cert_req_msg["certReq"].isValue, "certReq field is missing or empty")
        self.assertTrue(decoded_cert_req_msg["popo"].isValue, "popo field is missing or empty")

    def test_prepare_certreqmsg_without_popo_structure(self):
        """
        GIVEN a private key and common name.
        WHEN prepare_certreqmsg is called without providing a PoP structure.
        THEN it should generate a valid PoP and return a CertReqMsg structure with certReq and PoP.
        """
        cert_req_msg = prepare_cert_req_msg(
            private_key=self.private_key,
            common_name=self.common_name,
            cert_req_id=self.cert_req_id,
            hash_alg=self.hash_alg,
            popo_structure=None,
        )

        # Encode the CertReqMsg structure to DER format
        encoded_cert_req_msg = encoder.encode(cert_req_msg)

        # Decode the encoded CertReqMsg structure back
        decoded_cert_req_msg, rest = decoder.decode(encoded_cert_req_msg, asn1Spec=rfc4211.CertReqMsg())

        self.assertEqual(rest, b"", "Decoding did not consume the entire input")
        self.assertTrue(decoded_cert_req_msg["certReq"].isValue, "certReq field is missing or empty")
        self.assertTrue(decoded_cert_req_msg["popo"].isValue, "popo field is missing or empty")

    def test_prepare_certreqmsg_with_custom_extensions(self):
        """
        GIVEN a private key, common name, and custom extensions.
        WHEN prepare_certreqmsg is called with extensions.
        THEN it should return a CertReqMsg structure with certReq including the extensions.
        """
        # Prepare some sample extensions
        extensions = prepare_extensions(key_usage="nonRepudiation")

        cert_req_msg = prepare_cert_req_msg(
            private_key=self.private_key,
            common_name=self.common_name,
            cert_req_id=self.cert_req_id,
            hash_alg=self.hash_alg,
            extensions=extensions,
        )

        encoded_cert_req_msg = encoder.encode(cert_req_msg)
        decoded_cert_req_msg, rest = decoder.decode(encoded_cert_req_msg, asn1Spec=rfc4211.CertReqMsg())

        self.assertEqual(rest, b"", "Decoding did not consume the entire input")
        self.assertTrue(decoded_cert_req_msg["certReq"].isValue, "certReq field is missing or empty")
        self.assertTrue(
            decoded_cert_req_msg["certReq"]["certTemplate"]["extensions"].isValue,
            "Extensions field is missing or empty",
        )

    def test_prepare_certreqmsg_with_ra_verified_popo(self):
        """
        GIVEN a private key, common name, and ra_verified flag set to True.
        WHEN prepare_certreqmsg is called with `ra_verified` set to True.
        THEN it should return a CertReqMsg structure with a PoP indicating RA verification.
        """
        cert_req_msg = prepare_cert_req_msg(
            private_key=self.private_key,
            common_name=self.common_name,
            cert_req_id=self.cert_req_id,
            hash_alg=self.hash_alg,
            ra_verified=True,
        )

        self.assertTrue(cert_req_msg["popo"]["raVerified"].isValue, "RA verification flag is missing or empty")

        encoded_cert_req_msg = encoder.encode(cert_req_msg)
        decoded_cert_req_msg, rest = decoder.decode(encoded_cert_req_msg, asn1Spec=rfc4211.CertReqMsg())

        self.assertEqual(rest, b"", "Decoding did not consume the entire input")
        self.assertTrue(decoded_cert_req_msg["certReq"].isValue, "certReq field is missing or empty")
        self.assertTrue(decoded_cert_req_msg["popo"]["raVerified"].isValue, "RA verification flag is missing or empty")

    def test_calculation_of_popo(self):
        """
        GIVEN private key, common name, certReqID, hash algorithm
        WHEN calculating the Proof of Possession (PoP) signature.
        THEN the signature should match the expected value derived from signing the DER-encoded Certificate Request.
        """
        cert_req_msg = prepare_cert_req_msg(
            private_key=self.private_key,
            common_name=self.common_name,
            cert_req_id=self.cert_req_id,
            hash_alg=self.hash_alg,
            ra_verified=False,
        )

        der_cert_request = encoder.encode(cert_req_msg["certReq"])
        signature = cryptoutils.sign_data(data=der_cert_request, key=self.private_key, hash_alg=self.hash_alg)
        sig = cert_req_msg["popo"]["signature"]["signature"].asOctets()
        self.assertEqual(sig, signature, "Calculating the POPO failed!")


if __name__ == "__main__":
    unittest.main()
