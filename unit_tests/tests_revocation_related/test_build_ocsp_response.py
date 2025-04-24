# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp
from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc5280

from resources.certbuildutils import build_certificate
from resources.certutils import build_ocsp_response, parse_certificate
from resources.keyutils import load_private_key_from_file
from resources.oid_mapping import compute_hash
from resources.utils import load_and_decode_pem_file
from unit_tests.utils_for_test import convert_to_crypto_lib_cert


class TestBuildOCSPResponse(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        cls.ca_cert = parse_certificate(load_and_decode_pem_file("data/unittest/bare_certificate.pem"))

        cls.leaf_cert, _ = build_certificate(cls.leaf_key, "CN=Leaf Cert",
                                             ca_key=cls.ca_key,
                                             ca_cert=cls.ca_cert,
                                             )

        cls.certs = [cls.leaf_cert]

    def test_build_ocsp_response_good(self):
        """
        GIVEN a valid OCSP response with a good status.
        WHEN checking the OCSP response,
        THEN the response should be accepted.
        """
        status = "good"

        ocsp_response = build_ocsp_response(
            cert=self.leaf_cert,
            ca_cert=self.ca_cert,
            responder_key=self.ca_key,
            status=status,
            hash_alg="sha256",
            revocation_reason=None,
            responder_cert=None,  # By default, it will use ca_cert as the responder cert
            responder_hash_alg="sha256",
            build_by_key=False,
        )

        self.assertIsInstance(ocsp_response, ocsp.OCSPResponse)

        der_bytes = ocsp_response.public_bytes(serialization.Encoding.DER)
        parsed_response = ocsp.load_der_ocsp_response(der_bytes)

        self.assertEqual(parsed_response.response_status, ocsp.OCSPResponseStatus.SUCCESSFUL)

        responses = list(parsed_response.responses)  # is a generator so we convert it to a list.
        self.assertEqual(len(responses), 1)

        sr: ocsp.OCSPSingleResponse = responses[0]

        ca_cert = convert_to_crypto_lib_cert(self.ca_cert)
        _hash = compute_hash("sha256", ca_cert.subject.public_bytes(serialization.Encoding.DER))

        self.assertEqual(sr.certificate_status, ocsp.OCSPCertStatus.GOOD)
        self.assertEqual(sr.serial_number, int(self.leaf_cert["tbsCertificate"]["serialNumber"]))
        self.assertEqual(sr.issuer_name_hash.hex(), _hash.hex())

    def test_build_ocsp_response_revoked(self):
        """
        GIVEN a valid OCSP response with a revoked status.
        WHEN checking the OCSP response,
        THEN the response should be accepted.
        """
        status = "revoked"

        ocsp_response = build_ocsp_response(
            cert=self.leaf_cert,
            ca_cert=self.ca_cert,
            responder_key=self.ca_key,
            status=status,
            hash_alg="sha256",
            build_by_key=True,
        )

        der_bytes = ocsp_response.public_bytes(serialization.Encoding.DER)
        parsed_response = ocsp.load_der_ocsp_response(der_bytes)
        self.assertEqual(parsed_response.response_status, ocsp.OCSPResponseStatus.SUCCESSFUL)

        # excluding the tag and length fields.
        der_pub = self.ca_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        decoded_spki = decoder.decode(der_pub, asn1Spec=rfc5280.SubjectPublicKeyInfo())[0]

        decoded_spki = decoded_spki["subjectPublicKey"].asOctets()
        _hash = compute_hash("sha256", decoded_spki)

        responses = list(parsed_response.responses)
        self.assertEqual(len(responses), 1)
        sr = responses[0]
        self.assertEqual(sr.certificate_status, ocsp.OCSPCertStatus.REVOKED)
        self.assertEqual(sr.issuer_key_hash.hex(), _hash.hex())


if __name__ == "__main__":
    unittest.main()
