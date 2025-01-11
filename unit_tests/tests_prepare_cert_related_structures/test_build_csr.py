# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc6402, rfc6664, rfc9481
from resources.certbuildutils import build_csr, prepare_extensions
from resources.deprecatedutils import _sign_csr_builder, generate_csr
from resources.keyutils import load_private_key_from_file


class TestBuildCSR(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.private_key_rsa = load_private_key_from_file("./data/keys/private-key-rsa.pem", password=None)
        cls.private_key_ecc = load_private_key_from_file("./data/keys/private-key-ecdsa.pem")
        cls.subject = "CN=Hans the Tester"

    def test_csr_en_and_decode(self):
        """
        GIVEN a CSR generated using pyasn1
        WHEN the CSR is encoded to DER and decoded back.
        THEN it should decode without any remaining bytes, indicating the encoding and decoding processes are correct.
        """
        pyasn1_csr = build_csr(common_name=self.subject,
                               signing_key=self.private_key_rsa,
                               hash_alg="sha256")

        der_data = encoder.encode(pyasn1_csr)
        decoded, rest = decoder.decode(der_data, rfc6402.CertificationRequest())
        self.assertEqual(rest, b"")

    def test_simple_csr(self):
        """
        GIVEN a CSR generated using both pyasn1 and the cryptography library
        WHEN both CSRs are signed and encoded to DER
        THEN the CSRs should match in signature, content bytes, and DER encoding,
        ensuring consistency between the two methods.
        """
        csr = generate_csr(common_name=self.subject)
        csr_out = _sign_csr_builder(csr, self.private_key_rsa, hash_alg="sha256")
        der_data_crypto_lib = csr_out.public_bytes(serialization.Encoding.DER)
        pyasn1_csr = build_csr(common_name=self.subject,
                               signing_key=self.private_key_rsa,
                               hash_alg="sha256")

        self.assertEqual(csr_out.signature, pyasn1_csr["signature"].asOctets())
        self.assertEqual(csr_out.tbs_certrequest_bytes,
                         encoder.encode(pyasn1_csr["certificationRequestInfo"]))


        der_data_pyasn1 = encoder.encode(pyasn1_csr)
        # if the test case fails in the future, the reason might be,
        # because rsaEncryption removed the univ.NUll("").
        self.assertEqual(der_data_crypto_lib.hex(), der_data_pyasn1.hex())

    def test_simple_build_with_ski(self):
        """
        GIVEN a CSR generated with a SubjectKeyIdentifier (SKI) extension using both pyasn1 and the cryptography library
        WHEN both CSRs are signed and encoded to DER.
        THEN the DER encoded data from both CSRs should match, ensuring that the SKI extension is handled correctly.
        """
        csr = generate_csr(common_name=self.subject)
        csr = csr.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(self.private_key_rsa.public_key()),
            critical=False)
        csr_out = _sign_csr_builder(csr, self.private_key_rsa, hash_alg="sha256")
        der_data_crypto_lib = csr_out.public_bytes(serialization.Encoding.DER)

        extensions = prepare_extensions(key=self.private_key_rsa)
        pyasn1_csr = build_csr(common_name=self.subject,
                               signing_key=self.private_key_rsa,
                               extensions=extensions, hash_alg="sha256")


        der_data_pyasn1 = encoder.encode(pyasn1_csr)
        self.assertEqual(der_data_crypto_lib.hex(), der_data_pyasn1.hex())


    def test_build_csr_for_kga_rsa(self):
        """
        GIVEN a CSR generated with an RSA private key.
        WHEN for_kga is set to True,
        THEN the `subjectPublicKeyInfo` must be a nulled bit string.
        """
        pyasn1_csr = build_csr(for_kga=True, signing_key=self.private_key_rsa)
        der_data_pyasn1 = encoder.encode(pyasn1_csr)
        decoded_csr, rest = decoder.decode(der_data_pyasn1, rfc6402.CertificationRequest())
        self.assertEqual(rest, b"")

        public_key = decoded_csr["certificationRequestInfo"]["subjectPublicKeyInfo"]
        self.assertEqual(public_key["subjectPublicKey"],
                         univ.BitString(""))

        # TODO if oid checked, then update this test case.
        self.assertEqual(public_key["algorithm"]["algorithm"],
                         rfc9481.rsaEncryption)


    def test_build_csr_for_kga_ecc(self):
        """
        GIVEN a CSR generated with an EC private key.
        WHEN for_kga is set to True,
        THEN the `subjectPublicKeyInfo` must be a nulled bit string.
        """
        pyasn1_csr = build_csr(for_kga=True, signing_key=self.private_key_ecc)
        der_data_pyasn1 = encoder.encode(pyasn1_csr)
        decoded_csr, rest = decoder.decode(der_data_pyasn1, rfc6402.CertificationRequest())
        self.assertEqual(rest, b"")

        public_key = decoded_csr["certificationRequestInfo"]["subjectPublicKeyInfo"]
        self.assertEqual(public_key["subjectPublicKey"],
                         univ.BitString(""))

        # TODO if oid checked, then update this test case.
        self.assertEqual(public_key["algorithm"]["algorithm"],
                         rfc6664.id_ecPublicKey)
