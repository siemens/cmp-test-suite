# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import encoder, decoder
from pyasn1_alt_modules import rfc5280, rfc9480

from pq_logic.hybrid_sig.chameleon_logic import build_paired_csr, \
    build_chameleon_cert_from_paired_csr, build_delta_cert, extract_chameleon_attributes, \
    build_delta_cert_from_paired_cert
from resources.certbuildutils import prepare_extensions
from resources.certutils import parse_certificate, load_public_key_from_cert
from resources.keyutils import load_private_key_from_file
from resources.utils import load_and_decode_pem_file
from unit_tests.utils_for_test import compare_pyasn1_objects


class TestBuildChameleonCert(unittest.TestCase):

    def setUp(self):
        self.ec_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        # TODO verify if this is a bad key!
        self.mldsa_key = load_private_key_from_file("data/keys/private-key-ml-dsa-44.pem")
        self.common_name = "CN=Hans the Tester"
        self.ca_cert = parse_certificate(load_and_decode_pem_file("data/unittest/pq_root_ca_ml_dsa_44.pem"))

    def test_build_delta_cert(self):
        """
        GIVEN a paired CSR and a CA key and certificate.
        WHEN building a delta certificate.
        THEN the certificate is correctly built.
        """

        paired_csr = build_paired_csr(
            delta_private_key=self.mldsa_key,
            base_private_key=self.ec_key,
        )
        other_attr, delta_value, sig = extract_chameleon_attributes(paired_csr)

        cert = build_delta_cert(
            csr=paired_csr,
            delta_value=delta_value,
            ca_cert=self.ca_cert,
            ca_key=self.mldsa_key
        )
        der_data = encoder.encode(cert)
        decoded_cert, rest = decoder.decode(der_data, asn1Spec=rfc5280.Certificate())
        self.assertEqual(rest, b"")
        public_key = load_public_key_from_cert(cert)
        self.assertEqual(public_key, self.mldsa_key.public_key())

    def test_build_paired_cert_from_csr(self):
        """
        GIVEN a paired CSR and a CA key and certificate.
        WHEN building a paired certificate.
        THEN the certificate is correctly built.
        """
        paired_csr = build_paired_csr(
            delta_private_key=self.mldsa_key,
            base_private_key=self.ec_key,
        )

        cert, delta_cert = build_chameleon_cert_from_paired_csr(
            csr=paired_csr,
            ca_cert=self.ca_cert,
            ca_key=self.mldsa_key
        )
        public_key = load_public_key_from_cert(cert)
        self.assertEqual(public_key, self.ec_key.public_key())
        loaded_key = load_public_key_from_cert(delta_cert)
        self.assertEqual(loaded_key, self.mldsa_key.public_key())

    def test_build_delta_cert_from_extension(self):
        """
        GIVEN a paired CSR and a CA key and certificate.
        WHEN building a delta certificate.
        THEN the certificate is correctly built.
        """
        paired_csr = build_paired_csr(
            delta_private_key=self.mldsa_key,
            base_private_key=self.ec_key,
        )
        paired_cert, delta_cert = build_chameleon_cert_from_paired_csr(
            csr=paired_csr,
            ca_cert=self.ca_cert,
            ca_key=self.mldsa_key
        )

        delta_cert_build = build_delta_cert_from_paired_cert(
            paired_cert=paired_cert,
        )

        der_data = encoder.encode(delta_cert_build)
        decoded_cert, rest = decoder.decode(der_data, asn1Spec=rfc9480.CMPCertificate())
        self.assertEqual(rest, b"")

        result = compare_pyasn1_objects(delta_cert_build,
                                        delta_cert
                                        )

        self.assertTrue(result)



    def test_build_delta_cert_from_extension_with_skis(self):

        """
        GIVEN a paired CSR and a CA key and certificate.
        WHEN building a delta certificate.
        THEN the certificate is correctly built.
        """

        # TODO verify why this test case fails only sometimes!!!
        base_extensions = prepare_extensions(
            key=self.ec_key,
        )
        delta_extensions = prepare_extensions(
            key=self.mldsa_key,
        )
        paired_csr = build_paired_csr(
            delta_private_key=self.mldsa_key,
            base_private_key=self.ec_key,
            base_extensions=base_extensions,
            delta_extensions=delta_extensions

        )
        paired_cert, delta_cert = build_chameleon_cert_from_paired_csr(
            csr=paired_csr,
            ca_cert=self.ca_cert,
            ca_key=self.mldsa_key
        )

        delta_cert_build = build_delta_cert_from_paired_cert(
            paired_cert=paired_cert,
        )

        der_data = encoder.encode(delta_cert_build)
        decoded_cert, rest = decoder.decode(der_data, asn1Spec=rfc9480.CMPCertificate())
        self.assertEqual(rest, b"")

        result = compare_pyasn1_objects(decoded_cert,
                                        delta_cert
                                        )

        self.assertTrue(result)






