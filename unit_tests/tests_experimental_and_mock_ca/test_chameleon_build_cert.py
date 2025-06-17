# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from mock_ca.ca_handler import CAHandler
from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc5280, rfc9480

from pq_logic.hybrid_sig.chameleon_logic import (
    build_chameleon_cert_from_paired_csr,
    build_delta_cert,
    build_delta_cert_from_paired_cert,
    build_paired_csr,
    extract_chameleon_attributes,
)
from resources.certbuildutils import compare_ski_value, prepare_extensions, validate_subject_key_identifier_extension
from resources.certutils import load_public_key_from_cert
from resources.keyutils import load_private_key_from_file
from unit_tests.utils_for_test import compare_pyasn1_objects, load_ca_cert_and_key


class TestBuildChameleonCert(unittest.TestCase):

    def setUp(self):
        self.ec_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        self.mldsa_key = load_private_key_from_file("data/keys/private-key-ml-dsa-44-seed.pem")
        self.common_name = "CN=Hans the Tester"
        self.ca_cert, self.ca_key = load_ca_cert_and_key()

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

        cert = build_delta_cert(csr=paired_csr, delta_value=delta_value, ca_cert=self.ca_cert, ca_key=self.mldsa_key)
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
            csr=paired_csr, ca_cert=self.ca_cert, ca_key=self.mldsa_key
        )
        public_key = load_public_key_from_cert(cert)
        self.assertEqual(public_key, self.ec_key.public_key())
        loaded_key = load_public_key_from_cert(delta_cert)
        self.assertEqual(loaded_key, self.mldsa_key.public_key())

    def test_build_delta_cert_from_extension(self):
        """
        GIVEN a paired CSR and a CA key and certificate.
        WHEN building a delta certificate.
        THEN the certificate can be correctly re-built.
        """
        paired_csr = build_paired_csr(
            delta_private_key=self.mldsa_key,
            base_private_key=self.ec_key,
        )
        paired_cert, delta_cert = build_chameleon_cert_from_paired_csr(
            csr=paired_csr,
            ca_cert=self.ca_cert,
            ca_key=self.mldsa_key,
            include_ski=False,
        )

        delta_cert_build = build_delta_cert_from_paired_cert(
            paired_cert=paired_cert,
        )

        der_data = encoder.encode(delta_cert_build)
        decoded_cert, rest = decoder.decode(der_data, asn1Spec=rfc9480.CMPCertificate())
        self.assertEqual(rest, b"")

        result = compare_pyasn1_objects(delta_cert_build, delta_cert)

        self.assertTrue(result)

    def test_chameleon_cert_build_with_skis(self):
        """
        GIVEN a paired CSR and a CA key and certificate.
        WHEN building a delta certificate with SKI,
        THEN the certificate is correctly built.
        """
        paired_csr = build_paired_csr(
            delta_private_key=self.mldsa_key,
            base_private_key=self.ec_key,
        )
        paired_cert, delta_cert = build_chameleon_cert_from_paired_csr(
            csr=paired_csr,
            ca_cert=self.ca_cert,
            ca_key=self.mldsa_key,
            include_ski=True,
        )

        validate_subject_key_identifier_extension(paired_cert, must_be_present=True)
        validate_subject_key_identifier_extension(delta_cert, must_be_present=True)

        public_key = load_public_key_from_cert(paired_cert)
        self.assertEqual(public_key, self.ec_key.public_key())
        loaded_key = load_public_key_from_cert(delta_cert)
        self.assertEqual(loaded_key, self.mldsa_key.public_key())

    def test_chameleon_cert_build_with_base_ski(self):
        """
        GIVEN a paired CSR and a CA key and certificate.
        WHEN building a delta certificate.
        THEN the certificate is correctly built.
        """
        extn = prepare_extensions(
            key=self.ec_key,
            critical=True,
        )

        paired_csr = build_paired_csr(
            delta_private_key=self.mldsa_key,
            base_private_key=self.ec_key,
            base_extensions=extn,
        )
        paired_cert, delta_cert = build_chameleon_cert_from_paired_csr(
            csr=paired_csr,
            ca_cert=self.ca_cert,
            ca_key=self.mldsa_key,
            include_ski=False,
        )

        validate_subject_key_identifier_extension(paired_cert, must_be_present=True)
        with self.assertRaises(ValueError):
            validate_subject_key_identifier_extension(delta_cert, must_be_present=True)

        public_key = load_public_key_from_cert(paired_cert)
        self.assertEqual(public_key, self.ec_key.public_key())
        loaded_key = load_public_key_from_cert(delta_cert)
        self.assertEqual(loaded_key, self.mldsa_key.public_key())

    def test_build_delta_cert_from_extension_with_skis(self):
        """
        GIVEN a paired CSR and a CA key and certificate.
        WHEN building a delta certificate with parsed SKI's extensions,
        THEN the certificate is correctly built and can be correctly re-built.
        """
        paired_csr = build_paired_csr(
            delta_private_key=self.mldsa_key,
            base_private_key=self.ec_key,
            base_extensions=prepare_extensions(key=self.ec_key.public_key(), critical=True),
            delta_extensions=prepare_extensions(key=self.mldsa_key.public_key(), critical=False),
        )

        paired_cert, delta_cert = build_chameleon_cert_from_paired_csr(
            csr=paired_csr,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            include_ski=None,
        )
        self.assertTrue(
            compare_ski_value(paired_cert, self.ec_key.public_key()), "The SKI should match the public key."
        )
        self.assertTrue(
            compare_ski_value(delta_cert, self.mldsa_key.public_key()), "The SKI should match the public key."
        )

        delta_cert_build = build_delta_cert_from_paired_cert(
            paired_cert=paired_cert,
        )
        self.assertTrue(
            compare_ski_value(delta_cert_build, self.mldsa_key.public_key()), "The SKI should match the public key."
        )

        der_data = encoder.encode(delta_cert_build)
        decoded_cert, rest = decoder.decode(der_data, asn1Spec=rfc9480.CMPCertificate())
        self.assertEqual(rest, b"")

        result = compare_pyasn1_objects(decoded_cert, delta_cert)

        self.assertTrue(result)

    def test_build_delta_cert_from_extension_with_skis_and_other(self):
        """
        GIVEN a paired CSR and a CA key and certificate.
        WHEN building a delta certificate,
        THEN the certificate is correctly built with SKI's and other extensions.
        """
        extensions = CAHandler()._prepare_extensions(ca_cert=self.ca_cert)

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
            delta_extensions=delta_extensions,
        )
        paired_cert, delta_cert = build_chameleon_cert_from_paired_csr(
            csr=paired_csr,
            ca_cert=self.ca_cert,
            ca_key=self.mldsa_key,
            extensions=extensions,
        )

        self.assertEqual(len(extensions) + 1, len(delta_cert["tbsCertificate"]["extensions"]))
        self.assertEqual(len(extensions) + 2, len(paired_cert["tbsCertificate"]["extensions"]))

        delta_cert_build = build_delta_cert_from_paired_cert(
            paired_cert=paired_cert,
        )
        self.assertEqual(len(extensions) + 1, len(delta_cert_build["tbsCertificate"]["extensions"]))

        der_data = encoder.encode(delta_cert_build)
        decoded_cert, rest = decoder.decode(der_data, asn1Spec=rfc9480.CMPCertificate())
        self.assertEqual(rest, b"")

        result = compare_pyasn1_objects(decoded_cert, delta_cert)

        self.assertTrue(result)
