# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

import resources.certbuildutils
from cryptography import x509
from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc5280, rfc9480

import resources.prepareutils
from resources import cmputils, keyutils
from resources.asn1utils import encode_to_der
from resources.certbuildutils import generate_certificate, generate_signed_csr
from resources.prepareutils import prepare_name, prepare_general_name
from resources.certextractutils import get_field_from_certificate
from resources.compareutils import compare_general_name_and_name
from resources.utils import decode_pem_string

from unit_tests.utils_for_test import convert_to_crypto_lib_cert


class TestPrepareCertTemplate(unittest.TestCase):
    def test_crypto_name(self):
        """
        GIVEN a common name string.
        WHEN parsed and encoded to DER.
        THEN the resulting `pyasn1` Name object should correctly match the original common name string.
        """
        common_name = "CN=LDevID Issuing CA v3,OU=Secure Device Onboarding Backend,O=Siemens IT"
        name_obj = resources.prepareutils.parse_common_name_from_str(common_name=common_name)
        self.assertEqual(common_name, name_obj.from_rfc4514_string(common_name).rfc4514_string())
        der_bytes = name_obj.public_bytes()
        pyasn1_name, rest = decoder.decode(der_bytes, asn1Spec=rfc5280.Name())
        self.assertEqual(rest, b"")

    def test_prepare_name_with_cert(self):
        """
        GIVEN a generated RSA key and certificate with a complex common name
        WHEN the certificate's issuer name is prepared and encoded,
        THEN the DER-encoded name should match the issuer data, and decoding should yield no remaining bytes.
        """
        key = keyutils.generate_key("rsa")
        cert = generate_certificate(
            key, common_name="CN=LDevID Issuing CA v3,OU=Secure Device Onboarding Backend,O=Siemens IT"
        )
        asn1cert = get_field_from_certificate(cert, "issuer")
        other_data = encoder.encode(asn1cert)
        cert_data = encoder.encode(cert["tbsCertificate"]["issuer"])
        self.assertEqual(other_data.hex(), cert_data.hex())

        obj, rest = decoder.decode(other_data, rfc9480.Name())
        self.assertEqual(rest, b"")
        tmp_cert = convert_to_crypto_lib_cert(cert)
        issuer_str = tmp_cert.issuer.rfc4514_string()
        issuer = rfc5280.Name()
        issuer = resources.prepareutils.prepare_name(common_name=issuer_str, target=issuer)
        my_data = encoder.encode(issuer)
        self.assertEqual(my_data.hex(), cert_data.hex())

    def test_from_openssl_notation_csr(self):
        """
        GIVEN a parsed a valid Name
        WHEN the get_openssl_name_notation function is called,
        THEN the function should return the correct OpenSSL-style notation of the X509Name
        """
        default_x509name = "C=DE,L=Munich,CN=Hans Mustermann"

        csr_signed, csr_key = generate_signed_csr(default_x509name, key="rsa")
        decoded_csr = decode_pem_string(csr_signed)
        parsed_csr = encoder.encode(cmputils.parse_csr(decoded_csr))

        self.assertEqual(x509.load_der_x509_csr(parsed_csr).subject.rfc4514_string(), default_x509name)

    def test_compare_general_name_and_name(self):
        """
        GIVEN a GeneralName and a Name object
        WHEN compare_general_name_and_name is called,
        THEN the function should return True if the names match and False if they do not
        """
        common_name = "C=DE,ST=Bavaria,L=Munich,CN=Joe Mustermann"
        general_name = prepare_general_name("directoryName", name_str=common_name)
        name_obj1 = prepare_name(common_name)
        name_obj1, rest = decoder.decode(encode_to_der(name_obj1), rfc9480.Name())
        self.assertEqual(rest, b"")

        general_name, rest = decoder.decode(encode_to_der(general_name), rfc9480.GeneralName())
        self.assertEqual(rest, b"")

        diff_name = common_name + "1"
        name_obj2 = prepare_name(diff_name)
        name_obj2, rest = decoder.decode(encode_to_der(name_obj2), rfc9480.Name())
        self.assertEqual(rest, b"")

        self.assertTrue(compare_general_name_and_name(general_name, name_obj1))
        self.assertFalse(diff_name == common_name)
        self.assertFalse(compare_general_name_and_name(general_name, name_obj2))


    def test_prepare_name_null_dn(self):
        """
        GIVEN a Null-DN to prepare.
        WHEN the name is prepared,
        THEN the resulting name should be empty and
        the resulting DER encoding should be 0x3000
        """
        name_obj = prepare_name(common_name="Null-DN")
        self.assertEqual(encoder.encode(name_obj).hex(), "3000")
