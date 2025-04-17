# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1_alt_modules import rfc9480

from resources.ca_ra_utils import prepare_certified_key_pair
from resources.certutils import parse_certificate
from resources.envdatautils import prepare_signed_data, prepare_enveloped_data, prepare_ktri
from resources.keyutils import load_private_key_from_file
from resources.utils import load_and_decode_pem_file
from unit_tests.utils_for_test import try_encode_pyasn1
from resources.asn1utils import try_decode_pyasn1


class TestPrepareCertifiedKeyPair(unittest.TestCase):

    def setUp(self):
        self.key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        self.cert = parse_certificate(load_and_decode_pem_file("data/unittest/bare_certificate.pem"))

    def test_prepare_cert_key_pair_cert(self):
        """
        GIVEN a valid certificate.
        WHEN preparing a certified key pair.
        THEN the `CertifiedKeyPair` structure is correctly prepared.
        """
        cert_key_pair = prepare_certified_key_pair(cert=self.cert,
                                                  )
        self.assertTrue(cert_key_pair["certOrEncCert"].isValue)
        self.assertTrue(cert_key_pair["certOrEncCert"]["certificate"].isValue)
        self.assertFalse(cert_key_pair["privateKey"].isValue)
        self.assertFalse(cert_key_pair["publicationInfo"].isValue)

        der_data = try_encode_pyasn1(cert_key_pair)
        _, rest = try_decode_pyasn1(der_data, rfc9480.CertifiedKeyPair())
        self.assertEqual(rest, b"")

    def test_prepare_cert_key_pair_private_key(self):
        """
        GIVEN a valid private key.
        WHEN preparing a certified key pair.
        THEN the `CertifiedKeyPair` structure is correctly prepared.
        """
        signed_data = prepare_signed_data(
            signing_key=self.key,
            cert=self.cert,
            private_keys=[self.key],
            sig_hash_name="sha256",
        )
        signed_data_der = try_encode_pyasn1(signed_data)

        ktri = prepare_ktri(
           ee_key=self.key.public_key(),
           cmp_protection_cert=self.cert,
           cek=b"\x00" * 32,
        )

        enveloped_data = prepare_enveloped_data(
            recipient_infos=ktri,
            data_to_protect=signed_data_der,
            cek=b"\x00" * 32,
            version=2,
        )


        cert_key_pair = prepare_certified_key_pair(private_key=enveloped_data,
                                                   cert=self.cert,
                                                  )

        self.assertTrue(cert_key_pair["certOrEncCert"]["certificate"].isValue)
        self.assertTrue(cert_key_pair["privateKey"].isValue)
        self.assertFalse(cert_key_pair["publicationInfo"].isValue)

        der_data = try_encode_pyasn1(cert_key_pair)
        _, rest = try_decode_pyasn1(der_data, rfc9480.CertifiedKeyPair())
        self.assertEqual(rest, b"")


    def test_prepare_cert_key_pair_encrCert(self):
        """
        GIVEN a valid encrypted certificate.
        WHEN preparing a certified key pair.
        THEN the `CertifiedKeyPair` structure is correctly prepared.
        """
        ktri = prepare_ktri(
            ee_key=self.key.public_key(),
            cmp_protection_cert=self.cert,
            cek=b"\x00" * 32,
        )

        enveloped_data = prepare_enveloped_data(
            recipient_infos=ktri,
            data_to_protect=b"Encrypted certificate",
            cek=b"\x00" * 32,
            version=2,
        )
        # encrCert must bind more, for upper functions.
        # this test ensures that this logic is correct.
        cert_key_pair = prepare_certified_key_pair(enc_cert=enveloped_data,
                                                   cert=self.cert,
                                                   )

        self.assertTrue(cert_key_pair["certOrEncCert"]["encryptedCert"].isValue)
        self.assertFalse(cert_key_pair["privateKey"].isValue)

        der_data = try_encode_pyasn1(cert_key_pair)
        _, rest = try_decode_pyasn1(der_data, rfc9480.CertifiedKeyPair())
        self.assertEqual(rest, b"")




