# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import os
import unittest

from pyasn1_alt_modules import rfc9481
from resources.ca_kga_logic import validate_key_trans_recipient_info
from resources.certextractutils import get_field_from_certificate
from resources.certutils import parse_certificate
from resources.envdatautils import prepare_key_transport_recipient_info
from resources.certbuildutils import prepare_issuer_and_serial_number
from resources.utils import load_and_decode_pem_file, manipulate_first_byte


class TestValidationKTRI(unittest.TestCase):
    def setUp(self):
        self.cmp_cert = parse_certificate(load_and_decode_pem_file("data/unittest/rsa_cert_ski.pem"))
        self.bare_cert =  parse_certificate(load_and_decode_pem_file("data/unittest/bare_certificate.pem"))
        self.ski = get_field_from_certificate(self.cmp_cert, extension="ski")


    def test_valid_ktri_structure_with_ski(self):
        """
        GIVEN a KTRI structure with a certificate, which has the SKI extension,
        the `SubjectKeyIdentifier` structure is correctly used.
        WHEN validate_key_trans_recipient_info is called.
        THEN the validation should not raise an exception.
        """
        ktri = prepare_key_transport_recipient_info(version=2, key_enc_alg_oid=rfc9481.id_RSAES_OAEP,
                                                    encrypted_key=os.urandom(32), cmp_protection_cert=self.cmp_cert)

        validate_key_trans_recipient_info(ktri, cmp_cert=self.cmp_cert)

    def test_valid_ktri_structure_without_ski(self):
        """
        GIVEN a KTRI structure with a certificate, which has the SKI extension not set to
        the `IssuerAndSerialNumber` structure is correctly used.
        WHEN validate_key_trans_recipient_info is called.
        THEN the validation should not raise an exception.
        """
        ktri = prepare_key_transport_recipient_info(version=2, key_enc_alg_oid=rfc9481.id_RSAES_OAEP,
                                                    encrypted_key=os.urandom(32), cmp_protection_cert=self.bare_cert)
        validate_key_trans_recipient_info(ktri, cmp_cert=self.bare_cert)


    def test_ktri_invalid_use_of_serialNum_and_issuer(self):
        """
        GIVEN a KTRI structure with a certificate, which has the SKI extension,
        but the SKI is not set in the `rid` field, but the `IssuerAndSerialNumber` structure is used.
        WHEN validate_key_trans_recipient_info is called.
        THEN it should raise a ValueError indicating that version is incorrectly set.
        """
        iss_and_ser = prepare_issuer_and_serial_number(self.cmp_cert)
        ktri = prepare_key_transport_recipient_info(version=2, key_enc_alg_oid=rfc9481.id_RSAES_OAEP,
                                                    encrypted_key=os.urandom(32), issuer_and_ser=iss_and_ser)
        with self.assertRaises(ValueError):
            validate_key_trans_recipient_info(ktri, cmp_cert=self.cmp_cert)

    def test_ktri_invalid_version(self):
        """
        GIVEN a KTRI structure with an invalid version. (MUST be three)
        WHEN validate_key_trans_recipient_info is called.
        THEN it should raise a ValueError indicating that version is incorrectly set.
        """
        ktri = prepare_key_transport_recipient_info(version=3, cmp_protection_cert=self.cmp_cert)
        with self.assertRaises(ValueError):
            validate_key_trans_recipient_info(ktri, cmp_cert=self.cmp_cert)

    def test_ktri_invalid_rKeyId_ski(self):
        """
        GIVEN a KTRI structure with a certificate, which has the SKI extension,
        but the SKI is not correctly set in the `rid` field.
        WHEN validate_key_trans_recipient_info is called.
        THEN it should raise a ValueError indicating that the `rid` field is incorrectly set.
        """
        ktri = prepare_key_transport_recipient_info(version=2, ski=manipulate_first_byte(self.ski))
        with self.assertRaises(ValueError):
            validate_key_trans_recipient_info(ktri, cmp_cert=self.cmp_cert)

    def test_ktri_invalid_key_enc_alg(self):
        """
        GIVEN a KTRI structure with an invalid key encryption algorithm.
        WHEN validate_key_trans_recipient_info is called.
        THEN it should raise a ValueError indicating that the encryption algorithm is incorrectly set.
        """
        ktri = prepare_key_transport_recipient_info(version=2, cmp_protection_cert=self.cmp_cert, key_enc_alg_oid=rfc9481.id_Ed25519)
        with self.assertRaises(ValueError):
            validate_key_trans_recipient_info(ktri, cmp_cert=self.cmp_cert)

    def test_ktri_missing_encrypted_key(self):
        """
        GIVEN a KTRI structure missing the encryptedKey field.
        WHEN validate_key_trans_recipient_info is called.
        THEN it should raise a ValueError indicating that the encryptedKey field is absent.
        """
        ktri = prepare_key_transport_recipient_info(cmp_protection_cert=self.cmp_cert, version=2, encrypted_key=None)
        with self.assertRaises(ValueError):
            validate_key_trans_recipient_info(ktri, cmp_cert=self.cmp_cert)


if __name__ == "__main__":
    unittest.main()
