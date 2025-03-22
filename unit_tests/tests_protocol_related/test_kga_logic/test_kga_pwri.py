# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1_alt_modules import rfc9481
from resources.ca_kga_logic import validate_password_recipient_info
from resources.envdatautils import prepare_pwri_structure


class TestValidationPWRI(unittest.TestCase):
    def setUp(self):
        self.cmp_protection_salt = b"BBBBBBBBBBBBBBBB"
        self.pbkdf2_salt = b"AAAAAAAAAAAAAAAA"


    def test_parse_parameters_pbkdf2_and_other_salt(self):
        """
        GIVEN a PWRI a valid structure.
        WHEN validate_PasswordRecipientInfo is called with the same salt.
        THEN it should raise a ValueError due to a same salt used for CMP protection.
        """
        pwri = prepare_pwri_structure()
        with self.assertRaises(ValueError):
            validate_password_recipient_info(pwri, self.pbkdf2_salt)

    def test_pwri_valid(self):
        """
        GIVEN a valid PWRI structure and the correct salt.
        WHEN validate_password_recipient_info is called.
        THEN no exception should be raised, and the validation should pass.
        """
        pwri = prepare_pwri_structure()
        validate_password_recipient_info(pwri, self.cmp_protection_salt)

    def test_pwri_invalid_version(self):
        """
        GIVEN a PWRI structure with an invalid version (not 0).
        WHEN validate_password_recipient_info is called.
        THEN it should raise a ValueError indicating the version field must be 0.
        """
        pwri = prepare_pwri_structure(version=1)

        with self.assertRaises(ValueError):
            validate_password_recipient_info(pwri, self.cmp_protection_salt)


    def test_pwri_invalid_key_derivation_algorithm(self):
        """
        GIVEN a PWRI structure with an invalid key derivation algorithm.
        WHEN validate_password_recipient_info is called.
        THEN it should raise a ValueError indicating that only the PBKDF2 algorithm is allowed.
        """
        pwri = prepare_pwri_structure(key_der_alg_id=rfc9481.id_RSAES_OAEP)

        with self.assertRaises(ValueError):
            validate_password_recipient_info(pwri, self.cmp_protection_salt)

    def test_pwri_invalid_key_encryption_algorithm(self):
        """
        GIVEN a PWRI structure that has set an invalid key encryption algorithm.
        WHEN validate_password_recipient_info is called.
        THEN it should raise a ValueError indicating that the encryptedKey field is absent.
        """
        pwri = prepare_pwri_structure(key_enc_alg_id=rfc9481.id_RSAES_OAEP)

        with self.assertRaises(ValueError):
            validate_password_recipient_info(pwri, self.cmp_protection_salt)

    def test_pwri_missing_encrypted_key(self):
        """
        GIVEN a PWRI structure that is missing the encryptedKey field.
        WHEN validate_password_recipient_info is called.
        THEN it should raise a ValueError indicating that the encryptedKey field is absent.
        """
        pwri = prepare_pwri_structure(enc_key=False)

        with self.assertRaises(ValueError):
            validate_password_recipient_info(pwri, self.cmp_protection_salt)



if __name__ == "__main__":
    unittest.main()
