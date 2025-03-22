# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.certbuildutils import build_certificate
from resources.certutils import parse_certificate
from resources.general_msg_utils import (
    process_root_ca_update,
    validate_get_root_ca_cert_update,
    validate_root_ca_key_update_value_structure,
)
from resources.utils import load_and_decode_pem_file

from unit_tests.prepare_support_message_structures import (
    build_pkimessage_root_ca_key_update_content,
    build_root_ca_key_update_content,
)


class TestValidateRootCaKeyUpdateValueStructure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old_cert = parse_certificate(load_and_decode_pem_file("data/unittest/old_root_ca.pem"))
        cls.new_with_new_cert = parse_certificate(load_and_decode_pem_file("data/unittest/new_root_ca.pem"))
        cls.new_with_old_cert =  parse_certificate(load_and_decode_pem_file("data/unittest/new_with_old.pem"))
        cls.old_with_new_cert = parse_certificate(load_and_decode_pem_file( "data/unittest/old_with_new.pem"))

    def test_validate_RootCaKeyUpdateValue_structure_success(self):
        """
        GIVEN a correctly structured set of certificates representing a Root CA key update.
        WHEN `validate_root_ca_key_update_value_structure` is called.
        THEN it should validate successfully without raising an error.
        """
        validate_root_ca_key_update_value_structure(
            old_cert=self.old_cert,
            new_with_new=self.new_with_new_cert,
            new_with_old=self.new_with_old_cert,
            old_with_new=self.old_with_new_cert,
        )

    def test_validate_RootCaKeyUpdateValue_structure_public_key_mismatch(self):
        """
        GIVEN a set of certificates with a mismatched public key.
        WHEN `validate_root_ca_key_update_value_structure` is called.
        THEN a ValueError should be raised due to the public key mismatch.
        """
        mismatched_cert, _ = build_certificate(common_name="CN=MismatchedNewRootCA")

        with self.assertRaises(ValueError):
            validate_root_ca_key_update_value_structure(
                old_cert=self.old_cert,
                new_with_new=mismatched_cert,
                new_with_old=self.new_with_old_cert,
                old_with_new=self.old_with_new_cert,
            )

    def test_process_root_ca_update_with_valid_certs(self):
        """
        GIVEN a valid `RootCaKeyUpdateValue` structure with all required certificates.
        WHEN `process_root_ca_update` is called.
        THEN it should complete successfully, indicating that the update structure is valid.
        """
        root_ca_update = build_root_ca_key_update_content(
            new_with_new_cert=self.new_with_new_cert,
            new_with_old_cert=self.new_with_old_cert,
            old_with_new_cert=self.old_with_new_cert,
        )
        process_root_ca_update(root_ca_update, old_ca_cert=self.old_cert)

    def test_process_root_ca_update_mismatching_certs(self):
        """
        GIVEN a `RootCaKeyUpdateValue` structure with mismatched certificates.
        WHEN `process_root_ca_update` is called.
        THEN a ValueError should be raised due to the mismatched public keys in the certificates.
        """
        mismatched_cert, _ = build_certificate(common_name="CN=MismatchedNewRootCA")
        root_ca_update = build_root_ca_key_update_content(
            new_with_new_cert=mismatched_cert,
            new_with_old_cert=self.new_with_old_cert,
            old_with_new_cert=self.old_with_new_cert,
        )
        with self.assertRaises(ValueError):
            process_root_ca_update(root_ca_update, old_ca_cert=self.old_cert)

    def test_process_root_ca_update_missing_newWithNew(self):
        """
        GIVEN a `RootCaKeyUpdateValue` structure missing the `newWithNew` certificate.
        WHEN `process_root_ca_update` is called.
        THEN a ValueError should be raised, indicating that `newWithNew` is required but missing.
        """
        root_ca_update = build_root_ca_key_update_content(
            new_with_new_cert=None, new_with_old_cert=self.new_with_old_cert, old_with_new_cert=self.old_with_new_cert
        )
        with self.assertRaises(ValueError):
            process_root_ca_update(root_ca_update, old_ca_cert=self.old_cert)

    def test_process_root_ca_update_missing_newWithOld(self):
        """
        GIVEN a `RootCaKeyUpdateValue` structure missing the `newWithOld` certificate.
        WHEN `process_root_ca_update` is called.
        THEN a ValueError should be raised, indicating that `newWithOld` is required but missing.
        """
        root_ca_update = build_root_ca_key_update_content(
            new_with_new_cert=self.new_with_new_cert, new_with_old_cert=None, old_with_new_cert=self.old_with_new_cert
        )
        with self.assertRaises(ValueError):
            process_root_ca_update(root_ca_update, old_ca_cert=self.old_cert)

    def test_genp_message_with_valid_structure(self):
        """
        GIVEN a PKIMessage containing a valid `RootCaKeyUpdateValue` structure.
        WHEN `check_get_root_ca_cert_update` is called with the PKIMessage.
        THEN it should validate successfully, confirming the PKIMessage structure is valid.
        """
        pki_message = build_pkimessage_root_ca_key_update_content(
            new_with_new_cert=self.new_with_new_cert,
            new_with_old_cert=self.new_with_old_cert,
            old_with_new_cert=self.old_with_new_cert,
        )
        validate_get_root_ca_cert_update(pki_message, old_ca_cert=self.old_cert)


if __name__ == "__main__":
    unittest.main()
