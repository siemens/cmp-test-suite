# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import datetime
import unittest

from pyasn1_alt_modules import rfc4210
from resources.certbuildutils import build_csr
from resources.certutils import parse_certificate
from resources.cmputils import (
    build_p10cr_from_csr,
    patch_messageTime,
    patch_senderkid,
    patch_sendernonce,
    patch_transaction_id,
)
from resources.keyutils import load_private_key_from_file
from resources.utils import load_and_decode_pem_file

from unit_tests import utils_for_test
from unit_tests.utils_for_test import convert_to_crypto_lib_cert


class TestPKIMessagePatchingFunctions(unittest.TestCase):

    @classmethod
    def setUp(cls):
        private_key = load_private_key_from_file("./data/keys/private-key-ecdsa.pem")
        csr = build_csr(common_name="CN=Hans the Tester", signing_key=private_key)
        cls.sender_nonce = bytes.fromhex("A" * 32)
        pki_message = build_p10cr_from_csr(csr, exclude_fields="senderKID, transactionID")

        cls.pki_message = pki_message
        cls.private_key = private_key

        csr = build_csr(common_name="CN=Hans the Tester", signing_key=private_key)
        cls.other_pki_message = build_p10cr_from_csr(csr, sender_nonce=cls.sender_nonce)

    def test_patch_transaction_id(self):
        """
        GIVEN a PKIMessage with an existing transaction ID.
        WHEN patch_transaction_id is called with a new ID or prefix.
        THEN the transaction ID should be updated accordingly.
        """
        random_value = b"randombytes"
        updated_message = patch_transaction_id(self.pki_message, new_id=random_value, prefix="testprefix")

        # Verify the new transaction ID has the prefix
        expected_id = b"testprefixrandombytes"
        self.assertEqual(updated_message["header"]["transactionID"], expected_id)

    def test_patch_messagetime(self):
        """
        GIVEN a PKIMessage with an existing messageTime.
        WHEN patch_messagetime is called with a new time.
        THEN the messageTime should be updated to the new time or the current time.
        """
        new_time = datetime.datetime(2024, 1, 1, 12, 0, tzinfo=datetime.timezone.utc)
        updated_message = patch_messageTime(self.pki_message, new_time=new_time)

        # Convert the new time to GeneralizedTime format
        expected_time = rfc4210.useful.GeneralizedTime().fromDateTime(new_time)
        self.assertEqual(updated_message["header"]["messageTime"], expected_time)

    def test_patch_senderkid_with_bytes(self):
        """
        GIVEN a PKIMessage and a new senderKID.
        WHEN patch_senderkid is called with the new senderKID as bytes.
        THEN the senderKID should be updated accordingly.
        """
        new_sender_kid = b"newkid"
        updated_message = patch_senderkid(self.pki_message, new_sender_kid)

        # Verify the senderKID was updated
        self.assertEqual(updated_message["header"]["senderKID"].asOctets(), new_sender_kid)

    def test_patch_sendernonce(self):
        """
        GIVEN two PKIMessages, one with an existing senderNonce.
        WHEN patch_sendernonce is called to update the senderNonce.
        THEN the senderNonce of the first message should be updated to match the second message.
        """
        updated_message = patch_sendernonce(self.pki_message, self.other_pki_message, use_sender_nonce=True)

        self.assertEqual(self.pki_message["header"]["senderNonce"].asOctets(), self.sender_nonce)
        self.assertEqual(
            updated_message["header"]["senderNonce"].asOctets(), self.pki_message["header"]["senderNonce"].asOctets()
        )
        self.assertEqual(updated_message["header"]["senderNonce"].asOctets(), self.sender_nonce)

    def test_patch_senderkid_with_cert(self):
        """
        GIVEN a PKIMessage and a certificate object with a SubjectKeyIdentifier.
        WHEN patch_senderkid is called with the certificate object.
        THEN the senderKID should be extracted from the certificate and set correctly.
        """
        certificate = parse_certificate(load_and_decode_pem_file("data/unittest/rsa_cert_ski.pem"))
        updated_message = patch_senderkid(self.pki_message, certificate)
        crypto_lib = convert_to_crypto_lib_cert(cert=certificate)
        self.assertTrue(updated_message["header"]["senderKID"].isValue)
        self.assertEqual(
            updated_message["header"]["senderKID"].asOctets().hex(), utils_for_test.get_ski_extension(crypto_lib).hex()
        )

        with self.assertRaises(ValueError):
            certificate = parse_certificate(load_and_decode_pem_file("data/unittest/bare_certificate.pem"))
            patch_senderkid(self.pki_message, certificate)


if __name__ == "__main__":
    unittest.main()
