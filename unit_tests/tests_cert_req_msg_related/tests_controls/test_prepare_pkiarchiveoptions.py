# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import os
import unittest

from pyasn1_alt_modules import rfc9480, rfc4211

from resources.asn1utils import try_decode_pyasn1
from resources.cmputils import prepare_pkiarchiveoptions_controls
from resources.deprecatedutils import prepare_encrypted_value
from resources.envdatautils import prepare_enveloped_data_with_pwri
from resources.keyutils import generate_key
from unit_tests.utils_for_test import try_encode_pyasn1


class TestPreparePKIArchiveOptions(unittest.TestCase):

    def test_test_prepare_pkiarchiveoptions_with_use_archive_flag(self):
        """
        GIVEN `use_archive_flag` is set to True.
        WHEN `prepare_pkiarchiveoptions_controls` is called.
        THEN the encoded value is checked to ensure it contains the expected
        """
        attr_info_val = prepare_pkiarchiveoptions_controls(
            use_archive_flag=True,
        )
        der_data = try_encode_pyasn1(attr_info_val)
        decoded_obj, rest = try_decode_pyasn1(der_data, rfc9480.AttributeTypeAndValue()) # type: ignore
        decoded_obj: rfc9480.AttributeTypeAndValue
        self.assertEqual(rest, b"")
        self.assertEqual(
            decoded_obj['type'],
            rfc4211.id_regCtrl_pkiArchiveOptions
        )
        pki_archive, rest = try_decode_pyasn1(decoded_obj["value"], rfc4211.PKIArchiveOptions()) # type: ignore
        pki_archive: rfc4211.PKIArchiveOptions
        self.assertEqual(rest, b"")
        self.assertEqual(pki_archive.getName(), "archiveRemGenPrivKey")
        self.assertEqual(bool(pki_archive["archiveRemGenPrivKey"]), True)

    def test_test_prepare_pkiarchiveoptions_with_use_archive_flag_false(self):
        """
        GIVEN `use_archive_flag` is set to True.
        WHEN `prepare_pkiarchiveoptions_controls` is called.
        THEN the encoded value is checked to ensure it contains the expected
        """
        attr_info_val = prepare_pkiarchiveoptions_controls(
            use_archive_flag=False,
        )
        der_data = try_encode_pyasn1(attr_info_val)
        decoded_obj, rest = try_decode_pyasn1(der_data, rfc9480.AttributeTypeAndValue()) # type: ignore
        decoded_obj: rfc9480.AttributeTypeAndValue
        self.assertEqual(rest, b"")
        self.assertEqual(
            decoded_obj['type'],
            rfc4211.id_regCtrl_pkiArchiveOptions
        )
        pki_archive, rest = try_decode_pyasn1(decoded_obj["value"], rfc4211.PKIArchiveOptions()) # type: ignore
        pki_archive: rfc4211.PKIArchiveOptions
        self.assertEqual(rest, b"")
        self.assertEqual(pki_archive.getName(), "archiveRemGenPrivKey")
        self.assertEqual(bool(pki_archive["archiveRemGenPrivKey"]), False)

    def test_prepare_pkiarchiveoptions_with_password_and_key(self):
        """
        GIVEN `password` and `private_key` are set.
        WHEN `prepare_pkiarchiveoptions_controls` is called.
        THEN the encoded value is checked to ensure it contains the expected
        """
        attr_info_val = prepare_pkiarchiveoptions_controls(
            private_key=generate_key("ed25519"),
            password="secret",
        )
        der_data = try_encode_pyasn1(attr_info_val)
        decoded_obj, rest = try_decode_pyasn1(der_data, rfc9480.AttributeTypeAndValue()) # type: ignore
        decoded_obj: rfc9480.AttributeTypeAndValue
        self.assertEqual(rest, b"")

    def test_prepare_pkiarchiveoptions_with_env_data(self):
        """
        GIVEN an `EnvelopedData` object.
        WHEN `prepare_pkiarchiveoptions_controls` is called.
        THEN the encoded value is checked to ensure it contains the expected
        """
        key = generate_key("ed25519")

        key_data = key.private_bytes_raw()

        env_data = prepare_enveloped_data_with_pwri(
            password="secret",
            data=key_data,
            for_enc_key=True,
        )

        attr_info_val = prepare_pkiarchiveoptions_controls(
            enc_key=env_data,
        )
        der_data = try_encode_pyasn1(attr_info_val)
        decoded_obj, rest = try_decode_pyasn1(der_data, rfc9480.AttributeTypeAndValue()) # type: ignore
        decoded_obj: rfc9480.AttributeTypeAndValue
        self.assertEqual(rest, b"")
        self.assertEqual(
            decoded_obj['type'],
            rfc4211.id_regCtrl_pkiArchiveOptions
        )

    def test_test_prepare_pkiarchiveoptions_with_encr_value(self):
        """
        GIVEN an `EncryptedValue` object.
        WHEN `prepare_pkiarchiveoptions_controls` is called.
        THEN the encoded value is checked to ensure it contains the expected
        """
        key = generate_key("ed25519")
        key_data = key.private_bytes_raw()

        encrypted_value = prepare_encrypted_value(
            data=key_data,
            kek=os.urandom(16),
            cek=os.urandom(16),
        )
        attr_info_val = prepare_pkiarchiveoptions_controls(
            enc_key=encrypted_value,
        )
        der_data = try_encode_pyasn1(attr_info_val)
        decoded_obj, rest = try_decode_pyasn1(der_data, rfc9480.AttributeTypeAndValue())
        decoded_obj: rfc9480.AttributeTypeAndValue
        self.assertEqual(rest, b"")
        self.assertEqual(
            decoded_obj['type'],
            rfc4211.id_regCtrl_pkiArchiveOptions
        )





