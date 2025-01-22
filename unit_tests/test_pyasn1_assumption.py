# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

import pyasn1
from pyasn1.codec.der import encoder
from pyasn1.type import base, char, tag, univ, useful
from pyasn1_alt_modules import rfc5280, rfc5652, rfc9480, rfc9481
from resources.asn1utils import encode_to_der
from resources.envdatautils import prepare_encrypted_content_info


class TestPyasn1Assumptions(unittest.TestCase):

    def test_with_schema_object(self):
        """
        GIVEN two AlgorithmIdentifier objects with the same algorithm and parameters
        WHEN comparing them using the `==` operator, if one is a schema object,
        THEN the comparison should not throw an exception, but if one is not a schema object, it should thrown
        an exception, if values are not set.
        """
        alg_id = rfc5280.AlgorithmIdentifier()
        alg_id["algorithm"] = rfc9480.id_DHBasedMac
        self.assertFalse(alg_id == rfc9480.AlgorithmIdentifier())  # does not throw exception

        with self.assertRaises(Exception):
            alg_id = rfc9480.AlgorithmIdentifier()
            alg_id["algorithm"] = rfc9480.id_DHBasedMac
            alg_id["parameters"] = rfc9480.id_DHBasedMac

            alg_id2 = rfc9480.AlgorithmIdentifier()
            alg_id2["algorithm"] = rfc9480.id_DHBasedMac

            alg_id == alg_id2

    def test_null_diff(self):
        """
        GIVEN `pyasn1` Null objects and AlgorithmIdentifier objects with and without explicit Null parameters
        WHEN comparing their DER-encoded values
        THEN it should correctly handle the difference between an explicitly defined Null and a schema-defined Null
        """
        # needed for protectionAlgId comparison.
        self.assertEqual(encode_to_der(univ.Null("")).hex(), "0500")
        self.assertFalse(univ.Null().isValue)
        self.assertEqual(encode_to_der(univ.Null()).hex(), "0500")
        alg_id = rfc5280.AlgorithmIdentifier()
        alg_id2 = rfc5280.AlgorithmIdentifier()

        # so when every Null is required to be present use univ.Null("")
        alg_id["algorithm"] = rfc9481.sha384WithRSAEncryption
        alg_id["parameters"] = univ.Null("")

        alg_id2["algorithm"] = rfc9481.sha384WithRSAEncryption
        alg_id2["parameters"] = univ.Null()

        # because Null is a schema object!
        with self.assertRaises(Exception):
             alg_id2 == alg_id

        encoded_alg_id = encode_to_der(alg_id)
        encoded_alg_id2 = encode_to_der(alg_id2)

        # so show that Null is not encoded.
        self.assertNotEqual(encoded_alg_id, encoded_alg_id2)
        self.assertEqual(encoded_alg_id.hex(), "300d06092a864886f70d01010c0500")
        self.assertEqual(encoded_alg_id2.hex() + "0500", "300b06092a864886f70d01010c0500")

        # Only difference is the size!
        modified_encoded_alg_id2 = encoded_alg_id2.hex().replace("b", "d", 1) + "0500"
        self.assertEqual(modified_encoded_alg_id2, encoded_alg_id.hex())


    def test_for_correct_type(self):
        """
        GIVEN various pyasn1 data types
        WHEN checking the type of each using `assertIsInstance`
        THEN it should confirm that all instances are of the base `Asn1Type` type
        """
        # needed for type checks, to make sure that try_to_log_pkimessage
        # and so on, are checking for the correct type.
        self.assertIsInstance(univ.BitString(""), base.Asn1Type)
        self.assertIsInstance(univ.Integer(1), base.Asn1Type)
        self.assertIsInstance(univ.Sequence(), base.Asn1Type)
        self.assertIsInstance(univ.SequenceOf(), base.Asn1Type)
        self.assertIsInstance(univ.Set(), base.Asn1Type)
        self.assertIsInstance(univ.SetOf(), base.Asn1Type)
        self.assertIsInstance(char.UTF8String("Text"), base.Asn1Type)
        self.assertIsInstance(useful.GeneralizedTime(), base.Asn1Type)
        self.assertIsInstance(useful.UTCTime(), base.Asn1Type)

    def test_show_dict_empty_assignment(self):
        """
        GIVEN an empty list of RecipientInfos.
        WHEN setting the RecipientInfos in an EnvelopedData object directly,
        THEN the structure should be empty and nothing should be visible.
        """
        # But if set like this, the structure is empty.
        target = rfc5652.EnvelopedData().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        infos = rfc5652.RecipientInfos()
        infos.extend([])
        target["recipientInfos"] = infos
        enc_key = rfc9480.EncryptedKey()
        enc_key["envelopedData"] = target
        self.assertFalse(target.isValue)
        self.assertFalse(enc_key.isValue)
        self.assertEqual(enc_key.prettyPrint(), "EncryptedKey:\n")

    def test_show_set_by_component_name_is_insecure(self):
        """
        GIVEN an empty list of RecipientInfos.
        WHEN setting the RecipientInfos in an EnvelopedData object using `setComponentByName`,
        THEN the structure should not be empty and should not be able to be encoded,
        due to the RecipientInfos being treated as a value.
        """
        # This is a test to show that the behavior of the `setComponentByName` method
        # is different from the directly dictionary assignment.
        # This is important for debugging to now, why structures vanish or are not
        # able to be encoded.
        empty_list = []
        target = rfc5652.EnvelopedData().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        infos = rfc5652.RecipientInfos()
        infos.extend(empty_list)

        target["version"] = 2
        target["encryptedContentInfo"] = prepare_encrypted_content_info(cek=b"B" * 32, data_to_protect=b"AAAAAAAA")

        # needs to be set this way, otherwise the structure is empty, if an empty
        # list is parsed.
        target.setComponentByName("recipientInfos", infos)

        enc_key = rfc9480.EncryptedKey()
        enc_key["envelopedData"] = target
        self.assertTrue(target.isValue)
        # pyasn1 will not set the value, if non-optional fields are not set.
        # because `recipientInfos` is now treated as value.
        self.assertTrue(enc_key.isValue)

        with self.assertRaises(pyasn1.error.PyAsn1Error):
            encoder.encode(enc_key)





