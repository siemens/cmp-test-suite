# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1_alt_modules import rfc5280

from pq_logic.tmp_oids import COMPOSITE_KEM_DHKEMRFC9180_NAME_2_OID, id_chempat_x25519_sntrup761, \
    id_comp_kem_mlkem768_rsa2048
from resources.ca_ra_utils import get_popo_from_pkimessage, get_cert_template_from_pkimessage
from resources.cmputils import build_ir_from_key
from resources.keyutils import generate_key, load_public_key_from_spki
from resources.oidutils import XWING_OID_STR, id_ml_kem_768, PQ_NAME_2_OID
from unit_tests.utils_for_test import de_and_encode_pkimessage


class TestBuildPKIMessageNonSigKeys(unittest.TestCase):

    def test_build_mlkem_pkimessage(self):
        """
        GIVEN a key of type ml-kem-768.
        WHEN a PKIMessage is built from the key.
        THEN the PKIMessage should contain the correct SubjectPublicKeyInfo and POPO.
        """
        key = generate_key("ml-kem-768")
        ir = build_ir_from_key(key)
        obj = de_and_encode_pkimessage(ir)
        spki = get_cert_template_from_pkimessage(obj)["publicKey"]
        spki_new = rfc5280.SubjectPublicKeyInfo()

        spki_new["algorithm"] = spki["algorithm"]
        spki_new["subjectPublicKey"] = spki["subjectPublicKey"]
        self.assertEqual(str(spki["algorithm"]["algorithm"]), str(id_ml_kem_768))
        pub_key = load_public_key_from_spki(spki_new)
        self.assertEqual(pub_key, key.public_key())
        popo = get_popo_from_pkimessage(obj)
        self.assertTrue(popo["keyEncipherment"].isValue)
        self.assertTrue(popo["keyEncipherment"]["subsequentMessage"].isValue)
        self.assertEqual(str(popo["keyEncipherment"]["subsequentMessage"]), "encrCert")

    def test_build_frodokem(self):
        """
        GIVEN a key of type frodokem-1344-aes.
        WHEN a PKIMessage is built from the key.
        THEN the PKIMessage should contain the correct SubjectPublicKeyInfo and POPO.
        """
        key = generate_key("frodokem-1344-aes")
        ir = build_ir_from_key(key)
        obj = de_and_encode_pkimessage(ir)
        spki = get_cert_template_from_pkimessage(obj)["publicKey"]
        spki_new = rfc5280.SubjectPublicKeyInfo()

        spki_new["algorithm"] = spki["algorithm"]
        spki_new["subjectPublicKey"] = spki["subjectPublicKey"]
        self.assertEqual(str(spki["algorithm"]["algorithm"]), str(PQ_NAME_2_OID["frodokem-1344-aes"]))
        pub_key = load_public_key_from_spki(spki_new)
        self.assertEqual(pub_key, key.public_key())
        popo = get_popo_from_pkimessage(obj)
        self.assertTrue(popo["keyEncipherment"].isValue)
        self.assertTrue(popo["keyEncipherment"]["subsequentMessage"].isValue)
        self.assertEqual(str(popo["keyEncipherment"]["subsequentMessage"]), "encrCert")

    def test_build_xwing_pkimessage(self):
        """
        GIVEN a key of type xwing.
        WHEN a PKIMessage is built from the key.
        THEN the PKIMessage should contain the correct SubjectPublicKeyInfo and POPO.
        """
        key = generate_key("xwing")
        ir = build_ir_from_key(key)
        obj = de_and_encode_pkimessage(ir)
        spki = get_cert_template_from_pkimessage(obj)["publicKey"]
        spki_new = rfc5280.SubjectPublicKeyInfo()
        spki_new["algorithm"] = spki["algorithm"]
        spki_new["subjectPublicKey"] = spki["subjectPublicKey"]
        self.assertEqual(str(spki["algorithm"]["algorithm"]), XWING_OID_STR)
        pub_key = load_public_key_from_spki(spki_new)
        self.assertEqual(pub_key, key.public_key())
        popo = get_popo_from_pkimessage(obj)
        self.assertTrue(popo["keyEncipherment"].isValue)
        self.assertTrue(popo["keyEncipherment"]["subsequentMessage"].isValue)
        self.assertEqual(str(popo["keyEncipherment"]["subsequentMessage"]), "encrCert")


    def test_build_composite_kem(self):
        """
        GIVEN a key of type composite-kem.
        WHEN a PKIMessage is built from the key.
        THEN the PKIMessage should contain the correct SubjectPublicKeyInfo and POPO.
        """
        key = generate_key("composite-kem", pq_name="ml-kem-768", trad_name="rsa", length="2048")
        ir = build_ir_from_key(key)
        obj = de_and_encode_pkimessage(ir)
        spki = get_cert_template_from_pkimessage(obj)["publicKey"]
        self.assertEqual(str(spki["algorithm"]["algorithm"]), str(id_comp_kem_mlkem768_rsa2048))
        pub_key = load_public_key_from_spki(spki)
        self.assertEqual(pub_key, key.public_key())
        popo = get_popo_from_pkimessage(obj)
        self.assertTrue(popo["keyEncipherment"].isValue)
        self.assertTrue(popo["keyEncipherment"]["subsequentMessage"].isValue)
        self.assertEqual(str(popo["keyEncipherment"]["subsequentMessage"]), "encrCert")


    def test_build_composite_dhkem(self):
        """
        GIVEN a key of type composite-dhkem.
        WHEN a PKIMessage is built from the key.
        THEN the PKIMessage should contain the correct SubjectPublicKeyInfo and POPO.
        """
        key = generate_key("composite-dhkem")
        ir = build_ir_from_key(key)
        obj = de_and_encode_pkimessage(ir)
        spki = get_cert_template_from_pkimessage(obj)["publicKey"]
        spki_new = rfc5280.SubjectPublicKeyInfo()

        spki_new["algorithm"] = spki["algorithm"]
        spki_new["subjectPublicKey"] = spki["subjectPublicKey"]
        oid = COMPOSITE_KEM_DHKEMRFC9180_NAME_2_OID["composite-dhkem-ml-kem-768-x25519"]
        self.assertEqual(str(spki["algorithm"]["algorithm"]), str(oid))
        pub_key = load_public_key_from_spki(spki_new)
        self.assertEqual(pub_key, key.public_key())
        popo = get_popo_from_pkimessage(obj)
        self.assertTrue(popo["keyEncipherment"].isValue)
        self.assertTrue(popo["keyEncipherment"]["subsequentMessage"].isValue)
        self.assertEqual(str(popo["keyEncipherment"]["subsequentMessage"]), "encrCert")


    def test_build_chempat(self):
        """
        GIVEN a key of type chempat.
        WHEN a PKIMessage is built from the key.
        THEN the PKIMessage should contain the correct SubjectPublicKeyInfo and POPO.
        """
        key = generate_key("chempat", pq_name="sntrup761", trad_name="x25519")
        ir = build_ir_from_key(key)
        obj = de_and_encode_pkimessage(ir)
        spki = get_cert_template_from_pkimessage(obj)["publicKey"]
        spki_new = rfc5280.SubjectPublicKeyInfo()

        spki_new["algorithm"] = spki["algorithm"]
        spki_new["subjectPublicKey"] = spki["subjectPublicKey"]
        self.assertEqual(str(spki["algorithm"]["algorithm"]), str(
            id_chempat_x25519_sntrup761))
        pub_key = load_public_key_from_spki(spki_new)
        self.assertEqual(pub_key, key.public_key())
        popo = get_popo_from_pkimessage(obj)
        self.assertTrue(popo["keyEncipherment"].isValue)
        self.assertTrue(popo["keyEncipherment"]["subsequentMessage"].isValue)
        self.assertEqual(str(popo["keyEncipherment"]["subsequentMessage"]), "encrCert")

