# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.chempat_key import ChempatMLKEMPublicKey, ChempatSntrup761PrivateKey, ChempatMcEliecePublicKey, \
    ChempatSntrup761PublicKey, ChempatFrodoKEMPublicKey, ChempatMLKEMPrivateKey, ChempatMcEliecePrivateKey, \
    ChempatFrodoKEMPrivateKey
from resources.certbuildutils import prepare_cert_template
from resources.keyutils import generate_key, load_public_key_from_spki

class TestChempatLoadAndExportKey(unittest.TestCase):

    def test_chempat_mlkem768_x25519(self):
        """
        GIVEN a ChempatMLKEMPublicKey.
        WHEN the public key is generated, exported and converted to spki.
        THEN the public key can be loaded from the exported public key.
        """
        key_first = generate_key("chempat", pq_name="ml-kem-768", trad_name="x25519") # type: ignore
        key_first: ChempatMLKEMPrivateKey
        template = prepare_cert_template(key_first)

        self.assertEqual(key_first.public_key().key_size, 1216)
        self.assertEqual(len(key_first.private_bytes_raw()), 2432)
        self.assertEqual(key_first.ct_length, 1120)


        _name = "chempat-ml-kem-768-x25519"
        data = key_first.public_key().public_bytes_raw()
        key_second = ChempatMLKEMPublicKey.from_public_bytes(data, _name)


        key_third = load_public_key_from_spki(template["publicKey"])
        self.assertEqual(key_first.public_key(), key_second)
        self.assertEqual(key_first.public_key(), key_third)

    def test_chempat_sntrup761_x25519(self):
        """
        GIVEN a ChempatSntrup761PrivateKey.
        WHEN the public key is generated, exported and converted to spki.
        THEN the private key can be loaded from the exported private key.
        """
        key_first = ChempatSntrup761PrivateKey.generate()
        template = prepare_cert_template(key_first)

        self.assertEqual(key_first.public_key().key_size, 1190)
        self.assertEqual(len(key_first.private_bytes_raw()), 1795)
        self.assertEqual(key_first.ct_length, 1071)

        _name = "chempat-sntrup761-x25519"
        data = key_first.public_key().public_bytes_raw()
        key_second = ChempatSntrup761PublicKey.from_public_bytes(data, _name)

        key_third = load_public_key_from_spki(template["publicKey"])
        self.assertEqual(key_first.public_key(), key_second)
        self.assertEqual(key_first.public_key(), key_third)

    def test_chempat_mcelice_x25519(self):
        """
        GIVEN a ChempatMcEliecePublicKey.
        WHEN the public key is generated, exported and converted to spki.
        THEN the public key can be loaded from the exported public key.
        """
        key_first = generate_key("chempat", # type: ignore
                                 pq_name="mceliece-348864", trad_name="x25519")

        key_first: ChempatMcEliecePrivateKey
        template = prepare_cert_template(key_first)

        self.assertEqual(key_first.public_key().key_size, 261152)
        self.assertEqual(len(key_first.private_bytes_raw()), 6524)
        self.assertEqual(key_first.ct_length, 128)
        _name = "chempat-mceliece-348864-x25519"
        data = key_first.public_key().public_bytes_raw()
        key_second = ChempatMcEliecePublicKey.from_public_bytes(data, _name)
        key_third = load_public_key_from_spki(template["publicKey"])

        self.assertEqual(key_first.public_key(), key_second)
        self.assertEqual(key_first.public_key(), key_third)


    def test_chempat_frodokem_aes_1344_x448(self):
        """
        GIVEN a ChempatFrodoKEMPublicKey.
        WHEN the public key is generated, exported and converted to spki.
        THEN the public key can be loaded from the exported public key.
        """
        key_first = generate_key("chempat", pq_name="frodokem-1344-aes", trad_name="x448") # type: ignore
        key_first: ChempatFrodoKEMPrivateKey
        template = prepare_cert_template(key_first)

        _name = "chempat-frodokem-1344-aes-x448"
        data = key_first.public_key().public_bytes_raw()
        key_second = ChempatFrodoKEMPublicKey.from_public_bytes(data, _name)
        key_third = load_public_key_from_spki(template["publicKey"])
        self.assertEqual(key_first.public_key(), key_second)
        self.assertEqual(key_first.public_key(), key_third)




