import unittest

from pq_logic.chempatkem import ChempatMLKEMPublicKey, ChempatSntrup761PrivateKey, ChempatMcEliecePublicKey, \
    ChempatSntrup761PublicKey, ChempatFrodoKEMPublicKey
from resources.certbuildutils import prepare_cert_template
from resources.keyutils import generate_key, load_public_key_from_spki

class TestChempatLoadAndExportKey(unittest.TestCase):

    def test_chempat_mlkem768_x25519(self):
        """
        GIVEN a ChempatMLKEMPublicKey.
        WHEN the public key is generated, exported and converted to spki.
        THEN the public key can be loaded from the exported public key.
        """
        key_first = generate_key("chempat", pq_name="ml-kem-768", trad_name="x25519")
        template = prepare_cert_template(key_first)

        self.assertEqual(key_first.public_key().key_size, 1216)
        self.assertEqual(len(key_first.private_bytes_raw()), 2432)
        self.assertEqual(key_first.ct_length, 1120)


        key_second = ChempatMLKEMPublicKey.from_public_bytes(key_first.public_key().public_bytes_raw(), "Chempat-X25519-ML-KEM-768")

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

        key_second = ChempatSntrup761PublicKey.from_public_bytes(key_first.public_key().public_bytes_raw(), "Chempat-X25519-sntrup761")
        key_third = load_public_key_from_spki(template["publicKey"])
        self.assertEqual(key_first.public_key(), key_second)
        self.assertEqual(key_first.public_key(), key_third)

    def test_chempat_mcelice_x25519(self):
        """
        GIVEN a ChempatMcEliecePublicKey.
        WHEN the public key is generated, exported and converted to spki.
        THEN the public key can be loaded from the exported public key.
        """
        key_first = generate_key("chempat", pq_name="mceliece-348864", trad_name="x25519")
        template = prepare_cert_template(key_first)

        self.assertEqual(key_first.public_key().key_size, 261152)
        self.assertEqual(len(key_first.private_bytes_raw()), 6524)
        self.assertEqual(key_first.ct_length, 128)

        key_second = ChempatMcEliecePublicKey.from_public_bytes(key_first.public_key().public_bytes_raw(), "Chempat-X25519-mceliece348864")
        key_third = load_public_key_from_spki(template["publicKey"])
        self.assertEqual(key_first.public_key(), key_second)
        self.assertEqual(key_first.public_key(), key_third)


    def test_chempat_frodokem_aes_1344_x448(self):
        """
        GIVEN a ChempatFrodoKEMPublicKey.
        WHEN the public key is generated, exported and converted to spki.
        THEN the public key can be loaded from the exported public key.
        """
        key_first = generate_key("chempat", pq_name="frodokem-1344-aes", trad_name="x448")
        template = prepare_cert_template(key_first)

        key_second = ChempatFrodoKEMPublicKey.from_public_bytes(key_first.public_key().public_bytes_raw(), "Chempat-X448-frodokem-1344-aes")
        key_third = load_public_key_from_spki(template["publicKey"])
        self.assertEqual(key_first.public_key(), key_second)
        self.assertEqual(key_first.public_key(), key_third)




