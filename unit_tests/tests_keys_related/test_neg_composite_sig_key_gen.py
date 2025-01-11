import unittest

from pq_logic.keys.comp_sig_cms03 import CompositeSigCMSPrivateKey
from resources.exceptions import InvalidKeyCombination
from resources.keyutils import generate_key


class TestNegCompositeSigKey(unittest.TestCase):
    def test_neg_composite_sig_key_gen_rsa(self):
        """
        Generate a composite signature key with RSA traditional key and ML-DSA-44 post-quantum key.
        WHEN the key is generated,
        THEN the key is generated successfully.
        """
        key = generate_key("bad_rsa_key")
        comp_key = generate_key("composite-sig", trad_key=key, pq_key=None)
        self.assertEqual(comp_key.trad_key.public_key(), key.public_key())
        self.assertEqual(comp_key.pq_key.name, "ml-dsa-44")

    def test_neg_composite_sig_key_sign(self):
        """
        GIVEN A composite signature key with an invalid key combination.
        WHEN the key sign's the data, it should be successful, but when verified,
        THEN should an InvalidKeyCombination exception be raised.
        """
        key = generate_key("bad_rsa_key")
        pq_key = generate_key("ml-dsa-44")
        comp = CompositeSigCMSPrivateKey(trad_key=key, pq_key=pq_key)

        sig = comp.sign(b"data")

        with self.assertRaises(InvalidKeyCombination):
            comp.public_key().verify(sig, b"data")