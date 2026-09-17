import unittest

from resources.keyutils import generate_key, get_key_security_strength


# TODO add test cases to get the security strength for HSS keys with different digest output sizes.

class TestGetKeySecurityStrength(unittest.TestCase):

    def test_rsa_2048_key_strength(self):
        """
        GIVEN an RSA 2048 key.
        WHEN get_key_security_strength is called,
        THEN is the returned security strength 112 bits.
        """
        key = generate_key("rsa", length=2048)
        self.assertEqual(get_key_security_strength(key), 112)
        self.assertEqual(get_key_security_strength(key.public_key()), 112)

    def test_rsa_kem_2048_key_strength(self):
        """
        GIVEN an RSA-KEM-2048 key.
        WHEN get_key_security_strength is called,
        THEN is the returned security strength 112 bits.
        """
        key = generate_key("rsa-kem", length=2048)
        self.assertEqual(get_key_security_strength(key), 112)
        self.assertEqual(get_key_security_strength(key.public_key()), 112)

    def test_rsa_3072_key_strength(self):
        """
        GIVEN an RSA 3072 key.
        WHEN get_key_security_strength is called,
        THEN is the returned security strength 128 bits.
        """
        key = generate_key("rsa", length=3072)
        self.assertEqual(get_key_security_strength(key), 128)
        self.assertEqual(get_key_security_strength(key.public_key()), 128)

    def test_ecc_p256_key_strength(self):
        """
        GIVEN an ECC P-256 key.
        WHEN get_key_security_strength is called,
        THEN is the returned security strength 128 bits.
        """
        key = generate_key("ecc", curve="secp256r1")
        self.assertEqual(get_key_security_strength(key), 128)
        self.assertEqual(get_key_security_strength(key.public_key()), 128)

    def test_ecc_p384_key_strength(self):
        """
        GIVEN an ECC P-384 key.
        WHEN get_key_security_strength is called,
        THEN is the returned security strength 192 bits.
        """
        key = generate_key("ecc", curve="secp384r1")
        self.assertEqual(get_key_security_strength(key), 192)
        self.assertEqual(get_key_security_strength(key.public_key()), 192)

    def test_ed25519_key_strength(self):
        """
        GIVEN an Ed25519 key.
        WHEN get_key_security_strength is called,
        THEN is the returned security strength 128 bits.
        """
        key = generate_key("ed25519")
        self.assertEqual(get_key_security_strength(key), 128)
        self.assertEqual(get_key_security_strength(key.public_key()), 128)

    def test_x25519_key_strength(self):
        """
        GIVEN an X25519 key.
        WHEN get_key_security_strength is called,
        THEN is the returned security strength 128 bits.
        """
        key = generate_key("x25519")
        self.assertEqual(get_key_security_strength(key), 128)
        self.assertEqual(get_key_security_strength(key.public_key()), 128)

    def test_ed448_key_strength(self):
        key = generate_key("ed448")
        self.assertEqual(get_key_security_strength(key), 224)
        self.assertEqual(get_key_security_strength(key.public_key()), 224)

    def test_x448_key_strength(self):
        """
        GIVEN an X448 key.
        WHEN get_key_security_strength is called,
        THEN is the returned security strength 224 bits.
        """
        key = generate_key("x448")
        self.assertEqual(get_key_security_strength(key), 224)
        self.assertEqual(get_key_security_strength(key.public_key()), 224)

    def test_xmss_key_sha256_strength(self):
        """
        GIVEN an XMSS-SHA2-10-256 key.
        WHEN get_key_security_strength is called,
        THEN is the returned security strength 128 bits.
        """
        key = generate_key("xmss-sha2_10_256")
        # ensure that the pq_streng flag is always considered.
        self.assertEqual(get_key_security_strength(key), 128)
        self.assertEqual(get_key_security_strength(key.public_key()), 128)

    def test_xmss_key_sha192_strength(self):
        """
        GIVEN an XMSS-SHA2-10-192 key.
        WHEN get_key_security_strength is called,
        THEN is the returned security strength 96 bits.
        """
        key = generate_key("xmss-sha2_10_192")
        self.assertEqual(get_key_security_strength(key), 96)
        self.assertEqual(get_key_security_strength(key.public_key()), 96)

    def test_hss_key_shake_n24_m24_strength(self):
        """
        GIVEN an HSS-SHAKE with LMS and LMOTS digest output size set to 24 bytes.
        WHEN get_key_security_strength is called,
        THEN is the returned security strength 96 bits.
        """
        key = generate_key("hss_lms_shake_m24_h5_lmots_shake_n24_w4")
        self.assertEqual(get_key_security_strength(key), 96)
        self.assertEqual(get_key_security_strength(key.public_key()), 96)

    def test_hss_key_shake_n32_m32_strength(self):
        """
        GIVEN an HSS-SHAKE with LMS and LMOTS digest output size set to 32 bytes.
        WHEN get_key_security_strength is called,
        THEN is the returned security strength 128 bits.
        """
        key = generate_key("hss_lms_shake_m32_h5_lmots_shake_n32_w4")
        self.assertEqual(get_key_security_strength(key), 128)
        self.assertEqual(get_key_security_strength(key.public_key()), 128)

    def test_hss_key_sha2_n24_m24_strength(self):
        """
        GIVEN an HSS-SHA2 with LMS and LMOTS digest output size set to 24 bytes.
        WHEN get_key_security_strength is called,
        THEN is the returned security strength 96 bits.
        """
        key = generate_key("hss_lms_sha256_m24_h5_lmots_sha256_n24_w8")
        self.assertEqual(get_key_security_strength(key), 96)
        self.assertEqual(get_key_security_strength(key.public_key()), 96)

    def test_hss_key_sha2_n32_m32_strength(self):
        """
        GIVEN an HSS-SHA2 with LMS and LMOTS digest output size set to 32 bytes.
        WHEN get_key_security_strength is called,
        THEN is the returned security strength 256 bits.
        """
        key = generate_key("hss_lms_sha256_m32_h5_lmots_sha256_n32_w8")
        self.assertEqual(get_key_security_strength(key), 128)
        self.assertEqual(get_key_security_strength(key.public_key()), 128)

    def test_ml_kem_1024_key_strength(self):
        """
        GIVEN an ML-KEM-1024 key.
        WHEN get_key_security_strength is called,
        THEN is the returned security strength 256 bits.
        """
        key = generate_key("ml-kem-1024")
        self.assertEqual(get_key_security_strength(key), 256)
        self.assertEqual(get_key_security_strength(key.public_key()), 256)

    def test_ml_dsa_44_key_strength(self):
        """
        GIVEN an ML-DSA-44 key.
        WHEN get_key_security_strength is called,
        THEN is the returned security strength 256 bits.
        """
        key = generate_key("ml-dsa-44")
        self.assertEqual(get_key_security_strength(key), 192)
        self.assertEqual(get_key_security_strength(key.public_key()), 192)

    def test_slh_dsa_sha2_128f_key_strength(self):
        """
        GIVEN an SLH-DSA-SHA2-128f key.
        WHEN get_key_security_strength is called,
        THEN is the returned security strength 128 bits.
        """
        key = generate_key("slh-dsa-sha2-128f")
        self.assertEqual(get_key_security_strength(key), 128)
        self.assertEqual(get_key_security_strength(key.public_key()), 128)

    def test_slh_dsa_sha2_192f_key_strength(self):
        """
        GIVEN an SLH-DSA-SHA2-192f key.
        WHEN get_key_security_strength is called,
        THEN is the returned security strength 192 bits.
        """
        key = generate_key("slh-dsa-sha2-192f")
        self.assertEqual(get_key_security_strength(key), 192)
        self.assertEqual(get_key_security_strength(key.public_key()), 192)

    def test_slh_dsa_sha2_256f_key_strength(self):
        """
        GIVEN an SLH-DSA-SHA2-256f key.
        WHEN get_key_security_strength is called,
        THEN is the returned security strength 256 bits.
        """
        key = generate_key("slh-dsa-sha2-256f")
        self.assertEqual(get_key_security_strength(key), 256)
        self.assertEqual(get_key_security_strength(key.public_key()), 256)


if __name__ == "__main__":
    unittest.main()
