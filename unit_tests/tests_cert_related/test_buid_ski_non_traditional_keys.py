import unittest

from cryptography import x509

from resources.keyutils import generate_key


class TestPrepareSKINonTraditionalKey(unittest.TestCase):

    def test_composite_key(self):
        """
        GIVEN a composite key,
        WHEN the Subject Key Identifier is generated,
        THEN the Subject Key Identifier is generated successfully.
        """
        key = generate_key("composite-sig")
        ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
        self.assertTrue(ski)