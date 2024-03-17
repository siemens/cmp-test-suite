import unittest

from resources.certutils import parse_certificate
from resources.utils import load_and_decode_pem_file


class TestCertUtils(unittest.TestCase):
    def test_load_certificate(self):
        """
        GIVEN a DER-encoded X509 certificate
        WHEN we try to parse it into a pyasn1 object
        THEN no errors will occur
        """
        raw = load_and_decode_pem_file('data/dummy-cert.pem')
        result = parse_certificate(raw)
        self.assertIsNotNone(result)
