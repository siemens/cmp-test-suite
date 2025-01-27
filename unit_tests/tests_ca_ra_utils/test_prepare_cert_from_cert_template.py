import unittest
from resources.certbuildutils import prepare_cert_template, build_cert_from_cert_template
from resources.certutils import parse_certificate
from resources.keyutils import generate_key, load_private_key_from_file
from resources.utils import load_and_decode_pem_file


class TestBuildCertFromCertTemplate(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ca_key = load_private_key_from_file(
            "data/keys/private-key-rsa.pem", password=None
        )
        cls.ca_cert = parse_certificate(
            load_and_decode_pem_file("data/unittest/ca2_cert_rsa.pem")
        )

    def test_build_pq_key(self):
        """
        GIVEN a PQ key and certificate template.
        WHEN building a certificate from a template,
        THEN the certificate is built correctly.
        """
        pq_key = generate_key("ml-dsa-65")
        cert_template = prepare_cert_template(key=pq_key.public_key(),
                                              subject="CN=Hans the Tester",
                                              serial_number=15,
                                              )
        cert = build_cert_from_cert_template(cert_template,
                                             ca_key=self.ca_key,
                                             ca_cert=self.ca_cert,
                                             )
        self.assertEqual(int(cert["tbsCertificate"]["serialNumber"]), 15)

