import unittest

from pyasn1.codec.der import encoder, decoder
from pyasn1_alt_modules import rfc5652, rfc9480
from resources.ca_ra_utils import build_ip_cmp_message, prepare_cert_response
from resources.certbuildutils import build_certificate
from resources.certutils import parse_certificate
from resources.cmputils import build_p10cr_from_csr, parse_csr
from resources.envdatautils import prepare_enveloped_data, prepare_ktri
from resources.keyutils import load_private_key_from_file
from resources.utils import load_and_decode_pem_file


class TestBuildIpCmpMessage(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.cek = b"A" * 32
        cls.rsa_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.rsa_cert = parse_certificate(load_and_decode_pem_file("data/unittest/bare_certificate.pem"))

        kari = prepare_ktri(
            cmp_protection_cert=cls.rsa_cert,
            ee_key=cls.rsa_key.public_key(),
            cek=cls.cek,
        )
        cls.enc_cert = prepare_enveloped_data(
            enc_oid=rfc5652.id_data,
            recipient_infos=kari,
            cek=cls.cek,
            data_to_protect=b"Encrypted Data",
        )
        cls.cert_req_id = 0
        cls.ca_pubs = [cls.rsa_cert]
        csr = parse_csr(load_and_decode_pem_file("data/csrs/hybrid_csr_composite_sig_rsa2048_ml_dsa_44.pem"))
        cls.request =  build_p10cr_from_csr(
            csr=csr
        )

    def test_build_ip_cmp_message_with_cert(self):
        """
        GIVEN a certificate.
        WHEN the function is called with the certificate.
        THEN a valid PKIMessage is created.
        """
        pki_message, _ = build_ip_cmp_message(
            cert=self.rsa_cert,
            cert_req_id=self.cert_req_id,
            ca_pubs=self.ca_pubs,
        )
        self.assertIsInstance(pki_message, rfc9480.PKIMessage)
        self.assertEqual(pki_message["body"].getName(), "ip")

    def test_build_ip_cmp_message_with_enc_cert(self):
        """
        GIVEN an encrypted certificate.
        WHEN the function is called with the encrypted certificate.
        THEN a valid PKIMessage is created.
        """
        pki_message, _ = build_ip_cmp_message(
            enc_cert=self.enc_cert,
            cert_req_id=self.cert_req_id,
            ca_pubs=self.ca_pubs,
        )
        self.assertIsInstance(pki_message, rfc9480.PKIMessage)
        self.assertEqual(pki_message["body"].getName(), "ip")

    def test_build_ip_cmp_message_with_responses(self):
        """
        GIVEN an already prepared response.
        WHEN the function is called with the response.
        THEN a valid PKIMessage is created.
        """
        cert, key = build_certificate()
        responses = prepare_cert_response(
            cert=cert,
        )
        pki_message, _ = build_ip_cmp_message(
            responses=responses,
            cert_req_id=self.cert_req_id,
            ca_pubs=self.ca_pubs,
        )
        der_data = encoder.encode(pki_message)
        decoded_response, rest = decoder.decode(der_data, asn1Spec=rfc9480.PKIMessage())
        self.assertEqual(rest, b"")

    def test_build_ip_cmp_message_with_request(self):
        """
        GIVEN a request.
        WHEN the function is called with the request.
        THEN a valid PKIMessage is created.
        """
        pki_message, _ = build_ip_cmp_message(
            request=self.request,
            cert_req_id=self.cert_req_id,
            ca_pubs=self.ca_pubs,
            ca_cert=self.rsa_cert,
            ca_key=self.rsa_key,
        )
        self.assertIsInstance(pki_message, rfc9480.PKIMessage)
        self.assertEqual(pki_message["body"].getName(), "ip")

    def test_build_ip_cmp_message_raises_value_error(self):
        """
        GIVEN no arguments.
        WHEN the function is called.
        THEN a ValueError is raised.
        """
        with self.assertRaises(ValueError):
            build_ip_cmp_message()

if __name__ == "__main__":
    unittest.main()