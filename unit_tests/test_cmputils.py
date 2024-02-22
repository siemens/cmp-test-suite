import unittest

# from resources import asn1utils
from resources import cmputils
from resources import cryptoutils
from resources.utils import load_and_decode_pem_file, decode_pem_string

class TestCmpUtils(unittest.TestCase):
    @classmethod
    def setUp(cls):
        raw_csr = load_and_decode_pem_file('data/example-csr.pem')
        cls.csr_object = cmputils.parse_csr(raw_csr)

        raw_pki_message = load_and_decode_pem_file('data/example-cmp-response-accept.pem')
        cls.pki_message = cmputils.parse_pki_message(raw_pki_message)


    def test_parse_error_response(self):
        raw = load_and_decode_pem_file('data/example-response-unsupported-algo.pem')
        pki_message = cmputils.parse_pki_message(raw)
        body = pki_message['body']
        self.assertEqual("error", body.getName())
        self.assertEqual("rejection", str(body['error']['pKIStatusInfo']['status']))

        # these are optional, though present in the specific example we're loading
        stringified_status = str(body['error']['pKIStatusInfo']['statusString'])
        self.assertIn('cannot create', stringified_status)


    def test_get_cmp_status_from_pki_message(self):
        status = cmputils.get_cmp_status_from_pki_message(self.pki_message)
        self.assertEqual("accepted", status)

    def test_get_cmp_response_type(self):
        message_type = cmputils.get_cmp_response_type(self.pki_message)
        self.assertEqual("ip", message_type)

    def test_get_cert_from_pki_message(self):
        serial_number, cert = cmputils.get_cert_from_pki_message(self.pki_message)
        self.assertEqual("7286628116517592062", serial_number)

    def test_build_p10cr_without_attributes(self):
        keypair = cryptoutils.generate_rsa_keypair()
        csr = cryptoutils.generate_csr("CN=Hans")
        signed_csr = cryptoutils.sign_csr(csr, keypair)
        asn1_csr = cmputils.parse_csr(decode_pem_string(signed_csr))
        p10cr = cmputils.build_p10cr_from_csr(asn1_csr, omit_fields='senderKID,senderNonce')

        self.assertNotIn('senderKID', p10cr)
        self.assertNotIn('senderNonce', p10cr)

    def test_build_p10cr(self):
        # TODO this is just an easy way to test the function, but it's not a real test
        # in pycharm select `unittest` from the dropdown and press shift+f9, set breakpoints where needed
        keypair = cryptoutils.generate_rsa_keypair()
        csr = cryptoutils.generate_csr("CN=Hans")
        signed_csr = cryptoutils.sign_csr(csr, keypair)
        asn1_csr = cmputils.parse_csr(decode_pem_string(signed_csr))
        p10cr = cmputils.build_p10cr_from_csr(asn1_csr)

        print(p10cr.prettyPrint())



if __name__ == '__main__':
    unittest.main()


