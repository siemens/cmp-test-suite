import unittest

from cryptography.hazmat.primitives.serialization import load_pem_private_key

import keyutils
import oid_mapping
# from resources import asn1utils
from resources import cmputils
from resources import cryptoutils
from resources.asn1utils import get_asn1_value_as_bytes, get_asn1_value_as_string, get_asn1_value
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

    def test_parse_p10cr_success_response(self):
        raw = load_and_decode_pem_file('data/example-response-p10rp-cert.pem')
        pki_message = cmputils.parse_pki_message(raw)

        sender_nonce = get_asn1_value_as_bytes(pki_message, 'header.senderNonce')
        self.assertEqual(sender_nonce, b'\xd3\xcd\x9d\xdd\xe5n+\xad\x84\x82U\xac\xa8&\xf9\xc0')

        recip_nonce = get_asn1_value_as_bytes(pki_message, 'header.recipNonce')
        self.assertEqual(recip_nonce, b'1111111122222222')

        recipient = get_asn1_value_as_string(pki_message, 'header.recipient.directoryName.rdnSequence/0/0.value')
        self.assertEqual(recipient, 'Upstream-CMP-ENDENTITY')

        self.assertEqual("cp", cmputils.get_cmp_response_type(pki_message))

        response_status = str(get_asn1_value(pki_message, 'body.cp.response/0.status.status'))
        self.assertEqual('accepted', response_status)

        cert_subject = get_asn1_value_as_string(pki_message, 'body.cp.response/0.certifiedKeyPair.certOrEncCert.'
                                                             'certificate.tbsCertificate.subject.rdnSequence/0/0.value')
        self.assertEqual(cert_subject, 'Hans Mustermann')

    def test_get_cmp_status_from_pki_message(self):
        status = cmputils.get_cmp_status_from_pki_message(self.pki_message)
        self.assertEqual("accepted", status)

    def test_get_cmp_response_type(self):
        message_type = cmputils.get_cmp_response_type(self.pki_message)
        self.assertEqual("ip", message_type)

    def test_get_cert_from_pki_message(self):
        cert = cmputils.get_cert_from_pki_message(self.pki_message)
        serial_number = str(cert['serialNumber'])
        self.assertEqual("7286628116517592062", serial_number)

        sig_algorithm = (cert['signature']['algorithm'])
        self.assertEqual('1.2.840.113549.1.1.5', str(sig_algorithm))

        hash_alg_name = oid_mapping.get_hash_from_signature_oid(sig_algorithm)
        self.assertEqual('sha1', hash_alg_name.split("-")[1])

    def test_build_p10cr_without_attributes(self):
        keypair = keyutils.generate_key("rsa")
        csr = cryptoutils.generate_csr("CN=Hans")
        signed_csr = cryptoutils.sign_csr(csr, keypair)
        asn1_csr = cmputils.parse_csr(decode_pem_string(signed_csr))
        p10cr = cmputils.build_p10cr_from_csr(asn1_csr, omit_fields='senderKID,senderNonce')

        self.assertNotIn('senderKID', p10cr)
        self.assertNotIn('senderNonce', p10cr)

    def test_build_p10cr(self):
        # TODO this is just an easy way to test the function, but it's not a real test
        # in pycharm select `unittest` from the dropdown and press shift+f9, set breakpoints where needed
        keypair = keyutils.generate_key("rsa")
        csr = cryptoutils.generate_csr("CN=Hans")
        signed_csr = cryptoutils.sign_csr(csr, keypair)
        asn1_csr = cmputils.parse_csr(decode_pem_string(signed_csr))
        p10cr = cmputils.build_p10cr_from_csr(asn1_csr, implicit_confirm=True)
        der_encoded = cmputils.encode_to_der(p10cr)
        # print(b64encode(der_encoded))
        # print(p10cr.prettyPrint())

    def test_build_cert_conf(self):
        """This is just a way to invoke the logic in the given functions"""
        cert = cmputils.get_cert_from_pki_message(self.pki_message)
        pki_message = cmputils.build_cert_conf(cert, 245)
        der_encoded = cmputils.encode_to_der(pki_message)
        # print(b64encode(der_encoded))
        # print(pki_message.prettyPrint())

    def test_find_implicit_confirm_extension(self):
        raw = load_and_decode_pem_file('data/example-response-error-implicitConfirm.pem')
        pki_message = cmputils.parse_pki_message(raw)

        oid_implicit_confirm = '1.3.6.1.5.5.7.4.13'
        result = cmputils.find_oid_in_general_info(pki_message, oid_implicit_confirm)
        self.assertTrue(result)

    def test_build_cr(self):
        csr = self.csr_object
        raw_key = open('data/keys/private-key-rsa.pem', 'rb').read()
        private_key = load_pem_private_key(raw_key, password=None)
        pki_message = cmputils.build_cr_from_csr(csr, private_key, hash_alg="sha256", cert_req_id=1945)
        # print(pki_message.prettyPrint())

        self.assertEqual("cr", pki_message['body'].getName())
        cert_req_id = get_asn1_value(pki_message, 'body.cr/0.certReq.certReqId')
        self.assertEqual(1945, cert_req_id)

        popo_alg_oid = get_asn1_value(pki_message, 'body.cr/0.popo.signature.algorithmIdentifier.algorithm')
        self.assertEqual('1.2.840.113549.1.1.11', str(popo_alg_oid))



if __name__ == '__main__':
    unittest.main()
