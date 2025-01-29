import unittest

from pyasn1_alt_modules.rfc9480 import id_it_implicitConfirm

from resources.ca_ra_utils import build_ip_cmp_message, build_pki_conf_from_cert_conf
from resources.certutils import parse_certificate
from resources.cmputils import build_ir_from_key, find_oid_in_general_info, build_cert_conf_from_resp
from resources.keyutils import load_private_key_from_file
from resources.utils import load_and_decode_pem_file


class TestRequestResponseWorkflow(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ca_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.ca_cert = parse_certificate(load_and_decode_pem_file("data/unittest/bare_certificate.pem"))

    def test_ir_for_ip(self):
        """
        GIVEN a CA key and certificate, and new key,
        WHEN an IR is built and used to build an IP,
        THEN the IP contains the implicit confirm OID.
        """
        ir = build_ir_from_key(self.ca_key, implicit_confirm=True)
        ip, certs = build_ip_cmp_message(request=ir,
                                  ca_cert=self.ca_cert,
                                  ca_key=self.ca_key,
                                  implicit_confirm=True,
                                  )

        result = find_oid_in_general_info(
            pki_message=ip,
            oid=id_it_implicitConfirm,
        )
        self.assertTrue(result)

    def test_ir_for_ip_full(self):
        """
        GIVEN a CA key and certificate, and new key,
        WHEN an IR is built and used to build an IP,
        THEN the transaction is completed, correctly with cert conf and pki conf.
        """
        ir = build_ir_from_key(self.ca_key, implicit_confirm=True)
        ip, certs = build_ip_cmp_message(request=ir,
                                  ca_cert=self.ca_cert,
                                  ca_key=self.ca_key,
                                  implicit_confirm=False,
                                  )

        cert_conf = build_cert_conf_from_resp(ca_message=ip)
        build_pki_conf_from_cert_conf(
            request=cert_conf,
            issued_certs=certs,
        )







