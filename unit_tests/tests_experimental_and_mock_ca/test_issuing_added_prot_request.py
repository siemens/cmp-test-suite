import unittest

from pyasn1_alt_modules import rfc9480

from mock_ca.ca_handler import CAHandler
from resources import utils
from resources.asn1_structures import PKIMessageTMP
from resources.certbuildutils import build_certificate
from resources.certutils import parse_certificate
from resources.cmputils import (
    build_cert_conf_from_resp,
    build_ir_from_key,
    build_nested_pkimessage,
    get_cmp_message_type, find_oid_in_general_info,
)
from resources.keyutils import generate_key, load_private_key_from_file
from resources.protectionutils import protect_pkimessage
from resources.utils import display_pki_status_info
from unit_tests.utils_for_test import load_ca_cert_and_key


class TestIssuingAddedProtRequest(unittest.TestCase):
    """Test issuing added protection requests for a correct response and extra certificates."""

    @classmethod
    def setUpClass(cls):
        cls.ca_cert, cls.ca_key = load_ca_cert_and_key()
        cls.ra_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        cls.ra_cert = parse_certificate(utils.load_and_decode_pem_file("data/trusted_ras/ra_cms_cert_ecdsa.pem"))

    @classmethod
    def _get_ca_handler(cls) -> CAHandler:
        """Load CA certificate and key and return the CAHandler instance."""
        return CAHandler(ca_cert=cls.ca_cert, ca_key=cls.ca_key)

    def add_added_protection_cert(self, request: PKIMessageTMP):
        """Add an added protection certificate to the CA."""
        nested = build_nested_pkimessage(for_added_protection=True, other_messages=request, )
        return protect_pkimessage(nested, "signature", private_key=self.ra_key, cert=self.ra_cert)


    def test_added_protection_extra_certs_add_sig(self):
        """
        GIVEN an already issued certificate and a new added_protected certificate request
        WHEN the CA processes the request,
        THEN it should return a correct IP message.
        """
        ca_handler = self._get_ca_handler()

        sign_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        new_cert, _ = build_certificate(sign_key, common_name="CN=Hans the EE", ca_cert=ca_handler.ca_cert, ca_key=ca_handler.ca_key)

        ca_handler.add_cert_to_issued_certs(new_cert)

        key = generate_key("rsa")
        ir = build_ir_from_key(key, for_mac=True, sender="CN=Hans the Tester", sender_kid=b"CN=Hans the Tester")
        prot_ir = protect_pkimessage(ir, "signature", private_key=sign_key, cert=new_cert)

        ca_cert, ca_key = load_ca_cert_and_key()
        ca_handler = CAHandler(ca_cert=ca_cert, ca_key=ca_key)

        prot_nested = self.add_added_protection_cert(prot_ir)

        response = ca_handler.process_normal_request(prot_nested)
        self.assertEqual("ip", get_cmp_message_type(response),
            f"Body type: {get_cmp_message_type(response)}. Should be `ip`.\nStatus: {display_pki_status_info(response)}"
        )
        # Ensure that the certificate chain is completely added to the message.
        cert_conf = build_cert_conf_from_resp(response, sender="CN=Hans the Tester", sender_kid=b"CN=Hans the Tester")
        self.assertEqual("certConf", get_cmp_message_type(cert_conf))

    def test_added_protection_extra_certs_add_sig_without_impl_confirm(self):
        """
        GIVEN an already issued certificate and a new added_protected certificate request
        WHEN the CA processes the request and the certificate is issued without implicit confirmation
        THEN it should return a correct IP message and accept the certificate confirmation.
        """
        ca_handler = self._get_ca_handler()

        sign_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        new_cert, _ = build_certificate(sign_key, common_name="CN=Hans the EE", ca_cert=ca_handler.ca_cert, ca_key=ca_handler.ca_key)

        ca_handler.add_cert_to_issued_certs(new_cert)

        key = generate_key("rsa")
        ir = build_ir_from_key(key, for_mac=True, sender="CN=Hans the Tester", sender_kid=b"CN=Hans the Tester", implicit_confirm=False)
        prot_ir = protect_pkimessage(ir, "signature", private_key=sign_key, cert=new_cert)

        prot_nested = self.add_added_protection_cert(prot_ir)

        response = ca_handler.process_normal_request(prot_nested)
        self.assertEqual("ip", get_cmp_message_type(response),
                         f"Body type: {get_cmp_message_type(response)}. Should be `ip`.\nStatus: {display_pki_status_info(response)}"
                         )

        result = find_oid_in_general_info(pki_message=response, oid=str(rfc9480.id_it_implicitConfirm))
        self.assertFalse(result, f"Implicit confirmation should not be present in the response: {response.prettyPrint()}")

        # Ensure that the certificate chain is completely added to the message.
        cert_conf = build_cert_conf_from_resp(response, sender="CN=Hans the Tester", sender_kid=b"CN=Hans the Tester")
        prot_cert_conf =  protect_pkimessage(cert_conf, "signature", private_key=sign_key, cert=new_cert)
        nested_prot_cert_conf = self.add_added_protection_cert(prot_cert_conf)
        pki_conf_response = ca_handler.process_normal_request(nested_prot_cert_conf)
        self.assertEqual("pkiconf", get_cmp_message_type(pki_conf_response), f"pkiconf expected, got: {pki_conf_response.prettyPrint()}")

    def test_added_protection_extra_certs_add_mac(self):
        """
        GIVEN a new MAC Protected added protection certificate request.
        WHEN the CA processes the request,
        THEN it should return a correct IP message.
        """
        key = generate_key("rsa")
        ir = build_ir_from_key(key, for_mac=True, sender="CN=Hans the Tester", sender_kid=b"CN=Hans the Tester")
        prot_ir = protect_pkimessage(ir, "pbmac1", password=b"SiemensIT")

        prot_nested = self.add_added_protection_cert(prot_ir)

        ca_handler = self._get_ca_handler()

        response = ca_handler.process_normal_request(prot_nested)
        self.assertEqual("ip", get_cmp_message_type(response),
            f"Body type: {get_cmp_message_type(response)}. Should be `ip`.\nStatus: {display_pki_status_info(response)}"
        )
        # Ensure that the certificate chain is completely added to the message.
        cert_conf = build_cert_conf_from_resp(
            response, for_mac=True, sender="CN=Hans the Tester", sender_kid=b"CN=Hans the Tester"
        )
        self.assertEqual("certConf", get_cmp_message_type(cert_conf))

    def test_added_protection_extra_certs_add_mac_without_impl_confirm(self):
        """
        GIVEN a new MAC Protected added protection certificate request.
        WHEN the CA processes the request and the certificate is issued without implicit confirmation,
        THEN it should return a correct IP message and accept the certificate confirmation.
        """
        key = generate_key("rsa")
        ir = build_ir_from_key(key, for_mac=True, sender="CN=Hans the Tester", sender_kid=b"CN=Hans the Tester", implicit_confirm=False)
        prot_ir = protect_pkimessage(ir, "pbmac1", password=b"SiemensIT")

        prot_nested = self.add_added_protection_cert(prot_ir)

        ca_handler = self._get_ca_handler()

        response = ca_handler.process_normal_request(prot_nested)
        self.assertEqual("ip", get_cmp_message_type(response),
                         f"Body type: {get_cmp_message_type(response)}. Should be `ip`.\nStatus: {display_pki_status_info(response)}"
                         )

        result = find_oid_in_general_info(pki_message=response, oid=str(rfc9480.id_it_implicitConfirm))
        self.assertFalse(result, f"Implicit confirmation should not be present in the response: {response.prettyPrint()}")

        # Ensure that the certificate chain is completely added to the message.
        cert_conf = build_cert_conf_from_resp(
            response, for_mac=True, sender="CN=Hans the Tester", sender_kid=b"CN=Hans the Tester"
        )
        prot_cert_conf =  protect_pkimessage(cert_conf, "pbmac1", password=b"SiemensIT")
        nested_prot_cert_conf = self.add_added_protection_cert(prot_cert_conf)
        pki_conf_response = ca_handler.process_normal_request(nested_prot_cert_conf)
        self.assertEqual("pkiconf", get_cmp_message_type(pki_conf_response), f"pkiconf expected, got: {pki_conf_response.prettyPrint()}")


if __name__ == '__main__':
    unittest.main()
