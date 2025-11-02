# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from pyasn1_alt_modules import rfc5280

# from resources import asn1utils
from resources import cmputils, keyutils, oid_mapping
from resources.asn1utils import get_asn1_value, get_asn1_value_as_bytes, get_asn1_value_as_string
from resources.certbuildutils import build_csr
from resources.utils import load_and_decode_pem_file


class TestCmpUtils(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw_csr = load_and_decode_pem_file("data/example-csr.pem")
        cls.csr_object = cmputils.parse_csr(raw_csr)

        raw_pki_message = load_and_decode_pem_file("data/example-cmp-response-accept.pem")
        cls.pki_message = cmputils.parse_pkimessage(raw_pki_message)

    def test_parse_error_response(self):
        """
        GIVEN a CMP response with an error.
        WHEN parsing the response,
        THEN the error is correctly parsed.
        """
        raw = load_and_decode_pem_file("data/example-response-unsupported-algo.pem")
        pki_message = cmputils.parse_pkimessage(raw)
        body = pki_message["body"]
        self.assertEqual("error", body.getName())
        self.assertEqual("rejection", str(body["error"]["pKIStatusInfo"]["status"]))

        # these are optional, though present in the specific example we're loading
        stringified_status = str(body["error"]["pKIStatusInfo"]["statusString"])
        self.assertIn("cannot create", stringified_status)

    def test_parse_p10cr_success_response(self):
        """
        GIVEN a CMP response with a success message.
        WHEN parsing the response and extracting fields from the response,
        THEN the response is correctly parsed and the fields are extracted.
        """
        raw = load_and_decode_pem_file("data/example-response-p10rp-cert.pem")
        pki_message = cmputils.parse_pkimessage(raw)

        sender_nonce = get_asn1_value_as_bytes(pki_message, "header.senderNonce")
        self.assertEqual(sender_nonce, b"\xd3\xcd\x9d\xdd\xe5n+\xad\x84\x82U\xac\xa8&\xf9\xc0")

        recip_nonce = get_asn1_value_as_bytes(pki_message, "header.recipNonce")
        self.assertEqual(recip_nonce, b"1111111122222222")

        recipient = get_asn1_value_as_string(
            pki_message, "header.recipient.directoryName.rdnSequence/0/0.value", decode=True
        )
        self.assertEqual(recipient, "Upstream-CMP-ENDENTITY")

        self.assertEqual("cp", cmputils.get_cmp_message_type(pki_message))

        response_status = str(get_asn1_value(pki_message, "body.cp.response/0.status.status"))
        self.assertEqual("accepted", response_status)

        cert_subject = get_asn1_value_as_string(
            pki_message,
            "body.cp.response/0.certifiedKeyPair.certOrEncCert."
            "certificate.tbsCertificate.subject.rdnSequence/0/0.value",
            decode=True,
        )
        self.assertEqual(cert_subject, "Hans Mustermann")

    def test_get_cmp_status_from_pki_message(self):
        """
        GIVEN a CMP response message
        WHEN extracting the status from the message,
        THEN the status is correctly extracted.
        """
        status = cmputils.get_status_from_pkimessage(self.pki_message)
        self.assertEqual("accepted", status)

    def test_get_cmp_response_type(self):
        """
        GIVEN a CMP response message
        WHEN extracting the response type from the message,
        THEN the response type is correctly extracted.
        """
        message_type = cmputils.get_cmp_message_type(self.pki_message)
        self.assertEqual("ip", message_type)

    def test_get_cert_from_pki_message(self):
        """
        GIVEN a CMP response message.
        WHEN extracting the certificate from the message,
        THEN the certificate is correctly extracted.
        """
        cert: rfc5280.Certificate = cmputils.get_cert_from_pkimessage(self.pki_message)
        serial_number = str(cert["tbsCertificate"]["serialNumber"])
        self.assertEqual("7286628116517592062", serial_number)

        sig_algorithm = cert["signatureAlgorithm"]["algorithm"]
        self.assertEqual("1.2.840.113549.1.1.5", str(sig_algorithm))

        hash_alg_name = oid_mapping.get_hash_from_oid(sig_algorithm)
        self.assertEqual("sha1", hash_alg_name.split("-")[1])

    def test_build_p10cr_without_attributes(self):
        """
        GIVEN a CSR.
        WHEN building a P10CR from the CSR, with excluded fields,
        THEN the P10CR is correctly built without excluded fields.
        """
        keypair = keyutils.generate_key("rsa")
        asn1_csr = build_csr(signing_key=keypair, common_name="CN=Hans")
        p10cr = cmputils.build_p10cr_from_csr(asn1_csr, exclude_fields="senderKID,senderNonce")

        self.assertNotIn("senderKID", p10cr)
        self.assertNotIn("senderNonce", p10cr)

    def test_find_implicit_confirm_extension(self):
        """
        GIVEN a CMP response message.
        WHEN checking for an implicit confirm extension in the message,
        THEN the extension is found.
        """
        raw = load_and_decode_pem_file("data/example-response-error-implicitConfirm.pem")
        pki_message = cmputils.parse_pkimessage(raw)

        oid_implicit_confirm = "1.3.6.1.5.5.7.4.13"
        result = cmputils.find_oid_in_general_info(pki_message, oid_implicit_confirm)
        self.assertTrue(result)

    def test_build_cr(self):
        """
        GIVEN a CSR and a private key.
        WHEN building a CR from the CSR,
        THEN the CR is correctly built.
        """
        csr = self.csr_object
        raw_key = Path("data/keys/private-key-rsa.pem").read_bytes()
        private_key = load_pem_private_key(raw_key, password=None)
        pki_message = cmputils.build_cr_from_csr(csr, private_key, hash_alg="sha256", cert_req_id=1945)
        # print(pki_message.prettyPrint())

        self.assertEqual("cr", pki_message["body"].getName())
        cert_req_id = get_asn1_value(pki_message, "body.cr/0.certReq.certReqId")
        self.assertEqual(1945, cert_req_id)

        popo_alg_oid = get_asn1_value(pki_message, "body.cr/0.popo.signature.algorithmIdentifier.algorithm")
        self.assertEqual("1.2.840.113549.1.1.11", str(popo_alg_oid))


if __name__ == "__main__":
    unittest.main()
