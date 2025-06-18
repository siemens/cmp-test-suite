import unittest

from resources.asn1_structures import PKIMessageTMP
from resources.ca_ra_utils import validate_cert_req_id_nums
from resources.cmputils import (
    build_ccr_from_key,
    build_cr_from_key,
    build_ir_from_key,
    build_key_update_request,
    build_krr_from_key,
    build_p10cr_from_key,
    prepare_cert_req_msg,
)
from resources.exceptions import BadCertTemplate, BadRequest
from resources.keyutils import generate_key, load_private_key_from_file


class TestValidateCertReqIdNums(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        cls.cm = "CN=Hans the Tester"

    @staticmethod
    def get_cert_req_id(msg: PKIMessageTMP) -> int:
        """Extract the certReqId from the PKIMessage body."""
        body_name = msg["body"].getName()
        if body_name == "p10cr":
            return msg["body"]["p10cr"]["certificationRequestInfo"]["version"]
        elif body_name not in ["ir", "cr", "kur", "krr", "ccr"]:
            raise ValueError(f"Unsupported request type: {body_name}")
        return int(msg["body"][body_name][0]["certReq"]["certReqId"])

    def _build_request_by_name(self, body_name: str, cert_req_id: int = 0):
        """Build a PKIMessage with a certificate request id set to the given value."""
        if body_name not in ["ir", "cr", "p10cr", "kur", "krr", "ccr"]:
            raise ValueError(f"Unsupported request type: {body_name}")

        if body_name == "ir":
            msg = build_ir_from_key(self.key, cert_req_id=cert_req_id)
        elif body_name == "cr":
            msg = build_cr_from_key(self.key, cert_req_id=cert_req_id)
        elif body_name == "p10cr":
            msg = build_p10cr_from_key(self.key, version=cert_req_id)
        elif body_name == "kur":
            msg = build_key_update_request(self.key, cert_req_id=cert_req_id)
        elif body_name == "krr":
            msg = build_krr_from_key(self.key, cert_req_id=cert_req_id)
        elif body_name == "ccr":
            msg = build_ccr_from_key(self.key, cert_req_id=cert_req_id)
        else:
            raise ValueError(f"Unsupported request type: {body_name}")
        return msg

    def test_p10cr_version_zero(self):
        """
        GIVEN a P10CR message with version 0.
        WHEN validating the PKIMessage,
        THEN no error is raised.
        """
        p10cr = build_p10cr_from_key(self.key)
        validate_cert_req_id_nums(p10cr)

    def test_ir_cert_req_id_zero(self):
        """
        GIVEN an `ir` PKIMessage with a `certReqId` set to 0.
        WHEN validating the PKIMessage,
        THEN the `certReqId` in the message body should be 0 and no error is raised.
        """
        msg = self._build_request_by_name("ir", cert_req_id=0)
        self.assertEqual("ir", msg["body"].getName())
        self.assertEqual(0, self.get_cert_req_id(msg))
        validate_cert_req_id_nums(msg)

    def test_ir_cert_req_id(self):
        """
        GIVEN a `ir` PKIMessage with a `certReqId` set to 42.
        WHEN validating the PKIMessage,
        THEN the `certReqId` in the message body should be 42 and the validation should raise
        a `BadRequest` exception because the `certReqId` is not 0.
        """
        msg = self._build_request_by_name("ir", cert_req_id=42)
        self.assertEqual("ir", msg["body"].getName())
        self.assertEqual(42, self.get_cert_req_id(msg))
        with self.assertRaises(BadRequest):
            validate_cert_req_id_nums(msg)

    def test_cr_cert_req_id(self):
        """
        GIVEN a `cr` PKIMessage with a `certReqId` set to 42.
        WHEN validating the PKIMessage,
        THEN the `certReqId` in the message body should be 42 and the validation should raise
        a `BadRequest` exception because the `certReqId` is not 0.
        """
        msg = self._build_request_by_name("cr", cert_req_id=42)
        self.assertEqual("cr", msg["body"].getName())
        self.assertEqual(42, self.get_cert_req_id(msg))
        with self.assertRaises(BadRequest):
            validate_cert_req_id_nums(msg)

    def test_p10cr_cert_req_id(self):
        """
        GIVEN a `p10cr` PKIMessage with a CSR `version` set to 42.
        WHEN validating the PKIMessage,
        THEN the `version` in the message body should be 42 and the validation should raise
        a `BadCertTemplate` exception because the `certReqId` is not 0.
        """
        msg = self._build_request_by_name("p10cr", cert_req_id=42)
        self.assertEqual("p10cr", msg["body"].getName())
        self.assertEqual(42, self.get_cert_req_id(msg))
        with self.assertRaises(BadCertTemplate):
            validate_cert_req_id_nums(msg)

    def test_kur_cert_req_id(self):
        """
        GIVEN a `kur` PKIMessage with a `certReqId` set to 42.
        WHEN validating the PKIMessage,
        THEN the `certReqId` in the message body should be 42 and the validation should raise
        a `BadRequest` exception because the `certReqId` is not 0.
        """
        msg = self._build_request_by_name("kur", cert_req_id=42)
        self.assertEqual("kur", msg["body"].getName())
        self.assertEqual(42, self.get_cert_req_id(msg))
        with self.assertRaises(BadRequest):
            validate_cert_req_id_nums(msg)

    def test_krr_cert_req_id(self):
        """
        GIVEN a `krr` PKIMessage with a `certReqId` set to 42.
        WHEN validating the message,
        THEN the `certReqId` in the message body should be 42 and the validation should raise
        a `BadRequest` exception because the `certReqId` is not 0.
        """
        msg = self._build_request_by_name("krr", cert_req_id=42)
        self.assertEqual("krr", msg["body"].getName())
        self.assertEqual(42, self.get_cert_req_id(msg))
        with self.assertRaises(BadRequest):
            validate_cert_req_id_nums(msg)

    def test_ccr_cert_req_id(self):
        """
        GIVEN a `ccr` PKIMessage with a `certReqId` set to 42.
        WHEN validating the PKIMessage,
        THEN the `certReqId` in the message body should be 42 and the validation should raise
        a `BadRequest` exception because the `certReqId` is not 0.
        """
        msg = self._build_request_by_name("ccr", cert_req_id=42)
        self.assertEqual("ccr", msg["body"].getName())
        self.assertEqual(42, self.get_cert_req_id(msg))
        with self.assertRaises(BadRequest):
            validate_cert_req_id_nums(msg)

    def test_multiple_cert_req_valid(self):
        """
        GIVEN an IR with sequential certReqIds
        WHEN validating the PKIMessage,
        THEN no error is raised.
        """
        req1 = prepare_cert_req_msg(self.key, cert_req_id=0, common_name=self.cm)
        req2 = prepare_cert_req_msg(self.key, cert_req_id=1, common_name=self.cm)
        ir = build_ir_from_key(None, cert_req_msg=[req1, req2])
        validate_cert_req_id_nums(ir)

    def test_multiple_cert_req_duplicate(self):
        """
        GIVEN an IR with duplicate certReqIds
        WHEN validating the PKIMessage,
        THEN BadRequest is raised.
        """
        key1 = generate_key("rsa")
        key2 = generate_key("rsa")
        req1 = prepare_cert_req_msg(key1, cert_req_id=0, common_name=self.cm)
        req2 = prepare_cert_req_msg(key2, cert_req_id=0, common_name=self.cm)
        ir = build_ir_from_key(key1, cert_req_msg=[req1, req2])
        with self.assertRaises(BadRequest):
            validate_cert_req_id_nums(ir)

    def test_multiple_cert_req_missing_zero(self):
        """
        GIVEN an IR with certReqIds not starting at 0.
        WHEN validating the PKIMessage,
        THEN BadRequest is raised.
        """
        key1 = generate_key("rsa")
        key2 = generate_key("rsa")
        req1 = prepare_cert_req_msg(key1, cert_req_id=1, common_name=self.cm)
        req2 = prepare_cert_req_msg(key2, cert_req_id=2, common_name=self.cm)
        ir = build_ir_from_key(key1, cert_req_msg=[req1, req2])
        with self.assertRaises(BadRequest):
            validate_cert_req_id_nums(ir)
