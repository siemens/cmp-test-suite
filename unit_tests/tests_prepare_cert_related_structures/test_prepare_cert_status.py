# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc9480
from resources import oid_mapping
from resources.cmputils import prepare_certstatus


class TestPrepareCertStatus(unittest.TestCase):
    def setUp(self):
        self.cert_hash = bytes.fromhex("AA" * 16)
        self.cert_req_id = 1234
        self.valid_status = "accepted"
        self.invalid_status = "rejection"
        self.fail_info = "badCertId"
        self.text = "Test rejection"
        self.hash_alg = "sha256"

    def test_prepare_certstatus_encoding_decoding(self):
        """
        GIVEN a `CertStatus` prepared with a valid certificate hash and request ID.
        WHEN the `CertStatus` is encoded to DER and then decoded.
        THEN the decoded values should match the original certificate hash and request ID,
        with no leftover data after decoding.
        """
        cert_status = prepare_certstatus(
            cert_hash=self.cert_hash, cert_req_id=self.cert_req_id, status=self.valid_status
        )
        encoded_cert_status = encoder.encode(cert_status)
        decoded_cert_status, rest = decoder.decode(encoded_cert_status, asn1Spec=rfc9480.CertStatus())
        self.assertEqual(rest, b"")
        self.assertEqual(decoded_cert_status["certHash"], univ.OctetString(self.cert_hash))
        self.assertEqual(decoded_cert_status["certReqId"], self.cert_req_id)

    def test_certstatus_has_values(self):
        """
        GIVEN a `CertStatus` prepared with a certificate hash, request ID, and failure information.
        WHEN checking the `CertStatus` structure.
        THEN all the expected fields, including certHash, certReqId, status, failInfo,
        and statusString, should have values.
        """
        cert_status = prepare_certstatus(
            cert_hash=self.cert_hash,
            cert_req_id=self.cert_req_id,
            status=self.invalid_status,
            failinfo=self.fail_info,
            text=self.text,
        )
        self.assertTrue(cert_status["certHash"].isValue)
        self.assertTrue(cert_status["certReqId"].isValue)
        self.assertTrue(cert_status["statusInfo"].isValue)
        self.assertTrue(cert_status["statusInfo"]["status"].isValue)
        self.assertTrue(cert_status["statusInfo"]["failInfo"].isValue)
        self.assertTrue(cert_status["statusInfo"]["statusString"].isValue)

    def test_certstatus_with_hash_algorithm(self):
        """
        GIVEN a `CertStatus` prepared with a certificate hash, request ID, and hash algorithm.
        WHEN the `CertStatus` is encoded to DER and then decoded.
        THEN the decoded `CertStatus` should include a hashAlg field with the correct algorithm OID.
        """
        cert_status = prepare_certstatus(
            cert_hash=self.cert_hash, cert_req_id=self.cert_req_id, status=self.valid_status, hash_alg=self.hash_alg
        )
        encoded_cert_status = encoder.encode(cert_status)
        decoded_cert_status, rest = decoder.decode(encoded_cert_status, asn1Spec=rfc9480.CertStatus())
        self.assertEqual(rest, b"")
        self.assertTrue(decoded_cert_status["hashAlg"].isValue)
        self.assertEqual(decoded_cert_status["hashAlg"]["algorithm"], oid_mapping.sha_alg_name_to_oid(self.hash_alg))

    def test_certstatus_without_hash_algorithm(self):
        """
        GIVEN a `CertStatus` prepared without specifying a hash algorithm.
        WHEN the `CertStatus` is encoded to DER and then decoded.
        THEN the decoded `CertStatus` should not have a hashAlg field set.
        """
        cert_status = prepare_certstatus(
            cert_hash=self.cert_hash, cert_req_id=self.cert_req_id, status=self.valid_status, hash_alg=None
        )
        encoded_cert_status = encoder.encode(cert_status)
        decoded_cert_status, rest = decoder.decode(encoded_cert_status, asn1Spec=rfc9480.CertStatus())
        self.assertEqual(rest, b"")
        self.assertFalse(decoded_cert_status["hashAlg"].isValue)


if __name__ == "__main__":
    unittest.main()
