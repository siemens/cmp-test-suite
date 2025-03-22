# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives import hashes
from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc9480
from resources import cmputils
from resources.asn1utils import encode_to_der
from resources.certutils import parse_certificate
from resources.cmputils import (
    build_cert_conf,
    build_cert_conf_from_resp,
    get_cmp_message_type,
    patch_recipnonce,
    patch_sendernonce,
    patch_transaction_id,
    prepare_certstatus,
)
from resources.utils import load_and_decode_pem_file

from unit_tests.prepare_ca_response import build_ca_pki_message


class TestBuildCertConf(unittest.TestCase):
    def setUp(self):
        self.sender, self.recipient = "CN=Hans the Tester", "CN=Hans the Tester"
        self.cert = parse_certificate(load_and_decode_pem_file("data/unittest/ca2_cert_rsa.pem"))
        self.no_hash_alg_cert = parse_certificate(load_and_decode_pem_file("data/unittest/root_cert_ed25519.pem"))

    def test_build_cert_conf(self):
        """
        GIVEN a valid PKIMessage with a certConf body, which is build from an issued cert,
        from an CA Response
        WHEN the PKIMessage is encoded as DER.
        THEN the PKIMessage should be able to be decoded.
        """
        pki_message = cmputils.build_cert_conf(self.cert, cert_req_id=245)
        der_data = encode_to_der(pki_message)
        pki_msg, rest = decoder.decode(der_data, asn1Spec=rfc9480.PKIMessage())
        self.assertEqual(rest, b"", "Decoded PKIMessage should have no remaining undecoded data.")
        self.assertEqual(get_cmp_message_type(pki_msg), "certConf", "CMP message type should be 'certConf'.")

    def test_build_with_different_hash_alg(self):
        """
        GIVEN a valid PKIMessage with a certConf body, built from an issued cert with a specified
        hash algorithm and protocol version. With a certificate with hash algorithm sha256.
        WHEN the PKIMessage is encoded as DER using the SHA-512 hash algorithm and protocol version 3.
        THEN the PKIMessage should be able to be decoded, and should correctly identify as 'certConf'
        with the specified hash algorithm and protocol version.
        """
        pki_message = cmputils.build_cert_conf(self.cert, cert_req_id=0, hash_alg="sha512", pvno=3)
        der_data = encode_to_der(pki_message)
        pki_msg, rest = decoder.decode(der_data, asn1Spec=rfc9480.PKIMessage())
        self.assertEqual(rest, b"", "Decoded PKIMessage should have no remaining undecoded data.")
        self.assertEqual(get_cmp_message_type(pki_msg), "certConf", "CMP message type should be 'certConf'.")
        self.assertEqual(pki_msg["header"]["pvno"], 3, "Protocol version (pvno) should be set to 3.")

        digest = hashes.Hash(hashes.SHA512())
        digest.update(encode_to_der(self.cert))
        expected_cert_hash = digest.finalize()
        self.assertEqual(
            pki_msg["body"]["certConf"][0]["certHash"],
            expected_cert_hash,
            "The certHash should match the SHA-512 hash of the certificate.",
        )

    def test_build_cert_conf_with_cert_with_no_hash_alg(self):
        """
        GIVEN a certificate lacking a specified hash algorithm. (was signed by Ed25519)
        WHEN attempting to build a PKIMessage with this certificate.
        THEN a ValueError should be raised, as the certificate cannot be hashed without a defined hash algorithm.
        """
        with self.assertRaises(ValueError):
            build_cert_conf(cert=self.no_hash_alg_cert, pvno=3, sender=self.sender, recipient=self.recipient)

    def test_build_cert_conf_with_cert_hash(self):
        """
        GIVEN a specified cert_hash value for use in a PKIMessage.
        WHEN building a certConf PKIMessage with the given cert_hash, SHA-512 hash algorithm, and protocol version 3.
        THEN the certConf body of the PKIMessage should contain the provided cert_hash value.
        """
        cert_hash = b"A" * 16
        pki_message = cmputils.build_cert_conf(cert_hash=cert_hash, cert_req_id=0, hash_alg="sha512", pvno=3)

        self.assertEqual(
            pki_message["body"]["certConf"][0]["certHash"],
            cert_hash,
            "The certHash should match the provided cert_hash value.",
        )

    def test_build_cert_conf_with_cert_status(self):
        """
        GIVEN a specified cert_hash and cert_status for use in a PKIMessage.
        WHEN building a certConf PKIMessage with the cert_status containing cert_hash, SHA-256
        hash algorithm, and protocol version 3.
        THEN the certConf body of the PKIMessage should contain the cert_hash value which was provided.
        """
        cert_hash = b"A" * 16
        cert_status = prepare_certstatus(cert_hash=cert_hash, hash_alg="sha512")
        pki_message = cmputils.build_cert_conf(cert_status=cert_status, cert_req_id=0, hash_alg="sha256", pvno=3)

        self.assertEqual(
            pki_message["body"]["certConf"][0]["certHash"],
            cert_hash,
            "The certHash should match the provided cert_hash value.",
        )

    def test_build_cert_conf_with_no_cert_no_cert_hash_and_no_cert_status(self):
        """
        GIVEN no certificate, cert_hash, or cert_status provided, to build a
        WHEN attempting to build a `certConf` PKIMessage without any of these required values.
        THEN a ValueError should be raised, as at least one of these parameters is necessary.
        """
        with self.assertRaises(ValueError):
            cmputils.build_cert_conf()

    def test_build_cert_conf_from_resp(self):
        """
        GIVEN a valid PKIMessage with a certConf body, which is build from a valid CA Response
        WHEN the PKIMessage is encoded as DER.
        THEN the PKIMessage should be able to be decoded and have the same values as the CA message.
        """
        ca_message = build_ca_pki_message(cert=self.cert)
        ca_message = patch_sendernonce(ca_message, sender_nonce=b"A" * 16)
        ca_message = patch_transaction_id(ca_message, new_id=b"B" * 16)
        ca_message = patch_recipnonce(ca_message, recip_nonce=b"C" * 16)
        pki_message = build_cert_conf_from_resp(ca_message=ca_message,
                                                sender=self.sender, recipient=self.recipient)
        der_data = encode_to_der(pki_message)
        pki_msg, rest = decoder.decode(der_data, asn1Spec=rfc9480.PKIMessage())
        self.assertEqual(rest, b"")
        self.assertEqual(get_cmp_message_type(pki_msg), "certConf")
        self.assertEqual(pki_message["header"]["senderNonce"].asOctets(), b"C" * 16)
        self.assertEqual(pki_message["header"]["transactionID"].asOctets(), b"B" * 16)
        self.assertEqual(pki_message["header"]["recipNonce"].asOctets(), b"A" * 16)
