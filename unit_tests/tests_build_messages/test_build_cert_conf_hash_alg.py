# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pyasn1_alt_modules import rfc9480

from resources.asn1_structures import PKIMessageTMP
from resources.ca_ra_utils import build_ip_cmp_message, build_pki_conf_from_cert_conf
from resources.certbuildutils import build_certificate
from resources.cmputils import build_cert_conf_from_resp
from resources.exceptions import BadCertId
from resources.keyutils import load_private_key_from_file
from resources.oid_mapping import sha_alg_name_to_oid
from unit_tests.utils_for_test import load_ca_cert_and_key


class TestCertConfHashAlgByVersion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ee_key = load_private_key_from_file("./data/keys/private-key-ecdsa.pem")
        cls.ca_cert, cls.ca_key = load_ca_cert_and_key()
        if not isinstance(cls.ca_key, Ed25519PrivateKey):
            raise ValueError(
                "CA key is not Ed25519PrivateKey, this function should be tested with a implicit algorithm."
            )
        cls.cert, _ = build_certificate(
            ca_cert=cls.ca_cert,
            ca_key=cls.ca_key,
            private_key=cls.ee_key,
            subject_name="CN=Test Cert Conf HashAlg",
            is_ca=False,
            serial_number=123456789,
        )

    def _get_ip_msg(self, pvno: int = 2) -> PKIMessageTMP:
        """Build a sample IP message with a certificate request."""
        ip_msg, _ = build_ip_cmp_message(cert=self.cert, pvno=pvno)
        ip_msg["extraCerts"].append(self.ca_cert)
        return ip_msg

    def _first_cert_status(self, cert_conf_msg: PKIMessageTMP) -> rfc9480.CertStatus:
        """Extract the first CertStatus from a CertConf message."""
        self.assertEqual(cert_conf_msg["body"].getName(), "certConf")
        content = cert_conf_msg["body"]["certConf"]
        self.assertGreater(len(content), 0)
        return content[0]

    def test_v2_with_hash_alg_does_not_set_hashAlg(self):
        """
        GIVEN a pvno=2 and hash_alg provided for a certificate confirmation message.
        WHEN building the certificate confirmation message.
        THEN hashAlg must NOT be present in the CertStatus.
        """
        ip_msg = self._get_ip_msg(pvno=2)
        cert_conf = build_cert_conf_from_resp(
            ca_message=ip_msg,
            hash_alg="sha256",
            pvno=2,
            hash_for_v3=True,  # should be ignored for pvno=2
        )
        self.assertEqual(int(cert_conf["header"]["pvno"]), 2)
        status = self._first_cert_status(cert_conf)
        self.assertFalse(status["hashAlg"].isValue)
        self.assertTrue(status["certHash"].isValue)  # certHash must still be present
        with self.assertRaises(BadCertId):
            _ = build_pki_conf_from_cert_conf(cert_conf, issued_certs=[self.cert])
        _ = build_pki_conf_from_cert_conf(cert_conf, issued_certs=[self.cert], hash_alg="sha256")

    def test_v3_with_hash_alg_sets_hashAlg(self):
        """
        GIVEN a pvno=3 and hash_alg provided for a certificate confirmation message.
        WHEN building the certificate confirmation message.
        THEN hashAlg must be present in the CertStatus and set to the provided hash_alg.
        """
        ip_msg = self._get_ip_msg()
        cert_conf = build_cert_conf_from_resp(
            ca_message=ip_msg,
            hash_alg="sha256",
            pvno=3,
            hash_for_v3=True,
        )
        self.assertEqual(int(cert_conf["header"]["pvno"]), 3)
        status = self._first_cert_status(cert_conf)
        self.assertTrue(status["hashAlg"].isValue)
        self.assertEqual(str(status["hashAlg"]["algorithm"]), str(sha_alg_name_to_oid("sha256")))
        self.assertEqual(str(status["hashAlg"]["algorithm"]), "2.16.840.1.101.3.4.2.1")
        _ = build_pki_conf_from_cert_conf(cert_conf, issued_certs=[self.cert])

    def test_v3_without_hash_alg_still_sets_hashAlg(self):
        """
        GIVEN a pvno=3 and NO hash_alg provided for a certificate confirmation message.
        WHEN building the certificate confirmation message.
        THEN hashAlg must be present in the CertStatus and set to sha512 (default for v3).
        """
        ip_msg = self._get_ip_msg()
        cert_conf = build_cert_conf_from_resp(
            ca_message=ip_msg,
            pvno=3,
        )
        self.assertEqual(int(cert_conf["header"]["pvno"]), 3)
        status = self._first_cert_status(cert_conf)
        self.assertTrue(status["hashAlg"].isValue)
        # Default for ED25519 is sha512.
        self.assertEqual(status["hashAlg"]["algorithm"], sha_alg_name_to_oid("sha512"))
        _ = build_pki_conf_from_cert_conf(cert_conf, issued_certs=[self.cert])

    def test_v3_with_hash_for_v3_false_does_not_set_hashAlg(self):
        """
        GIVEN a pvno=3 and hash_for_v3=False for a certificate confirmation message.
        WHEN building the certificate confirmation message.
        THEN hashAlg must NOT be present in the CertStatus.
        """
        ip_msg = self._get_ip_msg()
        cert_conf = build_cert_conf_from_resp(
            ca_message=ip_msg,
            hash_alg="sha256",  # should be ignored
            pvno=3,
            hash_for_v3=False,
        )
        self.assertEqual(int(cert_conf["header"]["pvno"]), 3)
        status = self._first_cert_status(cert_conf)
        self.assertFalse(status["hashAlg"].isValue)
        self.assertTrue(status["certHash"].isValue)  # certHash must still be present
        with self.assertRaises(BadCertId):
            _ = build_pki_conf_from_cert_conf(cert_conf, issued_certs=[self.cert])


if __name__ == "__main__":
    unittest.main()
