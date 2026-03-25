# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.ca_ra_utils import build_cp_cmp_message, build_cp_from_p10cr, build_pki_conf_from_cert_conf
from resources.certutils import parse_certificate
from resources.cmputils import build_cert_conf_from_resp, build_cr_from_key, build_p10cr_from_key, prepare_certstatus
from resources.exceptions import BadRequest, BadCertId
from resources.keyutils import load_private_key_from_file
from resources.utils import load_and_decode_pem_file


class TestBuildPkiConfFromCertConf(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ca_key = load_private_key_from_file("data/keys/private-key-ml-dsa-44-seed.pem")
        cls.ca_cert = parse_certificate(load_and_decode_pem_file("data/unittest/pq_root_ca_ml_dsa_44.pem"))

        cls.comp_key = load_private_key_from_file("data/keys/private-key-composite-sig-rsa2048-ml-dsa-44.pem")
        cls.pki_message =  build_cr_from_key(
            signing_key=cls.comp_key,
            pvno=3,
        )

        cls.response, cls.certs = build_cp_cmp_message(
            request=cls.pki_message,
            ca_key=cls.ca_key,
            ca_cert=cls.ca_cert,
            cert_index=0,
        )
        cls.response["extraCerts"].append(cls.ca_cert)


    def test_valid_cert_conf(self):
        """
        GIVEN a valid certificate confirmation.
        WHEN building a pkiConf from the certificate confirmation,
        THEN the pkiConf is built correctly.
        """
        cert_conf = build_cert_conf_from_resp(
            ca_message=self.response,
            pvno=3,
            hash_alg="sha256"
        )
        pki_conf = build_pki_conf_from_cert_conf(
            request=cert_conf,
            issued_certs=self.certs,
        )
        self.assertEqual(pki_conf["body"].getName(), "pkiconf")

    def test_invalid_cert_conf_version(self):
        """
        GIVEN a certificate confirmation with an invalid version.
        WHEN building a pkiConf from the certificate confirmation,
        THEN a BadRequest exception is raised.
        """
        cert_conf = build_cert_conf_from_resp(
            ca_message=self.response,
            pvno=2,
            hash_alg="sha256"
        )

        with self.assertRaises(BadCertId):
            _ = build_pki_conf_from_cert_conf(
                request=cert_conf,
                issued_certs=self.certs,
            )

    def test_invalid_size(self):
        """
        GIVEN a certificate confirmation with an invalid size.
        WHEN building a pkiConf from the certificate confirmation,
        THEN a BadRequest exception is raised.
        """
        cert_status1 = prepare_certstatus(
            hash_alg="sha256",
            cert=self.certs[0],
            cert_req_id=0,
            status="accepted",
            status_info=None,
        )
        cert_status = [cert_status1, cert_status1]
        cert_conf = build_cert_conf_from_resp(
            ca_message=self.response,
            pvno=3,
            hash_alg="sha256",
            cert_status=cert_status
        )
        with self.assertRaises(BadRequest):
            _ = build_pki_conf_from_cert_conf(
                request=cert_conf,
                issued_certs=self.certs,
                enforce_lwcmp=True,
            )

    def test_invalid_cert_conf_hash(self):
        """
        GIVEN a certificate confirmation with an invalid hash of the certificate.
        WHEN building a pkiConf from the certificate confirmation,
        THEN a BadCertId exception is raised.
        """

        cert_status1 = prepare_certstatus(
            hash_alg="sha256",
            cert=self.certs[0],
            cert_req_id=0,
            status="accepted",
            status_info=None,
            bad_cert_id=True,
        )

        cert_conf = build_cert_conf_from_resp(
            ca_message=self.response,
            pvno=3,
            hash_alg="sha1",
            cert_status=cert_status1
        )
        with self.assertRaises(BadCertId):
            _ = build_pki_conf_from_cert_conf(
                request=cert_conf,
                issued_certs=self.certs,
            )

    def test_correct_p10cr_validation(self):
        """
        GIVEN a valid certificate confirmation for a P10CR request with certReqId set to -1.
        WHEN building a pkiConf from the certificate confirmation with was_p10cr=True,
        THEN the pkiConf is built correctly without raising an exception.
        """
        p10cr_request = build_p10cr_from_key(
            key=self.comp_key,
            pvno=3,
        )
        response, cert = build_cp_from_p10cr(
            request=p10cr_request,
            ca_key=self.ca_key,
            ca_cert=self.ca_cert,
        )
        response["extraCerts"].append(self.ca_cert)
        cert_conf = build_cert_conf_from_resp(
            ca_message=response,
            pvno=3,
            hash_alg="sha256",
            cert_req_id=-1,
        )

        pki_conf = build_pki_conf_from_cert_conf(
            request=cert_conf,
            issued_certs=[cert],
            was_p10cr=True,
        )
        self.assertEqual(pki_conf["body"].getName(), "pkiconf")


if __name__ == "__main__":
    unittest.main()