import os
import unittest

from pyasn1.codec.der import encoder
from pyasn1_alt_modules import rfc9480

from pq_logic.hybrid_sig.chameleon_logic import build_delta_cert_from_paired_cert
from pq_logic.tmp_oids import id_at_deltaCertificateRequest
from resources.certextractutils import get_extension
from resources.certutils import parse_certificate
from resources.utils import load_and_decode_pem_file


class TestLoadCertificates(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.base_path = "unit_tests/tests_pqc_and_hybrids/test_hybrid_sig/test_hybrid_chameleon/chameleon_certs/"


    def test_build_delta_cert_from_draft_appendix_b1(self):
        """
        GIVEN a paired certificate.
        WHEN building a delta certificate from the paired certificate.
        THEN the delta certificate is built correctly.
        """
        ml_dsa_65_root_cert = parse_certificate(load_and_decode_pem_file(
            os.path.join(self.base_path,
            "ml_dsa_65_root_cert.pem")))

        delta_cert = build_delta_cert_from_paired_cert(ml_dsa_65_root_cert)
        ec_root = parse_certificate(load_and_decode_pem_file(
            os.path.join(self.base_path,"ec_p-521_root_cert.pem")))
        ec_root_der = encoder.encode(ec_root)
        delta_cert_der = encoder.encode(delta_cert)
        self.assertEqual(ec_root_der, delta_cert_der)


    def test_appendix_b2_cert(self):
        """
        GIVEN a paired certificate.
        WHEN building a delta certificate from the paired certificate.
        THEN the delta certificate is built correctly.
        """

        ml_dsa_65_sign_ee = parse_certificate(load_and_decode_pem_file(
            os.path.join(self.base_path,"ml_dsa_65_signing_ee.pem")))

        ec_signing_ee = parse_certificate(
            load_and_decode_pem_file(os.path.join(self.base_path,"ec_signing_ee.pem")))


        _ = get_extension(ec_signing_ee["tbsCertificate"]["extensions"],
                                 id_at_deltaCertificateRequest)
        delta_cert = build_delta_cert_from_paired_cert(
            ec_signing_ee
        )
        delta_cert_der = encoder.encode(delta_cert)
        ml_dsa_65_sign_ee_der = encoder.encode(ml_dsa_65_sign_ee)
        self.assertEqual(ml_dsa_65_sign_ee_der, delta_cert_der)

    def test_appendix_b3_cert(self):
        """
        GIVEN a paired EC certificate.
        WHEN building a delta certificate from the paired certificate.
        THEN the delta certificate is built correctly.
        """
        ec_signing_ee = parse_certificate(
            load_and_decode_pem_file(os.path.join(self.base_path,
                                                  "ec_signing_ee_b3.pem"))
        )

        paired_ec_cert = parse_certificate(
            load_and_decode_pem_file(os.path.join(self.base_path,
                                                  "ec_signing_ee_b3_paired_cert.pem"))
        )

        delta_cert = build_delta_cert_from_paired_cert(
            paired_cert=paired_ec_cert
        )

        encoded = encoder.encode(delta_cert)
        encoded2 = encoder.encode(ec_signing_ee)
        self.assertEqual(encoded, encoded2)




if __name__ == '__main__':
    unittest.main()