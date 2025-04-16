# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from pq_logic.pq_verify_logic import build_migration_cert_chain
from resources.ca_ra_utils import build_ip_cmp_message
from resources.certbuildutils import build_certificate
from resources.certutils import build_cmp_chain_from_pkimessage
from resources.cmputils import prepare_cert_req_msg, build_ir_from_key
from resources.keyutils import generate_key
from unit_tests.utils_for_test import compare_pyasn1_objects


class TestBuildCompositeCertChain(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.root_cert, cls.root_key = build_certificate(private_key=generate_key("composite-sig"),
                                            common_name="CN=Root Composite Cert")

    def test_build_composite_cert_chain(self):
        """
        GIVEN a list of certificates.
        WHEN building a composite certificate chain.
        THEN the chain is built correctly.
        """
        key = generate_key("composite-sig")
        cert3, _ = build_certificate(private_key=key,
                                     ca_key=key,
                                     common_name="CN=Root Composite Cert")
        cert2, _ = build_certificate(private_key=key,
                                     ca_key=key,
                                     common_name="CN=Intermediate Composite Cert",
                                     ca_cert=cert3)

        cert1, _ = build_certificate(private_key=key,
                                     ca_key=key,
                                     common_name="CN=End Entity Composite Cert",
                                     ca_cert=cert2)

        certs = [cert1, cert2, cert3]
        chain = build_migration_cert_chain(cert1, certs, allow_self_signed=False)


        self.assertEqual(len(chain), 3)
        result = compare_pyasn1_objects(chain[0], cert1)
        self.assertTrue(result)
        result = compare_pyasn1_objects(chain[1], cert2)
        self.assertTrue(result)
        result = compare_pyasn1_objects(chain[2], cert3)
        self.assertTrue(result)

    def test_allow_self_signed(self):
        cert_chain = [self.root_cert]
        chain = build_migration_cert_chain(self.root_cert, cert_chain, allow_self_signed=True)
        self.assertEqual(len(chain), 1)
        result = compare_pyasn1_objects(chain[0], self.root_cert)
        self.assertTrue(result)

    def test_disallow_self_signed(self):
        """
        GIVEN a self-signed certificate.
        WHEN building a composite certificate chain, with allow_self_signed=False,
        THEN a ValueError is raised.
        """
        cert_chain = [self.root_cert]
        with self.assertRaises(ValueError):
            build_migration_cert_chain(self.root_cert, cert_chain, allow_self_signed=False)

    def test_build_composite_cert_chain_different_keys(self):
        """
        GIVEN a list of certificates.
        WHEN building a composite certificate chain.
        THEN the chain is built correctly.
        """
        key3 = generate_key("rsa")
        cert3, _ = build_certificate(private_key=key3,
                                     common_name="CN=Root RSA Cert")
        key2 = generate_key("ml-dsa-44")
        cert2, _ = build_certificate(private_key=key2,
                                     ca_key=key3,
                                     common_name="CN=Intermediate PQ Cert",
                                     ca_cert=cert3)

        key1 = generate_key("composite-sig")
        cert1, _ = build_certificate(private_key=key1,
                                     ca_key=key2,
                                     common_name="CN=End Entity Composite Cert",
                                     ca_cert=cert2)

        certs = [cert1, cert2, cert3]
        chain = build_migration_cert_chain(cert1, certs, allow_self_signed=False)


        self.assertEqual(len(chain), 3)
        result = compare_pyasn1_objects(chain[0], cert1)
        self.assertTrue(result)
        result = compare_pyasn1_objects(chain[1], cert2)
        self.assertTrue(result)
        result = compare_pyasn1_objects(chain[2], cert3)
        self.assertTrue(result)



if __name__ == '__main__':
    unittest.main()