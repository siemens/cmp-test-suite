# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.certutils import validate_migration_oid_in_certificate
from resources.certbuildutils import build_certificate
from resources.keyutils import generate_key


class TestValidateMigrationOidInCert(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.comp_sig_key = generate_key("composite-sig", trad_name="rsa", length=2048,
                                        pq_name="ml-dsa-44")

    def test_composite_oid(self):
        """
        GIVEN a certificate with a composite signature key
        WHEN validate_migration_oid_in_certificate is called with a matching name,
        THEN no exception is raised.
        """

        cert, key = build_certificate(
            private_key=self.comp_sig_key,
            use_rsa_pss=False,
        )
        validate_migration_oid_in_certificate(
            cert=cert,
            alg_name="composite-sig-07-ml-dsa-44-rsa2048",
        )

    def test_composite_oid_wrong(self):
        """
        GIVEN a certificate with a composite signature key
        WHEN validate_migration_oid_in_certificate is called with a wrong name,
        THEN a ValueError is raised.
        """

        cert, key = build_certificate(
            private_key=self.comp_sig_key,
            use_rsa_pss=False,
        )
        with self.assertRaises(ValueError):
            validate_migration_oid_in_certificate(
                cert=cert,
                alg_name="composite-sig-07-ml-dsa-44-rsa2048-pss",
            )
