# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from typing import List, Tuple

from mock_ca.mock_fun import CertificateDB, CertStateEnum
from pyasn1_alt_modules import rfc9480

from unit_tests.utils_for_test import compare_pyasn1_objects, load_or_generate_cert_chain, verbose_pyasn1_compare


def compare_cert_list(cert_list1: List[rfc9480.CMPCertificate], cert_list2: List[rfc9480.CMPCertificate]) -> bool:
    """Compare two lists of CMPCertificate objects for equality."""

    if len(cert_list1) != len(cert_list2):
        return False

    for x, y in zip(cert_list1, cert_list2):

        if not compare_pyasn1_objects(x, y):
            return False
    return True

def compare_cert_list_verbose(cert_list1: List[rfc9480.CMPCertificate], cert_list2: List[rfc9480.CMPCertificate]) -> List[Tuple]:
    """Compare two lists of CMPCertificate objects for equality."""

    if len(cert_list1) != len(cert_list2):
        to_add = len(cert_list2) - len(cert_list1)
        if to_add < 0:
            raise ValueError("cert_list1 is longer than cert_list2")
        for _ in range(to_add):
            # Append empty certificates to cert_list1 to match lengths
            # This is a placeholder, in practice you might want to handle this differently
            # depending on your application's logic.
            cert_list1.append(rfc9480.CMPCertificate())

    output = [
        verbose_pyasn1_compare(x, y) for x, y in zip(cert_list1, cert_list2)
    ]

    return output

class TestGetUpdateHistory(unittest.TestCase):
    def setUp(self):
        self.db = CertificateDB()
        self.certs, _ = load_or_generate_cert_chain()
        self.cert1 = self.certs[0]
        self.cert2 = self.certs[1]
        self.cert3 = self.certs[2]
        self.unrelated_cert = self.certs[3]
        self.unrelated_cert2 = self.certs[4]

    def test_get_cert(self):
        """
        GIVEN updated certificates.
        WHEN the updated certificate is requested.
        THEN the correct certificate is returned.
        """
        self.db.add_cert(self.cert1, cert_state=CertStateEnum.CONFIRMED)
        self.db.change_cert_state(self.cert1, new_state=CertStateEnum.UPDATED,
                                  updated_cert=self.cert2)

        self.db.add_cert(self.cert2, cert_state=CertStateEnum.CONFIRMED)
        self.db.change_cert_state(self.cert2, new_state=CertStateEnum.UPDATED,
                                  updated_cert=self.cert3)

        self.db.add_cert(self.cert3, cert_state=CertStateEnum.CONFIRMED)

        up1 = self.db.get_updated_history(self.cert1)
        self.assertIsNotNone(up1)
        result = self.db.get_updated_history(self.cert3) is None
        self.assertTrue(result)

    def test_get_update_history(self):
        """
        GIVEN a list of update certificates.
        WHEN the update history is requested for a certificate.
        THEN the correct list of update certificates is returned.
        """
        self.db.add_cert(self.cert1, cert_state=CertStateEnum.CONFIRMED)
        self.db.add_cert(self.cert2, cert_state=CertStateEnum.CONFIRMED)
        self.db.add_cert(self.cert3, cert_state=CertStateEnum.CONFIRMED)
        self.db.change_cert_state(self.cert1, CertStateEnum.UPDATED, updated_cert=self.cert2)
        self.db.change_cert_state(self.cert2, CertStateEnum.UPDATED, updated_cert=self.cert3)

        # Add an unrelated certificate to ensure it does not affect the history.
        self.db.add_cert(self.unrelated_cert, cert_state=CertStateEnum.CONFIRMED)
        self.db.add_cert(self.unrelated_cert2, cert_state=CertStateEnum.CONFIRMED)

        up1_hist = self.db.get_updated_history(self.cert1)
        result = compare_cert_list(up1_hist, [self.cert1, self.cert2, self.cert3])
        self.assertTrue(result, compare_cert_list_verbose(up1_hist, [self.cert1, self.cert2, self.cert3]))

        history2 = self.db.get_updated_history(self.cert2)
        self.assertEqual(len(history2), 2)
        result = compare_cert_list(history2, [self.cert2, self.cert3])
        self.assertTrue(result, "Expected history to contain only cert3")
        self.assertIsNone(self.db.get_updated_history(self.cert3))  # No updates from cert3


if __name__ == "__main__":
    unittest.main()
