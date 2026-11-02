# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1_alt_modules import rfc9480
from resources.cmputils import prepare_info_type_and_value
from resources.general_msg_utils import validate_get_ca_certs

from unit_tests.prepare_support_message_structures import build_genp_get_ca_certs, build_genp_pkimessage
from unit_tests.utils_for_test import compare_cert_chain, load_or_generate_cert_chain


class TestValidateGetCACerts(unittest.TestCase):

    def test_valid_structure_without(self):
        """
        GIVEN a valid certificate chain that starts from the root and ends with the end-entity certificate (EE).
        WHEN check_get_ca_certs is called with a `PKIMessage` containing this chain.
        THEN the extracted certificate chain should have the correct length of 6, and match the
        original chain in reverse order.
        """
        # start from root -> ee.
        cert_chain, keys = load_or_generate_cert_chain()
        genp = build_genp_get_ca_certs(cert_chain)
        # starts from ee -> root
        extracted_chain = validate_get_ca_certs(genp)
        self.assertTrue(len(extracted_chain), 6)
        self.assertTrue(compare_cert_chain(extracted_chain, cert_chain[::-1]))

    def test_valid_structure_with_ee(self):
        """
        GIVEN a certificate chain that starts from the root to the second-to-last certificate (without the EE cert).
        WHEN check_get_ca_certs is called with a `PKIMessage` containing this partial chain and the EE certificate.
        THEN the extracted certificate chain should have a length of 6 and match the original chain,
        including the EE cert, in reverse order.
        """
        # start from root -> ee.
        cert_chain, keys = load_or_generate_cert_chain()
        genp = build_genp_get_ca_certs(cert_chain[:-1])
        # starts from ee -> root
        extracted_chain = validate_get_ca_certs(genp, ee_cert=cert_chain[-1])
        self.assertTrue(len(extracted_chain), 6)
        self.assertTrue(compare_cert_chain(extracted_chain, cert_chain[::-1]))

    def test_absent_info_value(self):
        """
        GIVEN a `genp` with the `id-it-caCerts` OID and an absent `infoValue`.
        WHEN validate_get_ca_certs is called with the default `must_be_present=False`.
        THEN no exception is raised and `None` is returned.
        """
        genp = build_genp_pkimessage([prepare_info_type_and_value(rfc9480.id_it_caCerts)])
        self.assertIsNone(validate_get_ca_certs(genp))

    def test_absent_info_value_must_be_present(self):
        """
        GIVEN a `genp` with the `id-it-caCerts` OID and an absent `infoValue`.
        WHEN validate_get_ca_certs is called with `must_be_present=True`.
        THEN a ValueError is raised.
        """
        genp = build_genp_pkimessage([prepare_info_type_and_value(rfc9480.id_it_caCerts)])
        with self.assertRaises(ValueError):
            validate_get_ca_certs(genp, must_be_present=True)


if __name__ == "__main__":
    unittest.main()
