# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.general_msg_utils import validate_crl_update_retrieval
from resources.utils import load_crl_from_file

from unit_tests.prepare_support_message_structures import build_crl_update_retrieval_pkimessage


class TestValidateGetCACerts(unittest.TestCase):

    def test_valid_crl_update_retrieval_genp(self):
        """
        GIVEN a `genp` PKIMessage with a valid CRL Update Retrieval response with a CRL.
        WHEN validate_crl_update_retrieval is called with this PKIMessage.
        THEN the function should validate successfully, confirming the CRL Update Retrieval structure is correct.
        """
        crl_filepath = "data/unittest/test_verify_crl.crl"
        crl_list = load_crl_from_file(crl_filepath)
        genp = build_crl_update_retrieval_pkimessage(crl_list)
        validate_crl_update_retrieval(genp, ca_certs="./data/unittest")

    def test_valid_crl_update_retrieval_genp_without_data(self):
        """
        GIVEN a `genp` PKIMessage with a CRL Update Retrieval response without a CRL.
        WHEN validate_crl_update_retrieval is called with must_be_present=False.
        THEN the function should validate successfully, confirming the absence of a CRL is acceptable in this case.
        """
        genp = build_crl_update_retrieval_pkimessage(None)
        validate_crl_update_retrieval(genp, must_be_present=False)

if __name__ == "__main__":
    unittest.main()
