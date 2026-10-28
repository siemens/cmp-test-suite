# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1_alt_modules import rfc9480
from resources.cmputils import prepare_info_type_and_value
from resources.general_msg_utils import validate_general_response, validate_get_ca_certs

from unit_tests.prepare_support_message_structures import build_genp_pkimessage


class TestValidateGeneralResponse(unittest.TestCase):

    def test_single_element(self):
        """
        GIVEN a `genp` message with one `InfoTypeAndValue` element.
        WHEN `validate_general_response` is called with the default expected size.
        THEN no error should be raised.
        """
        genp = build_genp_pkimessage([prepare_info_type_and_value(rfc9480.id_it_caCerts)])
        validate_general_response(genp)

    def test_two_elements(self):
        """
        GIVEN a `genp` message with two `InfoTypeAndValue` elements.
        WHEN `validate_general_response` is called with the default expected size.
        THEN a `ValueError` should be raised, because RFC 9483 Section 4.3 requires one element.
        """
        genp = build_genp_pkimessage(
            [
                prepare_info_type_and_value(rfc9480.id_it_caCerts),
                prepare_info_type_and_value(rfc9480.id_it_certReqTemplate),
            ]
        )
        with self.assertRaises(ValueError):
            validate_general_response(genp)

    def test_get_ca_certs_with_two_elements(self):
        """
        GIVEN a `genp` message with an `id-it-caCerts` element and a second element.
        WHEN `validate_get_ca_certs` is called.
        THEN a `ValueError` should be raised before the content is checked.
        """
        genp = build_genp_pkimessage(
            [
                prepare_info_type_and_value(rfc9480.id_it_caCerts),
                prepare_info_type_and_value(rfc9480.id_it_certReqTemplate),
            ]
        )
        with self.assertRaises(ValueError):
            validate_get_ca_certs(genp)


if __name__ == "__main__":
    unittest.main()
