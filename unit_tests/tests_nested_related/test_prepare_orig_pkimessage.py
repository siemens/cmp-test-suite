# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import decoder

from resources.asn1_structures import PKIMessagesTMP, InfoTypeAndValue
from resources.cmputils import build_ir_from_key, prepare_orig_pki_message
from resources.keyutils import load_private_key_from_file
from unit_tests.utils_for_test import try_encode_pyasn1
from resources.asn1utils import try_decode_pyasn1


class TestPrepareOriginalPkiMessage(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.private_key = load_private_key_from_file("./data/keys/private-key-ecdsa.pem")


    def test_prepare_original_pki_message(self):
        """
        GIVEN an IR message.
        WHEN the original PKIMessage is prepared.
        THEN the PKIMessage must be prepared correctly.
        """
        ir = build_ir_from_key(self.private_key)
        info_val = prepare_orig_pki_message(ir)
        der_data = try_encode_pyasn1(info_val)
        info_val, rest = decoder.decode(der_data, asn1Spec=InfoTypeAndValue())
        self.assertEqual(rest, b"")

        info_val: InfoTypeAndValue
        info_val = info_val["infoValue"].asOctets()
        nested, rest = decoder.decode(info_val, asn1Spec=PKIMessagesTMP())
        self.assertEqual(rest, b"")



