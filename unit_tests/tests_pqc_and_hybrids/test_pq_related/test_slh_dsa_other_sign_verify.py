# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.keys.sig_keys import AltSLHDSAPrivateKey

# version from: pip install SLH-DSA

class TestSlhDsaOtherSignVerify(unittest.TestCase):

    def test_slh_dsa_other_sign_verify(self):
        """
        GIVEN a SLH-DSA key.
        WHEN data is signed with SLH-DSA-SHA2-128f.
        THEN the signature should be successfully verified.
        """
        private_key = AltSLHDSAPrivateKey("sha2_128f")
        pub_key = private_key.public_key()

        message = b"Hello World"
        signature = private_key.sign(message)
        pub_key.verify(signature=signature, data=message)
