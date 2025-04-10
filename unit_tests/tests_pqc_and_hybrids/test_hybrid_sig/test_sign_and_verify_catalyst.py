# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.hybrid_sig import catalyst_logic
from pq_logic.keys.pq_key_factory import PQKeyFactory
from resources.certbuildutils import prepare_extensions
from resources.keyutils import generate_key


class TestVerifyCatalyst(unittest.TestCase):

    def test_verify_catalyst_signature(self):
        """
        GIVEN a catalyst certificate
        WHEN verifying the signature,
        THEN it should pass if the signature is valid.
        """
        trad_key = generate_key("rsa")
        pq_key = PQKeyFactory.generate_pq_key("ml-dsa-44")
        issued_key = generate_key("rsa")
        cert_ = catalyst_logic.build_catalyst_cert(trad_key=trad_key, pq_key=pq_key,
                                                   client_key=issued_key)

        catalyst_logic.verify_catalyst_signature(cert_, issuer_pub_key=trad_key.public_key())

    def test_verify_catalyst_signature_with_extensions(self):
        """
        GIVEN a catalyst certificate
        WHEN verifying the signature,
        THEN it should pass if the signature is valid.
        """
        trad_key = generate_key("rsa")
        pq_key = PQKeyFactory.generate_pq_key("ml-dsa-44")
        issued_key = generate_key("rsa")
        extensions = prepare_extensions(key=trad_key, is_ca=True)
        cert_ = catalyst_logic.build_catalyst_cert(trad_key=trad_key, pq_key=pq_key,
                                                   client_key=issued_key,
                                                   extensions=extensions)
        catalyst_logic.verify_catalyst_signature(cert_,
                                                 issuer_pub_key=trad_key.public_key())