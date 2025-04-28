# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.hybrid_issuing import prepare_catalyst_cert_req_msg_approach, verify_sig_popo_catalyst_cert_req_msg
from resources.keyutils import load_private_key_from_file


class TestVerifyCatalystRequest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ec_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        cls.pq_mldsa = load_private_key_from_file("data/keys/private-key-ml-dsa-44-seed.pem")
        cls.pq_kem = load_private_key_from_file("data/keys/private-key-ml-kem-768-seed.pem")
        cls.common_name = "CN=Hans the Tester"

    def test_verify_catalyst_request_pq_sig_and_trad_composite(self):
        """
        GIVEN a composite key.
        WHEN the Composite request is verified.
        THEN the request is successfully verified.
        """
        cert_req_msg = prepare_catalyst_cert_req_msg_approach(
            first_key=self.pq_mldsa,
            alt_key=self.ec_key,
            subject=self.common_name,
            use_composite_sig=True,
        )
        verify_sig_popo_catalyst_cert_req_msg(cert_req_msg)

    def test_verify_catalyst_request_pq_and_trad_sig(self):
        """
        GIVEN a Catalyst request with a post-quantum and a traditional signature key.
        WHEN the request is verified.
        THEN the request is successfully verified.
        """
        cert_req_msg = prepare_catalyst_cert_req_msg_approach(
            first_key=self.pq_mldsa,
            alt_key=self.ec_key,
            subject=self.common_name,
            use_composite_sig=False,
        )
        verify_sig_popo_catalyst_cert_req_msg(cert_req_msg)


    def test_verify_catalyst_request_trad_and_pq_sig(self):
        """
        GIVEN a Catalyst request with a post-quantum and a traditional signature key.
        WHEN the request is verified.
        THEN the request is successfully verified.
        """
        cert_req_msg = prepare_catalyst_cert_req_msg_approach(
            first_key=self.ec_key,
            alt_key=self.pq_mldsa,
            subject=self.common_name,
            use_composite_sig=False,
        )
        verify_sig_popo_catalyst_cert_req_msg(cert_req_msg)

    def test_verify_trad_sig_and_pq_kem(self):
        """
        GIVEN a Catalyst request with a traditional and a post-quantum KEM key.
        WHEN the request is verified.
        THEN the request is successfully verified.
        """
        cert_req_msg = prepare_catalyst_cert_req_msg_approach(
            first_key=self.ec_key,
            alt_key=self.pq_kem,
            subject=self.common_name,
            use_composite_sig=False,
        )
        verify_sig_popo_catalyst_cert_req_msg(cert_req_msg)


    def test_verify_pq_kem_and_trad_sig(self):
        """
        GIVEN a Catalyst request with a post-quantum KEM and a traditional key.
        WHEN the request is verified.
        THEN the request is successfully verified.
        """
        cert_req_msg = prepare_catalyst_cert_req_msg_approach(
            first_key=self.pq_kem,
            alt_key=self.ec_key,
            subject=self.common_name,
            use_composite_sig=False,
        )
        verify_sig_popo_catalyst_cert_req_msg(cert_req_msg)

