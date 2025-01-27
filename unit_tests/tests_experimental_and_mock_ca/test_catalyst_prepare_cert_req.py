import unittest

from pq_logic.hybrid_issuing import prepare_catalyst_cert_req_msg_approach
from pq_logic.hybrid_sig.catalyst_logic import load_catalyst_public_key
from resources.ca_ra_utils import get_public_key_from_cert_req_msg
from resources.keyutils import load_private_key_from_file, generate_key


class TestPrepareCatalystCertReq(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ec_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        cls.pq_kem = load_private_key_from_file("data/keys/private-key-ml-kem-768.pem")
        cls.pq_mldsa = load_private_key_from_file("data/keys/private-key-ml-dsa-44.pem")
        cls.common_name = "CN=Hans the Tester"

    def test_trad_sig_key_and_pq_sig_key(self):
        """
        GIVEN a traditional signature key and a post-quantum signature key.
        WHEN preparing a certificate request message,
        THEN should the structure be correctly populated.
        """
        cert_req_msg = prepare_catalyst_cert_req_msg_approach(
            first_key=self.ec_key,
            alt_key=self.pq_mldsa,
            subject=self.common_name,
        )

        public_key = get_public_key_from_cert_req_msg(cert_req_msg)
        self.assertEqual(public_key, self.ec_key.public_key())
        loaded_key = load_catalyst_public_key(cert_req_msg["certReq"]["certTemplate"]["extensions"])
        self.assertEqual(loaded_key, self.pq_mldsa.public_key())

    def test_pq_sig_and_trad_sig_key(self):
        """
        GIVEN a post-quantum signature key and a traditional signature key.
        WHEN preparing a certificate request message,
        THEN should the structure be correctly populated.
        """
        cert_req_msg = prepare_catalyst_cert_req_msg_approach(
            first_key=self.pq_mldsa,
            alt_key=self.ec_key,
            subject=self.common_name,
        )

        public_key = get_public_key_from_cert_req_msg(cert_req_msg)
        self.assertEqual(public_key, self.pq_mldsa.public_key())
        loaded_key = load_catalyst_public_key(cert_req_msg["certReq"]["certTemplate"]["extensions"])
        self.assertEqual(loaded_key, self.ec_key.public_key())

    def test_pq_kem_and_trad_sig_key(self):
        """
        GIVEN a post-quantum key encapsulation key and a traditional signature key.
        WHEN preparing a certificate request message,
        THEN should the structure be correctly populated.
        """
        cert_req_msg = prepare_catalyst_cert_req_msg_approach(
            first_key=self.pq_kem,
            alt_key=self.ec_key,
            subject=self.common_name,
        )
        public_key = get_public_key_from_cert_req_msg(cert_req_msg)
        self.assertEqual(public_key, self.pq_kem.public_key())
        loaded_key = load_catalyst_public_key(cert_req_msg["certReq"]["certTemplate"]["extensions"])
        self.assertEqual(loaded_key, self.ec_key.public_key())

    def test_trad_sig_key_and_pq_kem(self):
        """
        GIVEN a traditional signature key and a post-quantum KEM key.
        WHEN preparing a certificate request message,
        THEN should the structure be correctly populated.
        """
        cert_req_msg = prepare_catalyst_cert_req_msg_approach(
            first_key=self.ec_key,
            alt_key=self.pq_kem,
            subject=self.common_name,
        )
        public_key = get_public_key_from_cert_req_msg(cert_req_msg)
        self.assertEqual(public_key, self.ec_key.public_key())
        loaded_key = load_catalyst_public_key(cert_req_msg["certReq"]["certTemplate"]["extensions"])
        self.assertEqual(loaded_key, self.pq_kem.public_key())


    def test_split_composite_key(self):
        """
        GIVEN a composite key.
        WHEN preparing a certificate request message,
        THEN should the structure be correctly populated.
        """
        key = generate_key("composite-sig")
        cert_req_msg = prepare_catalyst_cert_req_msg_approach(
            first_key=key.pq_key,
            alt_key=key.trad_key,
            subject=self.common_name,
        )
        public_key = get_public_key_from_cert_req_msg(cert_req_msg)
        self.assertEqual(public_key, key.pq_key.public_key())
        loaded_key = load_catalyst_public_key(cert_req_msg["certReq"]["certTemplate"]["extensions"])
        self.assertEqual(loaded_key, key.trad_key.public_key())
