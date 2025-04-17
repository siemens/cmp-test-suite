# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0


from pq_logic.keys.composite_sig03 import CompositeSig03PrivateKey
from pq_logic.pq_verify_logic import verify_composite_signature_with_hybrid_cert
from resources.certbuildutils import generate_certificate
from resources.certutils import parse_certificate
from resources.cryptoutils import sign_data
from resources.keyutils import load_private_key_from_file
from resources.utils import load_and_decode_pem_file


class TestSigVerificationMultiCert:

    @classmethod
    def setUpClass(cls):
        cls.pq_key = load_private_key_from_file("data/keys/private-key-ml-dsa-65.pem")
        cls.cert_a_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.cert_a = parse_certificate(load_and_decode_pem_file("data/unittest/rsa_cert_ski.pem"))
        cls.cert_b = parse_certificate(load_and_decode_pem_file("data/unittest/pq_root_ca_ml_dsa_44.pem"))
        cls.cert_related = generate_certificate(private_key=cls.cert_a_key, issuer_cert=cls.cert_b, hash_alg="sha256")

    def test_sig_with_related_cert(self):
        """
        GIVEN a signature with a related certificate.
        WHEN verifying the signature with the related certificate.
        THEN the signature is correctly verified.
        """
        mldsa_key = load_private_key_from_file("data/keys/private-key-ml-dsa-44.pem")
        rsa_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        composite_key = CompositeSig03PrivateKey(mldsa_key, rsa_key)
        signature = sign_data(key=composite_key, data=b"Hello World")


        verify_composite_signature_with_hybrid_cert(data=b"Hello World",
                                                    signature=signature,
                                                    cert=self.cert_related,
                                                    other_certs=[self.cert_a, self.cert_b])



