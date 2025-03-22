# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
import unittest

from pq_logic.keys.kem_keys import MLKEMPrivateKey
from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc9480
from resources.certbuildutils import generate_certificate
from resources.cmputils import build_ir_from_key
from resources.cryptoutils import compute_ansi_x9_63_kdf, compute_hmac
from resources.keyutils import load_private_key_from_file
from resources.protectionutils import (
    compute_kem_based_mac_from_alg_id,
    prepare_kem_based_mac_alg_id,
    prepare_kem_ciphertextinfo,
    prepare_kem_other_info,
    protect_pkimessage_kem_based_mac,
    verify_kem_based_mac_protection,
)


class TestKEMBasedMac(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.mlkem_key: MLKEMPrivateKey = load_private_key_from_file("./data/keys/private-key-ml-kem-768.pem")
        cls.rsa_key = load_private_key_from_file("./data/keys/private-key-rsa.pem", password=None)
        cls.kem_cert = generate_certificate(private_key=cls.mlkem_key, signing_key=cls.rsa_key)

    def test_prepare_kem_based_mac_alg_id(self):
        """
        GIVEN parameter for prepare_kem_based_mac_alg_id
        WHEN prepare_kem_based_mac_alg_id is called and the result is decoded,
        THEN the decoding should not have a remainder.
        """
        alg_id = prepare_kem_based_mac_alg_id(kdf="kdf3", length=32, hash_alg="sha256")
        self.assertIsNotNone(alg_id)
        decoded_alg_id, rest = decoder.decode(encoder.encode(alg_id), rfc9480.AlgorithmIdentifier())
        self.assertEqual(rest, b"")



    def test_compute_kem_based_mac(self):
        """
        GIVEN data, shared secret and algorithm ID.
        WHEN compute_kem_based_mac is called,
        THEN the computed MAC should be equal to the expected MAC.
        """
        data = b"AAAAAAAAAAAAAAAAAAAAAAAA"
        kem_context = prepare_kem_other_info(transaction_id=b"12345678", static_string="CMP-KEM")
        alg_id = prepare_kem_based_mac_alg_id(kdf="kdf3", length=32, hash_alg="sha256",
                                              kem_context=kem_context)
        ss, _ = self.mlkem_key.public_key().encaps()
        computed_mac = compute_kem_based_mac_from_alg_id(data=data, alg_id=alg_id, ss=ss)
        der_kem_context = encoder.encode(kem_context)
        mac_key = compute_ansi_x9_63_kdf(ss, 32, der_kem_context, hash_alg="sha256",
                                         use_version_2=False)
        mac = compute_hmac(key=mac_key, data=data, hash_alg="sha256")
        self.assertEqual(mac.hex(), computed_mac.hex())


    def test_protect_pkimessage_kem_based_mac(self):
        """
        GIVEN a PKIMessage and a KEM certificate.
        WHEN the PKIMessage is protected,
        THEN should no exception be raised.
        """
        protect_pkimessage_kem_based_mac(pki_message=build_ir_from_key(self.rsa_key),
                                                       peer_cert=self.kem_cert)

    def test_prepare_protect_from_kem_ct_info(self):
        """
        GIVEN a KEM CT info and a valid PKIMessage.
        WHEN the PKIMessage is protected with the KEM CT info,
        THEN should the protection be valid.
        """
        ss, ct = self.mlkem_key.public_key().encaps()
        kem_ct_info = prepare_kem_ciphertextinfo(key=self.mlkem_key,
                                                 ct=ct)["infoValue"]

        protected_ir = protect_pkimessage_kem_based_mac(pki_message=build_ir_from_key(self.rsa_key),
                                                         private_key=self.mlkem_key,
                                                            kem_ct_info=kem_ct_info)

        verify_kem_based_mac_protection(pki_message=protected_ir,
                                        private_key=None, shared_secret=ss)


    def test_verify_pkimessage_kem_based_mac(self):
        """
        GIVEN a PKIMessage protected with a KEM based MAC.
        WHEN the PKIMessage is verified with the private key,
        THEN should the verification be successful.
        """
        kem_context = prepare_kem_other_info(transaction_id=b"12345678", static_string="CMP-KEM")
        pki_message = protect_pkimessage_kem_based_mac(
            pki_message=build_ir_from_key(self.rsa_key, transaction_id=b"12345678"),
                                                       peer_cert=self.kem_cert,
            kem_context=kem_context,
        kdf = "kdf3", hash_alg = "sha256")

        decoded_pki_message, _ = decoder.decode(encoder.encode(pki_message), rfc9480.PKIMessage())
        verify_kem_based_mac_protection(decoded_pki_message, self.mlkem_key)




