# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from typing import Optional

from pyasn1_alt_modules import rfc5652, rfc9480

from resources.asn1_structures import PKIMessageTMP
from resources.ca_ra_utils import build_ip_cmp_message
from resources.certbuildutils import build_certificate
from resources.certutils import load_public_key_from_cert
from resources.cmputils import build_ir_from_key, prepare_cert_request, get_cert_from_pkimessage
from resources.envdatautils import prepare_enc_key_for_popo, prepare_recipient_identifier
from resources.extra_issuing_logic import prepare_enc_key_with_id
from resources.keyutils import generate_key
from resources.protectionutils import protect_pkimessage
from resources.typingutils import PrivateKey
from unit_tests.utils_for_test import load_ca_cert_and_key, load_env_data_certs


class TestBuildIPWithEncrKey(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ca_cert, cls.ca_key = load_ca_cert_and_key()
        cls.kga_certs = load_env_data_certs()
        cls.encr_cert = cls.kga_certs["encr_rsa_cert"]
        cls.encr_key = cls.kga_certs["encr_rsa_key"]

        cls.client_cert, cls.client_key = build_certificate()

    @staticmethod
    def _build_request(new_key: PrivateKey,
                       rid: rfc5652.RecipientIdentifier,
                       ca_cert: rfc9480.CMPCertificate,
                       common_name: str,
                       for_mac: bool = False,
                       ecc_private_key: Optional[PrivateKey] = None,
                       ) -> PKIMessageTMP:
        """Build a certificate request and a proof of possession object."""
        enc_key_with_id = prepare_enc_key_with_id(
            private_key=new_key,
            sender="CN=Hans the Tester",
            use_string=False,
        )
        cert_request = prepare_cert_request(new_key, common_name)
        popo = prepare_enc_key_for_popo(
            enc_key_with_id=enc_key_with_id,
            ca_cert=ca_cert,
            for_agreement=True,
            rid=rid,
            private_key=ecc_private_key,
        )

        ir = build_ir_from_key(
            signing_key=new_key,
            cert_request=cert_request,
            private_key=new_key,
            popo=popo,
            sender="CN=Hans the Tester",
            exclude_fields="sender,senderKID" if not for_mac else None,
        )
        return ir

    def test_build_ip_with_encr_key_ecc(self):
        """
        GIVEN an CA ECC encryption certificate and key and a client key.
        WHEN an IP is built using the encryption key.
        THEN the IP should be built successfully.
        """
        new_key = generate_key("x448")

        client_cert, client_key = build_certificate("ecc",
                                                    ca_cert=self.ca_cert,
                                                    ca_key=self.ca_key,
                                                    )

        rid = prepare_recipient_identifier(
            cert=client_cert, # MUST be the CMP-protection certificate.
        )
        ir = self._build_request(
            new_key=new_key,
            rid=rid,
            common_name="CN=Hans the Tester",
            for_mac=False,
            ca_cert=self.kga_certs["ecc_cert"],
            ecc_private_key=client_key,
        )

        protected_ir = protect_pkimessage(ir,
                                          protection="signature",
                                          cert=client_cert,
                                          private_key=client_key,
                                          )

        pki_message , _ = build_ip_cmp_message(
            request=protected_ir,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            ecc_key=self.kga_certs["ecc_key"], # ECC key for decryption
            ecc_cert=self.kga_certs["ecc_cert"], # ECC certificate for validation of the RID.
        )

        cert = get_cert_from_pkimessage(pki_message)
        public_key = load_public_key_from_cert(cert)
        self.assertEqual(new_key.public_key(), public_key)

    def test_build_ip_with_encr_key_x448(self):
        """
        GIVEN an CA x448 encryption certificate and key and a client key.
        WHEN an IP is built using the encryption key.
        THEN the IP should be built successfully.
        """
        new_key = generate_key("x25519")

        client_cert, client_key = build_certificate("x448",
                                                    ca_cert=self.ca_cert,
                                                    ca_key=self.ca_key,
                                                    )

        rid = prepare_recipient_identifier(
            cert=client_cert,
        )
        ir = self._build_request(
            new_key=new_key,
            rid=rid,
            common_name="CN=Hans the Tester",
            for_mac=False,
            ca_cert=self.kga_certs["x448_cert"],
            ecc_private_key=client_key,
        )
        kari_pub_key = load_public_key_from_cert(self.kga_certs["x448_cert"])
        ss = client_key.exchange(kari_pub_key)
        protected_ir = protect_pkimessage(ir,
                                            protection="dh",
                                            cert=client_cert,
                                            private_key=client_key,
                                            shared_secret=ss,
                                            )
        pki_message , _ = build_ip_cmp_message(
            request=protected_ir,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            x448_key=self.kga_certs["x448_key"],
            x448_cert=self.kga_certs["x448_cert"],
        )

    def test_build_ip_with_encr_key_x25519(self):
        """
        GIVEN an CA x25519 encryption certificate and key and a client key.
        WHEN an IP is built using the encryption key.
        THEN the IP should be built successfully.
        """
        new_key = generate_key("x448")

        client_cert, client_key = build_certificate("x25519",
                                                    ca_cert=self.ca_cert,
                                                    ca_key=self.ca_key,
                                                    )

        rid = prepare_recipient_identifier(
            cert=client_cert, # MUST be the CMP-protection certificate.
        )

        kari_cert = self.kga_certs["x25519_cert"]
        ir = self._build_request(
            new_key=new_key,
            rid=rid,
            common_name="CN=Hans the Tester",
            for_mac=False,
            ca_cert=kari_cert,
            ecc_private_key=client_key,
        )
        kari_pub_key = load_public_key_from_cert(kari_cert)
        ss = client_key.exchange(kari_pub_key)
        protected_ir = protect_pkimessage(ir,
                                          protection="dh",
                                          cert=client_cert,
                                          private_key=client_key,
                                          shared_secret=ss,
                                          )

        pki_message , _ = build_ip_cmp_message(
            request=protected_ir,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            x25519_key=self.kga_certs["x25519_key"],
            x25519_cert=self.kga_certs["x25519_cert"],
        )

        cert = get_cert_from_pkimessage(pki_message)
        public_key = load_public_key_from_cert(cert)
        self.assertEqual(new_key.public_key(), public_key)

    def test_build_x25519_ip_with_encr_key(self):
        """
        GIVEN an CA encryption certificate and key and a client key.
        WHEN an IP is built using the encryption key.
        THEN the IP should be built successfully.
        """
        new_key = generate_key("x448")

        rid = prepare_recipient_identifier(
            cert=self.client_cert, # MUST be the CMP-protection certificate.
        )
        ir = self._build_request(
            new_key=new_key,
            rid=rid,
            common_name="CN=Hans the Tester",
            for_mac=False,
            ca_cert=self.encr_cert,
        )

        protected_ir = protect_pkimessage(ir,
                                          protection="signature",
                                          cert=self.client_cert,
                                          private_key=self.client_key,
                                          )

        pki_message , _ = build_ip_cmp_message(
            request=protected_ir,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            encr_rsa_key=self.encr_key, # RSA key for decryption
        )

        cert = get_cert_from_pkimessage(pki_message)
        public_key = load_public_key_from_cert(cert)
        self.assertEqual(new_key.public_key(), public_key)

    def test_build_enc_key_kem(self):
        """
        GIVEN a CA KEM certificate and key and a client key.
        WHEN an IP is built using the encryption key.
        THEN the IP should be built successfully.
        """
        new_key = generate_key("x448")

        rid = prepare_recipient_identifier(
            cert=self.kga_certs["kem_cert"], # MUST be the KEM encryption certificate.
        )
        ir = self._build_request(
            new_key=new_key,
            rid=rid,
            common_name="CN=Hans the Tester",
            for_mac=False,
            ca_cert=self.kga_certs["kem_cert"],
        )

        protected_ir = protect_pkimessage(ir,
                                          protection="signature",
                                          cert=self.client_cert,
                                          private_key=self.client_key,
                                          )

        pki_message , _ = build_ip_cmp_message(
            request=protected_ir,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            kem_key=self.kga_certs["kem_key"], # KEM key for decryption
            kem_cert=self.kga_certs["kem_cert"], # KEM certificate for validation of the RID.
        )

        cert = get_cert_from_pkimessage(pki_message)
        public_key = load_public_key_from_cert(cert)
        self.assertEqual(new_key.public_key(), public_key)

    def test_build_enc_key_hybrid_kem(self):
        """
        GIVEN a CA hybrid KEM certificate and key and a client key.
        WHEN an IP is built using the encryption key.
        THEN the IP should be built successfully.
        """
        new_key = generate_key("x448")

        rid = prepare_recipient_identifier(
            cert=self.kga_certs["hybrid_kem_cert"], # MUST be the KEM certificate.
        )
        ir = self._build_request(
            new_key=new_key,
            rid=rid,
            common_name="CN=Hans the Tester",
            for_mac=True,
            ca_cert=self.kga_certs["hybrid_kem_cert"],
        )

        protected_ir = protect_pkimessage(ir,
                                          protection="signature",
                                          cert=self.client_cert,
                                          private_key=self.client_key,
                                          )

        pki_message, _ = build_ip_cmp_message(
            request=protected_ir,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            hybrid_kem_key=self.kga_certs["hybrid_kem_key"], # KEM key for decryption
            hybrid_kem_cert=self.kga_certs["hybrid_kem_cert"], # KEM certificate for validation of the RID.
            kem_cert=self.kga_certs["kem_cert"], # KEM certificate for validation of the RID.
            kem_key=self.kga_certs["kem_key"], # KEM key for decryption
        )

        cert = get_cert_from_pkimessage(pki_message)
        public_key = load_public_key_from_cert(cert)
        self.assertEqual(new_key.public_key(), public_key)
