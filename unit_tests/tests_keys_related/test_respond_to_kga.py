# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from pyasn1_alt_modules import rfc9480

from pq_logic.keys.composite_kem07 import CompositeKEM07PrivateKey, CompositeKEM07PublicKey
from pq_logic.keys.composite_sig04 import CompositeSig04PublicKey
from resources.asn1_structures import PKIMessageTMP
from resources.ca_ra_utils import prepare_cert_and_private_key_for_kga
from resources.certbuildutils import build_certificate, prepare_cert_template
from resources.certutils import load_public_key_from_cert
from resources.keyutils import generate_key


class TestRespondToKGA(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ca_cert, cls.ca_key = build_certificate(private_key=generate_key("rsa", length=2048),
                                                    use_rsa_pss=False)

        cls.request = PKIMessageTMP()
        cls.request["header"]["protectionAlg"]["algorithm"] = rfc9480.id_PasswordBasedMac

    def test_prepare_correct_kga_response(self):
        """
        GIVEN a KGA request.
        WHEN the response is prepared.
        THEN the response should be prepared correctly.
        """
        cert_template = prepare_cert_template(
            for_kga=True,
            subject="CN=KGA",
        )


        cert, env_data = prepare_cert_and_private_key_for_kga(
            cert_template=cert_template,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            request=self.request,
            password=b"password",
            kga_cert_chain=[self.ca_cert],
            kga_key=self.ca_key,
        )
        pub_key = load_public_key_from_cert(cert)
        self.assertIsInstance(pub_key, RSAPublicKey)

    def test_prepare_kga_response_with_composite_sig_key(self):
        """
        GIVEN a KGA request for a composite signature key.
        WHEN the response is prepared,
        THEN the response should be prepared correctly.
        """
        comp_key = generate_key("composite-sig", trad_name="rsa", pq_name="ml-dsa-44")
        cert_template = prepare_cert_template(
            for_kga=True,
            key=comp_key,
            subject="CN=KGA",
        )
        self.assertEqual(b"", cert_template["publicKey"]["subjectPublicKey"].asOctets())

        cert, env_data = prepare_cert_and_private_key_for_kga(
            cert_template=cert_template,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            request=self.request,
            password=b"password",
            kga_cert_chain=[self.ca_cert],
            kga_key=self.ca_key,
        )
        pub_key = load_public_key_from_cert(cert)
        self.assertIsInstance(pub_key, CompositeSig04PublicKey)


    def test_prepare_kga_response_with_composite_kem_key(self):
        """
        GIVEN a KGA request for a composite kem key.
        WHEN the response is prepared,
        THEN the response should be prepared correctly.
        """
        comp_key = generate_key("composite-kem", trad_name="rsa",
                                pq_name="ml-kem-768", length=2048)
        cert_template = prepare_cert_template(
            for_kga=True,
            key=comp_key,
            subject="CN=KGA",
        )
        self.assertEqual(b"", cert_template["publicKey"]["subjectPublicKey"].asOctets())

        cert, env_data = prepare_cert_and_private_key_for_kga(
            cert_template=cert_template,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            request=self.request,
            password=b"password",
            kga_cert_chain=[self.ca_cert],
            kga_key=self.ca_key,
        )
        pub_key = load_public_key_from_cert(cert)
        self.assertIsInstance(pub_key, CompositeKEM07PublicKey)

