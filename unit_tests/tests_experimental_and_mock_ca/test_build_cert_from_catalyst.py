# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc9480

from pq_logic.hybrid_issuing import build_cert_from_catalyst_request, prepare_catalyst_cert_req_msg_approach
from pq_logic.hybrid_sig.catalyst_logic import load_catalyst_public_key
from resources.asn1_structures import PKIMessageTMP
from resources.asn1utils import encode_to_der, try_decode_pyasn1
from resources.certutils import parse_certificate, load_public_key_from_cert
from resources.cmputils import build_ir_from_key, get_cert_from_pkimessage
from resources.extra_issuing_logic import get_enc_cert_from_pkimessage
from resources.keyutils import load_private_key_from_file
from resources.utils import load_and_decode_pem_file


class TestBuildCertFromCatalyst(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ec_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        cls.pq_mldsa = load_private_key_from_file("data/keys/private-key-ml-dsa-44-seed.pem")
        cls.pq_kem = load_private_key_from_file("data/keys/private-key-ml-kem-768-seed.pem")
        cls.common_name = "CN=Hans the Tester"
        cls.password = b"A" * 32
        cls.ca_cert = parse_certificate(load_and_decode_pem_file("data/unittest/pq_root_ca_ml_dsa_44.pem"))

    def test_trad_and_pq_sig_key(self):
        """
        GIVEN a request for a certificate with a traditional and a post-quantum key.
        WHEN the request is built into a certificate.
        THEN the certificate is correctly built.
        """
        cert_req_msg = prepare_catalyst_cert_req_msg_approach(
            first_key=self.ec_key,
            alt_key=self.pq_mldsa,
            subject=self.common_name,
        )
        pki_message = build_ir_from_key(
            signing_key=self.ec_key,
            cert_req_msg=cert_req_msg,
        )
        response, _ = build_cert_from_catalyst_request(request=pki_message,
                                                       ca_cert=self.ca_cert,
                                                       ca_key=self.pq_mldsa,
                                                       )
        der_data = encoder.encode(response)
        decoded_response, rest = decoder.decode(der_data, asn1Spec=rfc9480.PKIMessage())
        self.assertEqual(rest, b"")
        cert = get_cert_from_pkimessage(
            pki_message=decoded_response,
        )
        public_key = load_public_key_from_cert(cert)
        self.assertEqual(public_key, self.ec_key.public_key())
        loaded_key = load_catalyst_public_key(
            cert["tbsCertificate"]["extensions"]
        )
        self.assertEqual(loaded_key, self.pq_mldsa.public_key())

    def test_pq_and_trad_sig_key(self):
        """
        GIVEN a request for a certificate with a post-quantum and a traditional key.
        WHEN the request is built into a certificate.
        THEN the certificate is correctly built.
        """
        cert_req_msg = prepare_catalyst_cert_req_msg_approach(
            first_key=self.pq_mldsa,
            alt_key=self.ec_key,
            subject=self.common_name,
        )
        pki_message = build_ir_from_key(
            signing_key=self.pq_mldsa,
            cert_req_msg=cert_req_msg,
        )
        response, _ = build_cert_from_catalyst_request(
            request=pki_message,
            ca_cert=self.ca_cert,
            ca_key=self.pq_mldsa,
        )
        der_data = encoder.encode(response)
        decoded_response, rest = decoder.decode(der_data, asn1Spec=rfc9480.PKIMessage())
        self.assertEqual(rest, b"")
        cert = get_cert_from_pkimessage(
            pki_message=decoded_response,
        )
        public_key = load_public_key_from_cert(cert)
        self.assertEqual(public_key, self.pq_mldsa.public_key())
        loaded_key = load_catalyst_public_key(
            cert["tbsCertificate"]["extensions"]
        )
        self.assertEqual(loaded_key, self.ec_key.public_key())


    def test_trad_sig_key_and_pq_kem(self):
        """
        GIVEN a request for a certificate with an traditional and a post-quantum KEM key.
        WHEN the request is built into a certificate.
        THEN the certificate is correctly built.
        """
        cert_req_msg = prepare_catalyst_cert_req_msg_approach(
            first_key=self.ec_key,
            alt_key=self.pq_kem,
            subject=self.common_name,
        )
        pki_message = build_ir_from_key(
            signing_key=self.ec_key,
            cert_req_msg=cert_req_msg,
        )
        response, _ = build_cert_from_catalyst_request(request=pki_message,
                                                       ca_cert=self.ca_cert,
                                                       ca_key=self.pq_mldsa,
                                                       )
        der_data = encode_to_der(response)
        decoded_response, rest = try_decode_pyasn1(der_data, PKIMessageTMP())
        self.assertEqual(rest, b"")
        cert = get_enc_cert_from_pkimessage(
            pki_message=decoded_response,
            ee_private_key=self.pq_kem,
            exclude_rid_check=True,
        )
        public_key = load_public_key_from_cert(cert)
        self.assertEqual(public_key, self.ec_key.public_key())
        loaded_key = load_catalyst_public_key(
            cert["tbsCertificate"]["extensions"]
        )
        self.assertEqual(loaded_key, self.pq_kem.public_key())

    def test_pq_kem_and_trad_sig_key(self):
        """
        GIVEN a request for a certificate with a post-quantum KEM and a traditional key.
        WHEN the request is built into a certificate.
        THEN the certificate is correctly built.
        """
        cert_req_msg = prepare_catalyst_cert_req_msg_approach(
            first_key=self.pq_kem,
            alt_key=self.ec_key,
            subject=self.common_name,
        )
        pki_message = build_ir_from_key(
            signing_key=None,
            cert_req_msg=cert_req_msg,
        )
        response, _ = build_cert_from_catalyst_request(request=pki_message,
                                                       ca_cert=self.ca_cert,
                                                       ca_key=self.pq_mldsa,
                                                       )
        der_data = encode_to_der(response)
        decoded_response, rest = try_decode_pyasn1(der_data, PKIMessageTMP())
        self.assertEqual(rest, b"")
        cert = get_enc_cert_from_pkimessage(
            pki_message=decoded_response,
            ee_private_key=self.pq_kem,
            exclude_rid_check=True,
        )
        public_key = load_public_key_from_cert(cert)
        self.assertEqual(public_key, self.pq_kem.public_key())
        loaded_key = load_catalyst_public_key(
            cert["tbsCertificate"]["extensions"]
        )
        self.assertEqual(loaded_key, self.ec_key.public_key())
