# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from typing import Tuple

from pyasn1.codec.der import encoder
from pyasn1_alt_modules import rfc9480

from resources.asn1_structures import PKIMessageTMP
from resources.asn1utils import try_decode_pyasn1
from resources.ca_kga_logic import validate_enveloped_data
from resources.ca_ra_utils import build_ip_cmp_message, respond_to_key_agreement_request
from resources.certbuildutils import build_certificate
from resources.certutils import parse_certificate, load_public_key_from_cert
from resources.cmputils import build_ir_from_key, prepare_cert_req_msg
from resources.extra_issuing_logic import prepare_key_agreement_popo
from resources.keyutils import generate_key, load_private_key_from_file
from resources.utils import load_and_decode_pem_file


class TestBuildKeyAgreementResponse(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.x25519 = generate_key("x25519")
        cls.ca_key = load_private_key_from_file("data/keys/private-key-ed25519.pem")
        cls.root_cert = parse_certificate(load_and_decode_pem_file("data/unittest/root_cert_ed25519.pem"))
        cls.x25519_cert, cls.ca_x25519 = cls._generate_key_and_cert("x25519")
        cls.x448_cert, cls.x448 = cls._generate_key_and_cert("x448")
        cls.ecc_cert, cls.ecc_key = cls._generate_key_and_cert("ecc", curve="brainpoolP256r1")


    @classmethod
    def _generate_key_and_cert(cls, key_alg, **kwargs):
        private_key = generate_key(key_alg, **kwargs)
        cert, private_key = build_certificate(
            private_key=private_key,
            ca_key=cls.ca_key,
            ca_cert=cls.root_cert,
            key_usage="keyAgreement",
        )
        return cert, private_key

    def _prepare_cert_response(self, private_key, ca_key, cert_label) -> Tuple[rfc9480.CMPCertificate, rfc9480.EnvelopedData]:
        """Prepare the KARI EnvelopedData and the certificate"""
        popo = prepare_key_agreement_popo(
            use_encr_cert=True,
        )
        cert_req_msg = prepare_cert_req_msg(
        private_key=private_key,
        common_name="CN=Hans the Tester",
        popo_structure=popo
        )
        cert, enc_cert = respond_to_key_agreement_request(
        cert_req_msg=cert_req_msg,
        ca_key=self.ca_key,
        ca_cert=self.root_cert,
        cmp_protection_cert=self.root_cert,
        **{cert_label: ca_key},
       )
        return cert, enc_cert

    def test_build_key_agreement_response_x25519(self):
        cert, enc_cert = self._prepare_cert_response(
            private_key=self.x25519,
            ca_key=self.ca_x25519,
            cert_label="x25519_key",
        )
        public_key = load_public_key_from_cert(cert)
        self.assertEqual(public_key, self.x25519.public_key())
        pki_message = PKIMessageTMP()
        pki_message["extraCerts"].extend([self.root_cert, self.x25519_cert])

        data = validate_enveloped_data(
            env_data=enc_cert,
            expected_raw_data=True,
            ee_key=self.x25519,
            cmp_protection_cert=self.root_cert,
            kari_cert=self.x25519_cert,
        )
        out_cert, rest = try_decode_pyasn1(data, rfc9480.CMPCertificate())
        self.assertEqual(rest, b"")
        out = encoder.encode(out_cert)
        self.assertEqual(out, data)
        self.assertEqual(out, encoder.encode(cert))

    def test_build_key_agreement_response_x25519_extract_cert(self):
        """
        GIVEN an x25519 CertReqMsg.
        WHEN the request is processed,
        THEN is the EnvelopedData build correctly.
        """
        cert, enc_cert = self._prepare_cert_response(
            private_key=self.x25519,
            ca_key=self.ca_x25519,
            cert_label="x25519_key",
        )

        public_key = load_public_key_from_cert(cert)
        self.assertEqual(public_key, self.x25519.public_key())
        pki_message = PKIMessageTMP()
        pki_message["extraCerts"].extend([self.root_cert, self.x25519_cert])

        data = validate_enveloped_data(
            env_data=enc_cert,
            pki_message=pki_message,
            expected_raw_data=True,
            ee_key=self.x25519,
            cmp_protection_cert=self.root_cert,
            for_pop=True,
        )
        self.assertEqual(data, encoder.encode(cert))

    def test_build_key_agreement_response_x448(self):
        """
        GIVEN an x448 CertReqMsg.
        WHEN the request is processed,
        THEN is the EnvelopedData build correctly.
        """
        cert_req_msg = prepare_cert_req_msg(
            private_key=self.x448,
            common_name="CN=Hans the Tester",
        )
        cert, enc_cert = respond_to_key_agreement_request(
            cert_req_msg=cert_req_msg,
            ca_key=self.ca_key,
            ca_cert=self.root_cert,
            cmp_protection_cert=self.root_cert,
            x448_key=self.x448,
        )

        public_key = load_public_key_from_cert(cert)
        self.assertEqual(public_key, self.x448.public_key())
        pki_message = PKIMessageTMP()
        pki_message["extraCerts"].extend([self.root_cert, self.x448_cert])

        data = validate_enveloped_data(
            env_data=enc_cert,
            expected_raw_data=True,
            ee_key=self.x448,
            cmp_protection_cert=self.root_cert,
            kari_cert=self.x448_cert,
        )
        out_cert, rest = try_decode_pyasn1(data, rfc9480.CMPCertificate())
        self.assertEqual(rest, b"")
        out = encoder.encode(out_cert)
        self.assertEqual(out, data)
        self.assertEqual(out, encoder.encode(cert))

    def test_build_key_agreement_response_ecc(self):
        """
        GIVEN an ECC CertReqMsg.
        WHEN the request is processed,
        THEN is the EnvelopedData build correctly.
        """
        popo = prepare_key_agreement_popo(
            use_encr_cert=True,
        )

        cert_req_msg = prepare_cert_req_msg(
            private_key=self.ecc_key,
            common_name="CN=Hans the Tester",
            popo_structure=popo,
        )
        cert, enc_cert = respond_to_key_agreement_request(
            cert_req_msg=cert_req_msg,
            ca_key=self.ca_key,
            ca_cert=self.root_cert,
            cmp_protection_cert=self.root_cert,
            ecc_key=self.ecc_key, # type: ignore
        )

        public_key = load_public_key_from_cert(cert)
        self.assertEqual(public_key, self.ecc_key.public_key())
        pki_message = PKIMessageTMP()
        pki_message["extraCerts"].extend([self.root_cert, self.ecc_cert])

        data = validate_enveloped_data(
            env_data=enc_cert,
            expected_raw_data=True,
            ee_key=self.ecc_key,
            cmp_protection_cert=self.root_cert,
            kari_cert=self.ecc_cert,
        )
        out_cert, rest = try_decode_pyasn1(data, rfc9480.CMPCertificate())
        self.assertEqual(rest, b"")
        out = encoder.encode(out_cert)
        self.assertEqual(out, data)
        self.assertEqual(out, encoder.encode(cert))


    def build_ip_for_key_agreement_response(self):
        """
        GIVEN a valid IR request for X25519.
        WHEN the request is processed,
        THEN is the EnvelopedData build correctly.
        """
        ir = build_ir_from_key(self.x25519, common_name="CN=Hans the Tester")
        ip, cert = build_ip_cmp_message(ir)
        ip["extraCerts"].extend([self.root_cert, self.x25519_cert])
        data = validate_enveloped_data(
            pki_message=ip,
            expected_raw_data=True,
            ee_key=self.x25519,
        )
        self.assertEqual(data, encoder.encode(cert))


