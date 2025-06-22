# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.hybrid_issuing import build_sun_hybrid_cert_from_request
from pyasn1.type import tag
from pyasn1_alt_modules import rfc9480

from pq_logic.keys.composite_kem07 import CompositeKEM07PrivateKey
from pq_logic.keys.composite_sig04 import CompositeSig04PrivateKey
from resources.ca_kga_logic import validate_kemri_enveloped_data
from resources.certbuildutils import build_certificate
from resources.certutils import parse_certificate
from resources.cmputils import build_ir_from_key, get_cert_from_pkimessage, get_cert_response_from_pkimessage
from resources.keyutils import generate_key
from unit_tests.utils_for_test import compare_pyasn1_objects, try_encode_pyasn1
from resources.asn1utils import try_decode_pyasn1


class TestBuildSunHybridCertFromRequest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_key = generate_key("composite-sig") # type: ignore
        cls.ca_key: CompositeSig04PrivateKey
        cls.ca_cert, _ = build_certificate(cls.ca_key, "CN=Test CA")

    def test_build_with_composite_sig(self):
        """
        GIVEN a composite signature certificate request.
        WHEN the request is built.
        THEN the public key is extracted correctly.
        """
        comp_sig = generate_key("composite-sig")
        ir = build_ir_from_key(comp_sig, "CN=Hans the Tester")
        response, cert4, cert1 = build_sun_hybrid_cert_from_request(
            request=ir,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            pub_key_loc="https://example.com/pubkey/1",
            sig_loc="https://example.com/sig/1",
            serial_number=1,
        )
        loaded_cert = get_cert_from_pkimessage(response, cert_number=0)
        result = compare_pyasn1_objects(cert4, loaded_cert)
        self.assertTrue(result)

    def test_built_with_composite_kem(self):
        """
        GIVEN a composite KEM certificate template.
        WHEN the certificate is built.
        THEN the public key is extracted correctly.
        """
        comp_kem = generate_key("composite-kem", trad_name="rsa") # type: ignore
        comp_kem: CompositeKEM07PrivateKey
        ir = build_ir_from_key(comp_kem, "CN=Hans the Tester")
        response, cert4, cert1 = build_sun_hybrid_cert_from_request(
            request=ir,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            pub_key_loc="https://example.com/pubkey/1",
            sig_loc="https://example.com/sig/1",
            serial_number=1,
        )
        rep = get_cert_response_from_pkimessage(response, response_index=0)

        loaded_cert = rep["certifiedKeyPair"]["certOrEncCert"]["encryptedCert"]["envelopedData"]
        self.assertTrue(loaded_cert.isValue)

        target = rfc9480.EnvelopedData().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

        der_data = try_encode_pyasn1(loaded_cert)
        env_data, _ = try_decode_pyasn1(der_data, target) # type: ignore
        env_data: rfc9480.EnvelopedData

        data = validate_kemri_enveloped_data(
            env_data=env_data,
            for_pop=True,
            ee_key=comp_kem,
            expected_raw_data=True,
            is_sun_hybrid=True,
        )
        cert = parse_certificate(data)
        result = compare_pyasn1_objects(cert4, cert)
        self.assertTrue(result)
