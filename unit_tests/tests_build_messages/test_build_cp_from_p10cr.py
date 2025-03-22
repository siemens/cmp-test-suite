# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import encoder, decoder
from pyasn1_alt_modules import rfc9480

from resources.ca_ra_utils import build_cp_from_p10cr
from resources.certbuildutils import build_csr
from resources.certutils import load_public_key_from_cert, parse_certificate
from resources.keyutils import generate_key, load_private_key_from_file
from resources.cmputils import build_p10cr_from_csr, get_cert_from_pkimessage
from resources.utils import load_and_decode_pem_file


class TestBuildCpFromP10cr(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.common_name = "CN=Hans the Tester"
        cls.pq_mldsa = load_private_key_from_file("data/keys/private-key-ml-dsa-44.pem")
        cls.pq_cert = parse_certificate(load_and_decode_pem_file("data/unittest/pq_root_ca_ml_dsa_44.pem"))

    def test_build_cp_from_csr(self):
        """
        GIVEN a "p10cr" request for a certificate.
        WHEN the request is built into a "cp" message.
        THEN the message is correctly built.
        """
        comp_key = generate_key("composite-sig")
        csr = build_csr(
            signing_key=comp_key,
            common_name=self.common_name,
        )
        request = build_p10cr_from_csr(
            csr=csr,
            sender=self.common_name,
        )
        response, _ = build_cp_from_p10cr(
            request=request,
            common_name=self.common_name,
            ca_key=self.pq_mldsa,
            ca_cert=self.pq_cert,
        )
        der_data = encoder.encode(response)
        decoded_response, rest = decoder.decode(der_data, asn1Spec=rfc9480.PKIMessage())
        self.assertEqual(rest, b"")
        cert = get_cert_from_pkimessage(pki_message=decoded_response)
        public_key = load_public_key_from_cert(cert)
        self.assertEqual(
            public_key,
            comp_key.public_key(),
        )



