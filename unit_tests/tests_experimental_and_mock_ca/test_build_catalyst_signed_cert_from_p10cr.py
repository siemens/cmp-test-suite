# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.hybrid_issuing import build_catalyst_signed_cert_from_p10cr, build_catalyst_signed_cert_from_req
from pq_logic.hybrid_sig.catalyst_logic import validate_catalyst_extension, prepare_alt_sig_alg_id_extn
from resources.certbuildutils import prepare_sig_alg_id, build_csr, prepare_cert_template
from resources.certutils import parse_certificate
from resources.cmputils import parse_csr, build_p10cr_from_csr, prepare_cert_req_msg, build_ir_from_key, \
    get_cert_from_pkimessage
from resources.keyutils import load_private_key_from_file, generate_key
from resources.oidutils import id_ml_dsa_87_with_sha512
from resources.utils import load_and_decode_pem_file


class TestBuildCatalystCertFromP10cr(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ca_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.ca_cert = parse_certificate(
            load_and_decode_pem_file("data/unittest/bare_certificate.pem"))

        cls.csr = parse_csr(
            load_and_decode_pem_file(
                "data/csrs/hybrid_csr_composite_sig_rsa2048_ml_dsa_44.pem"
            )
        )
        cls.pki_message = build_p10cr_from_csr(
            csr=cls.csr,
        )

        mldsa_key = load_private_key_from_file(
            "data/keys/private-key-ml-dsa-87.pem",
        )
        alg_id = prepare_sig_alg_id(
            signing_key=mldsa_key,
            hash_alg="sha512",
            use_rsa_pss=False,

        )
        cls.sig_alg_id_extn = prepare_alt_sig_alg_id_extn(
            alg_id=alg_id,
            critical=False,
        )


    def test_build_catalyst_cert_from_p10cr(self):
        """
        GIVEN a PKIMessage without indicating the signature algorithm.
        WHEN the `build_catalyst_cert_from_p10cr` function is called.
        THEN is the message correctly built.
        """
        response, cert  = build_catalyst_signed_cert_from_p10cr(
            request=self.pki_message,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
        )

        extensions = validate_catalyst_extension(
            cert=cert,
        )
        self.assertEqual(len(extensions), 3)

    def test_build_with_sig_alg_id(self):
        """
        GIVEN a PKIMessage indicating the signature algorithm,
        for the catalyst certificate.
        WHEN the `build_catalyst_cert_from_p10cr` function is called.
        THEN is the message correctly built.
        """
        csr = build_csr(
            signing_key=self.ca_key,
            extensions=[self.sig_alg_id_extn],
        )

        pki_message = build_p10cr_from_csr(
            csr=csr,
        )

        response, cert  = build_catalyst_signed_cert_from_p10cr(
            request=pki_message,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
        )

        extensions = validate_catalyst_extension(
            cert=cert,
        )
        self.assertEqual(len(extensions), 3)

        self.assertEqual(
            str(extensions["alg_id"]["algorithm"]),
            str(id_ml_dsa_87_with_sha512))


    def test_build_cert_from_template(self):


        cert_template = prepare_cert_template(
            subject="CN=Hans the Tester",
            extensions=[self.sig_alg_id_extn],
            key=self.ca_key,
        )

        pki_message = build_ir_from_key(
            signing_key=self.ca_key,
            cert_template=cert_template,
        )

        response, cert  = build_catalyst_signed_cert_from_req(
            request=pki_message,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
        )
        self.assertEqual(len(response["body"]["ip"]["response"]), 1)
        self.assertEqual(len(cert), 1)

        cert = get_cert_from_pkimessage(
            pki_message=response,
            cert_number=0,
        )
        extensions = validate_catalyst_extension(
            cert=cert
        )

        self.assertEqual(
            str(extensions["alg_id"]["algorithm"]),
            str(id_ml_dsa_87_with_sha512)
        )


    def test_build_with_ir_multiple(self):
        """
        GIVEN multiple certificate requests.
        WHEN the certificate requests are built into a PKIMessage.
        THEN are the certificates correctly built.
        """
        ec_key = load_private_key_from_file(
            "data/keys/private-key-ecdsa.pem",
        )

        cert_req_msg1 = prepare_cert_req_msg(
            private_key=ec_key,
            common_name="CN=Hans the Tester",
        )

        cert_regs = [
            cert_req_msg1, cert_req_msg1, cert_req_msg1
        ]

        request = build_ir_from_key(
            signing_key=None,
            cert_req_msg=cert_regs,
        )

        response, certs = build_catalyst_signed_cert_from_req(
            request=request,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
        )

        self.assertEqual(len(response["body"]["ip"]["response"]), 3)
        self.assertEqual(len(certs), 3)












