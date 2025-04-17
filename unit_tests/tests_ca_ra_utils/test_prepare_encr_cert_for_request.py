# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from typing import Union, Tuple

from pyasn1.type import tag
from pyasn1_alt_modules import rfc9480

from pq_logic.keys.abstract_wrapper_keys import KEMPrivateKey, HybridKEMPrivateKey
from resources.typingutils import ECDHPrivateKey
from resources.ca_kga_logic import validate_enveloped_data
from resources.ca_ra_utils import prepare_encr_cert_from_request
from resources.certbuildutils import build_cert_from_cert_template
from resources.certutils import parse_certificate
from resources.cmputils import prepare_cert_req_msg
from resources.keyutils import load_private_key_from_file, generate_key
from resources.utils import load_and_decode_pem_file
from unit_tests.utils_for_test import compare_pyasn1_objects, try_encode_pyasn1
from resources.asn1utils import try_decode_pyasn1


class TestPrepareEncrCertForRequest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.hybrid_key = load_private_key_from_file("data/keys/private-key-x25519.pem")
        cls.xwing_key = load_private_key_from_file("data/keys/private-key-xwing.pem")
        cls.xwing_key_other = load_private_key_from_file("data/keys/private-key-xwing-other.pem")

        cls.ca_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.ca_cert = parse_certificate(load_and_decode_pem_file("data/unittest/bare_certificate.pem"))

        cls.mlkem_key = load_private_key_from_file("data/keys/private-key-ml-kem-768.pem")

    def set_up_data(self, client_key: Union[KEMPrivateKey],
                    hybrid_kem_key: Union[ECDHPrivateKey, HybridKEMPrivateKey]) \
            -> Tuple[rfc9480.CMPCertificate, rfc9480.EnvelopedData]:
        """Prepare the data for the test.

        :param client_key: The key of the client.
        :param hybrid_kem_key: The hybrid key, of the CA.
        Either uses an ECDHPrivateKey or a HybridKEMPrivateKey or can also support ephemeral keys,
        for the hybrid keys.
        :return: The encrypted certificate
        """
        # must be done every time because of pyasn1's mutable objects.
        # but the objects are not copy-able.
        # generate the client request.
        cert_req_msg = prepare_cert_req_msg(
            private_key=client_key,
            common_name="CN=Hans the Tester",
        )
        # process the client request to build a certificate.
        cert = build_cert_from_cert_template(
            cert_template=cert_req_msg["certReq"]["certTemplate"],
            ca_key=self.ca_key,
            ca_cert=self.ca_cert,
        )
        # prepare the encrypted certificate.
        enc_cert = prepare_encr_cert_from_request(
            cert_req_msg=cert_req_msg,
            ca_key=self.ca_key,
            hash_alg="sha256",
            ca_cert=self.ca_cert,
            new_ee_cert=cert,
            hybrid_kem_key=hybrid_kem_key,
        )
        target = rfc9480.EnvelopedData().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                                     tag.tagFormatSimple, 0))

        der_data = try_encode_pyasn1(enc_cert)
        enc_cert, rest = try_decode_pyasn1(der_data, target)
        if rest:
            raise ValueError("The data could not be decoded correctly.")
        return cert, enc_cert # type: ignore

    def test_prepare_enc_cert_with_ml_kem(self):
        """
        GIVEN a certificate and an ML-KEM key.
        WHEN preparing the encrypted certificate for a request.
        THEN the encrypted certificate should be correctly prepared.
        """
        cert, encr_cert = self.set_up_data(self.mlkem_key, None)

        der_cert = validate_enveloped_data(
            env_data=encr_cert,
            ee_key=self.mlkem_key,
            cmp_protection_cert=self.ca_cert,
            expected_raw_data=True,
            for_pop=True

        )
        decrypted_cert, rest = try_decode_pyasn1(der_cert, rfc9480.CMPCertificate())
        self.assertEqual(rest, b"")
        result = compare_pyasn1_objects(cert, decrypted_cert)
        self.assertTrue(result, "The decrypted certificate does not match the original certificate.")


    def test_prepare_encr_cert_hybrid_key_ephemeral(self):
        """
        GIVEN a certificate and an ephemeral key.
        WHEN preparing the encrypted certificate for a request.
        THEN the encrypted certificate should be correctly prepared.
        """
        cert, encr_cert = self.set_up_data(self.xwing_key, None)
        # TODO Talk about bug in recipient cert for encrCert.
        # if the other party does not have a certificate, the recipient ID should be None.
        # or at least the SKI to that the client can validate that.
        der_cert = validate_enveloped_data(
            env_data=encr_cert,
            ee_key=self.xwing_key,
            cmp_protection_cert=self.ca_cert,
            expected_raw_data=True,
            for_pop=True
        )
        decrypted_cert, rest = try_decode_pyasn1(der_cert, rfc9480.CMPCertificate())
        self.assertEqual(rest, b"")
        result = compare_pyasn1_objects(cert, decrypted_cert)
        self.assertTrue(result, "The decrypted certificate does not match the original certificate.")


    def test_prepare_encr_cert_with_composite_rsa(self):
        """
        GIVEN a certificate and a CompositeKEM key.
        WHEN preparing the encrypted certificate for a request.
        THEN the encrypted certificate should be correctly prepared.
        """
        comp_key = generate_key("composite-kem", trad_name="rsa", pq_name="ml-kem-768")
        cert, encr_cert = self.set_up_data(comp_key, None)
        der_cert = validate_enveloped_data(
            env_data=encr_cert,
            ee_key=comp_key,
            cmp_protection_cert=self.ca_cert,
            expected_raw_data=True,
            for_pop=True
        )
        decrypted_cert, rest = try_decode_pyasn1(der_cert, rfc9480.CMPCertificate())
        self.assertEqual(rest, b"")
        result = compare_pyasn1_objects(cert, decrypted_cert)
        self.assertTrue(result, "The decrypted certificate does not match the original certificate.")


    def test_prepare_encr_cert_with_xwing_and_xwing(self):
        """
        GIVEN two XWingPrivateKeys and a certificate.
        WHEN preparing the encrypted certificate for a request.
        THEN the encrypted certificate should be correctly prepared.
        """
        cert, encr_cert = self.set_up_data(self.xwing_key, self.xwing_key_other)
        der_cert = validate_enveloped_data(
            env_data=encr_cert,
            ee_key=self.xwing_key,
            cmp_protection_cert=self.ca_cert,
            expected_raw_data=True,
            for_pop=True
            # currently needs to be validated extra.
            # because encrCert, so the clients do not know the method, the CA-Will choose.
        )
        decrypted_cert, rest = try_decode_pyasn1(der_cert, rfc9480.CMPCertificate())
        self.assertEqual(rest, b"")
        result = compare_pyasn1_objects(cert, decrypted_cert)
        self.assertTrue(result, "The decrypted certificate does not match the original certificate.")


