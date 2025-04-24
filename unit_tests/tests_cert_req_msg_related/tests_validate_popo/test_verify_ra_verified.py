# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.asn1_structures import PKIMessageTMP
from resources.ca_ra_utils import verify_popo_for_cert_request, build_ip_cmp_message
from resources.certutils import parse_certificate
from resources.cmputils import prepare_cert_req_msg, build_ir_from_key
from resources.exceptions import NotAuthorized
from resources.keyutils import load_private_key_from_file
from resources.protectionutils import protect_pkimessage
from resources.utils import load_and_decode_pem_file


class TestVerifyRAVerified(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        cls.trusted_dir = "data/trusted_ras"
        cls.ra_key = cls.key
        cls.ra_cert = parse_certificate(load_and_decode_pem_file("data/trusted_ras/ra_cms_cert_ecdsa.pem"))
        cls.cm = "CN=Hans the Tester"

    def _generate_ir(self, ra_verified: bool) -> PKIMessageTMP:
        """Generate an ir PKIMessage with the raVerified flag set."""
        cert_req_msg = prepare_cert_req_msg(
            private_key=self.key,
            ra_verified=ra_verified,
            common_name=self.cm
        )
        return build_ir_from_key(
            self.key,
            cert_req_msg=cert_req_msg,
        )

    def test_let_ra_verified_parse(self):
        """
        GIVEN a valid ir PKIMessage, with the raVerified flag set.
        WHEN the PKIMessage is processed,
        THEN must the verification of the `raVerified` POP succeed.
        """
        cert_req_msg = prepare_cert_req_msg(
            private_key=self.key,
            ra_verified=True,
            common_name=self.cm
        )

        ir = build_ir_from_key(
            self.key,
            cert_req_msg=cert_req_msg,
        )

        with self.assertLogs(level='INFO') as cm:
            verify_popo_for_cert_request(
                pki_message=ir,
                verify_ra_verified=False,
            )
        self.assertTrue(any("Skipping `raVerified` verification." in message for message in cm.output))

    def test_verify_ra_verified_valid_protection_cert(self):
        """
        GIVEN a valid ir PKIMessage, with the raVerified flag set.
        WHEN the PKIMessage is processed,
        THEN must the verification of the `raVerified` POP succeed.
        """

        ir = self._generate_ir(ra_verified=True)

        ir = protect_pkimessage(
            ir,
            private_key=self.key,
            protection="signature",
            cert=self.ra_cert,
            certs_dir="data/unittest",
        )

        verify_popo_for_cert_request(
            pki_message=ir,
            verify_ra_verified=True,
            allowed_ra_dir=self.trusted_dir,
        )

    def test_verify_ra_verified_invalid_cert_chain(self):
        """
        GIVEN a valid ir PKIMessage, with the raVerified flag set without the cert chain.
        WHEN the PKIMessage is processed,
        THEN must the verification of the `raVerified` POP fail.
        """
        ir = self._generate_ir(ra_verified=True)

        ir = protect_pkimessage(
            ir,
            private_key=self.key,
            protection="signature",
            cert=self.ra_cert,
            exclude_certs=True,
        )
        ir["extraCerts"].append(self.ra_cert)
        with self.assertRaises(NotAuthorized) as cm:
            verify_popo_for_cert_request(
                pki_message=ir,
                verify_ra_verified=True,
                allowed_ra_dir=self.trusted_dir,
                verify_cert_chain=True,
            )

        msg = "RA certificate is not self-signed, but the certificate chain could not be build."
        self.assertTrue(any(msg in message for message in cm.exception.args))


    def test_verify_ra_verified_untrusted(self):
        """
        GIVEN a valid ir PKIMessage, with the raVerified flag set and an untrusted RA certificate.
        WHEN the PKIMessage is processed,
        THEN must the verification of the `raVerified` POP fail.
        """
        ir = self._generate_ir(ra_verified=True)


        ir = protect_pkimessage(
            ir,
            private_key=self.key,
            protection="signature",
            cert=self.ra_cert,
        )
        # untested ra, because the directory does not contain the certificate.
        with self.assertRaises(NotAuthorized):
            verify_popo_for_cert_request(
                pki_message=ir,
                verify_ra_verified=True,
                allowed_ra_dir="data/unittest"
            )


    def test_skip_ra_verified_build_ip(self):
        """
        GIVEN a valid ir PKIMessage, with the raVerified flag set.
        WHEN the PKIMessage is processed, with build_ip_cmp_message.
        THEN must the verification of the `raVerified` POP succeed.
        """
        ir = self._generate_ir(ra_verified=True)

        ir = protect_pkimessage(
            ir,
            private_key=self.key,
            protection="signature",
            cert=self.ra_cert,
            certs_dir="data/unittest",
        )

        with self.assertLogs(level='INFO') as cm:
            response, cert = build_ip_cmp_message(
                request=ir,
                ca_cert=self.ra_cert,
                ca_key=self.ra_key,
                verify_ra_verified=False,
            )
        self.assertTrue(any("Skipping `raVerified` verification." in message for message in cm.output))
        self.assertIsNotNone(response)
        self.assertIsNotNone(cert)

    def test_valid_ra_verified_build_ip(self):
        """
        GIVEN a valid ir PKIMessage, with the raVerified flag set.
        WHEN the PKIMessage is processed, with build_ip_cmp_message.
        THEN must the verification of the `raVerified` POP succeed.
        """
        ir = self._generate_ir(ra_verified=True)

        ir = protect_pkimessage(
            ir,
            private_key=self.key,
            protection="signature",
            cert=self.ra_cert,
            certs_dir="data/unittest",
        )

        response, cert = build_ip_cmp_message(
            request=ir,
            ca_cert=self.ra_cert,
            ca_key=self.ra_key,
            verify_ra_verified=True,
            allowed_ra_dir=self.trusted_dir,
        )
        self.assertIsNotNone(response)
        self.assertIsNotNone(cert)

