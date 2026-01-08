# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import subprocess
import time
import unittest

from mock_ca.client import send_pkimessage_to_mock_ca, build_example_rsa_mac_request
from resources.certutils import validate_ocsp_status_openssl, build_cmp_chain_from_pkimessage
from resources.cmputils import get_pkistatusinfo, build_cmp_revoke_request
from resources.protectionutils import protect_pkimessage
from resources.utils import display_pki_status_info


class TestOCSPOpenSSLMockCA(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # MUST be different from the default option, to also check the correct port usage.
        cls.port_num = 6000
        # Start the server as a subprocess (adjust command as needed)
        cls.service_process = subprocess.Popen(
            ["python3", "./mock_ca/ca_handler.py", "--port", str(cls.port_num)],
            stdout=subprocess.DEVNULL,  # Avoid blocking
            stderr=subprocess.DEVNULL,
            text=True  # So output is returned as strings instead of bytes
        )
        time.sleep(10)  # Give the service time to start
        if cls.service_process.poll() is not None:
            raise RuntimeError("Mock CA service did not start successfully.")

    def test_ocsp_openssl_mock_ca(self):
        """
        GIVEN an OpenSSL mock CA.
        WHEN OCSP is requested.
        THEN the response should be valid.
        """

        req, key = build_example_rsa_mac_request("CN=Test OCSP OpenSSL Mock CA")

        response = send_pkimessage_to_mock_ca(
            req,
            url=f"http://127.0.0.1:{self.port_num}/issuing",
        )
        self.assertIsNotNone(response, "The response should not be None")

        status = get_pkistatusinfo(response)
        self.assertEqual(status["status"].prettyPrint(), "accepted", display_pki_status_info(response))

        cert_chain = build_cmp_chain_from_pkimessage(response, for_issued_cert=True)
        time.sleep(5)

        validate_ocsp_status_openssl(
            cert=cert_chain[0],
            ca_cert=cert_chain[1],
            expected_status="good",
            use_nonce=True,
        )
        validate_ocsp_status_openssl(
            cert=cert_chain[1],
            ca_cert=cert_chain[1],
            ocsp_url=f"http://127.0.0.1:{self.port_num}/ocsp",
            expected_status="good",
            use_nonce=True,
        )

    def test_revocation_ocsp_openssl_mock_ca(self):
        """
        GIVEN an OpenSSL mock CA.
        WHEN a revocation request is processed.
        THEN the OCSP response should reflect the revocation status.
        """
        req, key = build_example_rsa_mac_request("CN=Test OCSP OpenSSL Mock CA")
        self.assertIsNotNone(req, "Request should not be None")
        response = send_pkimessage_to_mock_ca(
            req,
            url=f"http://localhost:{self.port_num}/issuing",
        )
        self.assertIsNotNone(response, "The response should not be None")

        status = get_pkistatusinfo(response)
        self.assertEqual(status["status"].prettyPrint(), "accepted", display_pki_status_info(response))

        cert_chain = build_cmp_chain_from_pkimessage(response, for_issued_cert=True)

        rr = build_cmp_revoke_request(
            cert=cert_chain[0],
            reason="keyCompromise",
        )
        prot_rr = protect_pkimessage(
            rr,
            "signature",
            private_key=key,
            cert_chain=cert_chain,
        )
        response = send_pkimessage_to_mock_ca(
            prot_rr,
            url=f"http://localhost:{self.port_num}/issuing",
        )
        status = get_pkistatusinfo(response)
        self.assertEqual(status["status"].prettyPrint(), "accepted", display_pki_status_info(response))

        # Simulate revocation
        time.sleep(5)
        validate_ocsp_status_openssl(
            cert=cert_chain[0],
            ca_cert=cert_chain[1],
            expected_status="revoked",
            use_nonce=True,
        )
        validate_ocsp_status_openssl(
            cert=cert_chain[1],
            ca_cert=cert_chain[1],
            ocsp_url=f"http://localhost:{self.port_num}/ocsp",
            expected_status="good",
            use_nonce=True,
        )

    @classmethod
    def tearDownClass(cls):
        if cls.service_process and cls.service_process.poll() is None:
            cls.service_process.terminate()
            try:
                cls.service_process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                cls.service_process.kill()

if __name__ == "__main__":
    unittest.main()