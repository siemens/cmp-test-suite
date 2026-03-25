# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import subprocess
import time
import unittest

import requests
from pyasn1.codec.der import encoder

from mock_ca.ca_handler import BODY_NAMES_2_EXPECTED_NAME
from mock_ca.client import send_pkimessage_to_mock_ca, build_example_rsa_mac_request
from resources.cmputils import get_pkistatusinfo
from resources.utils import display_pki_status_info

_PREFIXES = ["/", "/issuing/", "/.well-known/cmp/p/"]


def _post_raw(pki_message, url: str) -> int:
    """Send a PKIMessage to a URL and return the HTTP status code."""
    der_data = encoder.encode(pki_message)
    try:
        response = requests.post(url, data=der_data, timeout=60)
        return response.status_code
    except requests.RequestException:
        return -1

# TODO: Add another unit test for the correct check of each body type.
# But can also directly be tested with the CMP-Test-Suite, if that is
# interesting.

class TestRegisterRoutesMockCA(unittest.TestCase):
    """Test that all routes registered by _register_routes are reachable and functional.

    Three URL prefixes are registered, each combined with every body name:
        "/"                   + body_name  ->  e.g. /ir, /cr, /p10cr, ...
        "/issuing/"           + body_name  ->  e.g. /issuing/ir, /issuing/cr, ...
        "/.well-known/cmp/p/" + body_name  ->  e.g. /.well-known/cmp/p/ir, ...
    """

    @classmethod
    def setUpClass(cls):
        # MUST be different from the default option, to also check the correct port usage.
        cls.port_num = 6002
        cls.service_process = subprocess.Popen(
            ["python3", "./mock_ca/ca_handler.py", "--port", str(cls.port_num)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        time.sleep(10)  # Give the service time to start
        if cls.service_process.poll() is not None:
            raise RuntimeError("Mock CA service did not start successfully.")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _base(self) -> str:
        return f"http://127.0.0.1:{self.port_num}"

    def _url(self, prefix: str, body_name: str) -> str:
        """Return the full URL for *prefix* + *body_name*.

        :param prefix: One of "/", "/issuing/", "/.well-known/cmp/p/".
        :param body_name: A key from _BODY_NAMES_2_EXPECTED_NAME, e.g. "ir".
        :return: Full URL string, e.g. ``http://127.0.0.1:6002/issuing/ir``.
        """
        path = f"{prefix}{body_name}"
        if not path.startswith("/"):
            path = "/" + path
        return f"{self._base()}{path}"

    @staticmethod
    def _send_ir(url: str):
        """Send a valid MAC-protected IR to *url* and return the PKIMessage response."""
        req, _ = build_example_rsa_mac_request("CN=Test Register Routes Mock CA")
        return send_pkimessage_to_mock_ca(req, url=url)

    def _assert_route_exists(self, prefix: str, body_name: str) -> None:
        """Assert that the route responds with something other than 404.

        Sending an IR to a non-ir endpoint causes the server to return HTTP 400 with a
        CMP error body – that still proves the route is registered.  A 404 means it is not.
        """
        url = self._url(prefix, body_name)
        req, _ = build_example_rsa_mac_request(f"CN=Test Route {body_name}")
        status_code = _post_raw(req, url)
        self.assertNotEqual(
            status_code, 404,
            f"Route '{prefix}{body_name}' returned 404 – route is NOT registered.",
        )
        self.assertNotEqual(
            status_code, -1,
            f"Route '{prefix}{body_name}' caused a connection error.",
        )

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def test_ir_accepted_on_all_prefixes(self):
        """
        GIVEN the mock CA started on port 6002.
        WHEN a valid MAC-protected IR is sent to the /ir endpoint on each prefix.
        THEN every response should have status 'accepted'.
        """
        for prefix in _PREFIXES:
            with self.subTest(prefix=prefix):
                url = self._url(prefix, "ir")
                response = self._send_ir(url)
                self.assertIsNotNone(response, "The response should not be None")
                status = get_pkistatusinfo(response)
                self.assertEqual(
                    status["status"].prettyPrint(),
                    "accepted",
                    display_pki_status_info(response),
                )

    def test_all_routes_reachable(self):
        """
        GIVEN the mock CA started on port 6002.
        WHEN a request is sent to every registered endpoint (all prefixes x all body names).
        THEN every route should respond (not 404 / connection error).
        """
        for prefix in _PREFIXES:
            for body_name in BODY_NAMES_2_EXPECTED_NAME:
                with self.subTest(prefix=prefix, body_name=body_name):
                    self._assert_route_exists(prefix, body_name)

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
