# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Client to send requests to the Mock CA."""

import sys
from typing import Optional, Tuple

import requests
from pyasn1.codec.der import decoder, encoder

from resources.convertutils import ensure_is_sign_key
from resources.typingutils import SignKey

sys.path.append(".")
from resources import cmputils, keyutils, protectionutils
from resources.asn1_structures import PKIMessageTMP
from resources.cmputils import parse_pkimessage


def send_request_to_static_cert1() -> None:
    """Send an example request to the Mock CA."""
    url = "http://127.0.0.1:5000/issuing"
    key = keyutils.generate_key("composite-sig")
    pki_message = cmputils.build_cr_from_key(key)
    der_data = encoder.encode(pki_message)
    try:
        response = requests.post(url, data=der_data, timeout=60)
        if response.status_code == 200:
            print("Success:")
            der_data = response.content
            response, _ = decoder.decode(der_data, asn1Spec=PKIMessageTMP())
            print(response.prettyPrint())

        print(f"Error: {response.status_code}")
        print(response.text)
    except requests.RequestException as e:
        print(f"Request failed: {e}")


def send_pkimessage_to_mock_ca(
    pki_message: PKIMessageTMP, url: str = "http://127.0.0.1:5000/issuing", verify: bool = False
) -> Optional[PKIMessageTMP]:
    """Send a PKIMessage to a given URL.

    :param pki_message: The PKIMessage to send.
    :param url: The URL to send the PKIMessage to.
    :param verify: Whether to verify the server's SSL certificate.
    :return: The response from the server.
    """
    der_data = encoder.encode(pki_message)
    try:
        response = requests.post(url, data=der_data, timeout=60, verify=verify)
        if response.status_code == 200:
            print("Success:")
            der_data = response.content
            response = parse_pkimessage(der_data)
            return response

        print(f"Error: {response.status_code}")
        print(response.text)
    except requests.RequestException as e:
        print(f"Request failed: {e}")

    return None


def send_to_ejbca(pki_message: PKIMessageTMP, url: Optional[str] = None) -> None:
    """Send an example request to the Mock CA."""
    url = url or "http://mycahostname/ejbca/publicweb/cmp/cmpalias"

    der_data = encoder.encode(pki_message)
    try:
        response = requests.post(url, data=der_data, timeout=60)
        if response.status_code == 200:
            print("Success:")
            der_data = response.content
            response, _ = parse_pkimessage(der_data)
            print(response.prettyPrint())

        print(f"Error: {response.status_code}")
        print(response.text)
    except requests.RequestException as e:
        print(f"Request failed: {e}")


def build_example_rsa_mac_request() -> Tuple[PKIMessageTMP, SignKey]:
    """Build an example RSA request."""
    key = keyutils.generate_key("rsa")
    key = ensure_is_sign_key(key)

    pki_message = cmputils.build_ir_from_key(
        key,
        sender="CN=Hans the Tester",
        sender_kid=b"CN=Hans the Tester",
        for_mac=True,
        implicit_confirm=True,
    )
    protected_ir = protectionutils.protect_pkimessage(
        pki_message,
        protection="password_based_mac",
        password="SiemensIT",
    )
    return protected_ir, key


if __name__ == "__main__":
    send_request_to_static_cert1()
