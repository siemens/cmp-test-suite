# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
"""Client to send requests to the Mock CA."""

import logging
import sys
import time
from typing import List, Optional, Tuple

import requests
from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc9480

from resources.certutils import build_cmp_chain_from_pkimessage
from resources.convertutils import ensure_is_sign_key
from resources.protectionutils import protect_pkimessage
from resources.typingutils import SignKey
from resources.utils import display_pki_status_info

sys.path.append(".")
from resources import cmputils, keyutils, protectionutils
from resources.asn1_structures import PKIMessageTMP
from resources.cmputils import build_cmp_revoke_request, parse_pkimessage


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
            logging.info("Success:")
            der_data = response.content
            response, _ = parse_pkimessage(der_data)
            logging.debug(response.prettyPrint())

        logging.debug(f"Error: {response.status_code}")
        logging.info(response.text)
    except requests.RequestException as e:
        logging.debug(f"Request failed: {e}")


def build_example_rsa_mac_request(sender_cm: str = "CN=Hans The Tester") -> Tuple[PKIMessageTMP, SignKey]:
    """Build an example RSA request."""
    key = keyutils.generate_key("rsa")
    key = ensure_is_sign_key(key)

    pki_message = cmputils.build_ir_from_key(
        key,
        sender=sender_cm,
        sender_kid=sender_cm.encode("utf-8"),
        for_mac=True,
        implicit_confirm=True,
    )
    protected_ir = protectionutils.protect_pkimessage(
        pki_message,
        protection="password_based_mac",
        password="SiemensIT",
    )
    return protected_ir, key


def build_example_revoked_cert(
    sender_cm: str = "CN=Hans the Tester", url: str = "http://localhost:5000/issuing"
) -> Tuple[List[rfc9480.CMPCertificate], SignKey]:
    """Build an example MAC-protected request to issue a new certificate and revoke it.

    :param sender_cm: The common name of the sender.
    :param url: The URL of the CA.
    :return: A tuple containing the certificate chain and the private key.
    :raises ValueError: If no response is received from the server.
    """
    mac_ir, key = build_example_rsa_mac_request(sender_cm=sender_cm)
    response = send_pkimessage_to_mock_ca(pki_message=mac_ir, url=url)

    if response is None:
        raise ValueError("No response received from the server.")

    cert_chain = build_cmp_chain_from_pkimessage(response, for_issued_cert=True)
    time.sleep(3)
    revoke_request = build_cmp_revoke_request(cert=cert_chain[0], reason="keyCompromise")
    protected_revoke_request = protect_pkimessage(
        revoke_request,
        protection="signature",
        private_key=key,
        cert_chain=cert_chain,
    )
    response = send_pkimessage_to_mock_ca(pki_message=protected_revoke_request, url=url)
    if response is not None:
        status = display_pki_status_info(response)
        print(f"Status: {status}")
    else:
        raise ValueError("No response received from the server.")
    time.sleep(3)
    return cert_chain, key


if __name__ == "__main__":
    send_request_to_static_cert1()
