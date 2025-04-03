# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Minimal client that sends a CMP request to the mock CA."""

import sys

import requests
from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc9480

sys.path.append('.')
from resources import cmputils, keyutils
from resources.asn1_structures import PKIMessageTMP


def send_request_to_static_cert1():
    """Send a request to the mock CA."""
    url = "http://127.0.0.1:5000/issuing"
    key = keyutils.generate_key("composite-sig")
    pki_message = cmputils.build_cr_from_key(key)
    der_data = encoder.encode(pki_message)
    try:
        response = requests.post(url, data=der_data)
        if response.status_code == 200:
            print("Success:")
            der_data = response.content
            response, rest = decoder.decode(der_data, asn1Spec=PKIMessageTMP())
            print(response.prettyPrint())
        else:
            print(f"Error: {response.status_code}")
            print(response.text)
    except requests.RequestException as e:
        print(f"Request failed: {e}")


def send_pkimessage_to_mock_ca(pki_message: rfc9480.PKIMessage, url: str):
    """Send a PKIMessage to a given URL.

    :param pki_message: The PKIMessage to send.
    :param url: The URL to send the PKIMessage to.
    :return: The response from the server.
    """
    der_data = encoder.encode(pki_message)
    try:
        response = requests.post(url, data=der_data)
        if response.status_code == 200:
            print("Success:")
            der_data = response.content
            response, rest = decoder.decode(der_data, asn1Spec=PKIMessageTMP())
            return response
        else:
            print(f"Error: {response.status_code}")
            print(response.text)
    except requests.RequestException as e:
        print(f"Request failed: {e}")

if __name__ == "__main__":
    send_request_to_static_cert1()
