"""provides a utility function for handling HTTP responses."""
import requests
from pyasn1.error import PyAsn1Error

import cmputils


def http_response_contains_pki_message(data: requests.Response) -> False:  # noqa: D417
    """Check if a server returned a `rfc9480.PKIMessage` on failure.

    The server might respond with an error status code, and in such cases,
    this function attempts to parse the response as a `rfc9480.PKIMessage`.
    If the server response is empty or parsing of the `pyasn1` `PKIMessage`
    structure fails, the function returns `False`.

    Arguments:
    ---------
    - data: The Response object to parse.

    Returns:
    -------
    - True if the response contains a valid PKIMessage.
    - False if the response is empty or parsing fails.

    """
    if not data.content:
        return None

    try:
        cmputils.parse_pki_message(data.content)
        return True
    except PyAsn1Error:
        return False
