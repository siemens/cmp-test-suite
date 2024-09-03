import requests
from pyasn1.error import PyAsn1Error
from cmputils import parse_pki_message


def request_contains_pki_message(data: requests.Response) -> False:
    """Checks if a server returned a `PKIMessage` on failure.

    The server might respond with an error status code, and in such cases, this function attempts to parse the response as a `PKIMessage`.
    If the server response is empty or parsing of the `pyasn1` `PKIMessage` structure fails, the function returns `False`.

    Arguments:
        data (requests.Response): The Response object.

    Returns:
        pyasn1 parsed object: Represents the PKIMessage structure or None

    """
    if not data.content:
        return None

    try:
        parse_pki_message(data.content)
        return True
    except PyAsn1Error as err:
        return False