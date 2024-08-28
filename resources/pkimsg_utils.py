from typing import Union

import requests
from pyasn1_alt_modules import rfc9480

from asn1utils import get_asn1_value
from cmputils import parse_pki_message


def get_to_failure_info(data: Union[requests.Response, rfc9480.PKIMessage, bytes]) -> rfc9480.PKIFailureInfo:
    """Extract PKI failure information from the given input.


    The extracted failure information is retrieved from the `pKIStatusInfo` of the PKI message body.

    Arguments:
        data (requests.Response | rfc9480.PKIMessage | bytes): The input data to be parsed.

    Returns:
        rfc9480.PKIFailureInfo: The failure information extracted from the `pKIStatusInfo`.

    Example:
        | ${failure_info}= | Get To Failure Info | ${response} |
    """
    pki_msg = parse_pki_message(data, allow_cast=True)
    return get_asn1_value(pki_msg, query="body.error.pKIStatusInfo.failInfo")


def contains_pki_failure_info(data: Union[requests.Response, rfc9480.PKIMessage, bytes]) -> bool:
    """Check if the provided input contains PKI failure information.


    Arguments:
        data (requests.Response | rfc9480.PKIMessage | bytes): The input data to be checked.

    Returns:
        bool: `True` if the PKI failure information is present, `False` otherwise.

    Example:
        | ${is_failure_present}= | Contains PKI Failure Info | ${response} |
    """
    pki_msg = parse_pki_message(data, allow_cast=True)
    return get_to_failure_info(pki_msg).hasValue()


