# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Utility functions for preparing data which is not tied to a specific keyword.

These prepare functions are used in various other structures and do not require
 additional logic.
"""

# TODO refactor to shared prepare utils used by the CA and Client logic used.

from typing import Optional

from cryptography import x509
from pyasn1.codec.der import decoder
from pyasn1.type import tag
from pyasn1_alt_modules import rfc5280, rfc9480
from robot.api.deco import keyword, not_keyword


@not_keyword
def prepare_name(
    common_name: str, implicit_tag_id: Optional[int] = None, target: Optional[rfc9480.Name] = None
) -> rfc9480.Name:
    """Prepare a `rfc9480.Name` object or fill a provided object.

    When using a Null-DN set the common_name to "Null-DN".

    :param common_name: Common name in OpenSSL notation, e.g., "C=DE,ST=Bavaria,L= Munich,CN=Joe Mustermann"
    :param implicit_tag_id: the implicitTag id for the new object.
    :param target: An optional `pyasn1` Name object in which the data is parsed. Else creates a new object.
    :return: The filled object.
    """
    name_obj = parse_common_name_from_str(common_name)
    der_data = name_obj.public_bytes()

    if target is None:
        if implicit_tag_id is not None:
            target = rfc9480.Name().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, implicit_tag_id)
            )

    name_tmp, rest = decoder.decode(der_data, rfc9480.Name())
    if rest != b"":
        raise ValueError("The decoding of `Name` structure had a remainder!")

    if target is None:
        return name_tmp

    target["rdnSequence"] = name_tmp["rdnSequence"]
    return target


@not_keyword
def parse_common_name_from_str(common_name: str) -> x509.Name:
    """Parse a string representing common name attributes, convert it to `x509.Name` for X.509 certificate generation.

    :param common_name: The common name in OpenSSL notation, e.g., "C=DE,ST=Bavaria,L= Munich,CN=Joe Mustermann"
    :returns: x509.Name object.
    """
    if common_name == "Null-DN":
        return x509.Name([])

    if "=" not in common_name:
        raise ValueError("The common name must contain at least one attribute, e.g., 'CN=Joe Mustermann'")

    return x509.Name.from_rfc4514_string(data=common_name.replace(", ", ","))


# TODO Talk to alex about updating for CertDiscovery ?


@keyword(name="Prepare GeneralName")
def prepare_general_name(  # noqa D417 undocumented-param
    name_type: str, name_str: str
) -> rfc9480.GeneralName:
    """Prepare a `pyasn1` GeneralName object used by the `PKIHeader` structure.

    Arguments:
    ---------
        - `name`: The type of name to prepare, e.g., "directoryName" or "rfc822Name" or "uniformResourceIdentifier".
        - `name_str`: The actual name string to encode in the GeneralName. In OpenSSL notation, e.g.,
            "C=DE,ST=Bavaria,L=Munich,CN=Joe Mustermann" is *MUST* for directoryName.

    Returns:
    -------
        - A `GeneralName` object with the encoded name based on the provided `name_type`.

    Raises:
    ------
        - `NotImplementedError`: If the provided `name_type` is not supported.

    Examples:
    --------
    | ${general_name}= | Prepare GeneralName | directoryName | ${name_str} |
    | ${general_name}= | Prepare GeneralName | rfc822Name | ${name_str} |
    | ${general_name}= | Prepare GeneralName | uri | ${name_str} |

    """
    error_msg = "Supported name types are: 'directoryName', 'rfc822Name', 'uri', 'dNSName'."
    if name_type == "directoryName":
        name_obj = prepare_name(name_str, 4)
        general_name = rfc9480.GeneralName()
        return general_name.setComponentByName("directoryName", name_obj)

    if name_type == "rfc822Name":
        return rfc9480.GeneralName().setComponentByName("rfc822Name", name_str)

    if name_type in ["uniformResourceIdentifier", "uri"]:
        return rfc9480.GeneralName().setComponentByName("uniformResourceIdentifier", name_str)

    if name_type == "dNSName":
        return rfc5280.GeneralName().setComponentByName("dNSName", name_str)

    raise NotImplementedError(f"GeneralName name_type is Unsupported: {name_type}. {error_msg}")
