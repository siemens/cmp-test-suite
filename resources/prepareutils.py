# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Utility functions for preparing data which is not tied to a specific keyword.

These prepare functions are used in various other structures and do not require
 additional logic.
"""

from datetime import datetime, timezone

# TODO refactor to shared prepare utils used by the CA and Client logic used.
from typing import Optional, Sequence, Union

from cryptography import x509
from pyasn1.codec.der import decoder
from pyasn1.type import tag, useful
from pyasn1_alt_modules import rfc5280, rfc9480
from robot.api.deco import keyword, not_keyword
from robot.libraries import DateTime

_GeneralNamesType = Union[str, rfc9480.GeneralName, Sequence[rfc9480.GeneralName], rfc9480.GeneralNames, rfc9480.Name]


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
    if common_name in ["Null-DN", "NULL-DN"]:
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


def _prepare_date_time_object(
    date: Optional[Union[str, float, datetime]] = None,
) -> datetime:
    """Prepare a date time object.

    :param date: The date to use. If None, the current date is used.
    :return: The populated `datetime` object.
    """
    if date is None:
        return datetime.now(timezone.utc)
    if isinstance(date, str):
        new_time_obj = DateTime.convert_date(date, result_format="datetime")  # type: ignore
    elif isinstance(date, float):
        new_time_obj = datetime.fromtimestamp(date)

    elif isinstance(date, datetime):
        new_time_obj = date

    else:
        raise ValueError(f"Invalid date format: Got {type(date)}")
    return new_time_obj


@not_keyword
def prepare_generalized_time(
    date: Optional[Union[str, float, datetime]] = None,
) -> useful.GeneralizedTime:
    """Prepare a GeneralizedTime object.

    :param date: The date to use. If None, the current date is used.
    :return: The populated `GeneralizedTime` object.
    """
    target = useful.GeneralizedTime()
    new_time_obj = _prepare_date_time_object(date)
    return target.fromDateTime(new_time_obj)


@not_keyword
def prepare_utc_time(
    date: Optional[Union[str, float, datetime]] = None,
) -> useful.UTCTime:
    """Prepare a UTCTime object.

    :param date: The date to use. If None, the current date is used.
    :return: The populated `UTCTime` object.
    """
    target = useful.UTCTime()
    new_time_obj = _prepare_date_time_object(date)
    return target.fromDateTime(new_time_obj)


@not_keyword
def prepare_general_name_from_name(
    name_obj: Union[rfc9480.Name, rfc9480.CMPCertificate],
    extract_subject: bool = True,
    target: Optional[rfc9480.GeneralName] = None,
) -> rfc9480.GeneralName:
    """Prepare a `GeneralName` from a Name or CMPCertificate.

    :param name_obj: The Name or CMPCertificate object.
    :param extract_subject: If True, extract the subject from the CMPCertificate.
    :param target: An optional `GeneralName` object in which the data is parsed.
    Else creates a new object.
    :return: The populated GeneralName object.
    """
    if isinstance(name_obj, rfc9480.CMPCertificate):
        filed_name = "subject" if extract_subject else "issuer"
        name_obj = name_obj["tbsCertificate"][filed_name]

    general_name = rfc9480.GeneralName() if target is None else target
    general_name["directoryName"]["rdnSequence"] = name_obj["rdnSequence"]  # type: ignore
    return general_name


@not_keyword
def parse_to_general_name(
    sender: Union[str, rfc9480.GeneralName, rfc9480.Name, rfc9480.CMPCertificate],
    gen_type: str = "rfc822Name",
) -> rfc5280.GeneralName:
    """Prepare a `GeneralName` object from a string.

    :param sender: The sender's name to be converted to a `GeneralName`.
    :param gen_type: The type of the `GeneralName`. Defaults to "rfc822Name".
    :return: A `GeneralName` object.
    """
    if isinstance(sender, rfc9480.GeneralName):
        return sender
    if isinstance(sender, str):
        return prepare_general_name(
            name_type=gen_type,
            name_str=sender,
        )

    if isinstance(sender, (rfc9480.Name, rfc9480.CMPCertificate)):
        return prepare_general_name_from_name(
            name_obj=sender,
            extract_subject=True,
        )

    raise TypeError(f"Sender must be a string, Name or a GeneralName object.Got: {type(sender)}")


@not_keyword
def parse_to_general_names(
    name: _GeneralNamesType,
    gen_type: str = "uri",
) -> rfc9480.GeneralNames:
    """Parse a name to GeneralNames.

    :param name: The name to parse.
    :param gen_type: The type of `GeneralName` to create.
    :return: GeneralNames object.
    """
    if isinstance(name, list):
        gen_names = rfc9480.GeneralNames()
        for tmp_name in name:
            gen_name = parse_to_general_names(tmp_name, gen_type=gen_type)
            gen_names.extend(gen_name)
        return gen_names
    if isinstance(name, rfc9480.GeneralNames):
        return name

    elif isinstance(name, rfc9480.GeneralName):
        gen_names = rfc9480.GeneralNames()
        gen_names.append(name)
        return gen_names

    elif isinstance(name, (rfc9480.Name, str, rfc9480.CMPCertificate)):
        gen_name = parse_to_general_name(name, gen_type=gen_type)
        gen_names = rfc9480.GeneralNames()
        gen_names.append(gen_name)
        return gen_names
    else:
        raise NotImplementedError(
            f"GeneralName name_type is Unsupported: {type(name)}. Supported types are: "
            f"str, Name, GeneralName, GeneralNames."
        )
