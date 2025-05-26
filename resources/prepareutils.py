# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Utility functions for preparing data which is not tied to a specific keyword.

These prepare functions are used in various other structures and do not require
 additional logic.
"""

from datetime import datetime, timezone

# TODO refactor to shared prepare utils used by the CA and Client logic used.
from typing import Optional, Union

from cryptography import x509
from pyasn1.codec.der import decoder
from pyasn1.type import tag, useful
from pyasn1_alt_modules import rfc5280, rfc9480
from robot.api.deco import keyword, not_keyword
from robot.libraries import DateTime

from resources import asn1utils, utils
from resources.asn1_structures import (
    EmailAddressASN1,
    X520countryNameASN1,
    X520nameASN1,
    X520SerialNumberASN1,
)
from resources.exceptions import BadAsn1Data
from resources.oidutils import (
    CERT_ATTR_OID_2_CORRECT_STRUCTURE,
    CERT_ATTR_OID_2_STRUCTURE,
    OID_CM_NAME_MAP,
    PYASN1_CM_OID_2_NAME,
)
from resources.typingutils import GeneralNamesType


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
        new_time_obj = datetime.now(tz=timezone.utc)
    elif isinstance(date, str):
        new_time_obj = DateTime.convert_date(date, result_format="datetime")  # type: ignore
        new_time_obj: datetime
    elif isinstance(date, float):
        new_time_obj = datetime.fromtimestamp(date)

    elif isinstance(date, datetime):
        new_time_obj = date

    else:
        raise ValueError(f"Invalid date format: Got {type(date)}")

    # Ensure the datetime object is in UTC.
    # Otherwise, it will be incorrectly created.
    return new_time_obj.replace(microsecond=0)


@not_keyword
def prepare_generalized_time(
    date: Optional[Union[str, float, datetime]] = None,
) -> useful.GeneralizedTime:
    """Prepare a GeneralizedTime object.

    :param date: The date to use. If None, the current date is used.
    :return: The populated `GeneralizedTime` object.
    """
    new_time_obj = _prepare_date_time_object(date)
    return useful.GeneralizedTime.fromDateTime(new_time_obj)


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
    name: GeneralNamesType,
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

    if isinstance(name, rfc9480.GeneralName):
        gen_names = rfc9480.GeneralNames()
        gen_names.append(name)
        return gen_names

    if isinstance(name, (rfc9480.Name, str, rfc9480.CMPCertificate)):
        gen_name = parse_to_general_name(name, gen_type=gen_type)
        gen_names = rfc9480.GeneralNames()
        gen_names.append(gen_name)
        return gen_names

    raise NotImplementedError(
        f"GeneralName name_type is Unsupported: {type(name)}. Supported types are: "
        f"str, Name, GeneralName, GeneralNames."
    )


def _prepare_x520_name(value: str, name_type: str = "utf8String") -> X520nameASN1:
    """Prepare an X.520 name ASN.1 structure.

    :param value: The value to include in the X.520 name.
    :param name_type: The type of the name. Defaults to "utf8String".
    :return: An X.520 name structure.
    """
    x520name_allowed_string_types = ["teletexString", "printableString", "universalString", "utf8String", "bmpString"]
    if name_type not in x520name_allowed_string_types:
        raise ValueError(f"Unsupported name type: {name_type}. Allowed types are: {x520name_allowed_string_types}")

    x520_name = X520nameASN1()
    x520_name[name_type] = value
    return x520_name


def _get_bad_min_or_max_size(
    data_type: Union[X520nameASN1, X520SerialNumberASN1, EmailAddressASN1],
    bad_min_size: bool = False,
    bad_max_size: bool = False,
) -> str:
    """Get a value that is either too small or too large for the given data type.

    :param data_type: The data type to check.
    :param bad_min_size: If True, set a value that is too small.
    :param bad_max_size: If True, set a value that is too large.
    :return: A string representing the value.
    """
    if bad_min_size and bad_max_size:
        raise ValueError("Both `bad_min_size` and `bad_max_size` cannot be True at the same time.")

    if bad_min_size:
        if data_type.size_min - 1 == 0:
            return ""
        # MUST be converted to integer, some types used univ.Integer which will
        # create a `coerce` error.
        return "A" * int((data_type.size_min - 1))

    num = data_type.size_max + 1
    # MUST be converted to integer, some types used univ.Integer which will
    # create a `coerce` error.
    return "A" * int(num)


def _prepare_attr_and_type_value(
    name: str,
    value: str,
    bad_min_size: bool = False,
    bad_max_size: bool = False,
    invalid_type: bool = False,
    add_trailing_data: bool = False,
) -> rfc5280.AttributeTypeAndValue:
    """Prepare an AttributeTypeAndValue ASN.1 structure.

    :param name: The name of the attribute, e.g., "CN", "L", "ST".
    :param value: The value of the attribute.
    :param bad_min_size: If True, set a value that is too small.
    :param bad_max_size: If True, set a value that is too large.
    :param invalid_type: If True, set an invalid type to trigger an error.
    :param add_trailing_data: If True, add trailing data to the value.
    :return: An AttributeTypeAndValue structure.
    """
    atav = rfc5280.AttributeTypeAndValue()
    atav["type"] = OID_CM_NAME_MAP[name]

    data_type = CERT_ATTR_OID_2_STRUCTURE[atav["type"]].clone()

    if bad_min_size and bad_max_size:
        raise ValueError("Both `bad_min_size` and `bad_max_size` cannot be True at the same time.")

    if isinstance(data_type, rfc5280.X520dnQualifier):
        data_type = rfc5280.X520dnQualifier(value)

    elif isinstance(data_type, rfc5280.DomainComponent):
        data_type = rfc5280.DomainComponent(value)

    elif isinstance(data_type, X520SerialNumberASN1):
        if bad_min_size or bad_max_size:
            value = _get_bad_min_or_max_size(data_type, bad_min_size=bad_min_size, bad_max_size=bad_max_size)

        data_type = X520SerialNumberASN1(value)

    elif isinstance(data_type, EmailAddressASN1):
        if bad_min_size or bad_max_size:
            value = _get_bad_min_or_max_size(data_type, bad_min_size=bad_min_size, bad_max_size=bad_max_size)

        data_type = EmailAddressASN1(value)

    elif isinstance(data_type, X520countryNameASN1):
        if bad_min_size:
            value = "D"

        elif bad_max_size:
            value = "DEE"

        data_type = X520countryNameASN1(value)

    elif isinstance(data_type, X520nameASN1):
        if bad_min_size or bad_max_size:
            value = _get_bad_min_or_max_size(data_type, bad_min_size=bad_min_size, bad_max_size=bad_max_size)

        data_type = _prepare_x520_name(value, "utf8String")

    else:
        data_type["utf8String"] = value

    atav["value"] = data_type

    if invalid_type:
        # Set an invalid type to trigger an error
        atav["type"] = utils.manipulate_first_byte(asn1utils.encode_to_der(data_type))

    if not add_trailing_data:
        return atav

    # Add trailing data if specified
    atav["value"] = asn1utils.encode_to_der(data_type) + b"trailing_data"
    return atav


@keyword(name="Prepare RelativeDistinguishedName")
def prepare_relative_distinguished_name(  # noqa D417 undocumented-param
    values: str,
    bad_min_size: bool = False,
    bad_max_size: bool = False,
    invalid_type: bool = False,
    add_trailing_data: bool = False,
) -> rfc5280.RelativeDistinguishedName:
    """Prepare a RelativeDistinguishedName structure.

    Arguments:
    ---------
        - `values`: A string containing the values to include in the RDN, e.g., "CN=Joe Mustermann,ST=Bavaria".

    Returns:
    -------
        - A `RelativeDistinguishedName` object with the encoded values.

    Raises:
    ------
        - `ValueError`: If an unknown CM type is encountered in the input string.

    Examples:
    --------
    | ${rdn}= | Prepare RelativeDistinguishedName | CN=Joe Mustermann,ST=Bavaria |

    """
    options = values.replace(", ", ",").split(",")
    rdn = rfc5280.RelativeDistinguishedName()

    for option in options:
        name, value = option.split("=")
        if name not in OID_CM_NAME_MAP:
            raise ValueError(f"Unknown CM type: {name}")

        atav = _prepare_attr_and_type_value(
            name=name,
            value=value,
            bad_min_size=bad_min_size,
            bad_max_size=bad_max_size,
            invalid_type=invalid_type,
            add_trailing_data=add_trailing_data,
        )
        rdn.append(atav)

    return rdn


@not_keyword
def validate_relative_name_for_correct_data_types(
    name: rfc5280.RelativeDistinguishedName,
) -> None:
    """Validate the relative distinguished name.

    :param name: The relative distinguished name to validate.
    :return: True if the names match, False otherwise.
    """
    failed = []

    for x in name:
        name_type = x["type"]
        if name_type not in CERT_ATTR_OID_2_CORRECT_STRUCTURE:
            failed.append(f"Unknown CM type: {name_type}. Please check `CERT_ATTR_OID_2_CORRECT_STRUCTURE`")
            continue

        structure = CERT_ATTR_OID_2_CORRECT_STRUCTURE[name_type].clone()

        try:
            _, rest = asn1utils.try_decode_pyasn1(x["value"], structure)
            if rest:
                failed.append(f"Remainder in value for: {PYASN1_CM_OID_2_NAME[name_type]}. Remainder: {rest}")
        except BadAsn1Data as e:
            failed.append(
                f"Failed to decode value for: {PYASN1_CM_OID_2_NAME[name_type]}. "
                f"Error: {e.message}, details: {e.get_error_details()}"
            )

    if failed:
        raise BadAsn1Data(f"Failed to validate relative distinguished name: {failed}")


@not_keyword
def convert_to_generalized_time(
    date: Union[str, datetime, useful.GeneralizedTime, None],
) -> useful.GeneralizedTime:
    """Convert date to GeneralizedTime.

    :param date: The date to convert.
    :return: The converted `GeneralizedTime` structure.
    """
    if isinstance(date, useful.GeneralizedTime):
        return date
    return prepare_generalized_time(
        date=date,
    )
