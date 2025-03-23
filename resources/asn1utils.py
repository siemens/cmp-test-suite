# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Primitives for querying PyASN1 objects using ASN1Path, a notation similar to XPath for XML.

The primitives are meant to be invoked from RobotFramework test cases, hence the notation
is a compact, single string.

To understand the notation, imagine you have this structure pretty-printed by PyASN1:


|    PKIMessage:
|     header=PKIHeader:
|      pvno=cmp2000
|      sender=GeneralName:
|       directoryName=Name:
|        rdnSequence=RDNSequence:
|         RelativeDistinguishedName:
|          AttributeTypeAndValue:
|           type=2.5.4.10
|           value=0x13074e65746f506179
|         RelativeDistinguishedName:
|          AttributeTypeAndValue:
|           type=2.5.4.3
|           value=0x130755736572204341

The query `header.sender.directoryName.rdnSequence/0` will return the first (i.e. index 0) element inside `rdnSequence`:

|         RelativeDistinguishedName:
|          AttributeTypeAndValue:
|           type=2.5.4.10
|           value=0x13074e65746f506179

The query `header.sender.directoryName.rdnSequence/0/0.value` will return the first element of `rdnSequence`, then dive
in and extract the first element of that (which will be of type `AttributeTypeAndValue`), then it will return the
attribute called `value`:

| value=0x13074e65746f506179

A few points to make it easier to navigate through PyASN1's own stringified notation.
- if there's a `=` in the line (e.g., `header=PKIHeader`), then its children are accessed via the dot, e.g.:
  `header.pvno` or `header.sender`.
- if there's no equal sign, it is a sequence or a set, and elements are accessed by index (even if pyasn1 shows them
  as a string!). For instance, in the following piece you don't write the query as
  `RelativeDistinguishedName.AttributeTypeAndValue.type`, but as `/0/0.type`, which reads as "get inside the first
  element of the first element, then retrieve the attribute called `type`".

|    rdnSequence=RDNSequence:
|     RelativeDistinguishedName:
|      AttributeTypeAndValue:
|       type=2.5.4.10
"""
import argparse
import logging
import pathlib
import re
import sys
from base64 import b64decode
from typing import List

from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import BitString
from robot.api.deco import not_keyword

from typingutils import Strint


def asn1_must_contain_fields(data, fields: str):
    """Verify that the given ASN.1 structure contains the specified fields.

    `data` is the pyasn1 structure to check.
    `fields` is a string that represents a comma-separated list field names to check for in the ASN.1 structure. Spaces
    in this string will be ignored.

    Example:
    -------
    | Asn1 Must Contain Fields | ${asn1} | header,body,soul |
    | Asn1 Must Contain Fields | ${asn1} | header, body ,   soul |

    """
    # """Ensure that all fields listed in `fields` are present in the header of `data`
    #
    # :param data: pyasn1 object
    # :param fields: str, comma-separated list of field names that must be present. NOTE that we're not passing it as a
    #                list of str, this is syntactic sugar for invocation from within RobotFramework tests.
    # :returns: None, raise ValueError of the required fields are not present"""
    present_fields = list(data)
    absent_fields = []
    fields = [item.strip() for item in fields.split(",")]
    for entry in fields:
        if entry not in present_fields:
            absent_fields.append(entry)

    if len(absent_fields) > 0:
        raise ValueError(f"The following required fields were absent: {absent_fields}")


def get_asn1_value(asn1_obj, query):
    """Extract a value from a complex PyASN1 structure by specifying its path in ASN1Path notation.

    :param asn1_obj: pyasn1 object, the structure you want to query
    :param query: str, the path to the value you want to extract, given as a dot-notation, e.g.,
                 'header.sender.directoryName.rdnSequence/0', or 'header.sender.directoryName.rdnSequence/0/0.value'
    :returns: pyasn1 object, the value you were looking for; or will raise a ValueError with details
    """
    keys = query.split(".")

    # we use these to gradually build up the traversed path, to show an informative error message if an error occurs
    traversed_so_far = ""
    current_piece = ""
    try:
        for key in keys:
            current_piece = key
            if "/" in key:
                parts = key.split("/")
                for part in parts:
                    current_piece = part
                    if part.isdigit():
                        asn1_obj = asn1_obj[int(part)]
                    else:
                        asn1_obj = asn1_obj[part]
                    traversed_so_far += f"/{part}"
            else:
                asn1_obj = asn1_obj[key]
            traversed_so_far += f".{key}" if traversed_so_far else key
    except Exception as err:
        # except KeyError as err:
        available_keys = list(asn1_obj.keys())
        report = (
            f"> Traversal ERROR, got this far: `{traversed_so_far}`,"
            f" issue at `{current_piece}`, the query was `{query}`"
        )
        report += f"\n> Available keys at this step: {available_keys}"
        if len(available_keys) == 1:
            report += f", try `{traversed_so_far}.{available_keys[0]}`"
        report += f"\n> Underlying error: {err}"
        raise ValueError(report) from err

    return asn1_obj


def get_asn1_value_as_string(asn1_obj, query):
    """Wrap get_asn1_value to return a plain string

    :param asn1_obj: pyasn1 object, the structure you want to query
    :param query: str, the path to the value you want to extract, given as a dot-notation, e.g.,
                 'header.sender.directoryName.rdnSequence/0', or 'header.sender.directoryName.rdnSequence/0/0.value'
    :returns: str, the value you were looking for as a string; or will raise a ValueError with details.
    """
    result = get_asn1_value(asn1_obj, query)
    decoded, _rest = decoder.decode(result)
    return decoded.prettyPrint()


def get_asn1_value_as_number(asn1_obj, query):
    """Wrap get_asn1_value to return an integer

    :param asn1_obj: pyasn1 object, the structure you want to query
    :param query: str, the path to the value you want to extract, given as a dot-notation, e.g.,
                 'header.sender.directoryName.rdnSequence/0', or 'header.sender.directoryName.rdnSequence/0/0.value'
    :returns: int, the value you were looking for as an integer; or will raise a ValueError with details.
    """
    result = get_asn1_value(asn1_obj, query)
    decoded, _rest = decoder.decode(result)
    return int(decoded)


def get_asn1_value_as_bytes(asn1_obj, query):
    """Wrap get_asn1_value to return an integer

    :param asn1_obj: pyasn1 object, the structure you want to query
    :param query: str, the path to the value you want to extract, given as a dot-notation, e.g.,
                 'header.sender.directoryName.rdnSequence/0', or 'header.sender.directoryName.rdnSequence/0/0.value'
    :returns: bytes, the value you were looking for as bytes; or will raise a ValueError with details.
    """
    result = get_asn1_value(asn1_obj, query)
    # decoded, _rest = decoder.decode(result)
    return result.asOctets()


def get_asn1_value_as_datetime(asn1_obj, query):
    """Wrap get_asn1_value to return a DateTime object

    :param asn1_obj: pyasn1 object, the structure you want to query
    :param query: str, the path to the value you want to extract, given as a dot-notation, e.g.,
                 'header.messageTime'
    :returns: DateTime, the value you requested; or will raise a ValueError with details.
    """
    result = get_asn1_value(asn1_obj, query)
    return result.asDateTime


def get_asn1_value_as_der(asn1_obj, query):
    """Wrap get_asn1_value to return a DER-encoded version of the queried value

    :param asn1_obj: pyasn1 object, the structure you want to query
    :param query: str, the path to the value you want to extract, given as a dot-notation, e.g.,
                 'header.sender.directoryName.rdnSequence/0', or 'header.sender.directoryName.rdnSequence/0/0.value'
    :returns: bytes, the DER-encoded bytes of the value you were looking for; or will raise a ValueError with details.
    """
    result = get_asn1_value(asn1_obj, query)
    return encoder.encode(result)


@not_keyword
def _is_bit_set_in_bitstring(asn1_bitstring: BitString, bit_index: Strint, exclusive: bool = True) -> bool:
    """Check if a bit is set in a `univ.BitString`, optionally ensure it is the only bit set.

    :param asn1_bitstring:
    :param bit_index:
    :param exclusive: If True, ensure that no other bits are set except the one at `bit_index`
    :return:`True` if the check passes, otherwise `False`.
    """
    # Convert the bit index to an integer
    bit_index = int(bit_index)

    x = tuple(asn1_bitstring)

    try:
        # Check if the bit at the specified index is set
        if x[bit_index] == 1:
            if exclusive:
                # If exclusive, ensure that only this bit is set
                return sum(x) == 1
            return True  # The bit is set, but other bits may also be set
        return False  # The bit at the specified index is not set

    except IndexError:
        # If the index is out of range, return False
        return False


@not_keyword
def _is_either_bit_set_in_bitstring(
    asn1_bitstring: BitString,
    bit_indices: List[int],
    exclusive: bool = True,
) -> bool:
    """Check if one of the provided bit indices are set in a `univ.BitString` object. Either exclusive or not.

    :param asn1_bitstring: `univ.BitString` object.
    :param bit_indices: list of allowed positions to be set.
    :param exclusive: `bool` indicating if only one of the indices must be `True`
          or if any or all of them can be set to `False`. Default is `True`.
    :return: `True` if the specified bit or bits are set according to the `exclusive` parameter; otherwise, `False`.
    """
    logging.info(tuple(asn1_bitstring))
    for i in bit_indices:
        tmp = _is_bit_set_in_bitstring(asn1_bitstring, i, exclusive=exclusive)
        if tmp:
            return True
    return False


def is_bit_set(asn1_bitstring: BitString, bit_indices: Strint, exclusive: bool = True) -> bool:  # noqa: D417
    """Verify if a specific bit or bits are set within a given `BitString` object.

    It supports both integer index and named bit indices (which can be comma-separated). The check can be
    performed either exclusively or non-exclusively, depending on the `exclusive` parameter.

    Arguments:
    ---------
        - asn1_bitstring: A `univ.BitString` object to be checked.
        - bit_indices: A `str` representing the bit index or indices to check.
          This can be:
            - An integer index for a single bit check.
            - A comma-separated string of integers for multiple bit indices, e.g., "1, 9".
            - A comma-separated string of human-readable bit names, e.g., "duplicateCertReq, badPOP".
        - exclusive: A `bool` indicating if only one bit must be set (`True`)
          or if any of them can be set (`False`). Default is `True`.

    Returns:
    -------
        - `True` if the specified bit or bits are set according to the `exclusive`
          parameter; otherwise, `False`.

    Raises:
    ------
        - ValueError: If any of the provided human-readable names are not part of the options.
        - ValueError: If the input is not a `BitString` object.

    Examples:
    --------
        | Is Bit Set | ${failInfo} | 26                  | ${True} |
        | Is Bit Set | ${failInfo} | ${26}               | ${True} |
        | Is Bit Set | ${failInfo} | duplicateCertReq    | ${True} |
        | Is Bit Set | ${failInfo} | 1, 9                | ${True} |

    """
    if not asn1_bitstring.isValue:
        raise ValueError("The Provided BitString has not set a Value!")

    if isinstance(bit_indices, int):
        return _is_bit_set_in_bitstring(asn1_bitstring=asn1_bitstring, bit_index=bit_indices, exclusive=exclusive)

    if isinstance(bit_indices, str):
        # allows not only int to be parsed but also the correct human-readable-names.
        if bit_indices.replace(",", "").strip(" ").isdigit():
            if "," in bit_indices:
                values = [int(x) for x in bit_indices.strip(" ").split(",")]
                return _is_either_bit_set_in_bitstring(asn1_bitstring, values, exclusive=exclusive)
            return _is_bit_set_in_bitstring(asn1_bitstring, int(bit_indices.strip()), exclusive=exclusive)

        # gets the names of as single values.
        values = bit_indices.strip(" ").split(",")
        # gets the indices to the corresponding human-readable-names.
        names = list(asn1_bitstring.namedValues.keys())
        try:
            bit_indices = [names.index(val) for val in values]
        except ValueError as err:
            raise ValueError(f"Provided names: {values} but allowed are: {names}") from err

        return _is_either_bit_set_in_bitstring(asn1_bitstring, bit_indices, exclusive=exclusive)


def validate_structure(value):
    """
    Validate the `structure` argument, it must be of the form rfc****.ClassName.

    :param value: str, the structure argument to validate
    :returns: str, the validated structure
    :raises argparse.ArgumentTypeError: if the structure is invalid
    """
    pattern = r'^rfc\d+\.[A-Z][a-zA-Z]+$'
    if not re.match(pattern, value):
        raise argparse.ArgumentTypeError(f"Invalid ASN1 structure path: {value}")
    return value

def validate_query(value):
    """
    Validate the `query` argument, it must be of the form rfc****.ClassName.

    :param value: str, the asn1path query argument to validate
    :returns: str, the validated query
    :raises argparse.ArgumentTypeError: if the format of the query is invalid
    """
    if value.count(':') > 1:
        raise argparse.ArgumentTypeError("Invalid query, only one cast is allowed at most")

    pattern = r'^[a-zA-Z]+$'
    if not re.match(pattern, value):
        raise argparse.ArgumentTypeError(f"Invalid ASN1Path query: {value}")
    return value


def main():
    """Wrap the command-line interface"""
    parser = argparse.ArgumentParser(description='Query ASN1 structures using ASN1Path notation')
    parser.add_argument('filepath', type=pathlib.Path, help='Path to the file that contains the raw data,'
                                                            ' use `-` for stdin')
    parser.add_argument('structure', type=validate_structure, help='RFC and structure to use for schema,'
                                                                   ' e.g., rfc4210.PKIMessage')
    parser.add_argument('query', type=str, help='The query in ASN1Path notation')
    parser.add_argument('--inform', type=str, choices=['raw', 'base64', 'der', 'ber', 'hex'],
                        default='raw', help='The format of the input data')
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)

    rfc, target_class_name = args.structure.split('.')
    target_class = __import__(f'pyasn1_alt_modules.{rfc}', fromlist=[target_class_name])

    if args.filepath == '-':
        raw_data = sys.stdin.read()
    else:
        raw_data = args.filepath.read_bytes()

    if args.inform == 'base64':
        raw_data = b64decode(raw_data)
    elif args.inform == 'hex':
        raw_data = bytes.fromhex(raw_data)

    pyasn1_class = getattr(target_class, target_class_name)
    specific_decoder = decoder if args.inform in ('der', 'raw') else ber_decoder

    parsed_data, _rest = specific_decoder.decode(raw_data, asn1Spec=pyasn1_class())

    if ':' in args.query:
        query, cast = args.query.split(':')
    else:
        query = args.query
        cast = 'str'

    if cast not in ('str', 'int', 'bytes', 'der', 'datetime'):
        raise ValueError(f"Invalid cast type: {cast}")

    result = get_asn1_value(parsed_data, query)
    if cast == 'datetime':
        print(result.asDateTime)
    elif cast == 'str':
        print(result.prettyPrint())
    elif cast == 'int':
        print(int(result))
    elif cast == 'bytes':
        print(result.asOctets())
    else:
        print(result)


if __name__ == '__main__':
    main()
