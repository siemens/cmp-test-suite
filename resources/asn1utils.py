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

import logging
from datetime import datetime
from typing import Any, List, Optional, Tuple, Union

from pyasn1.codec.der import decoder, encoder
from pyasn1.type import base, univ
from pyasn1.type.base import Asn1Item, Asn1Type
from pyasn1.type.univ import BitString
from robot.api.deco import not_keyword

from resources.asn1_structures import PKIMessageTMP
from resources.exceptions import BadAsn1Data
from resources.typingutils import Strint


def asn1_must_have_values_set(asn1_obj: base.Asn1Type, queries: str):  # noqa D417 undocumented-param
    """Verify that the given ASN.1 structure contains values for the specified queries.

    Arguments:
    ---------
        - `asn1_obj`: The `pyasn1` structure to check.
        - `queries`: A string that represents a comma-separated list of queries to check, if a value is present.

    Raises:
    ------
        - `ValueError`: If the required fields are not present or if they are not set.

    Examples:
    --------
    | Asn1 Must Have Values Set | ${asn1} | header,body,soul |
    | Asn1 Must Have Values Set | ${asn1} | header.recipNonce, body.nested/0, soul |

    """
    fields_entries = [item.strip() for item in queries.split(",")]
    for entry in fields_entries:
        try:
            tmp = get_asn1_value(asn1_obj, entry)
            if not tmp.isValue:  # type: ignore
                obj_name = type(tmp).__name__
                logging.debug("%s", asn1_obj.prettyPrint())
                raise ValueError(f"The pyasn1 object: `{obj_name}` did not had a value set for the query: '{entry}'.")
        except KeyError:
            raise ValueError(f"The query '{entry}' is not present in the structure.")  # pylint: disable=raise-missing-from


def asn1_must_contain_fields(data: base.Asn1Type, fields: str):  # noqa D417 undocumented-param
    """Verify that the given ASN.1 structure contains the specified fields.

    Arguments:
    ---------
        - `data`: The `pyasn1` structure to check.
        - `fields` is a string that represents a comma-separated list field names to check for in the ASN.1 structure.
         Spaces in this string will be ignored.

    Examples:
    --------
    | Asn1 Must Contain Fields | ${asn1} | header,body,soul |
    | Asn1 Must Contain Fields | ${asn1} | header, body ,   soul |

    """
    # """Ensure that all fields listed in `fields` are present in the header of `data`
    #
    # :param data: pyasn1 object
    # :param fields: str, comma-separated list of field names that must be present. NOTE that we're not passing it as a
    #                list of str, this is syntactic sugar for invocation from within RobotFramework tests.
    # :returns: None, raise ValueError of the required fields are not present"""
    present_fields = list(data)  # type: ignore
    absent_fields = []
    fields_entries = [item.strip() for item in fields.split(",")]
    for entry in fields_entries:
        if entry not in present_fields:
            absent_fields.append(entry)

    if len(absent_fields) > 0:
        raise ValueError(f"The following required fields were absent: {absent_fields}")


def _split_last_parent(s: str) -> tuple[str, str]:
    """Split an asn1path query into parent and child.

    The returned value is a tuple, where the first element is the "prefix parent", i.e. the path leading to and
    including the last parent; the second element is the last part of the query. The latter can be an object or an
    index.  Examples of inputs and outputs:
    a.b.c         ->  a.b, c
    a.b.c/0       ->  a.b.c, 0
    a.b.c/0/0/1   ->  a.b.c/0/0, 1
    a.b/0.c       ->  a.b/0, c
    """
    upper_bound = max(s.rfind("."), s.rfind("/"))

    if upper_bound == -1:
        return "", s  # No parent, entire string is the child

    parent = s[:upper_bound]
    child = s[upper_bound + 1 :]
    return parent, child


def set_asn1_value(asn1_obj: base.Asn1Item, path: str, value: base.Asn1Item):
    """Update an ASN1 structure in-place by setting the attribute at path to value."""
    # There are some easy cases where we can figure out that the inputs are bad and there's nothing for us to set,
    # handle those and bail out early.
    if not path or path.strip() == "":
        raise ValueError("Cannot set root object. Specify a path to a child element.")

    if path.endswith("/") or path.endswith("."):
        raise ValueError("Path incomplete: it cannot end with '/' or '.'")

    if "." not in path and "/" not in path:
        raise ValueError(f"Path '{path}' is too shallow; specify a child element.")

    parent_path, child_key = _split_last_parent(path)

    # Traverse to parent. If parent_path is empty (e.g. path was "a.b"), parent is the root object
    try:
        parent = get_asn1_value(asn1_obj, parent_path) if parent_path else asn1_obj
    except Exception as e:
        raise ValueError(f"Could not reach parent structure at '{parent_path}': {e}")

    # Perform assignment
    try:
        if child_key.isdigit() and isinstance(parent, (univ.SequenceOf, univ.SetOf)):
            idx = int(child_key)

            # Bound check for SequenceOf
            if idx > len(parent):
                raise ValueError(
                    f"Index {idx} out of range. Current {type(parent).__name__} size is {len(parent)}. "
                    "Manual expansion of preceding indices is required."
                )
            parent[idx] = value
        else:
            # Sequence/Set: pyasn1 handles name-to-index mapping and type coercion here
            # We also suppress pyright's concern here, the set and sequence objects do have __setitem__
            parent[child_key] = value  # type: ignore

    except Exception as e:
        # This catches type mismatches, unknown component names, etc.
        raise ValueError(f"Assignment failed for path '{path}': {e}")

    return asn1_obj


def get_asn1_value(asn1_obj: base.Asn1Item, query: str) -> base.Asn1Item:  # noqa D417 undocumented-param
    """Extract a value from a complex `pyasn1` structure by specifying its path in ASN1Path notation.

    This function allows you to extract a value from a nested pyasn1 object by specifying the path
    using dot-notation or a combination of dot and slash notation (for sequences).

    Arguments:
    ---------
        - `asn1_obj`: The pyasn1 object structure you want to query.
        - `query`: The path to the value you want to extract, given as a dot-notation.

    Returns:
    -------
        - The extracted pyasn1 object based on the query path.

    Raises:
    ------
        - `ValueError`: If the traversal of the path fails or if the path is invalid, an informative
          error message is raised that includes details about the step where the error occurred and
          the available keys at that level.

    Examples:
    --------
    | ${pyasn1_value}= | Get Asn1 Value | ${asn1_obj} | query=header.sender.directoryName.rdnSequence/0 |
    | ${pyasn1_value}= | Get Asn1 Value | ${asn1_obj} | query=header.sender.directoryName.rdnSequence/0/0.value |

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
                        asn1_obj = asn1_obj[int(part)]  # type: ignore
                    else:
                        asn1_obj = asn1_obj[part]  # type: ignore
                    traversed_so_far += f"/{part}"
            else:
                asn1_obj = asn1_obj[key]  # type: ignore
            traversed_so_far += f".{key}" if traversed_so_far else key
    except Exception as err:
        # except KeyError as err:
        available_keys = list(asn1_obj.keys())  # type: ignore
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


def get_asn1_value_as_string(  # noqa D417 undocumented-param
    asn1_obj: base.Asn1Item, query: str, decode: bool = False
):
    """Retrieve a value from a pyasn1 object and return it as a string.

    :Arguments:
    ---------
        - `asn1_obj`: The pyasn1 object to query.
        - `query`: The path to the value you want to extract, given as dot-notation (e.g.,
          'header.sender.directoryName.rdnSequence/0', or 'header.sender.directoryName.rdnSequence/0/0.value').
        - `decode`: If `True`, the result is decoded before returning. Defaults to `False`.


    Returns
    -------
        - The extracted value as a string.

    Raises
    ------
        - `ValueError` if the value cannot be found. Will raise a ValueError with details.


    Examples
    --------
    | ${str_val}= | Get ASN1 Value As String | ${asn1_obj} | query=header.sender.directoryName.rdnSequence/0 | \
    decode=False |
    | ${str_val}= | Get ASN1 Value As String | ${asn1_obj} | query=header.sender.directoryName.rdnSequence/0/0.value |

    """
    result = get_asn1_value(asn1_obj, query)
    if decode:
        result, _rest = decoder.decode(result)
    return result.prettyPrint()  # type: ignore


def get_asn1_value_as_number(  # noqa D417 undocumented-param
    asn1_obj: base.Asn1Type, query: str, decode: bool = False
) -> int:
    """Retrieve a value from a pyasn1 object and return it as an integer.

    Arguments:
    ---------
        - `asn1_obj`: The pyasn1 object to query.
        - `query`: The path to the value you want to extract, given as dot-notation.
        - `decode`: If `True`, the result is decoded before returning. Defaults to `False`.

    Returns:
    -------
        - The extracted value as an integer.

    Raises:
    ------
        - `ValueError` if the value cannot be found. Will raise a ValueError with details.

    Examples:
    --------
    | ${int_val}= | Get Asn1 Value As Number | ${asn1_obj} | query=header.sender.directoryName.rdnSequence/0/0.value |
    | ${int_val}= | Get Asn1 Value As Number | ${asn1_obj} | query=body.rp.status/0.status/0.status |

    """
    result = get_asn1_value(asn1_obj, query)
    if decode:
        decoded, _rest = decoder.decode(result)  # type: ignore
    else:
        decoded = result  # type: ignore
    return int(decoded)  # type: ignore


def get_asn1_value_as_bytes(asn1_obj: base.Asn1Type, query: str) -> bytes:  # noqa D417 undocumented-param
    """Retrieve a value from a pyasn1 object and return it as bytes.

    Arguments:
    ---------
        - `asn1_obj`: The pyasn1 object to query.
        - `query`: The path to the value you want to extract, given as dot-notation (e.g., 'header.senderKID').

    Returns:
    -------
        - The extracted value as bytes.

    Raises:
    ------
        - `ValueError`: If the value cannot be found.

    Examples:
    --------
    | ${bytes_val}= | Get Asn1 Value As Bytes | ${asn1_obj} | query=header.senderKID |
    | ${bytes_val}= | Get Asn1 Value As Bytes | ${asn1_obj} | query=header.transactionID |

    """
    result = get_asn1_value(asn1_obj, query)  # type: ignore
    return result.asOctets()  # type: ignore


def get_asn1_value_as_datetime(  # noqa D417 undocumented-param
    asn1_obj: base.Asn1Type, query: str
) -> datetime:
    """Retrieve a value from a pyasn1 object and return it as a python `datetime.datetime` object.

    Arguments:
    ---------
        - `asn1_obj`: The pyasn1 object to query.
        - `query`: The path to the value you want to extract, given as dot-notation (e.g., 'header.messageTime').

    Returns:
    -------
        - The extracted value as a `datetime.datetime` object.

    Examples:
    --------
    | ${datetime_val}= | Get Asn1 Value As Datetime | ${asn1_obj} | query=header.messageTime |
    | ${datetime_val}= | Get Asn1 Value As Datetime | ${asn1_obj} | query=tbsCertificate.validity.notBefore.UtcNow |

    """
    result = get_asn1_value(asn1_obj, query)
    return result.asDateTime  # type: ignore


def get_asn1_value_as_der(asn1_obj: base.Asn1Type, query: str) -> bytes:  # noqa D417 undocumented-param
    """Retrieve a value from a pyasn1 object and return it as a DER-encoded byte sequence.

    Arguments:
    ---------
        - `asn1_obj`: The pyasn1 object to query.
        - `query` (str): The path to the value you want to extract, given as dot-notation.


    Returns:
    -------
        - The extracted value as a DER-encoded `bytes` object.

    Raises:
    ------
        - `ValueError`: If the value cannot be found.

    Examples:
    --------
    | ${der_data}= | Get ASN1 Value As DER | ${asn1_obj} | query=header.sender.directoryName.rdnSequence/0/0.value |
    | ${der_data}= | Get ASN1 Value As DER | ${asn1_obj} | query=extraCerts |

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


def is_bit_set(  # noqa D417 undocumented-param
    asn1_bitstring: BitString,
    bit_indices: Strint,
    exclusive: bool = True,
) -> bool:
    """Verify if a specific bit or bits are set within a given `BitString` object.

    It supports both integer index and named bit indices (which can be comma-separated). The check can be
    performed either exclusively or non-exclusively, depending on the `exclusive` parameter.

    Arguments:
    ---------
        - asn1_bitstring: A `pyasn1` `BitString` object to be checked.
        - bit_indices: A string representing the bit index or indices to check.
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
    | ${is_equal}= | Is Bit Set | ${failInfo} | 26 | ${True} |
    | ${is_equal}= | Is Bit Set | ${failInfo} | ${26}  | ${True} |
    | ${is_equal}= | Is Bit Set | ${failInfo} | duplicateCertReq  | ${True} |
    | ${is_equal}= | Is Bit Set | ${failInfo} | 1, 9  | ${True} |

    """
    logging.info("exclusive: %s ", str(exclusive))
    logging.info("type %s: ", type(asn1_bitstring))
    logging.info("input: %s type: %s", bit_indices, type(bit_indices))

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
        names = get_all_asn1_named_value_names(asn1_bitstring, get_keys=True)
        all_set_names = get_set_bitstring_names(asn1_bitstring).split(", ")

        try:
            bit_indices = [names.index(val.strip()) for val in values]  # type: ignore
        except ValueError as err:
            raise ValueError(f"Provided names: {values} but allowed are: {names}") from err

        if all_set_names == values and not exclusive:
            # to ensure that if all bits are set, it will return True.
            return True

        if all_set_names == values and exclusive:
            return True

        if all_set_names == names and exclusive:
            raise ValueError("All bits are set, so exclusive check is not possible!")

        return _is_either_bit_set_in_bitstring(asn1_bitstring, bit_indices, exclusive=exclusive)  # type: ignore

    raise ValueError("Expected to get either an int or a string as input, for `bit_indices`!")


@not_keyword
def get_all_asn1_named_value_names(
    asn1_object: Union[base.Asn1Item, base.Asn1Type], get_keys: bool = True
) -> List[str]:
    """Retrieve all named values from a `pyasn1` object.

    :param asn1_object: The `pyasn1` object to extract names from.
    :param get_keys: If `True`, return the keys of the named values. Default is `True`.
    :return: A list of names corresponding to the named values in the `pyasn1` object.
    :raises ValueError: If the provided object does not have named values.
    """
    if not hasattr(asn1_object, "namedValues"):
        raise ValueError(
            f"The provided object does not have named values. "
            f"Please provide a valid `pyasn1` object with named values. Type: {type(asn1_object)}"
        )

    if get_keys:
        return list(asn1_object.namedValues.keys())  # type: ignore
    return list(asn1_object.namedValues.values())  # type: ignore


@not_keyword
def get_set_bitstring_names(asn1_bitstring: univ.BitString) -> str:
    """Retrieve the set bit names from a pyasn1 `BitString` object.

    :param asn1_bitstring: The pyasn1 `BitString` to extract names from.
    :return: A comma-separated string of names corresponding to the set bits.
    """
    binary_string = asn1_bitstring.asBinary()
    options = get_all_asn1_named_value_names(asn1_bitstring, get_keys=True)
    names = []
    for i, name in enumerate(options):
        if len(binary_string) == i:
            break
        if binary_string[i] == "1":
            names.append(name)
    return ", ".join(names)


@not_keyword
def asn1_names_to_bitstring(asn1object: Union[univ.BitString, type], values: str) -> univ.BitString:
    """Return a `univ.BitString` object with provided values.

    :param asn1object: calls object to generate from.
    :param values: The human-readable name of the value to set.
    :return:
    """
    # starts from zero! and 'dict_keyiterator' has no len()
    bit_string = ["0"] * (len(list(asn1object.namedValues.keys())) + 1)

    names = list(asn1object.namedValues.keys())

    for value in values.strip(" ").split(","):
        value = value.strip()
        if value not in names:
            raise ValueError(f"Provided name: {value} but allowed are: {names}")
        ind = names.index(value)
        bit_string[ind] = "1"

    reversed_str = "".join(bit_string[::-1]).lstrip("0")[::-1]  # to only set needed values.
    if isinstance(asn1object, type):
        return asn1object(f"'{reversed_str}'B")

    return type(asn1object)(f"'{reversed_str}'B")


@not_keyword
def asn1_get_named_value(asn1_object, value_name: str) -> Any:
    """Return the value with a human-readable representation.

    :param asn1_object:  The `pyasn1` object to search for the named value.
    :param value_name: The human-readable name of the value to retrieve.
    :return: The `pyasn1` value corresponding to the provided `value_name`.
    :raises ValueError: If the `value_name` is not found in the `pyasn1` object's named values,
                        a `ValueError` is raised with a list of allowed name
    """
    for name, value in asn1_object.namedValues.items():
        if name == value_name:
            if isinstance(asn1_object, type):
                # if is true something like rfc9480.PKIStatus was given so it will return the encoded value.
                # only internal use, for more information look at the Unittests.
                return asn1_object(value)
            return value

    names = list(asn1_object.namedValues.keys())
    raise ValueError(f"Provided name: {value_name} but allowed are: {names} \nis of type: {type(asn1_object)}")


@not_keyword
def asn1_compare_named_integer(asn1_integer: univ.Integer, value: str) -> bool:  # noqa D417 undocumented-param
    """Check if the provided `pyasn` Integer matches the human-readable representation.

    :param asn1_integer: An `pyasn` Integer with named values.
    :param value: The human-readable string representing the named value to compare against.
    :return: True if the integer matches the named value, False otherwise.
    """
    names = list(asn1_integer.namedValues.keys())

    if value in names:
        int_value = names.index(value.strip(" "))
        return int_value == int(asn1_integer)

    raise ValueError(f"Provided name: {value} but allowed are: {names}")


def asn1_compare_named_values(  # noqa D417 undocumented-param
    asn1_object: base.Asn1Type,
    values: str,
    exclusive: bool = True,
    raise_exception: bool = False,
    query: Optional[str] = None,
) -> bool:
    """Verify if specific human-readable representations of values are set for `pyasn1` named object.

    It supports both integer index and named bit indices (which can be comma-separated). The check can be
    performed either exclusively or non-exclusively, depending on the `exclusive` parameter.

    Arguments:
    ---------
        - asn1_object: A  pyasn1 `univ.Integer` or `univ.BitString` object to be checked.
        - values: A `str` a human-readable representation of the values.
          This can be:
            - An integer index for a single bit check.
            - A comma-separated string of integers for multiple bit indices, e.g., "1, 9".
            - A comma-separated string of human-readable bit names, e.g., "duplicateCertReq, badPOP".
        - exclusive: A `bool` indicating if only one bit must be set (`True`)
          or if any of them can be set (`False`). Default is `True`.
        - `raise_exception`: If `True`, raises a `ValueError` if the comparison fails. Default is `False`.
        - `query`: The path to the value in the ASN.1 object if nested. Uses dot-notation for the path.

    Raises:
    ------
        - `ValueError`: If `raise_exception` is set to `True` and the specified value(s) are not found or do not match.


    Returns:
    -------
        - `True` if the specified values or bits are set according to the `exclusive`
          parameter; otherwise, `False`.

    Examples:
    --------
    | ${result}= | Asn1 Compare Named Values | ${asn1_object} | values=duplicateCertReq | exclusive=True |
    | ${result}= | Asn1 Compare Named Values | ${asn1_object} | values=1, 9 | exclusive=False |

    """
    if query is not None:
        asn1_object = get_asn1_value(asn1_object, query=query)  # type: ignore

    if isinstance(asn1_object, univ.BitString):
        result = is_bit_set(asn1_object, values, exclusive=exclusive)

    elif isinstance(asn1_object, univ.Integer):
        vals = values.strip(" ").split(",")

        tmp = [asn1_compare_named_integer(asn1_integer=asn1_object, value=value.strip(" ")) for value in vals]
        result = sum(tmp)
        if result == 0:
            result = False
        else:
            result = exclusive
    else:
        other_asn1_object = asn1_get_named_value(asn1_object=asn1_object.__class__, value_name=values)  # type: ignore
        result = other_asn1_object == asn1_object

    if not result:
        if raise_exception:
            ex = " (exclusive)" if exclusive else ""
            raise ValueError(f"{asn1_object.__class__.__name__} and {values} and different!{ex}")
        return result

    return result


def encode_to_der(  # noqa D417 undocumented-param
    asn1_structure: base.Asn1Item,
) -> bytes:
    """DER-encode a `pyasn1` data structure.

    Arguments:
    ---------
        - `asn1_structure`: The `pyasn1` data structure to be encoded.

    Returns:
    -------
       - The DER-encoded bytes of the pyasn1 structure.

    Examples:
    --------
    | ${der_bytes}= | Encode To Der | ${asn1_structure} |
    | ${der_bytes}= | Encode To Der | asn1_structure=${pki_message} |

    """
    return encoder.encode(asn1_structure)


@not_keyword
def try_decode_pyasn1(
    data: Union[bytes, univ.Any, univ.OctetString], asn1_spec: Asn1Type, for_nested: bool = False, verbose: bool = False
) -> Tuple[Asn1Item, bytes]:
    """Try to decode a DER-encoded data using the provided ASN.1 specification.

    :param data: The DER-encoded data to decode.
    :param asn1_spec: The PyASN1 specification to use for decoding.
    :param for_nested: If True, the function will return the decoded data and not the rest of the data.
    :param verbose: If `True`, the remainder of the data will be included in the error message.
    :return: The decoded PyASN1 object.
    """
    from resources.cmputils import parse_pkimessage  # pylint: disable=import-outside-toplevel

    if isinstance(data, univ.Any):
        der_data = data.asOctets()
    elif isinstance(data, univ.OctetString):
        der_data = data.asOctets()
    elif isinstance(data, bytes):
        der_data = data
    else:
        raise TypeError(f"Expected bytes, got {type(data)}")

    try:
        if for_nested:
            out = parse_pkimessage(der_data)
            _, rest = decoder.decode(der_data, PKIMessageTMP())
            return out, rest
        return decoder.decode(der_data, asn1_spec)
    except Exception:  # pylint: disable=broad-except
        remainder = f"Remainder: {der_data.hex()}" if verbose else ""
        raise BadAsn1Data(  # pylint: disable=raise-missing-from
            f"Error decoding data for {type(asn1_spec)}.{remainder}",
            overwrite=True,
        )
