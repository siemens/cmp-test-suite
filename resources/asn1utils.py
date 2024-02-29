"""This library contains generic primitives for querying PyASN1 objects using ASN1Path,
a notation similar to XPath for XML or JSONPath for JSON.

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

from pyasn1.codec.der import decoder, encoder


def asn1_must_contain_fields(data, fields):
    """
    Verifies that the given ASN.1 structure contains the specified fields.

    `data` is the pyasn1 structure to check.
    `fields` is a string that represents a comma-separated list field names to check for in the ASN.1 structure. Spaces
    in this string will be ignored.

    Example:
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
    fields = [item.strip() for item in fields.split(',')]
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
    keys = query.split('.')

    # we use these to gradually build up the traversed path, to show an informative error message if an error occurs
    traversed_so_far = ''
    current_piece = ''
    try:
        for key in keys:
            current_piece = key
            if '/' in key:
                parts = key.split('/')
                for part in parts:
                    current_piece = part
                    if part.isdigit():
                        asn1_obj = asn1_obj[int(part)]
                    else:
                        asn1_obj = asn1_obj[part]
                    traversed_so_far += f'/{part}'
            else:
                asn1_obj = asn1_obj[key]
            traversed_so_far += f'.{key}' if traversed_so_far else key
    except Exception as err:
        # except KeyError as err:
        available_keys = list(asn1_obj.keys())
        report = f"> Traversal ERROR, got this far: `{traversed_so_far}`, issue at `{current_piece}`, the query was `{query}`"
        report += f'\n> Available keys at this step: {available_keys}'
        if len(available_keys) == 1:
            report += f', try `{traversed_so_far}.{available_keys[0]}`'
        report += f'\n> Underlying error: {err}'
        raise ValueError(report)
    else:
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
