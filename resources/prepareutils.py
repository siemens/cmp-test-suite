from typing import Optional

from cryptography import x509
from pyasn1.codec.der import decoder
from pyasn1.type import tag
from pyasn1_alt_modules import rfc9480
from robot.api.deco import not_keyword


@not_keyword
def prepare_name(
    common_name: str, implicit_tag_id: Optional[int] = None, name: Optional[rfc9480.Name] = None
) -> rfc9480.Name:
    """Prepare a `rfc9480.Name` object or fill a provided object.

    :param common_name: Common name in OpenSSL notation, e.g., "C=DE,ST=Bavaria,L= Munich,CN=Joe Mustermann"
    :param implicit_tag_id: the implicitTag id for the new object.
    :param name: An optional `pyasn1` Name object in which the data is parsed. Else creates a new object.
    :return: The filled object.
    """
    name_obj = parse_common_name_from_str(common_name)
    der_data = name_obj.public_bytes()

    if name is None:
        if implicit_tag_id is not None:
            name = rfc9480.Name().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, implicit_tag_id)
            )

    name_tmp, rest = decoder.decode(der_data, rfc9480.Name())
    if rest != b"":
        raise ValueError("The decoding of `Name` structure had a remainder!")

    if name is None:
        return name_tmp

    name["rdnSequence"] = name_tmp["rdnSequence"]
    return name


@not_keyword
def parse_common_name_from_str(common_name: str) -> x509.Name:
    """Parse a string representing common name attributes, convert it to `x509.Name` for X.509 certificate generation.

    :param common_name: The common name in OpenSSL notation, e.g., "C=DE,ST=Bavaria,L= Munich,CN=Joe Mustermann"
    :returns: x509.Name object.
    """
    if common_name == "Null-DN":
        return x509.Name([])

    return x509.Name.from_rfc4514_string(data=common_name.replace(", ", ","))
