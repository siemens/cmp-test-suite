from typing import Union, Optional

from cryptography.hazmat.primitives.asymmetric import x25519, x448, ec, rsa
from pyasn1.type import univ

from pq_logic.tmp_oids import COMPOSITE_KEM_NAME_2_OID


def get_oid_composite(
    pq_name: str,
    trad_key: Union[x25519.X25519PrivateKey, x448.X448PrivateKey, ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey],
    length: Optional[int] = None,
    curve_name: Optional[str] = None,
    use_dhkemrfc9180: bool = False,
) -> univ.ObjectIdentifier:
    """Return the OID for a composite KEM combination.

    :param pq_name: The name of the post-quantum algorithm.
    :param trad_key: The traditional key object.
    :param length: The length of the RSA key.
    :param curve_name: The name of the elliptic curve
    (only needed for negative testing)
    :param use_dhkemrfc9180: Whether to use the DHKEMRFC9180 and not ECDH mechanism.
    :return: The Object Identifier.
    """
    if isinstance(trad_key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        trad_name = f"rsa{length or trad_key.key_size}"

    elif isinstance(trad_key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        curve_name = curve_name or trad_key.curve.name
        trad_name = f"ecdh-{curve_name}"

    elif isinstance(trad_key, (x25519.X25519PrivateKey, x25519.X25519PublicKey)):
        trad_name = "x25519"

    elif isinstance(trad_key, (x448.X448PrivateKey, x448.X448PublicKey)):
        trad_name = "x448"
    else:
        raise ValueError(f"Unsupported traditional key type.: {type(trad_key).__name__}")

    prefix = "" if not use_dhkemrfc9180 else "dhkemrfc9180-"

    return COMPOSITE_KEM_NAME_2_OID[f"{prefix}{pq_name}-{trad_name}"]
