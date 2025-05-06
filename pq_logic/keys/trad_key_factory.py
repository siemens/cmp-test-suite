# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Generate cryptographic keys using the `cryptography` library."""

import logging
import os
from typing import Optional, Tuple, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, ed448, ed25519, rsa, x448, x25519
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc3279, rfc4211, rfc5480, rfc5915, rfc5958, rfc6664, rfc8017, rfc9480, rfc9481
from robot.api.deco import not_keyword

from pq_logic.keys.abstract_wrapper_keys import TradKEMPublicKey
from pq_logic.keys.serialize_utils import ecc_private_key_to_bytes, prepare_ec_private_key, prepare_rsa_private_key
from resources.asn1utils import try_decode_pyasn1
from resources.exceptions import BadAlg, BadAsn1Data, InvalidKeyData, MisMatchingKey
from resources.oid_mapping import get_curve_instance, may_return_oid_to_name
from resources.typingutils import PrivateKey, PublicKey, TradPrivateKey


@not_keyword
def generate_ec_key(algorithm: str, curve: Optional[str] = None) -> PrivateKey:
    """Generate a private key for a specified elliptic curve algorithm and curve.

    This function generates a private key for Ed25519, Ed448, X25519, and X448.

    :param algorithm: The name of the elliptic curve algorithm. Supported values are:
                      - "ed25519" for Ed25519PrivateKey
                      - "ed448" for Ed448PrivateKey
                      - "x25519" for X25519PrivateKey
                      - "x448" for X448PrivateKey
    :param curve: the name of the elliptic curve.
    :return: A generated private key object corresponding to the specified algorithm.
    :raises ValueError: If the provided algorithm is not supported.
    """
    if algorithm in ["ecdh", "ecdsa", "ecc", "ec"]:
        if curve is None:
            curve = "secp256r1"
        curve_instance = get_curve_instance(curve_name=curve)
        return ec.generate_private_key(curve=curve_instance)

    if algorithm == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()

    if algorithm == "ed448":
        return ed448.Ed448PrivateKey.generate()

    if algorithm == "x25519":
        return x25519.X25519PrivateKey.generate()

    if algorithm == "x448":
        return x448.X448PrivateKey.generate()

    raise ValueError(f"Unsupported ecc algorithm: {algorithm}")


def _generate_dh_private_key(
    p: Optional[int] = None, g: int = 2, secret_scalar: Optional[int] = None, length: int = 2048
) -> dh.DHPrivateKey:
    """Generate a Diffie-Hellman (DH) private key using the provided parameters.

    :param p: The prime modulus for the DH parameters. If not provided, a new prime modulus
              will be generated based on the specified `length`.
    :param g: The generator for the DH parameters. Defaults to 2.
    :param secret_scalar: The secret scalar value to use for key generation. If not provided,
                          a new secret scalar will be generated.
    :param length: The length of the key in bits if `p` is not provided. Default to 2048.
    :return: The generated DH private key.
    :raises ValueError: If the `secret_scalar` parameter is provided, but not `p`.
    """
    if p is None:
        parameters = dh.generate_parameters(generator=g, key_size=length)
    else:
        parameters = dh.DHParameterNumbers(p, g).parameters()

    if secret_scalar is not None:
        if p is None:
            raise ValueError("Parameter `p` must be provided when using a `secret_scalar`.")
        public_number = pow(g, secret_scalar, p)
        private_key = dh.DHPrivateNumbers(
            x=secret_scalar, public_numbers=dh.DHPublicNumbers(public_number, parameters.parameter_numbers())
        ).private_key()
    else:
        private_key = parameters.generate_private_key()

    return private_key


@not_keyword
def generate_trad_key(algorithm="rsa", **params) -> TradPrivateKey:  # noqa: D417 for RF docs
    """Generate a `cryptography` key based on the specified algorithm.

    This function supports generating keys for various cryptographic algorithms including RSA, DSA, ECDSA, ECDH,
    Ed25519, and DH. Depending on the selected algorithm, additional parameters can be provided.

    Arguments:
    ---------
        - `algorithm`: The cryptographic algorithm to use for key generation.
        - `**params`: Additional parameters specific to the algorithm.

    Supported algorithms:
    ---------------------
        - "rsa": RSA (default).
        - "dsa": DSA.
        - "ecdsa" or "ecdh": Elliptic Curve.
        - "ed25519": Ed25519.
        - "dh": Diffie-Hellman.
        - "bad_rsa_key": RSA with a bit size of 512.

    Additional Parameters:
    ----------------------
        - For "rsa" and "dsa":
            - length (int, str): The length of the key to generate, in bits. Default is 2048.
        - For "ecdsa" or "ecdh":
            - curve (str): Curve name, see `cryptography.hazmat.primitives.asymmetric.ec`. Default is `secp256r1`.
        - For "dh":
            - g (int): The generator for DH key generation. Default is 2.
            - secret_scalar (str, int): the private key value for DH key generation. If not provided, one is generated.
            - length (int, str): The length of the modulus to generate if `p` is not provided. Default is 2048.


    Returns:
    -------
        - The generated private key.

    Raises:
    ------
        - `ValueError` if the specified algorithm is not supported or if invalid parameters are provided.

    Examples:
    --------
    | ${private_key}= | Generate Key | algorithm=rsa | length=2048 |
    | ${private_key}= | Generate Key | algorithm=dh | length=2048 |
    | ${private_key}= | Generate Key | algorithm=ecdsa | curve=secp384r1 |

    """
    algorithm = algorithm.lower()

    if algorithm == "bad_rsa_key":
        from cryptography.hazmat.bindings._rust import (  # pylint: disable=import-outside-toplevel
            openssl as rust_openssl,
        )

        private_key = rust_openssl.rsa.generate_private_key(65537, 512)  # type: ignore

    elif algorithm == "rsa":
        length = int(params.get("length") or 2048)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=length)

    elif algorithm == "dsa":
        length = int(params.get("length", 2048))
        private_key = dsa.generate_private_key(key_size=length)

    elif algorithm in {"ed25519", "ed448", "x25519", "x448", "ecdh", "ecdsa", "ecc", "ec"}:
        curve = params.get("curve", "secp256r1")
        private_key = generate_ec_key(algorithm, curve)

    elif algorithm == "dh":
        private_key = _generate_dh_private_key(
            p=params.get("p"),
            g=params.get("g", 2),
            secret_scalar=params.get("secret_scalar"),
            length=int(params.get("length", 2048)),
        )

    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    return private_key


def _prepare_one_asym_key(
    private_key_bytes: bytes,
    alg_id: rfc9480.AlgorithmIdentifier,
    version: int = 1,
    public_key_bytes: Optional[bytes] = None,
) -> rfc5958.OneAsymmetricKey:
    """Prepare a OneAsymmetricKey object from a private key.

    :param private_key_bytes: The private key bytes to be included in the OneAsymmetricKey.
    :param alg_id: The private key algorithm identifier.
    :param version: The version of the OneAsymmetricKey. Defaults to `1`.
    :param public_key_bytes: The corresponding public key bytes, if available.
    :return: A OneAsymmetricKey object containing the private key.
    """
    one_asym_key = rfc5958.OneAsymmetricKey()
    one_asym_key["version"] = univ.Integer(version)
    one_asym_key["privateKeyAlgorithm"] = alg_id
    one_asym_key["privateKey"] = private_key_bytes

    if public_key_bytes:
        one_asym_key["publicKey"] = (
            rfc5958.PublicKey()
            .fromOctetString(public_key_bytes)
            .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
        )

    return one_asym_key


def _prepare_private_key_bytes(
    private_key: PrivateKey, invalid_private_key: bool
) -> Tuple[bytes, rfc9480.AlgorithmIdentifier]:
    """Prepare the private key bytes for encoding.

    :param private_key: The private key to be converted.
    :return: The private key bytes in DER format and the algorithm identifier.
    """
    der_data = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    one_asym_key, _ = decoder.decode(der_data, rfc5958.OneAsymmetricKey())
    alg_id = one_asym_key["privateKeyAlgorithm"]

    if invalid_private_key and not isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise ValueError("Invalid private key is only supported for RSA and ECC keys.")
    if invalid_private_key:
        return prepare_invalid_trad_private_key(private_key), alg_id
    return one_asym_key["privateKey"].asOctets(), alg_id


def _get_public_key_bytes(public_key: PublicKey) -> Optional[bytes]:
    """Get the public key bytes from a public key object.

    :param public_key: The public key to be converted.
    :return: The public key bytes in DER format or None if the public key is not provided.
    """
    if public_key is None:
        return None

    if isinstance(public_key, rsa.RSAPublicKey):
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.PKCS1
        )
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint
        )
    elif isinstance(
        public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey, x25519.X25519PublicKey, x448.X448PublicKey)
    ):
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

    elif isinstance(public_key, TradKEMPublicKey):
        public_key_bytes = public_key.encode()

    else:
        raise TypeError(f"Unsupported public key type. Got: {type(public_key)}")

    return public_key_bytes


def prepare_trad_private_key_one_asym_key(
    private_key: PrivateKey,
    public_key: Optional[PublicKey] = None,
    version: int = 1,
    include_public_key: Optional[bool] = None,
    invalid_private_key: bool = False,
) -> bytes:
    """Prepare a OneAsymmetricKey object from a private key.

    :param private_key: The private key to be converted.
    :param public_key: The corresponding public key, if available.
    :param version: The version of the OneAsymmetricKey. Defaults to `1`.
    :param include_public_key: If True, include the public key in the OneAsymmetricKey. Default is `None`.
    :param invalid_private_key: If True, the private key is invalid, only supported for RSA and ECC keys.
    Defaults to `False`.
    :return: A OneAsymmetricKey object containing the private key.
    """
    private_key_bytes, alg_id = _prepare_private_key_bytes(private_key, invalid_private_key)

    if version == 0 and not include_public_key or include_public_key is False:  # noqa: E711
        return encoder.encode(
            _prepare_one_asym_key(
                private_key_bytes=private_key_bytes,
                version=version,
                alg_id=alg_id,
            )
        )

    public_key = public_key or private_key.public_key()
    public_key_bytes = _get_public_key_bytes(public_key)

    one_asym_key = _prepare_one_asym_key(
        private_key_bytes=private_key_bytes,
        version=version,
        alg_id=alg_id,
        public_key_bytes=public_key_bytes,
    )
    return encoder.encode(one_asym_key)


def _load_raw_public_key(trad_name: Union[str, univ.ObjectIdentifier], public_key_bytes: bytes) -> PublicKey:
    """Load a raw public key from bytes.

    :param trad_name: The name of the traditional key or the OID.
    :param public_key_bytes: The raw public key bytes.
    :return: The loaded public key.
    :raises ValueError: If the key is not supported.
    """
    if trad_name in ["x25519", rfc9481.id_X25519]:
        if len(public_key_bytes) != 32:
            raise InvalidKeyData(
                f"The X25519 public key has an invalid length. Expected: 32 bytes, got: {len(public_key_bytes)} bytes."
            )
        return x25519.X25519PublicKey.from_public_bytes(public_key_bytes)
    if trad_name in ["x448", rfc9481.id_X448]:
        if len(public_key_bytes) != 56:
            raise InvalidKeyData(
                f"The X448 public key has an invalid length. Expected: 56 bytes, got: {len(public_key_bytes)} bytes."
            )
        return x448.X448PublicKey.from_public_bytes(public_key_bytes)
    if trad_name in ["ed25519", rfc9481.id_Ed25519]:
        if len(public_key_bytes) != 32:
            raise InvalidKeyData(
                f"The Ed25519 public key has an invalid length. Expected: 32 bytes, got: {len(public_key_bytes)} bytes."
            )
        return ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
    if trad_name in ["ed448", rfc9481.id_Ed448]:
        if len(public_key_bytes) != 57:
            raise InvalidKeyData(
                f"The Ed448 public key has an invalid length. Expected: 57 bytes, got: {len(public_key_bytes)} bytes."
            )
        return ed448.Ed448PublicKey.from_public_bytes(public_key_bytes)

    raise ValueError(f"Unsupported raw algorithm name: {trad_name}")


@not_keyword
def load_trad_public_key(
    trad_name: Union[str, univ.ObjectIdentifier], data: bytes, curve_name: Optional[str] = None
) -> PublicKey:
    """Load a traditional public key from bytes.

    Supported algorithms are RSA, ECDSA, ECDH, Ed25519, Ed448, X25519, and X448.

    :param trad_name: The traditional public key name or the OID.
    :param data: The data to load.
    :param curve_name: The name of the curve for ECC keys.
    :return: The loaded public key.
    :raises NotImplementedError: If the algorithm is not implemented.
    :raises ValueError: If the curve name is not provided for ECC keys or not supported.
    :raises InvalidKeyData: If the key data is invalid.
    """
    if trad_name in ["rsa", rfc9481.rsaEncryption]:
        _, rest = try_decode_pyasn1(data, rfc3279.RSAPublicKey())
        if rest:
            raise InvalidKeyData("The `RSAPublicKey` data contains trailing data.")
        try:
            return serialization.load_der_public_key(data)
        except ValueError as e:
            raise InvalidKeyData("The `RSAPublicKey` cannot be loaded.") from e
    if trad_name in ["ecdsa", "ecdh", "ec", rfc6664.id_ecPublicKey, rfc5480.id_ecMQV, rfc5480.id_ecDH]:
        if curve_name is None:
            raise ValueError("Curve name is required for ECC keys.")
        curve_instance = get_curve_instance(curve_name=curve_name)
        try:
            return ec.EllipticCurvePublicKey.from_encoded_point(curve_instance, data)
        except ValueError as e:
            raise InvalidKeyData("The `ECPoint` data is not a valid point on the curve.") from e

    _oids = [
        "x25519",
        rfc9481.id_X25519,
        "ed25519",
        rfc9481.id_Ed25519,
        "x448",
        rfc9481.id_X448,
        "ed448",
        rfc9481.id_Ed448,
    ]

    if trad_name in _oids:
        return _load_raw_public_key(public_key_bytes=data, trad_name=trad_name)

    raise NotImplementedError(f"The algorithm name: {trad_name} is not implemented to be loaded.")


def _load_public_key(public_key_bytes: bytes, oid: univ.ObjectIdentifier) -> PublicKey:
    """Load a raw public key from bytes.

    :param public_key_bytes: The raw public key bytes.
    :param oid: The OID of the public key algorithm.
    :return: The loaded public key.
    """
    try:
        return load_trad_public_key(oid, public_key_bytes)
    except ValueError as e:
        _name = may_return_oid_to_name(oid)
        raise InvalidKeyData(f"Failed to load {_name} public key.") from e


def _load_private_key(one_asym_key: rfc5958.OneAsymmetricKey) -> PrivateKey:
    """Load a private key from a OneAsymmetricKey object.

    :param one_asym_key: The OneAsymmetricKey object.
    :return: The loaded private key.
    """
    private_key_bytes = one_asym_key["privateKey"].asOctets()

    oid = one_asym_key["privateKeyAlgorithm"]["algorithm"]
    # the `cryptography` library does not support v2.
    tmp = rfc4211.PrivateKeyInfo()
    tmp["privateKeyAlgorithm"]["algorithm"] = oid
    tmp["privateKeyAlgorithm"]["parameters"] = one_asym_key["privateKeyAlgorithm"]["parameters"]
    tmp["privateKey"] = one_asym_key["privateKey"]
    tmp["version"] = 0

    private_info = encoder.encode(tmp)

    if oid in [rfc9481.id_Ed25519, rfc9481.id_Ed448, rfc9481.id_X25519, rfc9481.id_X448]:
        _, rest = decoder.decode(private_key_bytes, univ.OctetString())
        if rest:
            name = may_return_oid_to_name(oid)
            raise InvalidKeyData(f"The {name.upper()} private key contained trailing data")

    if oid == rfc6664.id_ecPublicKey:
        _, rest = decoder.decode(private_key_bytes, asn1Spec=rfc5915.ECPrivateKey())
        if rest:
            raise InvalidKeyData("The `ECPrivateKey` data contains trailing data.")

    if oid == rfc9481.rsaEncryption:
        _, rest = decoder.decode(private_key_bytes, asn1Spec=rfc8017.RSAPrivateKey())
        if rest:
            raise InvalidKeyData("The `RSAPrivateKey` data contains trailing data.")

    try:
        return serialization.load_der_private_key(private_info, password=None)
    except ValueError as e:
        raise InvalidKeyData("The private key is not a valid DER-encoded private key.") from e
    except BaseException as e:
        raise InvalidKeyData("The ECC private key is not a valid private key.") from e


def _check_one_asym_key_version(
    one_asym_key: rfc5958.OneAsymmetricKey,
    must_be_version_2: bool = True,
) -> None:
    """Validate the version of a OneAsymmetricKey object."""
    version = int(one_asym_key["version"])
    if version not in [0, 1]:
        raise InvalidKeyData(f"Unsupported `OneAsymmetricKey` version: {version}. Supported versions are 0 and 1.")

    if version != 1 and must_be_version_2:
        raise ValueError("The provided key is not a version 2 key.")

    if version == 0 and one_asym_key["publicKey"].isValue:
        raise InvalidKeyData("The `OneAsymmetricKey` version is 0, but a public key is present.")


@not_keyword
def parse_trad_key_from_one_asym_key(
    one_asym_key: Union[rfc5958.OneAsymmetricKey, bytes, rfc4211.PrivateKeyInfo],  # type: ignore
    must_be_version_2: bool = True,
) -> TradPrivateKey:
    """Parse a traditional key from a single asymmetric key.

    :param one_asym_key: The OneAsymmetricKey object or its DER-encoded bytes.
    :param must_be_version_2: If True, the key must be a version 2 key.
    :return: The parsed private key.
    :raises BadAsn1Data: If the provided data is not a OneAsymmetricKey object.
    :raises ValueError: If the key is not a version 2 key.
    """
    if isinstance(one_asym_key, bytes):
        one_asym_key, rest = decoder.decode(one_asym_key, rfc5958.OneAsymmetricKey())  # type: ignore
        one_asym_key: rfc5958.OneAsymmetricKey
        if rest:
            raise BadAsn1Data("OneAsymmetricKey")
    elif isinstance(one_asym_key, rfc4211.PrivateKeyInfo):
        one_asym_key = rfc5958.OneAsymmetricKey()
        one_asym_key["privateKeyAlgorithm"] = one_asym_key["privateKeyAlgorithm"]
        one_asym_key["privateKey"] = one_asym_key["privateKey"]
        one_asym_key["version"] = 0

    _check_one_asym_key_version(one_asym_key, must_be_version_2)

    private_key_bytes = one_asym_key["privateKey"].asOctets()
    public_key_bytes = one_asym_key["publicKey"].asOctets() if one_asym_key["publicKey"].isValue else None

    oid = one_asym_key["privateKeyAlgorithm"]["algorithm"]

    private_key = _load_private_key(one_asym_key)

    if public_key_bytes is None:
        return private_key

    private_len = len(private_key_bytes)
    pub_len = len(public_key_bytes)

    logging.info("The Private Key size is: %d bytes", private_len)
    logging.info("The Public Key size is: %d bytes", pub_len)

    if oid == rfc6664.id_ecPublicKey:
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise ValueError("The private key is not an Elliptic Curve private key.")
        try:
            public_key = serialization.load_der_public_key(public_key_bytes)
        except ValueError:
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(data=public_key_bytes, curve=private_key.curve)

        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise InvalidKeyData("The public key is not an Elliptic Curve public key.")

    elif oid in [
        rfc9481.id_Ed25519,
        rfc9481.id_Ed448,
        rfc9481.id_X25519,
        rfc9481.id_X448,
        rfc9481.rsaEncryption,
    ]:
        # The public key is saved as raw bytes, so we do not need to decode it.
        public_key = _load_public_key(public_key_bytes, oid)

    else:
        _name = may_return_oid_to_name(oid)
        raise BadAlg(f"Can not load the traditional key for the algorithm: {_name}")

    if private_key.public_key() != public_key:
        raise MisMatchingKey("The public key does not match the private key.")

    return private_key


def prepare_invalid_trad_private_key(
    private_key: TradPrivateKey,
    invalid_key: bool = False,
    invalid_key_size: bool = False,
) -> bytes:
    """Prepare an invalid traditional private key.

    This function creates an invalid version of the provided traditional private key.
    The invalid key can be used for testing validation and error handling.

    :param private_key: The private key to be prepared to be invalid.
    :param invalid_key: If True, the key will be invalid.
    :param invalid_key_size: If True, the key size will be invalid.
    :return: The DER-encoded invalid private key bytes.
    :raises ValueError: If the private key type is not supported.
    """
    if not invalid_key and not invalid_key_size:
        raise ValueError("Either `invalid_key` or `invalid_key_size` must be True.")

    if isinstance(private_key, rsa.RSAPrivateKey):
        if invalid_key_size:
            return prepare_rsa_private_key(private_key, add_to_n=False) + os.urandom(10)
        return prepare_rsa_private_key(private_key, add_to_n=True)

    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        if invalid_key_size:
            ec_private_key = prepare_ec_private_key(private_key)
            # Add random data to the end of the DER-encoded key
            der_data = encoder.encode(ec_private_key) + os.urandom(10)
            return der_data
        # creates a too big private key for the curve.
        neg_ecc_key_bytes = ecc_private_key_to_bytes(private_key) + os.urandom(10)
        ec_private_key = prepare_ec_private_key(private_key, private_key_bytes=neg_ecc_key_bytes)
        return encoder.encode(ec_private_key)

    if isinstance(private_key, (X25519PrivateKey, X448PrivateKey, Ed25519PrivateKey, Ed448PrivateKey)):
        if invalid_key:
            raise ValueError(f"Invalid key is not supported for this type of key.Got: {type(private_key)}")

        return private_key.private_bytes_raw() + os.urandom(10)

    raise ValueError(f"Unsupported private key type: {type(private_key)}")
