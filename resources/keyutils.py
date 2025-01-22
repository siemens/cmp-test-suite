# Copyright 2024 Siemens AG
# SPDX-FileCopyrightText: 2024 SPDX-FileCopyrightText:
#
# SPDX-License-Identifier: Apache-2.0

"""Utility functions for generating, saving, and loading cryptographic keys.

Designed to facilitate key management by offering simple methods to create new keys,
store them and retrieve them when needed.
"""

import base64
import re
import textwrap
from typing import List, Optional, Union

from cryptography.hazmat import backends
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
    dh,
    dsa,
    ec,
    ed448,
    ed25519,
    rsa,
    x448,
    x25519,
)
from pq_logic.key_pyasn1_utils import load_enc_key
from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc5280

from resources import oid_mapping, utils
from resources.typingutils import PrivateKey, PublicKey


def _add_armour(raw: str) -> str:
    """Add PEM armour for private keys.

    :param raw: str, unarmoured input data
    :returns: str, armoured data with PEM headers and footers "-----BEGIN PRIVATE KEY-----"
    """
    pem_header = "-----BEGIN PRIVATE KEY-----\n"
    pem_footer = "\n-----END PRIVATE KEY-----"
    pem_data = pem_header + raw + pem_footer
    return pem_data


def save_key(key: PrivateKey, path: str, passphrase: Union[None, str] = "11111"):  # noqa: D417 for RF docs
    """Save a private key to a file, optionally encrypting it with a passphrase.

    Arguments:
    ---------
        - `key`: The private key object to save.
        - `path`: The file path where the key will be saved.
        - `passphrase`: Optional passphrase to encrypt the key. If None, save without encryption. Defaults to "11111".

    Notes:
    -----
        - `DHPrivateKey`: Serialized in PKCS8 format.
        - `X448PrivateKey` and `X25519PrivateKey` and ed versions: (cannot be encrypted).

    Raises:
    ------
        - `TypeError` if the provided key is not a valid private key object.

    Examples:
    --------
    | Save Key | ${key} | /path/to/save/key.pem | password123 |

    """
    encoding_ = serialization.Encoding.PEM
    format_ = serialization.PrivateFormat.PKCS8
    passphrase = passphrase.encode("utf-8") if passphrase else None  # type: ignore

    if passphrase is None:
        encrypt_algo = serialization.NoEncryption()
    else:
        encrypt_algo = serialization.BestAvailableEncryption(passphrase)  # type: ignore

    if isinstance(
        key, (x448.X448PrivateKey, x25519.X25519PrivateKey, ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)
    ):
        data = key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

        base64_encoded = base64.b64encode(data).decode("utf-8")
        data = _add_armour(base64_encoded)

        with open(path, "w", encoding="utf-8") as f:
            f.write(data)

        return

    data = key.private_bytes(
        encoding=encoding_,
        format=format_,
        encryption_algorithm=encrypt_algo,
    )

    with open(path, "wb") as f:
        f.write(data)


def _generate_ec_key(algorithm: str, curve: str):
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
        curve_instance = oid_mapping.get_curve_instance(curve_name=curve)
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


def _check_starts_with(algorithm: str, prefixes: List[str]) -> bool:
    """Check if the algorithm starts with any of the specified prefixes."""
    return any(algorithm.startswith(prefix) for prefix in prefixes)


# TODO fix docstring
def generate_key(algorithm: str = "rsa", **params) -> PrivateKey:  # noqa: D417 for RF docs
    """Generate a `cryptography` key based on the specified algorithm.

    This function supports generating keys for various cryptographic algorithms including RSA, DSA, ECDSA, ECDH,
    Ed25519, and DH. Depending on the selected algorithm, additional parameters can be provided.

    Post-quantum signature algorithms are not based on hash versions alone but can be specified within the
    signing functions.

    Arguments:
    ---------
        - `algorithm`: The cryptographic algorithm to use for key generation. Defaults to "rsa".
        - `**params`: Additional parameters specific to the algorithm.

    Traditional algorithms:
    ---------------------
        - "rsa": RSA.
        - "dsa": DSA.
        - "ecdsa" or "ecdh": Elliptic Curve.
        - "ed25519": Ed25519.
        - "dh": Diffie-Hellman.
        - "bad_rsa_key": RSA with a bit size of 512.

    PQ Signature algorithms:
    ------------------------
        - "ml-dsa-44", "ml-dsa-65", "ml-dsa-87"
        - "slh-dsa" or specified version.
        - "falcon512", "falcon1024", "falcon-padded-512", "falcon-padded-1024"

    KEM algorithms:
    ---------------
        - "ml-kem-512", "ml-kem-768", "ml-kem-1024"
        - "sntrup761"
        - "mceliece-348864", "mceliece-460896", "mceliece-6688128", "mceliece-6960119"
        - "frdokem-640-aes", "frodokem-640-shake", "frodokem-976-aes",
        "frodokem-976-shake", "frodokem-1344-aes", "frodokem-1344-shake"

    Hybrid algorithms:
    ------------------
        - "xwing"
        - "composite-sig"
        - "composite-kem"
        - "composite-dhkem" (uses DHKEM: RFC9180)
        - "chempat"

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

    Additional Hybrid Parameters:
    ----------------------------
        - pq_name (str): The name of the post-quantum algorithm.
        - trad_param (str): The name of the traditional algorithm. needs to be ecdh for
        composite-kem/composite-dhkem/chempat and
        ecdsa for composite-sig.
        - pq_key (PQPrivateKey): The post-quantum private key.
        - trad_key (ECDHPrivateKey or RSA): The traditional private key.

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
    backend = backends.default_backend()

    if algorithm == "bad_rsa_key":
        from cryptography.hazmat.bindings._rust import (  # pylint: disable=import-outside-toplevel
            openssl as rust_openssl,
        )

        private_key = rust_openssl.rsa.generate_private_key(65537, 512)

    elif algorithm == "rsa":
        length = int(params.get("length", 2048))
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=length, backend=backend)

    elif algorithm == "dsa":
        length = int(params.get("length", 2048))
        private_key = dsa.generate_private_key(key_size=length, backend=backend)

    elif algorithm in {"ed25519", "ed448", "x25519", "x448", "ecdh", "ecdsa", "ecc", "ec"}:
        curve = params.get("curve", "secp256r1")
        private_key = _generate_ec_key(algorithm, curve)

    elif algorithm == "dh":
        private_key = _generate_dh_private_key(
            p=params.get("p"),
            g=params.get("g", 2),
            secret_scalar=params.get("secret_scalar"),
            length=int(params.get("length", 2048)),
        )

    else:
        from pq_logic.combined_factory import CombinedKeyFactory

        private_key = CombinedKeyFactory.generate_key(algorithm=algorithm, **params)

    return private_key


def _extract_and_format_key(pem_file_path: str) -> bytes:
    """Extract and format the private key from a PEM file, including metadata if present.

    :param pem_file_path: Path to the PEM file.
    :return: The formatted key in PEM format as bytes.
    """
    with open(pem_file_path, "r", encoding="utf-8") as file:
        pem_content = file.read()

    # Regex to match PEM header, metadata, and footer
    match = re.search(
        r"-----BEGIN (.*?) PRIVATE KEY-----\n"
        r"(Proc-Type: .*?\nDEK-Info: .*?\n\n)?"
        r"(.*?)"
        r"-----END \1 PRIVATE KEY-----",
        pem_content,
        re.DOTALL,
    )

    if match:
        key_name = match.group(1).encode("utf-8")
        metadata = match.group(2) or ""
        key_content = match.group(3).strip()

        wrapped_key_content = "\n".join(textwrap.wrap(key_content, width=64))

        pem_data = (
            b"-----BEGIN "
            + key_name
            + b" PRIVATE KEY-----\n"
            + metadata.encode("utf-8")
            + wrapped_key_content.encode("utf-8")
            + b"\n-----END "
            + key_name
            + b" PRIVATE KEY-----\n"
        )
        return pem_data
    else:
        raise ValueError("No valid private key found in the file.")


def _clean_data(data: bytes) -> bytes:
    """Remove comments and newlines from the data.

    :param data: The data to clean.
    :return: The cleaned data.
    """
    out = b""
    for line in data.split(b"\n"):
        if not line.startswith(b"#") and line:
            out += line + b"\n"
    return out


def load_private_key_from_file(  # noqa: D417 for RF docs
    filepath: str, password: Union[None, str] = "11111", key_type: Optional[str] = None
) -> PrivateKey:
    """Load a private key from a file.

    Arguments:
    ---------
        - `filepath`: The path to the file containing the PEM-encoded key.
        - `password`: The password to decrypt the key file, if it is encrypted. Defaults to "11111".
          (`x448` and `x25519` and ed versions do not support encryption.)
        - `key_type`: the type of the key, needed for x448 and x25519. (also ed-versions)
        the value "custom" is used for pq- and hybrid-keys.

    Returns:
    -------
        - An instance of the loaded key, such as `RSAPrivateKey`, `X448PrivateKey`, or `X25519PrivateKey`.

    Raises:
    ------
        - `FileNotFoundError` if the file does not exist.

    Examples:
    --------
    | ${key}= | Load Private Key From File | /path/to/key.pem | password123 |
    | ${x448_key}= | Load Private Key From File | /path/to/x448_key.pem | key_type=x448 |
    | ${x25519_key}= | Load Private Key From File | /path/to/ed25519_key.pem | key_type=ed25519 |

    """
    if key_type in ["x448", "x25519", "ed448", "ed25519"]:
        pem_data = utils.load_and_decode_pem_file(filepath)
    else:
        with open(filepath, "rb") as pem_file:
            pem_data = pem_file.read()

    if key_type == "x448":
        return x448.X448PrivateKey.from_private_bytes(data=pem_data)
    if key_type == "x25519":
        return x25519.X25519PrivateKey.from_private_bytes(data=pem_data)

    if key_type == "ed448":
        return ed448.Ed448PrivateKey.from_private_bytes(data=pem_data)
    if key_type == "ed25519":
        return ed25519.Ed25519PrivateKey.from_private_bytes(data=pem_data)

    from pq_logic.key_pyasn1_utils import CUSTOM_KEY_TYPES, parse_key_from_one_asym_key

    try:
        if b"SPDX-License-Identifier:" in pem_data:
            pem_data2 = _extract_and_format_key(filepath)
        else:
            pem_data2 = pem_data
    except ValueError:
        pem_data2 = pem_data

    is_custom = False
    for key in CUSTOM_KEY_TYPES:
        if pem_data2.startswith(b"-----BEGIN " + key + b" PRIVATE KEY-----"):
            is_custom = True
            break

    if key_type in ["custom"] or is_custom:
        # pem_data = pem_data.replace(b"\r", b"\n")
        if password is not None:
            pem_data = load_enc_key(password=password, data=pem_data2)
        return parse_key_from_one_asym_key(pem_data)

    password = password if not password else password.encode("utf-8")  # type: ignore

    pem_data = _clean_data(pem_data)
    private_key = serialization.load_pem_private_key(
        pem_data,
        password=password,  # type: ignore
    )
    return private_key


def load_public_key_from_file(filepath: str, key_type: Optional[str] = None) -> PublicKey:  # noqa: D417 for RF docs
    """Load a public key from a file.

    Load a cryptographic public key from a PEM-encoded file.

    Arguments:
    ---------
        - `filepath`: the path to the file containing the key data.
        - `key_type`: the type of the key, needed for x448 and x25519 (also ed-versions).


    Returns:
    -------
        - An instance of the loaded public key, such as `RSAPublicKey`, `X448PublicKey`, or `X25519PublicKey`.

    Raises:
    ------
        - `FileNotFoundError`: If the file does not exist.
        - `ValueError`: If the file content is not a valid public key format.

    Examples:
    --------
    | ${public_key}= | Load Public Key From File | /path/to/public_key.pem |
    | ${x448_key}= | Load Public Key From File | /path/to/x448_public_key.pem | key_type=x448 |
    | ${x25519_key}= | Load Public Key From File | /path/to/ed25519_public_key.pem | key_type=ed25519 |

    """
    if key_type in ["x448", "x25519", "ed448", "ed25519"]:
        pem_data = utils.load_and_decode_pem_file(filepath)
    else:
        with open(filepath, "rb") as pem_file:
            pem_data = pem_file.read()

    if key_type == "x448":
        return x448.X448PublicKey.from_public_bytes(data=pem_data)
    if key_type == "x25519":
        return x25519.X25519PublicKey.from_public_bytes(data=pem_data)

    if key_type == "ed448":
        return ed448.Ed448PublicKey.from_public_bytes(data=pem_data)
    if key_type == "ed25519":
        return ed25519.Ed25519PublicKey.from_public_bytes(data=pem_data)

    return serialization.load_pem_public_key(pem_data)


def load_public_key_from_spki(data: Union[bytes, rfc5280.SubjectPublicKeyInfo]) -> PublicKey:  # noqa: D417 for RF docs
    """Load a public key from a DER-encoded SubjectPublicKeyInfo structure.

    Arguments:
         - `data`: DER-encoded SubjectPublicKeyInfo structure or a pyasn1 `SubjectPublicKeyInfo` object.

    Returns:
        - The loaded public key.

    Raises:
          - `ValueError`: If the public key is incorrectly formatted, or the OID is not valid/unknown.

    Examples:
    --------
    ${public_key}= | Load Public Key From Spki| ${data} |

    """
    if isinstance(data, bytes):
        data, rest = decoder.decode(data, rfc5280.SubjectPublicKeyInfo())
        if rest != b"":
            raise ValueError("The decoded SubjectPublicKeyInfo structure had trailing data.")

    from pq_logic.combined_factory import CombinedKeyFactory

    return CombinedKeyFactory.load_public_key_from_spki(spki=data)
