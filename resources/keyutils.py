# Copyright 2024 Siemens AG
# SPDX-FileCopyrightText: 2024 SPDX-FileCopyrightText:
#
# SPDX-License-Identifier: Apache-2.0

"""Utility functions for generating, saving, and loading cryptographic keys.

Designed to facilitate key management by offering simple methods to create new keys,
store them and retrieve them when needed.
"""

import re
import textwrap
from typing import List, Optional, Union

import pyasn1.error
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
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from pq_logic.combined_factory import CombinedKeyFactory
from pq_logic.keys import serialize_utils
from pq_logic.keys.abstract_pq import PQSignaturePrivateKey, PQSignaturePublicKey
from pq_logic.keys.composite_sig03 import CompositeSig03PrivateKey, CompositeSig03PublicKey
from pq_logic.keys.composite_sig04 import CompositeSig04PrivateKey, CompositeSig04PublicKey
from pq_logic.keys.kem_keys import MLKEMPrivateKey
from pq_logic.keys.key_pyasn1_utils import load_enc_key
from pq_logic.keys.sig_keys import MLDSAPrivateKey, SLHDSAPrivateKey
from pq_logic.keys.xwing import XWingPrivateKey
from pq_logic.tmp_oids import COMPOSITE_SIG03_OID_2_NAME, COMPOSITE_SIG04_OID_2_NAME
from pyasn1.codec.der import decoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc4211, rfc5280, rfc5480, rfc6664, rfc9480
from robot.api.deco import keyword, not_keyword

from resources import oid_mapping, utils
from resources.convertutils import str_to_bytes
from resources.exceptions import BadAlg, BadAsn1Data, BadCertTemplate, UnknownOID
from resources.oid_mapping import KEY_CLASS_MAPPING, get_curve_instance, get_hash_from_oid, may_return_oid_to_name
from resources.oidutils import (
    CMS_COMPOSITE03_NAME_2_OID,
    CURVE_OID_2_NAME,
    MSG_SIG_ALG_NAME_2_OID,
    PQ_NAME_2_OID,
    PQ_OID_2_NAME,
    PQ_SIG_PRE_HASH_OID_2_NAME,
    TRAD_STR_OID_TO_KEY_NAME,
)
from resources.typingutils import PrivateKey, PublicKey, SignKey, VerifyKey


def save_key(key: PrivateKey, path: str, password: Union[None, str] = "11111"):  # noqa: D417 for RF docs
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
    passphrase = password.encode("utf-8") if password else None
    encrypt_algo = serialization.NoEncryption()

    if passphrase is not None:
        encrypt_algo = serialization.BestAvailableEncryption(passphrase)

    data = key.private_bytes(
        encoding=encoding_,
        format=format_,
        encryption_algorithm=encrypt_algo,  # type: ignore
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


def generate_key(algorithm: str = "rsa", **params) -> PrivateKey:  # noqa: D417 for RF docs
    """Generate a `cryptography` key based on the specified algorithm.

    This function supports generating keys for various cryptographic algorithms including RSA, DSA, ECDSA, ECDH,
    Ed25519, and DH. Depending on the selected algorithm, additional parameters can be provided.

    Post-quantum signature algorithms are not based on hash versions alone but can be specified within the
    signing functions.

    Arguments:
    ---------
        - `algorithm`: The cryptographic algorithm to use for key generation. Defaults to "rsa".
        - `by_name`: If True, the key is generated based on the algorithm name. Defaults to `False`.
        (e.g., "rsa" -> RSAPrivateKey) The parameters are ignored in this case.
        - `**params`: Additional parameters specific to the algorithm.

    Traditional algorithms:
    ---------------------
        - "rsa": RSA.
        - "dsa": DSA.
        - "ecdsa" or "ecdh": Elliptic Curve.
        - "ed25519": Ed25519.
        - "dh": Diffie-Hellman.
        - "bad_rsa_key": RSA with a bit size of 512.
        - "rsa-kem": RSA-KEM RFC9690 (either by directly using the algorithm name or with trad_key=${key}).

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
        - "composite-sig" (v3)
        - "composite-sig-04"
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
        - trad_param (str): The name of the traditional algorithm. needs to be `ecdh` for
        composite-kem/composite-dhkem/chempat and
        `ecdsa` for composite-sig.
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

    if params.get("seed") is not None:
        return CombinedKeyFactory.generate_key_from_seed(
            algorithm,
            seed=params.get("seed"),  # type: ignore
            curve=params.get("curve"),
        )  # type: ignore

    if algorithm == "bad_rsa_key":
        from cryptography.hazmat.bindings._rust import (  # pylint: disable=import-outside-toplevel
            openssl as rust_openssl, #type: ignore
        )

        private_key = rust_openssl.rsa.generate_private_key(65537, 512)  # type: ignore

    elif algorithm == "rsa":
        length = int(params.get("length", 2048))
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=length)

    elif algorithm == "dsa":
        length = int(params.get("length", 2048))
        private_key = dsa.generate_private_key(key_size=length)

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


def _extract_pem_private_key_block(data: bytes) -> bytes:
    """Extract the full PEM block (BEGIN ... PRIVATE KEY ... END) from raw byte data.

    :param data: The bytes content that may contain one or more PEM blocks.
    :return: The matched PEM block, or an empty bytes object if not found.
    """
    pem_pattern = re.compile(
        rb"-----BEGIN ([A-Za-z0-9-]+) PRIVATE KEY-----"
        rb".*?"
        rb"-----END \1 PRIVATE KEY-----",
        re.DOTALL,
    )

    match = pem_pattern.search(data)
    if match:
        return match.group(0)

    return b""


def load_private_key_from_file(  # noqa: D417 for RF docs
        filepath: str,
        password: Optional[str] = "11111",
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
    | ${x448_key}= | Load Private Key From File | /path/to/x448_key.pem |
    | ${x25519_key}= | Load Private Key From File | /path/to/ed25519_key.pem |

    """
    with open(filepath, "rb") as key_file:
        data = key_file.read()

    out = _extract_pem_private_key_block(data)
    from pq_logic.keys.key_pyasn1_utils import CUSTOM_KEY_TYPES

    if out != b"":
        is_custom = any((b"-----BEGIN " + key + b" PRIVATE KEY-----") in out for key in CUSTOM_KEY_TYPES)
        if is_custom:
            if password is not None:
                out = load_enc_key(password=password, data=out)
            else:
                out = utils.decode_pem_string(out)

            return CombinedKeyFactory.load_key_from_one_asym_key(data=out)

    pem_data = utils.load_and_decode_pem_file(filepath)

    try:
        # try to load the key with the password.
        _pem_data = _clean_data(pem_data)
        if password is not None:
            password = str_to_bytes(password)  # type: ignore
        return serialization.load_der_private_key(data=_pem_data, password=password)  # type: ignore
    except ValueError:
        pass

    try:
        if b"SPDX-License-Identifier:" in pem_data:
            pem_data2 = _extract_and_format_key(filepath)
        else:
            pem_data2 = pem_data
    except ValueError:
        pem_data2 = pem_data

    is_custom = any((b"-----BEGIN " + key + b" PRIVATE KEY-----") in pem_data2 for key in CUSTOM_KEY_TYPES)
    print("is_custom:", is_custom)
    if is_custom:
        pem_data = pem_data.replace(b"\r", b"\n")
        if password is not None:
            pem_data = load_enc_key(password=password, data=pem_data2)

        return CombinedKeyFactory.load_key_from_one_asym_key(data=pem_data)

    if password is not None:
        password = str_to_bytes(password)  # type: ignore

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
    ---------
         - `data`: DER-encoded SubjectPublicKeyInfo structure or a pyasn1 `SubjectPublicKeyInfo` object.

    Returns:
    -------
        - The loaded public key.

    Raises:
    ------
          - `BadAsn1Data`: If the provided data is not a valid DER-encoded SubjectPublicKeyInfo structure.
          - `BadAlg`: If the public key is incorrectly formatted, or the OID is not valid/unknown.

    Examples:
    --------
    ${public_key}= | Load Public Key From Spki| ${data} |

    """
    if isinstance(data, bytes):
        try:
            data, rest = decoder.decode(data, rfc5280.SubjectPublicKeyInfo())
        except pyasn1.error.PyAsn1Error as e:
            raise BadAsn1Data("The SubjectPublicKeyInfo structure was not valid.", overwrite=True) from e
        if rest != b"":
            raise BadAsn1Data("SubjectPublicKeyInfo")

    return CombinedKeyFactory.load_public_key_from_spki(spki=data)


@not_keyword
def generate_key_based_on_alg_id(alg_id: rfc5280.AlgorithmIdentifier) -> PrivateKey:
    """Generate a private key based on the provided algorithm identifier.

    :param alg_id: The algorithm identifier.
    :return: The generated private key.
    :raises ValueError: If the algorithm is not supported.
    :raises UnknownOID: If the OID is unknown.
    :raises BadAsn1Data: If the provided ASN.1 data is invalid.
    :raises NotImplementedError: Hybrid keys are not supported yet.
    """
    oid = alg_id["algorithm"]
    if oid in PQ_OID_2_NAME or str(oid) in PQ_OID_2_NAME:
        for tmp_oid, name in PQ_OID_2_NAME.items():
            if str(oid) == str(tmp_oid):
                if oid in PQ_SIG_PRE_HASH_OID_2_NAME:
                    tmp = PQ_SIG_PRE_HASH_OID_2_NAME[oid].split("-")
                    name = "-".join(tmp[:-1])
                return CombinedKeyFactory.generate_key(algorithm=name)

    elif oid == rfc6664.id_ecPublicKey:
        curve_oid, rest = decoder.decode(alg_id["parameters"], asn1Spec=rfc5480.ECParameters())
        if rest != b"":
            raise BadAsn1Data("ECParameters")
        curve_oid = curve_oid["namedCurve"]
        curve_name = CURVE_OID_2_NAME.get(curve_oid)
        if curve_name is None:
            raise ValueError(f"Unsupported curve OID: {curve_oid}")
        curve_instance = get_curve_instance(curve_name)
        return ec.generate_private_key(curve=curve_instance)

    elif str(oid) in TRAD_STR_OID_TO_KEY_NAME:
        return CombinedKeyFactory.generate_key(algorithm=TRAD_STR_OID_TO_KEY_NAME[str(oid)])

    elif oid in CMS_COMPOSITE03_NAME_2_OID:
        raise NotImplementedError("Composite keys are not supported yet.")

    raise UnknownOID(oid=oid, extra_info="For generating a private key.")


@keyword(name="Get PublicKey From CertTemplate")
def load_public_key_from_cert_template(  # noqa: D417 undocumented param
        cert_template: rfc4211.CertTemplate, must_be_present: bool = True
) -> Optional[PublicKey]:
    """Extract and load the public key inside a `CertTemplate`structure.

    Arguments:
    ---------
        - `cert_template`: The `CertTemplate`structure to extract the key from.
        - `must_be_present`: Whether the public key must be present. Defaults to `True`.

    Returns:
    -------
        - The loaded public key.

    Raises:
    ------
       - `BadCertTemplate`: If the `CertTemplate`structure is invalid.

    Examples:
    --------
    | ${pub_key}= | Get PublicKey From CertTemplate | ${cert_template} |
    | ${pub_key}= | Get PublicKey From CertTemplate | ${cert_template} | False

    """
    if not cert_template["publicKey"].isValue and must_be_present:
        raise BadCertTemplate("The expected public key was not inside the certificate template.")
    if not cert_template["publicKey"].isValue:
        return None

    if cert_template["publicKey"]["subjectPublicKey"].asOctets() == b"" and must_be_present:
        raise BadCertTemplate(
            "The public key was for a KGA request. The public key can not be loaded from the `CertTemplate`."
        )

    if cert_template["publicKey"]["subjectPublicKey"].asOctets() == b"":
        return None

    spki = cert_template["publicKey"]
    old_spki = rfc5280.SubjectPublicKeyInfo()
    old_spki["algorithm"] = spki["algorithm"]
    old_spki["subjectPublicKey"] = spki["subjectPublicKey"]
    try:
        return load_public_key_from_spki(old_spki)
    except (BadAlg, ValueError) as e:
        raise BadCertTemplate(f"Error loading public key from CertTemplate: {e}") from e


def get_key_name(key: Union[PrivateKey, PublicKey]) -> str:  # noqa: D417 undocumented param
    """Retrieve the name of the key's class.

    Arguments:
    ---------
        - `key`: The key instance.

    Returns:
    -------
        - The name of the key class.

    Examples:
    --------
    | ${key_name}= | Get Key Name | ${key} |

    """
    if hasattr(key, "name"):
        return key.name  # type: ignore
    return KEY_CLASS_MAPPING[key.__class__.__name__]


def _check_trad_alg_id(public_key, oid: str, hash_alg: Optional[str]) -> None:
    """Validate if the public key is of the same type as the algorithm identifier."""
    if isinstance(public_key, Ed448PublicKey):
        if str(MSG_SIG_ALG_NAME_2_OID["ed448"]) == oid:
            return
    elif isinstance(public_key, Ed25519PublicKey):
        if str(MSG_SIG_ALG_NAME_2_OID["ed25519"]) == oid:
            return

    elif isinstance(public_key, EllipticCurvePublicKey):
        if str(MSG_SIG_ALG_NAME_2_OID[f"ecdsa-{hash_alg}"]) == oid:
            return

    elif isinstance(public_key, RSAPublicKey):
        if str(MSG_SIG_ALG_NAME_2_OID[f"rsa-{hash_alg}"]) == oid:
            return

    else:
        raise BadAlg(f"Unknown key type to verify the alg id and the matching key: {type(public_key)}")

    raise BadAlg(
        "The public key was not of the same type as the, algorithm identifier implied."
        f"Given OID: {may_return_oid_to_name(univ.ObjectIdentifier(oid))}. Key type: {type(public_key).__name__}"
    )


def check_consistency_alg_id_and_key(alg_id: rfc9480.AlgorithmIdentifier, key: Union[SignKey, VerifyKey]) -> None:
    """Check the consistency of the algorithm identifier and the key.

    :param alg_id: The algorithm identifier for the key.
    :param key: The key to check.
    :raises BadAlg: If the key is not of the same type as the algorithm identifier.
    """
    oid = alg_id["algorithm"]

    result1 = isinstance(key, (CompositeSig04PublicKey, CompositeSig04PrivateKey))
    result2 = isinstance(key, (CompositeSig03PublicKey, CompositeSig03PrivateKey))

    if (result1 and oid in COMPOSITE_SIG04_OID_2_NAME) or (result2 and oid in COMPOSITE_SIG03_OID_2_NAME):
        if result1:
            name = COMPOSITE_SIG04_OID_2_NAME[oid]
        else:
            name = COMPOSITE_SIG03_OID_2_NAME[oid]

        use_pss = name.endswith("-pss")
        pre_hash = "hash-" in name

        if str(key.get_oid(use_pss=use_pss, pre_hash=pre_hash)) != str(oid):  # type: ignore
            raise BadAlg("The public key was not of the same type as the,algorithm identifier implied.")

        return

    hash_alg = get_hash_from_oid(alg_id["algorithm"], only_hash=True)

    if isinstance(key, (PQSignaturePublicKey, PQSignaturePrivateKey)):
        _alg = "" if hash_alg is None else "-" + hash_alg
        _name = key.name + _alg
        if str(PQ_NAME_2_OID[_name]) != str(oid):
            raise BadAlg("The public key was not of the same type as the,algorithm identifier implied.")
    else:
        _check_trad_alg_id(key, str(oid), hash_alg=hash_alg)


@not_keyword
def private_key_to_private_numbers(private_key: PrivateKey) -> bytes:
    """Return the seed or private value of the private key, to be used for key generation.

    :param private_key: The private key to extract the parameters from.
    :return: The `KeyGenParameters` structure with the extracted parameters.
    """
    if isinstance(private_key, (MLKEMPrivateKey, MLDSAPrivateKey, SLHDSAPrivateKey, XWingPrivateKey)):
        data = private_key.private_numbers()

    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        private_nums = private_key.private_numbers()
        data = private_nums.private_value.to_bytes((private_nums.private_value.bit_length() + 7) // 8, "big")

    elif isinstance(
            private_key,
            (
                    x25519.X25519PrivateKey,
                    ed25519.Ed25519PrivateKey,
                    x448.X448PrivateKey,
                    ed448.Ed448PrivateKey,
            ),
    ):
        data = private_key.private_bytes_raw()

    elif isinstance(private_key, rsa.RSAPrivateKey):
        data = serialize_utils.prepare_rsa_private_key(private_key)

    else:
        raise ValueError(f"Unsupported private key type: {private_key}. Cannot extract key generation parameters.")

    return data
