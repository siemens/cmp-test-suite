# Copyright 2024 Siemens AG
# SPDX-FileCopyrightText: 2024 SPDX-FileCopyrightText:
#
# SPDX-License-Identifier: Apache-2.0

"""Utility functions for generating, saving, and loading cryptographic keys.

Designed to facilitate key management by offering simple methods to create new keys,
store them and retrieve them when needed.
"""

import os
import re
import textwrap
import warnings
from typing import List, Optional, Tuple, Union

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
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pyasn1.codec.der import decoder
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc4211, rfc5280, rfc5480, rfc5958, rfc6402, rfc6664, rfc9480
from robot.api.deco import keyword, not_keyword

from pq_logic.combined_factory import CombinedKeyFactory
from pq_logic.keys import serialize_utils
from pq_logic.keys.abstract_pq import PQSignaturePrivateKey, PQSignaturePublicKey
from pq_logic.keys.abstract_stateful_hash_sig import PQHashStatefulSigPrivateKey, PQHashStatefulSigPublicKey
from pq_logic.keys.abstract_wrapper_keys import AbstractCompositePrivateKey, HybridPublicKey
from pq_logic.keys.composite_sig03 import CompositeSig03PrivateKey, CompositeSig03PublicKey
from pq_logic.keys.composite_sig04 import CompositeSig04PrivateKey, CompositeSig04PublicKey
from pq_logic.keys.kem_keys import MLKEMPrivateKey
from pq_logic.keys.key_pyasn1_utils import load_enc_key
from pq_logic.keys.sig_keys import MLDSAPrivateKey, SLHDSAPrivateKey
from pq_logic.keys.trad_kem_keys import RSAEncapKey
from pq_logic.keys.xwing import XWingPrivateKey
from pq_logic.tmp_oids import COMPOSITE_SIG03_OID_2_NAME, COMPOSITE_SIG04_OID_2_NAME, id_rsa_kem_spki
from resources import oid_mapping, typingutils, utils
from resources.asn1utils import try_decode_pyasn1
from resources.convertutils import str_to_bytes, subject_public_key_info_from_pubkey
from resources.exceptions import BadAlg, BadAsn1Data, BadCertTemplate, BadSigAlgID, UnknownOID
from resources.oid_mapping import KEY_CLASS_MAPPING, get_curve_instance, get_hash_from_oid, may_return_oid_to_name
from resources.oidutils import (
    CMS_COMPOSITE03_NAME_2_OID,
    CURVE_OID_2_NAME,
    PQ_NAME_2_OID,
    PQ_OID_2_NAME,
    PQ_SIG_PRE_HASH_OID_2_NAME,
    TRAD_SIG_NAME_2_OID,
    TRAD_STR_OID_TO_KEY_NAME,
)
from resources.suiteenums import KeySaveType
from resources.typingutils import PrivateKey, PublicKey, SignKey, TradPrivateKey, TradSignKey, TradVerifyKey, VerifyKey


def save_key(  # noqa: D417 undocumented-params
    key: PrivateKey,
    path: str,
    password: Optional[str] = "11111",
    save_type: str = "seed",
    save_old: bool = False,
):
    """Save a private key to a file, optionally encrypting it with a passphrase.

    Arguments:
    ---------
        - `key`: The private key object to save.
        - `path`: The file path where the key will be saved.
        - `passphrase`: Optional passphrase to encrypt the key. If None, save without encryption. Defaults to "11111".
        - `save_type`: How to save the pq-key. Can be "seed", "raw" or "seed_and_raw". Defaults to "seed".
        - `save_old`: If True, save the ML-KEM or ML-DSA key as raw bytes \
        (Otherwise uses the new `Choice` structure.) Defaults to `False`.

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

    if isinstance(key, TradPrivateKey):
        data = key.private_bytes(
            encoding=encoding_,
            format=format_,
            encryption_algorithm=encrypt_algo,  # type: ignore
        )

    elif isinstance(key, (MLKEMPrivateKey, MLDSAPrivateKey, HybridPublicKey)) and save_old:
        warnings.warn(
            "'old_param=True' is deprecated and will be removed in a future version. "
            "Please update your code so that you can support the ne export for ML-KEM and ML-DSA keys."
            "Hybrid keys will be supported until the next release, of the corresponding drafts.",
            category=DeprecationWarning,
            stacklevel=2,
        )
        # Save the key as raw bytes (old format)
        data = key.private_bytes(
            encoding=encoding_,
            format=format_,
            encryption_algorithm=encrypt_algo,
        )

    else:
        data = CombinedKeyFactory.save_private_key_one_asym_key(
            private_key=key,
            save_type=save_type,
            password=password,
            version=1,
            encoding=encoding_,
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
            openssl as rust_openssl,  # type: ignore
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

            return CombinedKeyFactory.load_private_key_from_one_asym_key(data=out)

    pem_data = utils.load_and_decode_pem_file(filepath)

    try:
        # try to load the key with the password.
        if password is not None:
            password = str_to_bytes(password)  # type: ignore
        return serialization.load_der_private_key(data=pem_data, password=password)  # type: ignore
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

        return CombinedKeyFactory.load_private_key_from_one_asym_key(data=pem_data)

    if password is not None:
        password = str_to_bytes(password)  # type: ignore

    private_key = serialization.load_der_private_key(
        pem_data,
        password=password,  # type: ignore
    )
    return private_key


def load_public_key_from_file(filepath: str) -> PublicKey:  # noqa: D417 for RF docs
    """Load a public key from a file.

    Load a cryptographic public key from a PEM-encoded file.

    Arguments:
    ---------
        - `filepath`: the path to the file containing the key data.

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
    der_data = utils.load_and_decode_pem_file(filepath)

    spki, rest = try_decode_pyasn1(der_data, rfc5280.SubjectPublicKeyInfo())  # type: ignore
    spki: rfc5280.SubjectPublicKeyInfo
    if rest != b"":
        raise BadAsn1Data("SubjectPublicKeyInfo")

    return CombinedKeyFactory.load_public_key_from_spki(spki)


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


def _check_trad_sig_alg_id(public_key: TradVerifyKey, oid: str, hash_alg: Optional[str]) -> None:
    """Validate if the public key is of the same type as the algorithm identifier."""
    if isinstance(public_key, Ed448PublicKey):
        if str(TRAD_SIG_NAME_2_OID["ed448"]) == oid:
            return
    elif isinstance(public_key, Ed25519PublicKey):
        if str(TRAD_SIG_NAME_2_OID["ed25519"]) == oid:
            return

    elif isinstance(public_key, EllipticCurvePublicKey):
        if str(TRAD_SIG_NAME_2_OID[f"ecdsa-{hash_alg}"]) == oid:
            return

    elif isinstance(public_key, RSAPublicKey):
        if str(TRAD_SIG_NAME_2_OID[f"rsa-{hash_alg}"]) == oid:
            return

    else:
        raise BadAlg(f"Unknown key type to verify the alg id and the matching key: {type(public_key)}")

    raise BadSigAlgID(
        "The public key was not of the same type as the, algorithm identifier implied."
        f"Given OID: {may_return_oid_to_name(univ.ObjectIdentifier(oid))}. Key type: {type(public_key).__name__}"
    )


@not_keyword
def check_consistency_sig_alg_id_and_key(alg_id: rfc9480.AlgorithmIdentifier, key: Union[SignKey, VerifyKey]) -> None:
    """Check the consistency of the algorithm identifier and the key.

    :param alg_id: The algorithm identifier for the key.
    :param key: The key to check.
    :raises BadAlg: If the key is not of the same type as the algorithm identifier.
    """
    oid = alg_id["algorithm"]

    # Because the v4 is a subclass of the v3, we need to check the v4 first.
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
            raise BadSigAlgID("The public key was not of the same type as the,algorithm identifier implied.")

        return

    try:
        hash_alg = get_hash_from_oid(alg_id["algorithm"], only_hash=True)
    except ValueError as e:
        raise BadSigAlgID("The algorithm identifier was not valid, and does not match the key.") from e

    if isinstance(key, (PQSignaturePublicKey, PQSignaturePrivateKey)):
        _alg = "" if hash_alg is None else "-" + hash_alg
        _name = key.name + _alg

        if _name not in PQ_NAME_2_OID:
            raise BadSigAlgID(
                "The public key was not of the same type as the, algorithm identifier implied.",
                error_details=[
                    f"OID: {oid}. The Public Key was of type: {type(key).__name__}. "
                    f"OID-Lookup: {may_return_oid_to_name(oid)}"
                ],
            )

        if str(PQ_NAME_2_OID[_name]) != str(oid):
            raise BadSigAlgID("The public key was not of the same type as the,algorithm identifier implied.")

    elif isinstance(key, (PQHashStatefulSigPrivateKey, PQHashStatefulSigPublicKey)):
        if key.get_oid() != oid:
            raise BadSigAlgID(
                "The public key was not of the same type as the, algorithm identifier implied.",
                error_details=[
                    f"OID: {oid}. The Public Key was of type: {type(key).__name__}. "
                    f"OID-Lookup: {may_return_oid_to_name(oid)}"
                ],
            )

    elif isinstance(key, (TradSignKey, TradVerifyKey)):
        if isinstance(key, TradSignKey):
            key = key.public_key()

        try:
            _check_trad_sig_alg_id(key, str(oid), hash_alg=hash_alg)  # type: ignore
        except KeyError as e:
            raise BadSigAlgID(
                "The public key was not of the same type as the, algorithm identifier implied.",
                error_details=[
                    f"{e}",
                    f"OID: {oid}. The Public Key was of type: {type(key).__name__}. "
                    f"OID-Lookup: {may_return_oid_to_name(oid)}",
                ],
            ) from e

    else:
        raise ValueError(
            "Unknown key type to verify the alg id and the matching key."
            f"Given OID: {may_return_oid_to_name(univ.ObjectIdentifier(oid))}. "
            f"Key type: {type(key).__name__}"
        )


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


def generate_different_public_key(  # noqa D417 undocumented-param
    key_source: Union[rfc9480.CMPCertificate, rfc6402.CertificationRequest, PrivateKey, PublicKey],
    algorithm: Optional[str] = None,
) -> typingutils.PublicKey:
    """Generate a new public key using the specified algorithm, ensuring it differs from the certificate's public key.

    Used to ensure the revocation request sends a different public key but for the same type.

    Arguments:
    ---------
        - `key_source`: The certificate from which to extract the existing public key or a key object.
        - `algorithm`: The algorithm to use for generating the new key pair (e.g., `"rsa"`, `"ec"`).

    Raises:
    ------
        - `ValueError`: If the function fails to generate a different public key after 100 attempts.

    Returns:
    -------
        - The generated public key, guaranteed to be different from the public key in `cert`.

    Examples:
    --------
    | ${new_public_key}= | Generate Different Public Key | cert=${certificate} | algorithm="rsa" |
    | ${new_public_key}= | Generate Different Public Key | cert=${certificate} | algorithm="ec" |

    """
    if isinstance(key_source, rfc9480.CMPCertificate):
        spki = key_source["tbsCertificate"]["subjectPublicKeyInfo"]
        public_key = load_public_key_from_spki(spki)

    elif isinstance(key_source, rfc6402.CertificationRequest):
        spki = key_source["certificationRequestInfo"]["subjectPublicKeyInfo"]
        public_key = load_public_key_from_spki(spki)

    elif isinstance(key_source, PrivateKey):
        public_key = key_source.public_key()
    else:
        public_key = key_source

    length = None
    curve_name = None
    if isinstance(public_key, RSAEncapKey):
        length = public_key._public_key.key_size  # type: ignore
    elif isinstance(public_key, RSAPublicKey):
        length = public_key.key_size
    elif isinstance(public_key, EllipticCurvePublicKey):
        curve_name = public_key.curve.name

    # just to reduce the extremely slim chance, they are actually the same.
    pub_key = None
    key_name = get_key_name(public_key)
    for _ in range(100):
        if algorithm is not None:
            pub_key = generate_key(algorithm=algorithm, length=length, curve=curve_name).public_key()
        else:
            pub_key = generate_key(algorithm=key_name, by_name=True).public_key()
        if pub_key != public_key:
            break
        pub_key = None

    if pub_key is None:
        raise ValueError("Failed to generate a different public key.")

    return pub_key


def _get_version_and_tmp_version(version: Union[int, str]) -> Tuple[int, int]:
    """Get the version and temporary version for the `OneAsymmetricKey` structure.

    :param version: The version of the structure. Can be an integer or a string.
    :return: A tuple containing the version and temporary version.
    :raises ValueError: If the string version is not valid.
    """
    if isinstance(version, int):
        tmp_version = 1 if version >= 1 else 0
    elif isinstance(version, str) and not version.isdigit():
        if version not in ["v1", "v2"]:
            raise ValueError("Invalid version only supports 'v1', 'v2'")
        version = 1 if version == "v2" else 0
        tmp_version = version
    else:
        version = int(version)
        tmp_version = 1 if version >= 1 else 0

    return version, tmp_version


def _prepare_one_asym_key(
    private_key_bytes: bytes,
    public_key_bytes: Optional[bytes],
    version: int,
    alg_id: rfc5280.AlgorithmIdentifier,
) -> rfc5958.OneAsymmetricKey:
    """Parse the `OneAsymmetricKey` structure from the given bytes.

    :param private_key_bytes: The private key bytes.
    :param public_key_bytes: The public key bytes, if available.
    :param version: The version of the structure.
    :param alg_id: The algorithm identifier.
    :return: The parsed `OneAsymmetricKey` structure.
    """
    one_asym_key = rfc5958.OneAsymmetricKey()
    one_asym_key["version"] = univ.Integer(version)
    one_asym_key["privateKeyAlgorithm"] = alg_id
    one_asym_key["privateKey"] = univ.OctetString(private_key_bytes)
    if public_key_bytes is not None:
        public_key_bit_str = (
            rfc5958.PublicKey()
            .fromOctetString(public_key_bytes)
            .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
        )
        one_asym_key["publicKey"] = public_key_bit_str
    return one_asym_key


@keyword(name="Prepare OneAsymmetricKey")
def prepare_one_asymmetric_key(  # noqa: D417 undocumented-params
    private_key: PrivateKey,
    public_key: Optional[PublicKey] = None,
    version: Union[int, str] = "v2",
    key_save_type: Union[str, KeySaveType] = "seed",
    invalid_priv_key_size: bool = False,
    invalid_pub_key_size: bool = False,
    mis_matching_key: bool = False,
    invalid_private_key: bool = False,
    include_public_key: Optional[bool] = None,
) -> rfc5958.OneAsymmetricKey:
    """Create a `OneAsymmetricKey` structure for a private key.

    Wraps a private key into the `OneAsymmetricKey` structure,
    including the algorithm identifier and the public key. It's used when
    preparing an `AsymmetricKeyPackage`.

    Arguments:
    ---------
        - `private_key`: The private key to wrap.
        - `version`: The version of the structure. Defaults to "v2".
        - `key_save_type`: The type of key to save. Can be "seed", "raw", or "seed_and_raw". Defaults to "raw".
        - `invalid_private_key`: If True, the private key is invalid. Only supported for RSA, ECC,
        ML-DSA and ML-KEM keys. Defaults to `False`.
        - `invalid_pub_key_size`: If True, the public key size is invalid. Defaults to `False`.
        - `mis_matching_key`: If True, the public key does not match the private key. Defaults to `False`.
        - `invalid_priv_key_size`: If True, the private key size is invalid. Defaults to `False`.
        - `include_public_key`: If True, the public key is included in the structure. If `None`, \
        it is set to `False` for version 0. Defaults to `None`.

    Returns:
    -------
        - The populated `OneAsymmetricKey` structure.

    Raises:
    ------
        - `ValueError`: If the private key is not of a supported type or if the version is invalid.
        - `ValueError`: If the key_save_type is invalid.
        - `ValueError`: If the string version is not supported.
        - `ValueError`: If the private key is invalid and the invalid_priv_key option is set.

    Examples:
    --------
    | ${one_asym_key}= | Prepare OneAsymmetricKey | ${private_key} | "v2" |
    | ${one_asym_key}= | Prepare OneAsymmetricKey | ${private_key} | key_save_type="seed" |

    """
    if (
        not isinstance(private_key, (RSAPrivateKey, EllipticCurvePrivateKey, MLDSAPrivateKey, MLKEMPrivateKey))
        and invalid_private_key
    ):
        raise ValueError(
            "The invalid private key option is only supported for `RSA`, `ECC`, `ML-DSA` and `ML-KEM` keys."
        )

    if mis_matching_key:
        public_key = generate_different_public_key(key_source=private_key)

    version, tmp_version = _get_version_and_tmp_version(version)

    if include_public_key is None:
        if version in ["v1", 0]:
            include_public_key = False

    der_data = CombinedKeyFactory.save_private_key_one_asym_key(
        private_key=private_key,
        public_key=public_key,
        save_type=key_save_type,
        version=tmp_version,
        include_public_key=include_public_key,
        invalid_private_key=invalid_private_key,
        password=None,
        unsafe=True,
    )
    one_asym_key, _ = decoder.decode(der_data, asn1Spec=rfc5958.OneAsymmetricKey())

    public_key_bytes = None if not one_asym_key["publicKey"].isValue else one_asym_key["publicKey"].asOctets()
    private_key_bytes = one_asym_key["privateKey"].asOctets()

    if invalid_priv_key_size:
        private_key_bytes = private_key_bytes + os.urandom(16)

    if invalid_pub_key_size:
        public_key_bytes = b"" if public_key_bytes is None else public_key_bytes
        public_key_bytes = public_key_bytes + os.urandom(16)

    return _prepare_one_asym_key(
        private_key_bytes=private_key_bytes,
        public_key_bytes=public_key_bytes,
        version=version,
        alg_id=one_asym_key["privateKeyAlgorithm"],
    )


@keyword(name="Prepare SubjectPublicKeyInfo")
def prepare_subject_public_key_info(  # noqa D417 undocumented-param
    key: Optional[Union[PrivateKey, PublicKey]] = None,
    for_kga: bool = False,
    key_name: Optional[str] = None,
    use_rsa_pss: bool = False,
    use_pre_hash: bool = False,
    hash_alg: Optional[str] = None,
    invalid_key_size: bool = False,
    add_params_rand_bytes: bool = False,
    add_null: bool = False,
) -> rfc5280.SubjectPublicKeyInfo:
    """Prepare a `SubjectPublicKeyInfo` structure for a `Certificate`, `CSR` or `CertTemplate`.

    For invalid Composite keys must the private key be provided.

    Note: If the key is a CompositeSig key, the `key_name` the private key must be provided,
    if the RSA key has an invalid key size.

    Arguments:
    ---------
        - `key`: The public or private key to use for the `SubjectPublicKeyInfo`.
        - `for_kga`: A flag indicating whether the key is for a key generation authority (KGA).
        - `key_name`: The key algorithm name to use for the `SubjectPublicKeyInfo`.
        (can be set to `rsa_kem`. RFC9690). Defaults to `None`.
        - `use_rsa_pss`: Whether to use RSA-PSS padding. Defaults to `False`.
        - `use_pre_hash`: Whether to use the pre-hash version for a composite-sig key. Defaults to `False`.
        - `hash_alg`: The pre-hash algorithm to use for the pq signature key. Defaults to `None`.
        - `invalid_key_size`: A flag indicating whether the key size is invalid. Defaults to `False`.
        - `add_params_rand_bytes`: A flag indicating whether to add random bytes to the key parameters. \
        Defaults to `False`.
        - `add_null`: A flag indicating whether to add a null value to the key parameters. Defaults to `False`.

    Returns:
    -------
        - The populated `SubjectPublicKeyInfo` structure.

    Raises:
    ------
        - `ValueError`: If no key is provided and the for_kga flag is not set.
        - `ValueError`: If both `add_null` and `add_params_rand_bytes` are set.


    Examples:
    --------
    | ${spki}= | Prepare SubjectPublicKeyInfo | key=${key} | use_rsa_pss=True |
    | ${spki}= | Prepare SubjectPublicKeyInfo | key=${key} | key_name=rsa-kem |
    | ${spki}= | Prepare SubjectPublicKeyInfo | key=${key} | for_kga=True |
    | ${spki}= | Prepare SubjectPublicKeyInfo | key=${key} | add_null=True |

    """
    if key is None and not for_kga:
        raise ValueError("Either a key has to be provided or the for_kga flag have to be set.")

    if add_null and add_params_rand_bytes:
        raise ValueError("Either `add_null` or `add_params_rand_bytes` can be set, not both.")

    if isinstance(key, AbstractCompositePrivateKey):
        pub_key = key.public_key().public_bytes(encoding=Encoding.DER, format=PublicFormat.Raw)
        spki = rfc5280.SubjectPublicKeyInfo()
        pub_key = pub_key if not invalid_key_size else pub_key + b"\x00"
        spki["subjectPublicKey"] = univ.BitString.fromOctetString(pub_key)
        if isinstance(key, CompositeSig03PrivateKey):
            oid = key.get_oid(use_pss=use_rsa_pss, pre_hash=use_pre_hash)
        else:
            oid = key.get_oid()
        spki["algorithm"]["algorithm"] = oid

        if add_null:
            spki["algorithm"]["parameters"] = univ.Null("")

        if add_params_rand_bytes:
            spki["algorithm"]["parameters"] = univ.BitString.fromOctetString(os.urandom(16))

        return spki

    if isinstance(key, PrivateKey):
        key = key.public_key()

    if for_kga:
        return _prepare_spki_for_kga(
            key=key,
            key_name=key_name,
            use_pss=use_rsa_pss,
            use_pre_hash=use_pre_hash,
            add_null=add_null,
            add_params_rand_bytes=add_params_rand_bytes,
        )

    if key_name in ["rsa-kem", "rsa_kem"]:
        key = RSAEncapKey(key)  # type: ignore

    spki = subject_public_key_info_from_pubkey(
        public_key=key,  # type: ignore
        use_rsa_pss=use_rsa_pss,
        use_pre_hash=use_pre_hash,
        hash_alg=hash_alg,
    )

    if invalid_key_size:
        tmp = spki["subjectPublicKey"].asOctets() + b"\x00\x00"
        spki["subjectPublicKey"] = univ.BitString.fromOctetString(tmp)

    if add_params_rand_bytes:
        spki["algorithm"]["parameters"] = univ.BitString.fromOctetString(os.urandom(16))

    return spki


def _prepare_spki_for_kga(
    key: Optional[Union[PrivateKey, PublicKey]] = None,
    key_name: Optional[str] = None,
    use_pss: bool = False,
    use_pre_hash: bool = False,
    add_null: bool = False,
    *,
    add_params_rand_bytes: bool = False,
) -> rfc5280.SubjectPublicKeyInfo:
    """Prepare a SubjectPublicKeyInfo for KGA usage.

    :param key: A private or public key.
    :param key_name: An optional key algorithm name.
    :param use_pss: Whether to use PSS padding for RSA and a RSA-CompositeKey.
    :param use_pre_hash: Whether to use the pre-hash version for a composite-sig key. Defaults to `False`.
    :param add_null: Whether to add a null value to the key parameters. Defaults to `False`.
    :param add_params_rand_bytes: Whether to add random bytes to the key parameters. Defaults to `False`.
    :return: The populated `SubjectPublicKeyInfo` structure.
    """
    if add_null and add_params_rand_bytes:
        raise ValueError("Either `add_null` or `add_params_rand_bytes` can be set, not both.")

    spki = rfc5280.SubjectPublicKeyInfo()
    spki["subjectPublicKey"] = univ.BitString("")

    if key is not None:
        if isinstance(key, typingutils.PrivateKey):
            key = key.public_key()

    if key_name and key_name in ["rsa", "dsa", "ecc", "rsa-kem"]:
        names_2_oid = {
            "rsa": univ.ObjectIdentifier("1.2.840.113549.1.1.1"),
            "dsa": univ.ObjectIdentifier("1.2.840.10040.4.1"),
            "ecc": univ.ObjectIdentifier("1.2.840.10045.3.1.7"),
            "rsa-kem": id_rsa_kem_spki,
        }
        spki["algorithm"]["algorithm"] = names_2_oid[key_name]
        if key_name == "ecc":
            spki["algorithm"]["parameters"] = rfc5480.ECParameters()
            spki["algorithm"]["parameters"]["namedCurve"] = rfc5480.secp256r1

    if key_name is not None:
        key = generate_key(key_name).public_key()
        spki_tmp = subject_public_key_info_from_pubkey(public_key=key, use_rsa_pss=use_pss, use_pre_hash=use_pre_hash)
        spki["algorithm"]["algorithm"] = spki_tmp["algorithm"]["algorithm"]

    elif key is not None:
        spki_tmp = subject_public_key_info_from_pubkey(public_key=key, use_rsa_pss=use_pss)
        spki["algorithm"]["algorithm"] = spki_tmp["algorithm"]["algorithm"]

    if add_null:
        spki["algorithm"]["parameters"] = univ.Null("")

    if add_params_rand_bytes:
        spki["algorithm"]["parameters"] = univ.BitString.fromOctetString(os.urandom(16))

    return spki
