"""Provides utility functions for generating, saving, and loading cryptographic keys.
It is designed to facilitate key management by offering simple methods to create new keys,
store them and retrieve them when needed.

"""
from typing import Optional

from cryptography.hazmat import backends
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed25519,
    ed448,
    dsa,
    x25519,
    x448,
    dh,
    rsa,
)

from oid_mapping import get_curve_instance
from typingutils import PrivateKey, PublicKey


def save_key(key: PrivateKey, path, passphrase: Optional[str] = "11111"):
    """Save a `cryptographic` `PrivateKey` object to a file.

    Saves a private key to a specified file path. The key can be encrypted with a passphrase
    or saved without encryption.

    Args:
        key (cryptography.hazmat.primitives.asymmetric): The private key object to save.
        path (str): The file path where the key will be saved.
        passphrase (Optional[str]): An optional passphrase used to encrypt the key. If set to None,
                                    the key will be saved without encryption. Defaults to "11111".

    Key Types and Formats:
        - `DHPrivateKey`: Serialized in PKCS8 format.
        - `X448PrivateKey` and `X25519PrivateKey`: Serialized in Raw format (cannot be encrypted).
        - Other key types: Serialized in Traditional OpenSSL format (PEM encoding).

    Raises:
        TypeError: If the provided key is not a valid private key object.

    Example:
        | Save Key | ${key} | /path/to/save/key.pem | password123 |

    """
    encoding_ = serialization.Encoding.PEM
    format_ = serialization.PrivateFormat.TraditionalOpenSSL
    passphrase = passphrase.encode("utf-8") if passphrase else None

    if passphrase is None:
        encrypt_algo = serialization.NoEncryption()
    else:
        encrypt_algo = serialization.BestAvailableEncryption(passphrase)

    if isinstance(key, dh.DHPrivateKey):
        # DH only supports PKCS8 serialization
        format_ = serialization.PrivateFormat.PKCS8

    elif isinstance(key, (x448.X448PrivateKey, x25519.X25519PrivateKey)):
        encoding_ = serialization.Encoding.Raw
        format_ = serialization.PrivateFormat.Raw
        encrypt_algo = serialization.NoEncryption()

    with open(path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=encoding_,
                format=format_,
                encryption_algorithm=encrypt_algo,
            )
        )



def generate_key(algorithm="rsa", **params) -> PrivateKey:
    """
    Generates a cryptographic key based on the specified algorithm.

    This function supports generating keys for various cryptographic algorithms including RSA, DSA, ECDSA, ECDH, Ed25519, DH, and AES.
    Depending on the selected algorithm, additional parameters can be provided to customize the key generation.

    Arguments:
    - algorithm (str): The cryptographic algorithm to use for key generation.
      Supported values include:
        - "rsa": RSA key pair generation (default).
        - "dsa": DSA key pair generation.
        - "ecdsa" or "ecdh": Elliptic Curve key pair generation.
        - "ed25519": Ed25519 key pair generation.
        - "dh": Diffie-Hellman key pair generation.
    - **params: Additional parameters specific to the algorithm.
        - For "rsa" and "dsa":
            - length (int , str): The length of the key to generate, in bits. Default is 2048.
        - For "ecdsa" or "ecdh":
            - curve (str): An elliptic curve instance from `cryptography.hazmat.primitives.asymmetric.ec`. Default is `secp256r1`.
        - For "dh":
            - g (int): The generator for DH key generation. Default is 2.
            - secret_scalar (int): the private key value for DH key generation. If not provided, one is generated.
            - length (int , str): The length of the modulus to generate if `p` is not provided. Default is 2048.

    Returns:
    - private_key (object): The generated private key. For "aes", this will be a raw byte string representing the symmetric key.

    Raises:
    - ValueError: If the specified algorithm is not supported or if invalid parameters are provided.

    Example usage:
    ```python
    private_key = generate_key(algorithm="rsa", length=2048)
    private_key = generate_key(algorithm="ecdsa", curve=ec.SECP384R1())
    ```
    """

    algorithm = algorithm.lower()  # Convert to lowercase once
    backend = default_backend()

    if algorithm == "rsa":
        length = int(params.get("length", 2048))  # it is allowed to parse a string.
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=length, backend=backend)

    elif algorithm == "dsa":
        length = int(params.get("length", 2048))  # it is allowed to parse a string.
        private_key = dsa.generate_private_key(key_size=length, backend=backend)

    elif algorithm in ["ecdh", "ecdsa"]:
        curve = params.get("curve", "secp256r1")
        curve = get_curve_instance(curve_name=curve)
        private_key = ec.generate_private_key(curve=curve, backend=backend)

    elif algorithm == "ed25519":
        private_key = ed25519.Ed25519PrivateKey.generate()

    elif algorithm == "ed448":
        private_key = ed448.Ed448PrivateKey.generate()

    elif algorithm == "x25519":
        private_key = x25519.X25519PrivateKey.generate()

    elif algorithm == "x448":
        private_key = x448.X448PrivateKey.generate()

    elif algorithm == "dh":
        p = params.get("p")
        g = params.get("g", 2)
        secret_scalar = params.get("secret_scalar")

        if p is None:
            length = int(params.get("length", 2048))
            parameters = dh.generate_parameters(generator=g, key_size=length, backend=backend)
        else:
            parameters = dh.DHParameterNumbers(p, g).parameters(backend)

        if secret_scalar is not None:
            private_key = dh.DHPrivateNumbers(
                x=secret_scalar,
                public_numbers=dh.DHPublicNumbers(pow(g, secret_scalar, p), parameters.parameter_numbers()),
            )
        else:
            private_key = parameters.generate_private_key()

    else:
        raise ValueError("Unsupported algorithm: {}".format(algorithm))

    return private_key


def load_private_key_from_file(filepath: str, password: str = None) -> PrivateKey:
    """Load a cryptographic Private key from a PEM file.

    Arguments:
    ---------
        filepath (str): The path to the file containing the PEM-encoded key.
        password (str, optional): The password to decrypt the key file, if it is encrypted. Defaults to None.

    Returns:
    -------
        PrivateKey: An instance of the loaded key, such as `RSAPrivateKey`.

    Raises:
    ------
        FileNotFoundError: If the File does not exist.

    Example:
    -------
        | ${key}= | Load Private Key From File | rsa | /path/to/key.pem | password123 |

    """
    with open(filepath, "rb") as pem_file:
        pem_data = pem_file.read()

    private_key = serialization.load_pem_private_key(
        pem_data,
        password=password,  # your password if the key is encrypted
        backend=default_backend(),
    )
    return private_key


def load_public_key_from_file(filepath: str) -> PublicKey:
    """Load a cryptographic Public key from a PEM file.

    Arguments:
    ---------
        filepath (str): The path to the file containing the PEM-encoded key.

    Returns:
    -------
        PublicKey: An instance of the loaded key, such as `RSAPublicKey`.

    Raises:
    ------
        FileNotFoundError: If the File does not exist.

    Example:
    -------
        | ${key}= | Load Public Key From File | rsa | /path/to/key.pem

    """
    with open(filepath, "rb") as pem_file:
        pem_data = pem_file.read()

    public_key = serialization.load_pem_public_key(pem_data, backend=default_backend())
    return public_key
