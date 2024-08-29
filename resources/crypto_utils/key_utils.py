"""
This module provides utility functions for generating, saving, and loading cryptographic keys.
It is designed to facilitate key management by offering simple methods to create new keys,
store them and retrieve them when needed.

Functions:
----------
- generate_key() -> str:
    Generates a new cryptographic key using a secure algorithm and returns it as a string.

- save_key(key: str, filepath: str) -> None:
    Saves a given key to a specified file path. Ensures the key is securely stored
    by using appropriate file permissions.

- load_key(filepath: str) -> str:
    Loads a cryptographic key from a specified file path. Verifies the integrity of the key
    during the loading process.

Usage:
------
1. Generate a new cryptographic key using `generate_key()` or `generate_keypair()`.
2. Save the generated key to a file using `save_key(key, filepath, password)`.
3. Load an existing key from a file using `load_key(filepath)` when needed.

"""

import os
from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh, rsa, ec, dsa, ed25519
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from typingutils import PrivateKey, PublicKey


# already implemented.
def get_curve():
    raise NotImplementedError()

def generate_diffie_hellman_keypair(p: int, g: int, private_value: int = None) -> Tuple[dh.DHPrivateKey, dh.DHPublicKey]:
    """
    Generates a Diffie-Hellman shared key using the provided parameters.

    Args:
        p (int): The prime number for the Diffie-Hellman group.
        g (int): The generator for the Diffie-Hellman group.
        private_value (int): The private value (private key) used by the current party.

    Returns:
        bytes: The derived shared key.

    Raises:
        ValueError: If there is an error during key exchange.
    """


    # Create DH parameter numbers from provided p and g
    dh_parameters = dh.DHParameterNumbers(p, g).parameters(default_backend())

    # Generate the private key using the provided private value
    private_key = dh_parameters.generate_private_key()

    if private_value is None:
        # Generate the public key based on the provided private value
        public_numbers = dh.DHPublicNumbers(private_value, dh_parameters)
        public_key = public_numbers.public_key(default_backend())
    else:
        public_key = private_key.public_key()


    return private_key, public_key


def save_key(key, path, passphrase=b"11111"):
    """Save key to a file

    :param key: cryptography.hazmat.primitives.asymmetric, key you want to save
    :param path: str, where to save it
    :param passphrase: optional str, password to use for encrypting the key"""
    with open(path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
            )
        )





def generate_rsa_key(length: int = 2048) -> RSAPrivateKey:
    """Generates an RSA private key of the specified length.

    The function generates an RSA key pair with a public exponent of 65537, which is a common choice for RSA encryption.

    Arguments:
    - length: The length of the RSA key to generate, in bits. Default is 2048.

    Returns:
    - An RSAPrivateKey object representing the generated RSA private key.

    Example:
    | ${private_key} = | Generate RSA Keypair | length=2048 |
    """

    return rsa.generate_private_key(public_exponent=65537, key_size=length)

def generate_dsa_key(length: int = 2048) -> DSAPrivateKey:
    """Generates an DSA private key of the specified length.

    The function generates an DSA Private key.

    Arguments:
    - length: The length of the DSA key to generate, in bits. Default is 2048.

    Returns:
    - An RSAPrivateKey object representing the generated RSA private key.

    Example:
    | ${private_key} = | Generate DSA Keypair | length=2048 |
    """

    return dsa.generate_private_key(key_size=length)


def generate_ec_key(curve_name: str = 'secp256r1') -> EllipticCurvePrivateKey:

    curve_name = curve_name.lower()

    curve_class = get_curve(name=curve_name)

    # Generate the ECC private key
    private_key = ec.generate_private_key(curve_class, default_backend())
    return private_key

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
            - length (int): The length of the key to generate, in bits. Default is 2048.
        - For "ecdsa" or "ecdh":
            - curve (str): An elliptic curve instance from `cryptography.hazmat.primitives.asymmetric.ec`. Default is `secp256r1`.
        - For "dh":
            - p (int): The prime modulus for DH key generation. If not provided, a modulus is generated.
            - g (int): The generator for DH key generation. Default is 2.
            - length (int): The length of the modulus to generate if `p` is not provided. Default is 2048.
        - For "aes":
            - length (int): The length of the AES key in bits. Valid values are 128, 192, or 256. Default is 256.

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

    if algorithm == 'rsa':
        length = int(params.get('length', 2048)) # it is allowed to parse a string.
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=length,
            backend=backend
        )

    elif algorithm == 'dsa':
        length = int(params.get('length', 2048)) # it is allowed to parse a string.
        private_key = dsa.generate_private_key(
            key_size=length,
            backend=backend
        )

    elif algorithm in ['ecdh', 'ecdsa']:
        curve = params.get('curve', "")
        curve = get_curve(curve, default=ec.SECP256R1())
        private_key = ec.generate_private_key(
            curve=curve,
            backend=backend
        )

    elif algorithm == 'ed25519':
        private_key = ed25519.Ed25519PrivateKey.generate()

    elif algorithm == 'dh':
        p = params.get('p')
        g = params.get('g', 2)
        if p is None:
            length = params.get('length', 2048)
            parameters = dh.generate_parameters(generator=g, key_size=length, backend=backend)
        else:
            parameters = dh.DHParameterNumbers(p, g).parameters(backend)
        private_key = parameters.generate_private_key()

    else:
        raise ValueError("Unsupported algorithm: {}".format(algorithm))

    return private_key


def generate_keypair(algorithm: str = "rsa", **kwargs) -> Tuple[PrivateKey, PublicKey]:
    """
    Generates a cryptographic key pair based on the specified algorithm.

    This function is a wrapper around `generate_key`, returning both the private and public keys for algorithms
    that support public/private key pairs (e.g., RSA, DSA, ECDSA, ECDH, Ed25519, DH).

    Arguments:
    - algorithm (str): The cryptographic algorithm to use for key generation. Supported values are the same as in `generate_key`.
    - **kwargs: Additional parameters specific to the algorithm. Refer to `generate_key` for details.

    Returns:
    - (private_key, public_key): A tuple containing the generated private and public keys.

    Raises:
    - ValueError: If the specified algorithm is not supported or if invalid parameters are provided.

    Example usage:
    ```python
    private_key, public_key = generate_keypair(algorithm="rsa", length=2048)
    private_key, public_key = generate_keypair(algorithm="ecdsa", curve=ec.SECP384R1())
    ```
    """
    private_key = generate_key(algorithm, **kwargs)
    public_key = private_key.public_key()
    return private_key, public_key


def load_private_key_from_file(filepath: str, password: str = None) -> PrivateKey:
    """Load a cryptographic Private key from a PEM file.


    Arguments:
        filepath (str): The path to the file containing the PEM-encoded key.
        password (str, optional): The password to decrypt the key file, if it is encrypted. Defaults to None.

    Returns:
        PrivateKey: An instance of the loaded key, such as `RSAPrivateKey`.

    Raises:
        FileNotFoundError: If the File does not exist.

    Example:
        | ${key}= | Load Key From File | rsa | /path/to/key.pem | password123 |
    """
    with open(filepath, 'rb') as pem_file:
        pem_data = pem_file.read()

    private_key = serialization.load_pem_private_key(
        pem_data,
        password=password,  # your password if the key is encrypted
        backend=default_backend()
    )
    return private_key

def load_public_key_from_file(filepath: str) -> PublicKey:
    """Load a cryptographic Public key from a PEM file.

    Arguments:
        filepath (str): The path to the file containing the PEM-encoded key.
    Returns:
        PublicKey: An instance of the loaded key, such as `RSAPublicKey`.

    Raises:
        FileNotFoundError: If the File does not exist.

    Example:
        | ${key}= | Load Key From File | rsa | /path/to/key.pem
    """
    with open(filepath, 'rb') as pem_file:
        pem_data = pem_file.read()

    public_key = serialization.load_pem_public_key(
        pem_data,
        backend=default_backend()
    )
    return public_key