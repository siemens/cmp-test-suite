"""
This module provides utility functions for generating, saving, and loading cryptographic keys.
It is designed to facilitate key management by offering simple methods to create new keys,
store them and retrieve them when needed.

"""

from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh, rsa, ec, dsa, ed25519

from typingutils import PrivateKey, PublicKey


# already implemented. in next Merge.
def get_curve():
    raise NotImplementedError()

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
            - length (int): The prime modulus for DH key generation If not provided, a modulus is generated.
            - g (int): The generator for DH key generation. Default is 2.
            - secret_scalar (int): the private key value for DH key generation. If not provided, one is generated.
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
        # TODO change with Config
        length = int(params.get('length', 2048)) # it is allowed to parse a string.
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=length,
            backend=backend
        )

    elif algorithm == 'dsa':
        # TODO change with Config
        length = int(params.get('length', 2048)) # it is allowed to parse a string.
        private_key = dsa.generate_private_key(key_size=length, backend=backend)

    elif algorithm in ['ecdh', 'ecdsa']:
        curve = params.get('curve', None)
        # TODO change with Config
        # TODO implementation in next Merge.
        curve = get_curve(curve, default="secp256r1")
        private_key = ec.generate_private_key(
            curve=curve,
            backend=backend
        )

    elif algorithm == 'ed25519':
        private_key = ed25519.Ed25519PrivateKey.generate()

    elif algorithm == 'dh':
        p = params.get('p')
        g = params.get('g', 2)
        secret_scalar = params.get("secret_scalar")

        if p is None:
            # TODO change with Config
            length = int(params.get('length', 2048))
            parameters = dh.generate_parameters(generator=g, key_size=length, backend=backend)
        else:
            parameters = dh.DHParameterNumbers(p, g).parameters(backend)

        if secret_scalar is not None:
            private_key = dh.DHPrivateNumbers(
                x=secret_scalar,
                public_numbers=dh.DHPublicNumbers(
                    pow(g, secret_scalar, p),
                    parameters.parameter_numbers()
                )
            )
        else:
            private_key = parameters.generate_private_key()

    else:
        raise ValueError("Unsupported algorithm: {}".format(algorithm))

    return private_key


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
        | ${key}= | Load Private Key From File | rsa | /path/to/key.pem | password123 |
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
        | ${key}= | Load Public Key From File | rsa | /path/to/key.pem
    """
    with open(filepath, 'rb') as pem_file:
        pem_data = pem_file.read()

    public_key = serialization.load_pem_public_key(
        pem_data,
        backend=default_backend()
    )
    return public_key