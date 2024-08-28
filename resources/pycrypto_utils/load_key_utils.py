from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


def load_key_from_file(key_type: str, filepath: str, password: str = None) -> Any:
    """Load a cryptographic key from a PEM file based on the specified key type.


    Arguments:
        key_type (str): The type of key to load (e.g., "rsa").
        filepath (str): The path to the file containing the PEM-encoded key.
        password (str, optional): The password to decrypt the key file, if it is encrypted. Defaults to None.

    Returns:
        Any: An instance of the loaded key, such as `RSAPrivateKey` or `RSAPublicKey`.

    Raises:
        NotImplementedError: If the specified key type is not supported or implemented.

    Example:
        | ${key}= | Load Key From File | rsa | /path/to/key.pem | password123 |
    """
    if key_type == "rsa":
        return load_rsa_key(filepath=filepath, password=password)
    else:
        raise NotImplementedError(f"Key type: {key_type} not implemented")


def load_rsa_key(filepath: str, password: str = None) -> RSAPrivateKey | RSAPublicKey:
    """Load an RSA private key from a PEM file. If the key is encrypted,
    an optional password can be provided to decrypt it.

    Arguments:
        filepath (str): The path to the file containing the PEM-encoded RSA key.
        password (str, optional): The password to decrypt the key file, if it is encrypted. Defaults to None.

    Returns:
        RSAPrivateKey | RSAPublicKey: An instance of `RSAPrivateKey` or `RSAPublicKey` representing the loaded key.

    Raises:
        ValueError: If the file does not contain a valid RSA key or is malformed.
        TypeError: If the key is of an incorrect type or cannot be loaded with the provided password.

    Example:
        | ${rsa_key}= | Load RSA Key | /path/to/rsa_key.pem | password123 |
    """
    with open(filepath, 'rb') as pem_file:
        pem_data = pem_file.read()

    private_key = serialization.load_pem_private_key(
        pem_data,
        password=password,  # your password if the key is encrypted
        backend=default_backend()
    )
    return private_key
