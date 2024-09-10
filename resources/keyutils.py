"""Provides utility functions for generating, saving, and loading cryptographic keys.
It is designed to facilitate key management by offering simple methods to create new keys,
store them and retrieve them when needed."""

from typing import Optional

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

from oid_mapping import get_curve_instance
from typingutils import PrivateKey, PublicKey


def save_key(key: PrivateKey, path: str, passphrase: Optional[str] = "11111"):
    """Save a `cryptography` `PrivateKey` object to a file.

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

    elif isinstance(
        key, (x448.X448PrivateKey, x25519.X25519PrivateKey, ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)
    ):


        data = key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ).hex()

        with open(path, "w") as f:
            f.write(data)

        return

    with open(path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=encoding_,
                format=format_,
                encryption_algorithm=encrypt_algo,
            )
        )


def generate_key(algorithm="rsa", **params) -> PrivateKey:
    """Generate a cryptographic key based on the specified algorithm.

    This function supports generating keys for various cryptographic algorithms including
    RSA, DSA, ECDSA, ECDH, Ed25519, DH, and AES.
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
            - curve (str): An elliptic curve instance from `cryptography.hazmat.primitives.asymmetric.ec`.
                          Default is `secp256r1`.
        - For "dh":
            - g (int): The generator for DH key generation. Default is 2.
            - secret_scalar (int): the private key value for DH key generation. If not provided, one is generated.
            - length (int , str): The length of the modulus to generate if `p` is not provided. Default is 2048.

    Returns:
    - private_key (object): The generated private key. For "aes", this will be a raw byte string
                            representing the symmetric key.

    Raises:
    - ValueError: If the specified algorithm is not supported or if invalid parameters are provided.

    Examples:
    | ${private_key}= | Generate Key | algorithm=rsa | length=2048 |
    | ${private_key}= | Generate Key | algorithm=dh | length=2048 |
    | ${private_key}= | Generate Key | algorithm=ecdsa | curve=secp384r1 |

    """
    algorithm = algorithm.lower()
    backend = backends.default_backend()

    if algorithm == "rsa":
        length = int(params.get("length", 2048))
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=length, backend=backend)

    elif algorithm == "dsa":
        length = int(params.get("length", 2048))
        private_key = dsa.generate_private_key(key_size=length, backend=backend)

    elif algorithm in ["ecdh", "ecdsa", "ecc", "ec"]:
        curve = params.get("curve", "secp256r1")
        curve = get_curve_instance(curve_name=curve)
        private_key = ec.generate_private_key(curve=curve)

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


def load_private_key_from_file(filepath: str, password: Optional[str] = "11111") -> PrivateKey:
    """Load Private Key From File.

    Loads a cryptographic private key from a PEM-encoded file, or Hex-String for x448, ed448, x25519, ed25519 keys.

    Arguments:
    - `filepath` (str): The path to the file containing the PEM-encoded key.
    - `password` (str, optional): The password to decrypt the key file, if it is encrypted. Defaults to "11111".
      For raw key formats such as `x448` and `x25519`, set the password to `"x448"` or `"x25519"` to indicate
      that these raw keys should be loaded. (also for ed-versions).

    Returns:
    - `PrivateKey`: An instance of the loaded key, such as `RSAPrivateKey`, `X448PrivateKey`, or `X25519PrivateKey`.

    Raises:
    - `FileNotFoundError`: If the file does not exist.

    Examples:
    | ${key}= | Load Private Key From File | /path/to/key.pem | password123 |
    | ${x448_key}= | Load Private Key From File | /path/to/x448_key.pem | x448 |
    | ${x25519_key}= | Load Private Key From File | /path/to/x25519_key.pem | x25519 |

    """

    if password in ["x448", "x25519", "ed448", "ed25519"]:
        with open(filepath, "r") as pem_file:
            pem_data = pem_file.read()

        pem_data = bytes.fromhex(pem_data)
    else:
        with open(filepath, "rb") as pem_file:
            pem_data = pem_file.read()


    if password == "x448":
        return x448.X448PrivateKey.from_private_bytes(data=pem_data)
    elif password == "x25519":
        return x25519.X25519PrivateKey.from_private_bytes(data=pem_data)

    elif password == "ed448":
        return ed448.Ed448PrivateKey.from_private_bytes(data=pem_data)
    elif password == "ed25519":
        return ed25519.Ed25519PrivateKey.from_private_bytes(data=pem_data)

    password = password if not password else password.encode("utf-8")

    private_key = serialization.load_pem_private_key(
        pem_data,
        password=password,
        backend=backends.default_backend(),
    )
    return private_key


def load_public_key_from_file(filepath: str, key_type: str = None) -> PublicKey:
    """Load Public Key From File.

    Load a cryptographic public key from a PEM-encoded file
    unless it is a x448, ed448, x25519, or ed25519 key. Then the raw format is used.

    Arguments:
    - `filepath` (str): the path to the file containing the key data.
    - `key_type` (optional str): the type of the key. needed for x448 and x25519. (also ed-versions)


    Returns:
    - `PublicKey`: An instance of the loaded public key, such as `RSAPublicKey`, `X448PublicKey`, or `X25519PublicKey`.

    Raises:
    - `FileNotFoundError`: If the file does not exist.
    - `ValueError`: If the file content is not a valid public key format.

    Examples:
    | ${public_key}= | Load Public Key From File | /path/to/public_key.pem |
    | ${x448_key}= | Load Public Key From File | /path/to/x448_public_key.raw |
    | ${x25519_key}= | Load Public Key From File | /path/to/x25519_public_key.raw |

    """
    if key_type in ["x448", "x25519", "ed448", "ed25519"]:
        with open(filepath, "r") as pem_file:
            pem_data = pem_file.read()

        pem_data = bytes.fromhex(pem_data)
    else:
        with open(filepath, "rb") as pem_file:
            pem_data = pem_file.read()

    if key_type == "x448":
        return x448.X448PublicKey.from_public_bytes(data=pem_data)
    elif key_type == "x25519":
        return x25519.X25519PublicKey.from_public_bytes(data=pem_data)

    elif key_type == "ed448":
        return ed448.Ed448PublicKey.from_public_bytes(data=pem_data)
    elif key_type == "ed25519":
        return ed25519.Ed25519PublicKey.from_public_bytes(data=pem_data)
    else:
        public_key = serialization.load_pem_public_key(pem_data, backend=backends.default_backend())
    return public_key
