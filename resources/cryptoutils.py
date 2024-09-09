import datetime
import logging
import os
from typing import Tuple, Union, Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dh, ed25519, ed448, dsa, x25519, x448, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pyasn1_alt_modules import rfc9481
from robot.api.deco import not_keyword

from oid_mapping import NAME_MAP, hash_name_to_instance

from keyutils import generate_key
from typingutils import PrivateKey, PrivateKeySig


@not_keyword
def parse_common_name_from_str(common_name: str) -> x509.Name:
    """Parse a string representing common name attributes (e.g., "C=DE,ST=Bavaria,L=Munich,O=CMP Lab")
    and converts it into an `x509.Name` object that can be used for X.509 certificate generation

    :param common_name: str, common name in OpenSSL notation, e.g.,
    "C=DE,ST=Bavaria,L= Munich,O=CMP Lab,CN=Joe Mustermann,emailAddress=joe.mustermann@example.com"
    :returns: x509.Name
    """
    items = common_name.strip().split(",")
    common_names = []
    for item in items:
        attribute, value = item.split("=")
        new_entry = x509.NameAttribute(NAME_MAP[attribute], value.strip())
        common_names.append(new_entry)

    return x509.Name(common_names)


def generate_csr(common_name: str = None, subjectAltName=None):
    """Generate a CSR based on the given string parameters

    :param common_name: str, common name in OpenSSL notation, e.g.,
           "C=DE,ST=Bavaria,L= Munich,O=CMP Lab,CN=Joe Mustermann,emailAddress=joe.mustermann@example.com"
    :param subjectAltName: optional str, list of subject alternative names, e.g.,
                           "example.com,www.example.com,pki.example.com"
    :returns: x509.CertificateSigningRequestBuilder
    """
    csr = x509.CertificateSigningRequestBuilder()

    common_name = (
        common_name or "C=DE,ST=Bavaria,L= Munich,O=CMP Lab,CN=Joe Mustermann,emailAddress=joe.mustermann@example.com"
    )

    x509_name = parse_common_name_from_str(common_name)
    csr = csr.subject_name(x509_name)
    # this produces something like
    # csr = csr.subject_name(x509.Name([
    #     x509.NameAttribute(NameOID.COUNTRY_NAME, u"DE"),
    #     x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"CMP Lab"),
    #     ]))

    if subjectAltName:
        # if there are any subjectAltNames given, process the list into objects that the CSRBuilder can deal with
        items = subjectAltName.strip().split(",")
        dns_names = [x509.DNSName(item) for item in items]
        csr = csr.add_extension(x509.SubjectAlternativeName(dns_names), critical=False)

        # the logic above will essentially boil down to a call like this one:
        # csr = csr.add_extension(
        #     x509.SubjectAlternativeName([
        #     x509.DNSName(u"mysite.com"),
        #     x509.DNSName(u"www.mysite.com"),
        #     x509.DNSName(u"subdomain.mysite.com"),
        # ]), critical=False)

    return csr


def sign_data(data: bytes, key: PrivateKeySig, hash_alg: Optional[str] = None) -> bytes:
    """Sign the given data with a given private key, using a specified hashing algorithm.

    :param data: bytes the data to sign.
    :param key: A `cryptography.hazmat.primitives.asymmetric` PrivateKey object.
    :param hash_alg: optional str name of the hash function to use
    :return: bytes the singed data.
    """

    if isinstance(hash_alg, hashes.HashAlgorithm):
        pass
    elif hash_alg is not None:
        hash_alg = hash_name_to_instance(hash_alg)

    # isinstance(ed448.Ed448PrivateKey.generate(), EllipticCurvePrivateKey) → False
    # so can check in this Order.
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.sign(data, ec.ECDSA(hash_alg))
    elif isinstance(key, rsa.RSAPrivateKey):
        return key.sign(data, padding.PKCS1v15(), hash_alg)
    elif isinstance(key, ed25519.Ed25519PrivateKey):
        return key.sign(data)
    elif isinstance(key, ed448.Ed448PrivateKey):
        return key.sign(data)
    elif isinstance(key, dsa.DSAPrivateKey):
        if not hash_alg:
            raise ValueError("DSA signatures require a hash algorithm.")
        return key.sign(data, hash_alg)
    elif isinstance(key, (x25519.X25519PrivateKey, x448.X448PrivateKey)):
        raise ValueError(
            f"Key type '{type(key).__name__}' is not used for signing or verifying signatures. It is used for key exchange."
        )
    else:
        raise ValueError(f"Unsupported private key type: {type(key).__name__}.")


def sign_csr(csr, key, hash_alg="sha256"):
    """Sign a CSR with a given key, using a specified hashing algorithm

    :param csr: x509.CertificateSigningRequestBuilder, the CSR to be signed
    :param key: cryptography.hazmat.primitives.asymmetric, private key used for the signature
    :param hash_alg: optional str, a hashing algorithm name
    :returns: bytes, PEM-encoded CSR
    """
    hash_alg_instance = hash_name_to_instance(hash_alg)
    csr_out = csr.sign(key, hash_alg_instance)
    return csr_out.public_bytes(serialization.Encoding.PEM)


def compute_hmac(data, key, hash_alg="sha256"):
    """Compute HMAC for the given data using specified key.

    :param data: bytes, data to be hashed.
    :param key: bytes, key to use for the HMAC.
    :param hash_alg: optional str, name of the hash algorithm to use.

    :returns: bytes, the HMAC signature
    """
    hash_alg_instance = hash_name_to_instance(hash_alg)

    if type(key) is str:
        key = key.encode("utf-8")

    h = hmac.HMAC(key, hash_alg_instance)
    h.update(data)
    signature = h.finalize()
    return signature


def compute_pbmac1(data: bytes, key: Union[str, bytes], iterations=262144, salt=None, length=32, hash_alg="sha256"):
    """Compute HMAC for the given data using specified key.

    :param data: bytes, data to be hashed.
    :param key: bytes, key to use for the HMAC.
    :param salt:
    :param hash_alg: optional str, name of the hash algorithm to use.

    :returns: bytes, the HMAC signature
    """
    hash_alg_instance = hash_name_to_instance(hash_alg)

    if type(key) is str:
        key = key.encode("utf-8")

    salt = salt or os.urandom(16)

    # step 1, derive key
    kdf = PBKDF2HMAC(
        algorithm=hash_alg_instance,
        length=length,
        salt=salt,
        iterations=iterations,
    )
    derived_key = kdf.derive(key)
    logging.info(f"Derived key: {derived_key}")

    signature = compute_hmac(key=derived_key, hash_alg=hash_alg, data=data)
    logging.info(f"Signature: {signature}")
    return signature


def compute_hash(alg_name, data):
    """Calculate the hash of data using an algorithm given by its name

    :param alg_name: str, name of algorithm, e.g., 'sha256', see HASH_NAME_OBJ_MAP
    :param data: bytes, the buffer we want to hash
    :return: bytes, the resulting hash
    """
    hash_class = hash_name_to_instance(alg_name)
    digest = hashes.Hash(hash_class)
    digest.update(data)
    return digest.finalize()


def compute_password_based_mac(data, key, iterations=1000, salt=None, hash_alg="sha256"):
    """Implement the password-based MAC algorithm defined in RFC 4210 Sec. 5.1.3.1. The MAC is always HMAC_hash_alg.

    :param data: bytes, data to be hashed.
    :param key: bytes, key to use for the HMAC.
    :param iterations: optional int, the number of times to do the hash iterations
    :param salt: optional bytes, salt to use; if not given, a random 16-byte salt will be generated
    :param hash_alg: optional str, name of the hash algorithm to use, e.g., 'sha256'

    :returns: bytes, the HMAC signature
    """
    salt = salt or os.urandom(16)

    if type(key) is str:
        key = key.encode("utf-8")

    initial_input = key + salt
    for i in range(iterations):
        initial_input = compute_hash(hash_alg, initial_input)

    signature = compute_hmac(data=data, key=initial_input, hash_alg=hash_alg)
    logging.info(f"Signature: {signature}")
    return signature


def generate_signed_csr(  # noqa: D417
    common_name: str, key: Union[PrivateKey, str, None] = None, **params
) -> Tuple[bytes, PrivateKey]:
    """Generate Signed CSR.

    Generates a signed Certificate Signing Request (CSR) for a given common name (CN).
    Optionally, use a specified private key or generate a new one if none is provided.

    If a key is not provided, a new RSA key is generated. If a string is provided, it is used as the key generation
    algorithm (e.g., "rsa") with additional parameters. If a `PrivateKey` object is provided, it is used directly.

    Args:
    ----
    - `common_name`: The common name (CN) to include in the CSR.
    - `key`: Optional. The private key to use for signing the CSR. Can be one of:
        - A `PrivateKey` object from the cryptography library.
        - A string representing the key generation algorithm (e.g., "rsa").
        - `None` (default). If `None`, a new RSA key is generated.
    - `params`: Additional keyword arguments to customize key generation when `key` is a string.

    Returns:
    -------
    - `csr_signed`: The signed CSR in bytes.
    - `key`: The private key used for signing, as a cryptography library Key-Object.

    Raises:
    ------
    - `ValueError`: If the provided key is neither a valid key generation algorithm string nor a `PrivateKey` object.

    Example:
    -------
    | ${csr_signed} | ${private_key} = | Generate Signed CSR | example.com | rsa | length=2048 |

    """
    if key is None:
        key = generate_key(algorithm="rsa", length=2048)
    elif isinstance(key, str):
        key = generate_key(algorithm=key, **params)
    elif isinstance(key, PrivateKey):
        pass
    else:
        raise ValueError("the provided key must be either be the name of the generate key or a private key")

    csr = generate_csr(common_name=common_name)
    csr_signed = sign_csr(csr=csr, key=key)

    return csr_signed, key


def _generate_private_dh_from_key(password: str, other_party_key: Union[dh.DHPrivateKey, dh.DHPublicKey]) -> dh.DHPrivateKey:
    """Generates a `cryptography.hazmat.primitives.asymmetric.dh DHPrivateKey` based on the parsed password.
    Used to perform a DH Key-Agreement with a provided password.

    :param password: str password which one of the parties uses as secret DH-Key.
    :param other_party_key: `cryptography.hazmat.primitives.asymmetric.dh DHPrivateKey or DHPublicKey
    :return: `cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKey` object
    """
    parameters = other_party_key.parameters().parameter_numbers()

    private_key: dh.DHPrivateKey = generate_key(
        algorithm="dh",
        p=parameters.p,
        g=parameters.g,
        secret_scalar=int.from_bytes(password.encode("utf-8")),
    )
    return private_key


def do_dh_key_exchange_password_based(password: str, other_party_key: Union[dh.DHPrivateKey, dh.DHPublicKey]) -> bytes:
    """Performs a Diffie-Hellman key exchange to derive a shared secret key based on a password.

    Arguments:
    - `password`: A string used to derive the DH private key for the server or local party.
    - `other_party_key`: A `cryptography` `dh.DHPrivateKey` or `dh.DHPublicKey` object representing the other party's key.

    Returns:
    - `bytes`: A byte sequence representing the shared secret key derived from the Diffie-Hellman key exchange.

    Example:
    | ${shared_secret} = | Do DH Key Exchange Password Based | password=my_password | other_party_key=${public_key} |

    """

    private_key = _generate_private_dh_from_key(password, other_party_key)

    if isinstance(other_party_key, dh.DHPublicKey):
        shared_key = private_key.exchange(other_party_key)
        logging.info(f"DH shared secret: {shared_key.hex()}")
        return shared_key

    other_public_key: dh.DHPublicKey = private_key.public_key()


    shared_key = private_key.exchange(other_public_key)
    logging.info(f"DH shared secret: {shared_key.hex()}")
    return shared_key


def compute_dh_based_mac(data: bytes, password: Union[str, dh.DHPublicKey], key: dh.DHPrivateKey, hash_alg: str = "sha1") -> bytes:
    """Computes a Message Authentication Code (MAC) using a Diffie-Hellman (DH) based shared secret.
    Derives a shared Secret, hashes the key and then computes te HMAC.

    :param data: The input data to be authenticated, given as a byte sequence.
    :param password: str or `cryptography` `dh.DHPublicKey` A string password used to generate the Server's secret Key
                     or a provided Public key.
    :param key: A `cryptography` `dh.DHPrivateKey` object. Which represents the client's Secret.
    :param hash_alg: (str) The name of the hash algorithm to be used for key derivation and HMAC computation.
                     Defaults to "sha1".
    :return: A byte sequence representing the computed HMAC of the input data using the derived key.
    """

    if isinstance(password, str):
        shared_key = do_dh_key_exchange(password=password, key=key)
    else:
        shared_key = key.exchange(password)

    key = compute_hash(data=shared_key, alg_name=hash_alg)
    return compute_hmac(data=data, key=key, hash_alg=hash_alg)

def compute_gmac(data: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Computes the AES-GMAC (Galois Message Authentication Code) for given data.

    :param key: The encryption key (16, 24, or 32 bytes for AES-128, AES-192, AES-256)
    :param nonce: Initialization vector (must be 12 bytes for GCM mode)
    :param data: Data to authenticate
    :return: The computed MAC (authentication tag)
    """
    # Create AES cipher in GCM mode for MAC computation
    aes_gcm = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend()).encryptor()

    # Authenticate data and return the authentication tag
    aes_gcm.authenticate_additional_data(data)
    aes_gcm.finalize()  # Finalize to get the authentication tag
    return aes_gcm.tag

def generate_cert_from_private_key(private_key: PrivateKey, common_name: Optional[str] = "CN=Hans",
                                   hash_alg: Optional[str] = "sha256") -> x509.Certificate:
    """Generates a self-signed x509 certificate from a provided private key.

    Args:
        private_key (PrivateKey): The private key to use for certificate generation.
        common_name (str, optional): The common name in OpenSSL notation. Defaults to "CN=Hans".
        hash_alg (str, optional): The name of the hash function to use for signing the certificate. Defaults to "sha256".

    Returns:
    `cryptography.x509.Certificate`: The generated self-signed x509 certificate.

    Raises:
    ValueError: If the private key is not supported for certificate signing.

    Examples:
    | ${private_key} | Generate Key | algorithm=rsa | length=2048 |
    | ${certificate} | Generate Cert From Private Key | ${private_key} | CN=Hans |
    """

    # Define the certificate subject and issuer
    subject = issuer = parse_common_name_from_str(common_name)

    if not isinstance(private_key, PrivateKey):
        raise ValueError("Needs a `cryptography.hazmat.primitives.asymmetric PrivateKey` object for generating a "
                         "self-singed `cryptography.x509.Certificate`")

    # Create the certificate builder
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now())
        .not_valid_after(datetime.datetime.now() + datetime.timedelta(days=365))
    )

    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        hash_alg = hash_name_to_instance(hash_alg)

        # Sign the certificate with the private key
        certificate = cert_builder.sign(
            private_key=private_key,
            algorithm=hash_alg
        )
    elif isinstance(private_key, rsa.RSAPrivateKey):
        hash_alg = hash_name_to_instance(hash_alg)
        certificate = cert_builder.sign(
            private_key=private_key,
            algorithm=hash_alg,
            rsa_padding=padding.PKCS1v15()
        )

    elif isinstance(private_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        certificate = cert_builder.sign(
            private_key=private_key,
            algorithm=None
        )

    else:
        raise ValueError("Unsupported to sign a Certificate!")

    return certificate
