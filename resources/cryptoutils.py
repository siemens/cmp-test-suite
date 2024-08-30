import logging
import os
from typing import Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.x509.oid import NameOID
from pyasn1_alt_modules import rfc9481

from keyutils import generate_key
from typingutils import PrivateKey

# map strings used in OpenSSL-like common name notation to objects of NameOID types that
# cryptography.x509 uses internally
NAME_MAP = {
    'C': NameOID.COUNTRY_NAME,
    'ST': NameOID.STATE_OR_PROVINCE_NAME,
    'L': NameOID.LOCALITY_NAME,
    'O': NameOID.ORGANIZATION_NAME,
    'CN': NameOID.COMMON_NAME,
    'emailAddress': NameOID.EMAIL_ADDRESS,
}

# map OIDs of signature algorithms to the stringified names of hash functions
# used in the signature; this is needed to compute the certificate has for
# certConfirm messages, since it must contain the hash of the certificate,
# computed with the same algorithm as the one in the signature
OID_HASH_MAP = {
    '1.2.840.113549.1.1.5': 'sha1',  # sha1-with-rsa-signature
    '1.2.840.113549.1.1.11': 'sha256',  # sha256WithRSAEncryption
    '1.2.840.113549.1.1.12': 'sha384',  # sha384WithRSAEncryption
    '1.2.840.113549.1.1.13': 'sha512',  # sha512WithRSAEncryption

    '1.2.840.10045.4.3.1': 'sha224',  # ecdsa-with-SHA224
    '1.2.840.10045.4.3.2': 'sha256',  # ecdsa-with-SHA256
    '1.2.840.10045.4.3.3': 'sha384',  # ecdsa-with-SHA384
    '1.2.840.10045.4.3.4': 'sha512',  # ecdsa-with-SHA512
}

HASH_NAME_OBJ_MAP = {
    'sha1': hashes.SHA1(),
    'sha224': hashes.SHA224(),
    'sha256': hashes.SHA256(),
    'sha384': hashes.SHA384(),
    'sha512': hashes.SHA512(),
}

# Map of tuples (asymmetric algorithm OID, hash algorithm name) to the OID of a signature algorithm, e.g.
# ('1.2.840.113549.1.1.1', 'sha256') -> '1.2.840.113549.1.1.11', i.e. (RSA, SHA256) -> sha256WithRSAEncryption
# The OIDs are taken from pyasn1-alt-modules, so they are not strings, but rather univ.Oid objects (which can be
# stringified, if necessary). This is needed when creating the `popo` (ProofOfPossession) structure for CRMF.
OID_SIG_HASH_MAP = {
    (rfc9481.rsaEncryption, 'sha256'): rfc9481.sha256WithRSAEncryption,
    (rfc9481.rsaEncryption, 'sha384'): rfc9481.sha384WithRSAEncryption,
    (rfc9481.rsaEncryption, 'sha512'): rfc9481.sha512WithRSAEncryption,
}


def get_alg_oid_from_key_hash(key, hash_alg):
    """Find the pyasn1 oid given the hazmat key instance and a name of a hashing algorithm

    :param key: cryptography.hazmat.primitives.asymmetric, key instance
    :param hash_alg: str, name of hashing algorithm, e.g., 'sha256'
    :return: pyasn1.type.univ.ObjectIdentifier of signature algorithm
    """
    if isinstance(key, rsa.RSAPrivateKey):
        if hash_alg == 'sha256':
            return rfc9481.sha256WithRSAEncryption
        elif hash_alg == 'sha384':
            return rfc9481.sha384WithRSAEncryption
        elif hash_alg == 'sha512':
            return rfc9481.sha512WithRSAEncryption

    elif isinstance(key, ec.ECDSA):
        if hash_alg == 'sha256':
            return rfc9481.ecdsa_with_SHA256
        elif hash_alg == 'sha384':
            return rfc9481.ecdsa_with_SHA384
        elif hash_alg == 'sha512':
            return rfc9481.ecdsa_with_SHA512

    raise ValueError(f'Unsupported signature algorithm for ({key}, {hash_alg})')


def get_sig_oid_from_key_hash(alg_oid, hash_alg):
    """Determine the OID of a signature algorithm given by the OID of the asymmetric algorithm and the name of the
    hashing function used in the signature

    :param: alg_oid: pyasn1.type.univ.ObjectIdentifier, OID of asymmetric algorithm
    :param: hash_alg: str, name of hashing algorithm, e.g., 'sha256'
    :returns: pyasn1.type.univ.ObjectIdentifier of signature algorithm, e.g., '1.2.840.113549.1.1.11' (i.e., sha256WithRSAEncryption)"""

    try:
        return OID_SIG_HASH_MAP[(alg_oid, hash_alg)]
    except KeyError:
        raise ValueError(f'Unsupported signature algorithm for ({alg_oid}, {hash_alg}), '
                         f'see cryptoutils.OID_SIG_HASH_MAP')


def get_hash_from_signature_oid(oid):
    """Determine the name of a hashing function used in a signature algorithm given by its oid

    :param oid: str, OID of signing algorithm
    :return: str, name of hashing algorithm, e.g., 'sha256'"""
    try:
        return OID_HASH_MAP[oid]
    except KeyError:
        raise ValueError(f'Unknown signature algorithm OID {oid}, '
                         f'check OID_HASH_MAP in cryptoutils.py')


def hash_name_to_instance(alg):
    """Return an instance of a hash algorithm object based on its name

    :param alg: str, name of hashing algorithm, e.g., 'sha256'
    :return: cryptography.hazmat.primitives.hashes"""
    try:
        return HASH_NAME_OBJ_MAP[alg]
    except KeyError:
        raise ValueError(f"Unsupported hash algorithm: {alg}")



def save_key(key, path, passphrase=b"11111"):
    """Save key to a file

    :param key: cryptography.hazmat.primitives.asymmetric, key you want to save
    :param path: str, where to save it
    :param passphrase: optional str, password to use for encrypting the key"""
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
        ))


def generate_csr(common_name: str = None, subjectAltName=None):
    """Generate a CSR based on the given string parameters

    :param common_name: str, common name in OpenSSL notation, e.g., "C=DE,ST=Bavaria,L= Munich,O=CMP Lab,CN=Joe Mustermann,emailAddress=joe.mustermann@example.com"
    :param subjectAltName: optional str, list of subject alternative names, e.g., "example.com,www.example.com,pki.example.com"
    :returns: x509.CertificateSigningRequestBuilder
    """
    csr = x509.CertificateSigningRequestBuilder()

    common_name = common_name or "C=DE,ST=Bavaria,L= Munich,O=CMP Lab,CN=Joe Mustermann,emailAddress=joe.mustermann@example.com"

    # take a string like "C=DE,ST=Bavaria,L=Munich,O=CMP Lab" and transform it into a dictionary that maps each component to a
    # corresponding x509.NameAttribute.
    items = common_name.strip().split(',')
    common_names = []
    for item in items:
        attribute, value = item.split('=')
        new_entry = x509.NameAttribute(NAME_MAP[attribute], value.strip())
        common_names.append(new_entry)

    csr = csr.subject_name(x509.Name(common_names))
    # this produces something like
    # csr = csr.subject_name(x509.Name([
    #     x509.NameAttribute(NameOID.COUNTRY_NAME, u"DE"),
    #     x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"CMP Lab"),
    #     ]))

    if subjectAltName:
        # if there are any subjectAltNames given, process the list into objects that the CSRBuilder can deal with
        items = subjectAltName.strip().split(',')
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


def sign_data(data, key, hash_alg="sha256"):
    """Sign the given data with a given private key, using a specified hashing algorithm

    :param data: bytes, data to be signed
    :param key: cryptography.hazmat.primitives.asymmetric, private key used for the signature (RSA or ECDSA for now)
    :param hash_alg: optional str, a hashing algorithm name
    :return: bytes, the signature
    """
    hash_alg_instance = hash_name_to_instance(hash_alg)

    if isinstance(key, rsa.RSAPrivateKey):
        # use PKCS1v15 padding, because we have to: https://crypto.stackexchange.com/a/76760
        signature = key.sign(data, padding.PKCS1v15(), hash_alg_instance)
    elif isinstance(key, ec.ECDSA):
        signature = key.sign(data, ec.ECDSA(hash_alg_instance))
    else:
        raise ValueError(f"Unsupported key type: {type(key)}, only RSA and ECDSA is implemented for now")
    return signature


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
        key = key.encode('utf-8')

    h = hmac.HMAC(key, hash_alg_instance)
    h.update(data)
    signature = h.finalize()
    return signature


def compute_pbmac1(data, key, iterations=262144, salt=None, length=32, hash_alg="sha256"):
    """Compute HMAC for the given data using specified key.

    :param data: bytes, data to be hashed.
    :param key: bytes, key to use for the HMAC.
    :param salt:
    :param hash_alg: optional str, name of the hash algorithm to use.

    :returns: bytes, the HMAC signature
    """
    hash_alg_instance = hash_name_to_instance(hash_alg)

    if type(key) is str:
        key = key.encode('utf-8')

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

    # step 2, compute HMAC using this derived key
    h = hmac.HMAC(derived_key, hash_alg_instance)
    h.update(data)
    signature = h.finalize()
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
        key = key.encode('utf-8')

    initial_input = key + salt
    for i in range(iterations):
        initial_input = compute_hash(hash_alg, initial_input)

    hash_alg_instance = hash_name_to_instance(hash_alg)

    h = hmac.HMAC(initial_input, hash_alg_instance)
    h.update(data)
    signature = h.finalize()
    logging.info(f"Signature: {signature}")
    return signature


def generate_signed_csr(common_name: str, key: Union[PrivateKey, str, None] = None, **params)-> Tuple[
    bytes, PrivateKey]:
    """

    :param common_name:
    :param key:
    :param params: for the key generation for more information, look at `generate_key`
    :return:
    """

    if key is None:
        key = generate_key(algorithm="rsa", length=2048)
    elif isinstance(key, str):
        key = generate_key(algorithm=key, **params)

    elif isinstance(key, PrivateKey):
        pass
    else:
        raise ValueError("the provided key must be either be the name of the generate key or a private key")


    csr = generate_csr(common_name)
    csr_signed = sign_csr(csr=csr, key=key)

    return csr_signed, key