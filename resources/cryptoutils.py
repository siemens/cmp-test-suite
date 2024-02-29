import logging
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# map strings used in OpenSSL-like common name notation to objects of NameOID types that
# cryptography.x509 uses internally
NAME_MAP = {
    'C': NameOID.COUNTRY_NAME,
    'ST': NameOID.STATE_OR_PROVINCE_NAME,
    'L': NameOID.LOCALITY_NAME,
    'O': NameOID.ORGANIZATION_NAME,
    'CN': NameOID.COMMON_NAME,
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


def generate_rsa_keypair(length=2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=length)

def generate_keypair(algorithm="rsa", length=2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=length)


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

def generate_csr(common_name, subjectAltName=None):
    """Generate a CSR based on the given string parameters

    :param common_name: str, common name in OpenSSL notation, e.g., "C=DE,ST=Bavaria,L= Munich,O=CMP Lab,CN=Joe Mustermann,emailAddress=joe.mustermann@example.com"
    :param subjectAltName: optional str, list of subject alternative names, e.g., "example.com,www.example.com,pki.example.com"
    :returns: x509.CertificateSigningRequestBuilder
    """
    csr = x509.CertificateSigningRequestBuilder()

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


def compute_password_based_mac(data, key, iterations=5, salt=None, hash_alg="sha256"):
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
