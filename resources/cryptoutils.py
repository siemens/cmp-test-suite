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
    match hash_alg:
        case "sha256":
            hash_alg_instance = hashes.SHA256()
        case "sha384":
            hash_alg_instance = hashes.SHA384()
        case "sha512":
            hash_alg_instance = hashes.SHA512()
        case _:
            raise ValueError(f"Unsupported hash algorithm: {hash_alg}")

    csr_out = csr.sign(key, hash_alg_instance)
    return csr_out.public_bytes(serialization.Encoding.PEM)


def compute_hmac(data, key, hash_alg="sha256"):
    """Compute HMAC for the given data using specified key.
    :param data: bytes, data to be hashed.
    :param key: bytes, key to use for the HMAC.
    :param hash_alg: optional str, name of the hash algorithm to use.

    :returns: bytes, the HMAC signature
    """
    match hash_alg:
        case "sha256":
            hash_alg_instance = hashes.SHA256()
        case "sha384":
            hash_alg_instance = hashes.SHA384()
        case "sha512":
            hash_alg_instance = hashes.SHA512()
        case _:
            raise ValueError(f"Unsupported hash algorithm: {hash_alg}")

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
    match hash_alg:
        case "sha256":
            hash_alg_instance = hashes.SHA256()
        case "sha384":
            hash_alg_instance = hashes.SHA384()
        case "sha512":
            hash_alg_instance = hashes.SHA512()
        case _:
            raise ValueError(f"Unsupported hash algorithm: {hash_alg}")

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

    # step 2, compute HMAC using this derived key
    h = hmac.HMAC(derived_key, hash_alg_instance)
    h.update(data)
    signature = h.finalize()
    return signature
