"""Provides utilities for working with cryptographic operations and data structures, specifically focusing on
OID (Object Identifier) mappings for signature and hash algorithms, symmetric and asymmetric cryptography, and PKI
(Public Key Infrastructure) message protections. It includes functions to retrieve OIDs for specific cryptographic
algorithms, create cryptographic instances, and perform lookups between human-readable algorithm names and their
corresponding OIDs.
"""
from typing import Dict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID
from pyasn1.type import univ
from pyasn1_alt_modules import rfc3370, rfc5480, rfc8017, rfc8018, rfc9480, rfc9481
from robot.api.deco import not_keyword

from typingutils import PrivateKey

AES_GMAC_NAME_2_OID = {
    "aes128_gmac": rfc9481.id_aes128_GMAC,
    "aes192_gmac": rfc9481.id_aes192_GMAC,
    "aes256_gmac": rfc9481.id_aes256_GMAC,
    "aes-gmac": rfc9481.id_aes256_GMAC,
    "aes_gmac": rfc9481.id_aes256_GMAC,
}


AES_GMAC_OID_2_NAME: Dict[univ.ObjectIdentifier, str] = {
    rfc9481.id_aes128_GMAC: "aes128_gmac",
    rfc9481.id_aes192_GMAC: "aes192_gmac",
    rfc9481.id_aes256_GMAC: "aes256_gmac",
}


RSA_SHA_OID_2_NAME = {
    rfc8017.sha1WithRSAEncryption: "rsa-sha1",
    rfc9481.sha224WithRSAEncryption: "rsa-sha224",
    rfc9481.sha256WithRSAEncryption: "rsa-sha256",
    rfc9481.sha384WithRSAEncryption: "rsa-sha384",
    rfc9481.sha512WithRSAEncryption: "rsa-sha512",
}

ECDSA_SHA_OID_2_NAME = {
    rfc9481.ecdsa_with_SHA224: "ecdsa-sha224",
    rfc9481.ecdsa_with_SHA256: "ecdsa-sha256",
    rfc9481.ecdsa_with_SHA384: "ecdsa-sha384",
    rfc9481.ecdsa_with_SHA512: "ecdsa-sha512",
}

# These mappings facilitate the identification of the specific HMAC-SHA algorithm
# used for MAC (Message Authentication Code) protection algorithms for the PKIMessage.
HMAC_SHA_OID_2_NAME = {
    rfc3370.hMAC_SHA1: "hmac-sha1",
    rfc9481.id_hmacWithSHA224: "hmac-sha224",
    rfc9481.id_hmacWithSHA256: "hmac-sha256",
    rfc9481.id_hmacWithSHA384: "hmac-sha384",
    rfc9481.id_hmacWithSHA512: "hmac-sha512",
}


# Used for preparing Signature Protection of the PKIMessage.
SHA_OID_2_NAME = {
    rfc5480.id_sha1: "sha1",
    rfc5480.id_sha224: "sha224",
    rfc5480.id_sha256: "sha256",
    rfc5480.id_sha384: "sha384",
    rfc5480.id_sha512: "sha512",
}
# SHA3 -> id-sha3-224 OID ::= { hashAlgs 7}

# map OIDs of signature algorithms to the names of the hash functions
# used in the signature; this is needed to compute the certificate has for
# certConfirm messages, since it must contain the hash of the certificate,
# computed with the same algorithm as the one in the signature
OID_HASH_MAP: Dict[univ.ObjectIdentifier, str] = {}
OID_HASH_MAP.update(RSA_SHA_OID_2_NAME)
OID_HASH_MAP.update(ECDSA_SHA_OID_2_NAME)
OID_HASH_MAP.update(HMAC_SHA_OID_2_NAME)
OID_HASH_MAP.update(SHA_OID_2_NAME)


# Updating the main dictionary with RSA and ECDSA OIDs
# to check quickly if a given OID is supported by the Test-Suite
SUPPORTED_SIG_MAC_OIDS = {rfc9481.id_Ed25519: "ed25519", rfc9481.id_Ed448: "ed448"}
SUPPORTED_SIG_MAC_OIDS.update(RSA_SHA_OID_2_NAME)
SUPPORTED_SIG_MAC_OIDS.update(ECDSA_SHA_OID_2_NAME)


SYMMETRIC_PROT_ALGO = {}
SYMMETRIC_PROT_ALGO.update(
    {
        rfc8018.id_PBMAC1: "pbmac1",
        rfc9480.id_DHBasedMac: "dh_based_mac",
        rfc9480.id_PasswordBasedMac: "password_based_mac",
    }
)

SYMMETRIC_PROT_ALGO.update(HMAC_SHA_OID_2_NAME)
SYMMETRIC_PROT_ALGO.update(AES_GMAC_OID_2_NAME)

SUPPORTED_MAC_OID_2_NAME = {}
SUPPORTED_MAC_OID_2_NAME.update(SUPPORTED_SIG_MAC_OIDS)
SUPPORTED_MAC_OID_2_NAME.update(SYMMETRIC_PROT_ALGO)

# reverse the dictionary to get OIDs with names
# to perform lookups for getting PKIMessage Protection AlgorithmIdentifier
SUPPORTED_MAC_NAME_2_OID = {y: x for x, y in SUPPORTED_MAC_OID_2_NAME.items()}

# map strings used in OpenSSL-like common name notation to objects of NameOID types that
# cryptography.x509 uses internally
NAME_MAP = {
    "C": NameOID.COUNTRY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "L": NameOID.LOCALITY_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "CN": NameOID.COMMON_NAME,
}

# Used to get the hash instances with their respective names.
# This is used to make it easier for users to parse and select hash algorithms by name.
# These hash instances are typically used for signing purposes, computing message digests,
# or for MAC (Message Authentication Code) protection algorithms such as HMAC.
ALLOWED_HASH_TYPES = {
    "sha1": hashes.SHA1(),
    "sha224": hashes.SHA224(),
    "sha256": hashes.SHA256(),
    "sha384": hashes.SHA384(),
    "sha512": hashes.SHA512(),
}


# Map of tuples (asymmetric algorithm OID, hash algorithm name) to the OID of a signature algorithm, e.g.
# ('1.2.840.113549.1.1.1', 'sha256') -> '1.2.840.113549.1.1.11', i.e. (RSA, SHA256) -> sha256WithRSAEncryption
# The OIDs are taken from pyasn1-alt-modules, so they are not strings, but rather univ.Oid objects (which can be
# stringified, if necessary). This is needed when creating the `popo` (ProofOfPossession) structure for CRMF.
OID_SIG_HASH_MAP = {
    (rfc9481.rsaEncryption, "sha256"): rfc9481.sha256WithRSAEncryption,
    (rfc9481.rsaEncryption, "sha384"): rfc9481.sha384WithRSAEncryption,
    (rfc9481.rsaEncryption, "sha512"): rfc9481.sha512WithRSAEncryption,
}

# Saves the supported Curves to Perform a Lookup for key Generation.
CURVE_NAMES_TO_INSTANCES = {
    "secp192r1": ec.SECP192R1(),  # NIST P-192
    "prime192v1": ec.SECP192R1(),  # NIST P-192 (alias)
    "secp224r1": ec.SECP224R1(),  # NIST P-224
    "prime224v1": ec.SECP224R1(),  # NIST P-224 (alias)
    "secp256r1": ec.SECP256R1(),  # NIST P-256
    "prime256v1": ec.SECP256R1(),  # NIST P-256 (alias)
    "secp384r1": ec.SECP384R1(),  # NIST P-384
    "secp521r1": ec.SECP521R1(),  # NIST P-521
    "secp256k1": ec.SECP256K1(),  # SECG curve over a 256 bit prime field (used in Bitcoin)
    "sect163k1": ec.SECT163K1(),  # SECG/WTLS curve over a 163 bit binary field
    "sect163r2": ec.SECT163R2(),  # SECG curve over a 163 bit binary field
    "sect233k1": ec.SECT233K1(),  # SECG curve over a 233 bit binary field
    "sect233r1": ec.SECT233R1(),  # SECG curve over a 233 bit binary field
    "sect283k1": ec.SECT283K1(),  # SECG curve over a 283 bit binary field
    "sect283r1": ec.SECT283R1(),  # SECG curve over a 283 bit binary field
    "sect409k1": ec.SECT409K1(),  # SECG curve over a 409 bit binary field
    "sect409r1": ec.SECT409R1(),  # SECG curve over a 409 bit binary field
    "sect571k1": ec.SECT571K1(),  # SECG curve over a 571 bit binary field
    "sect571r1": ec.SECT571R1(),  # SECG curve over a 571 bit binary field
    "brainpoolP256r1": ec.BrainpoolP256R1(),  # Brainpool curve over a 256 bit prime field
    "brainpoolP384r1": ec.BrainpoolP384R1(),  # Brainpool curve over a 384 bit prime field
    "brainpoolP512r1": ec.BrainpoolP512R1(),  # Brainpool curve over a 512 bit prime field
}


@not_keyword
def get_hash_name_to_oid(hash_name: str) -> univ.ObjectIdentifier:
    """Perform a lookup for the provided hash name.

    :param hash_name: A string representing the hash name to look up. Example hash names could be "sha256"
                      or "hmac-sha256"
    :return: pyasn1.type.univ.ObjectIdentifier
    """
    hash_name = hash_name.lower().replace("_", "-").strip()

    if hash_name in OID_HASH_MAP.values():
        for key, value in OID_HASH_MAP.items():
            if hash_name == value:
                return key

    else:
        raise ValueError("Hash name is not supported: {}".format(hash_name))


@not_keyword
def get_curve_instance(curve_name: str) -> ec.EllipticCurve:
    """Retrieve an instance of an elliptic curve based on its name.
    Used for generating an Ecc Private Key on the named curve.

    :param curve_name: A string name of the elliptic curve to retrieve.
    :raises ValueError: If the specified curve name is not supported.
    :return: `cryptography.hazmat.primitives.ec` EllipticCurve instance.
    """
    if curve_name not in CURVE_NAMES_TO_INSTANCES:
        raise ValueError(f"The Curve: {curve_name} is not Supported!")

    return CURVE_NAMES_TO_INSTANCES[curve_name]


@not_keyword
def get_alg_oid_from_key_hash(key: PrivateKey, hash_alg: str) -> univ.ObjectIdentifier:
    """Find the pyasn1 oid given the hazmat key instance and a name of a hashing algorithm

    :param key: cryptography.hazmat.primitives.asymmetric, key instance
    :param hash_alg: str, name of hashing algorithm, e.g., 'sha256'
    :return: pyasn1.type.univ.ObjectIdentifier of signature algorithm
    """
    if isinstance(key, rsa.RSAPrivateKey):
        if hash_alg == "sha256":
            return rfc9481.sha256WithRSAEncryption
        elif hash_alg == "sha384":
            return rfc9481.sha384WithRSAEncryption
        elif hash_alg == "sha512":
            return rfc9481.sha512WithRSAEncryption

    elif isinstance(key, ec.EllipticCurvePrivateKey):
        if hash_alg == "sha256":
            return rfc9481.ecdsa_with_SHA256
        elif hash_alg == "sha384":
            return rfc9481.ecdsa_with_SHA384
        elif hash_alg == "sha512":
            return rfc9481.ecdsa_with_SHA512

    elif isinstance(key, ed25519.Ed25519PrivateKey):
        return SUPPORTED_MAC_NAME_2_OID["ed448"]

    elif isinstance(key, ed448.Ed448PrivateKey):
        return SUPPORTED_MAC_NAME_2_OID["ed448"]

    raise ValueError(f"Unsupported signature algorithm for ({key}, {hash_alg})")


@not_keyword
def get_sig_oid_from_key_hash(alg_oid, hash_alg):
    """Determine the OID of a signature algorithm given by the OID of the asymmetric algorithm and the name of the
    hashing function used in the signature

    :param: alg_oid: pyasn1.type.univ.ObjectIdentifier, OID of asymmetric algorithm
    :param: hash_alg: str, name of hashing algorithm, e.g., 'sha256'
    :returns: pyasn1.type.univ.ObjectIdentifier of signature algorithm, e.g., '1.2.840.113549.1.1.11' (i.e., sha256WithRSAEncryption)
    """
    try:
        return OID_SIG_HASH_MAP[(alg_oid, hash_alg)]
    except KeyError:
        raise ValueError(
            f"Unsupported signature algorithm for ({alg_oid}, {hash_alg}), " f"see cryptoutils.OID_SIG_HASH_MAP"
        )


@not_keyword
def get_hash_from_signature_oid(oid: univ.ObjectIdentifier) -> str:
    """Determine the name of a hashing function used in a signature algorithm given by its oid

    :param oid: `pyasn1 univ.ObjectIdentifier`, OID of signing algorithm
    :return: str, name of hashing algorithm, e.g., 'sha256'
    """
    try:
        tmp = OID_HASH_MAP[oid]
        return tmp
    except KeyError:
        raise ValueError(f"Unknown signature algorithm OID {oid}, " f"check OID_HASH_MAP in cryptoutils.py")


@not_keyword
def hash_name_to_instance(alg: str) -> hashes.HashAlgorithm:
    """Return an instance of a hash algorithm object based on its name

    :param alg: str, name of hashing algorithm, e.g., 'sha256'
    :return: cryptography.hazmat.primitives.hashes
    """
    try:
        # to also get the hash function with rsa-sha1 and so on.
        if "-" in alg:
            return ALLOWED_HASH_TYPES[alg.split("-")[1]]

        return ALLOWED_HASH_TYPES[alg]
    except KeyError:
        raise ValueError(f"Unsupported hash algorithm: {alg}")
