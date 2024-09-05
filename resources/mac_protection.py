"""
Provides functionality to prepare the `pyasn1` `rfc9480.PKIMessage` protection: AlgorithmIdentifier field and computes the PKIProtection.
"""


import os

from pyasn1.codec.der import encoder
from pyasn1.type import univ, constraint
from pyasn1.type.tag import Tag, tagClassContext, tagFormatSimple
from pyasn1_alt_modules import rfc9044, rfc5280, rfc8018, rfc4210, rfc9480
from typing_extensions import Optional

from cryptoutils import compute_dh_based_mac
from oid_mapping import AES_GMAC_OIDS, get_alg_oid_from_key_hash, get_hash_name_oid
from test_suite_enums import ProtectionAlgorithm
from resources.cryptoutils import (
    compute_pbmac1,
    compute_gmac,
    compute_password_based_mac,
    sign_data,
    compute_hmac,
)
from resources.aaa_typingutils import PrivateKey



def _prepare_pbmac1_parameters(salt: Optional[bytes]=None, iterations=100, length=32, hash_alg="sha256"):
    """Prepares the PBMAC1 pyasn1 `rfc8018.PBMAC1_params`. Used for the `rfc9480.PKIMessage` structure´.
       PBKDF2 with HMAC as message authentication scheme is used..

    :param salt: Optional bytes for uniqueness.
    :param iterations: The number of iterations to be used in the PBKDF2 key derivation function.
                       Default is 100.
    :param length: int The desired length of the derived key in bytes. Default is 32 bytes.
    :param hash_alg:
    :return:
    """
    salt = salt or os.urandom(16)

    match hash_alg:
        case "sha256":
            hmac_alg = rfc8018.id_hmacWithSHA256
        case "sha384":
            hmac_alg = rfc8018.id_hmacWithSHA384
        case "sha512":
            hmac_alg = rfc8018.id_hmacWithSHA512
        case _:
            raise ValueError(f"Unsupported hash algorithm: {hash_alg}")

    outer_params = rfc8018.PBMAC1_params()
    outer_params['keyDerivationFunc'] = rfc8018.AlgorithmIdentifier()

    pbkdf2_params = rfc8018.PBKDF2_params()
    pbkdf2_params['salt']['specified'] = univ.OctetString(salt)
    pbkdf2_params['iterationCount'] = iterations
    pbkdf2_params['keyLength'] = length
    pbkdf2_params['prf'] = rfc8018.AlgorithmIdentifier()
    pbkdf2_params['prf']['algorithm'] = hmac_alg
    pbkdf2_params['prf']['parameters'] = univ.Null()

    outer_params['keyDerivationFunc']['algorithm'] = rfc8018.id_PBKDF2
    outer_params['keyDerivationFunc']['parameters'] = pbkdf2_params

    outer_params['messageAuthScheme']['algorithm'] = hmac_alg
    outer_params['messageAuthScheme']['parameters'] = univ.Null()

    return outer_params


