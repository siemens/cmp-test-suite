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



