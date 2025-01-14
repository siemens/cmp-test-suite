# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0


"""Contains logic to perform all kind of verification tasks.

Either has functionality to verify signatures of PKIMessages or certificates.


"""
# TODO fix to include CRL-Verification
# currently only works for PQ and traditional signatures.
# But in the next update will be Completely support CRL-Verification.

from pyasn1_alt_modules import rfc9480
from resources.cryptoutils import verify_signature
from resources.oid_mapping import get_hash_from_oid
from resources.oidutils import CMS_COMPOSITE_OID_2_NAME, MSG_SIG_ALG, PQ_OID_2_NAME, RSASSA_PSS_OID_2_NAME
from resources.protectionutils import verify_rsassa_pss_from_alg_id
from robot.api.deco import not_keyword

from pq_logic.keys.comp_sig_cms03 import CompositeSigCMSPublicKey


@not_keyword
def verify_signature_with_alg_id(public_key, alg_id: rfc9480.AlgorithmIdentifier, data: bytes, signature: bytes):
    """Verify the provided data and signature using the given algorithm identifier.

    Supports traditional-, pq- and composite signature algorithm.

    :param public_key: The public key object used to verify the signature.
    :param alg_id: An `AlgorithmIdentifier` specifying the algorithm and any
                   associated parameters for signature verification.
    :param data: The original message or data whose signature needs verification,
                 as a byte string.
    :param signature: The digital signature to verify, as a byte string.

    :raises ValueError: If the algorithm identifier is unsupported or invalid.
    :raises InvalidSignature: If the signature does not match the provided data
                              under the given algorithm and public key.
    """
    oid = alg_id["algorithm"]

    if oid in CMS_COMPOSITE_OID_2_NAME:
        name: str = CMS_COMPOSITE_OID_2_NAME[oid]
        use_pss = name.endswith("-pss")
        pre_hash = name.startswith("hash-")
        public_key: CompositeSigCMSPublicKey
        public_key.verify(data=data, signature=signature, use_pss=use_pss, pre_hash=pre_hash)

    elif oid in RSASSA_PSS_OID_2_NAME:
        return verify_rsassa_pss_from_alg_id(public_key=public_key, data=data, signature=signature, alg_id=alg_id)

    elif oid in PQ_OID_2_NAME or str(oid) in PQ_OID_2_NAME or oid in MSG_SIG_ALG:
        hash_alg = get_hash_from_oid(oid, only_hash=True)
        verify_signature(public_key=public_key, signature=signature, data=data, hash_alg=hash_alg)
    else:
        raise ValueError(f"Unsupported public key type: {type(public_key).__name__}.")
