# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Contains utility functions for validating PQ keys and certificates."""
import logging

from pyasn1.type import univ
from pyasn1_alt_modules import rfc9480
from resources import asn1utils
from resources.certextractutils import get_field_from_certificate
from resources.certutils import load_public_key_from_cert
from resources.oidutils import PQ_OID_2_NAME

from pq_logic.keys.abstract_composite import AbstractCompositeKEMPublicKey
from pq_logic.keys.abstract_pq import PQKEMPublicKey, PQPublicKey, PQSignaturePublicKey
from pq_logic.keys.xwing import XWingPublicKey

# https://www.ietf.org/archive/id/draft-ietf-lamps-kyber-certificates-06.txt
# section 3:
# When any of the ML-KEM AlgorithmIdentifier appears in the
# SubjectPublicKeyInfo field of an X.509 certificate, the key usage
# certificate extension MUST only contain `keyEncipherment`.

NIST_ALGORITHMS = "2.16.840.1.101.3.4"
SIG_ALGS = f"{NIST_ALGORITHMS}.3"

id_SLH_DSA_SHA2_128S = univ.ObjectIdentifier(f"{SIG_ALGS}.20")
id_SLH_DSA_SHA2_128F = univ.ObjectIdentifier(f"{SIG_ALGS}.21")
id_SLH_DSA_SHA2_192S = univ.ObjectIdentifier(f"{SIG_ALGS}.22")
id_SLH_DSA_SHA2_192F = univ.ObjectIdentifier(f"{SIG_ALGS}.23")
id_SLH_DSA_SHA2_256S = univ.ObjectIdentifier(f"{SIG_ALGS}.24")
id_SLH_DSA_SHA2_256F = univ.ObjectIdentifier(f"{SIG_ALGS}.25")
id_SLH_DSA_SHAKE_128S = univ.ObjectIdentifier(f"{SIG_ALGS}.26")
id_SLH_DSA_SHAKE_128F = univ.ObjectIdentifier(f"{SIG_ALGS}.27")
id_SLH_DSA_SHAKE_192S = univ.ObjectIdentifier(f"{SIG_ALGS}.28")
id_SLH_DSA_SHAKE_192F = univ.ObjectIdentifier(f"{SIG_ALGS}.29")
id_SLH_DSA_SHAKE_256S = univ.ObjectIdentifier(f"{SIG_ALGS}.30")
id_SLH_DSA_SHAKE_256F = univ.ObjectIdentifier(f"{SIG_ALGS}.31")





def validate_migration_alg_id(alg_id: rfc9480.AlgorithmIdentifier) -> None:
    """Validate a post-quantum or hybrid algorithm identifier.

    :param alg_id: The `AlgorithmIdentifier`.
    :raises ValueError: If the `parameters` field must be absent.
    """
    if alg_id["algorithm"] not in PQ_OID_2_NAME:
        if alg_id["parameters"].isValue:
            name = PQ_OID_2_NAME.get(alg_id["algorithm"])
            name = name or PQ_OID_2_NAME.get(str(alg_id["algorithm"]))
            raise ValueError(f"The Post-Quantum algorithm identifier {name} does not `allow` the parameters"
                             f" field to be set: {alg_id['parameters']}")




def validate_migration_certificate_key_usage(cert: rfc9480.CMPCertificate) -> None:
    """Validate the key usage of a certificate with a PQ public key.

    :param cert: The certificate to validate.
    :return: None
    """
    public_key: PQPublicKey = load_public_key_from_cert(cert)  # type: ignore
    key_usage = get_field_from_certificate(cert, extension="key_usage")

    if key_usage is None:
        logging.info("Key usage extension was not present parsed certificate.")
        return

    key_usage = asn1utils.get_set_bitstring_names(key_usage).split(", ")  # type: ignore

    sig_usages = {"digitalSignature", "nonRepudiation", "keyCertSign", "cRLSign"}

    if isinstance(public_key, PQSignaturePublicKey):
        ml_dsa_disallowed = {"keyEncipherment", "dataEncipherment", "keyAgreement", "encipherOnly", "decipherOnly"}

        if not set(key_usage).issubset(sig_usages):
            raise ValueError(f"The post-quantum {public_key.name} keyUsage must be one of: {sig_usages}")
        if set(key_usage) & ml_dsa_disallowed:
            raise ValueError(f"ML-DSA keyUsage must not include: {ml_dsa_disallowed}")

    elif isinstance(public_key, PQKEMPublicKey):
        ml_kem_allowed = {"keyEncipherment"}
        if set(key_usage) != ml_kem_allowed:
            raise ValueError(f"ML-KEM keyUsage must only contain: {ml_kem_allowed}")

    elif isinstance(public_key, AbstractCompositeKEMPublicKey):
        pq_allowed = {"keyEncipherment"}
        if set(key_usage) != pq_allowed:
            raise ValueError("A CompositeKEM public key MUST have only the keyUsage 'keyEncipherment'.")

    elif isinstance(public_key, XWingPublicKey):
        pq_allowed = {"keyEncipherment"}
        if set(key_usage) != pq_allowed:
            raise ValueError("A XWing public key MUST have only the keyUsage 'keyEncipherment'.")

    else:
        raise ValueError(f"Unsupported public key type: {type(public_key)}")
