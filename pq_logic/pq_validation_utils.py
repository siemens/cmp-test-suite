# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Contains utility functions for validating PQ keys and certificates."""

from pyasn1.type import univ
from pyasn1_alt_modules import rfc9480
from resources import asn1utils
from resources.certextractutils import get_field_from_certificate
from resources.certutils import load_public_key_from_cert

from pq_logic.keys.abstract_pq import PQPublicKey, PQSignaturePublicKey

# https://www.ietf.org/archive/id/draft-ietf-lamps-kyber-certificates-06.txt
# section 3:
# When any of the ML-KEM AlgorithmIdentifier appears in the
# SubjectPublicKeyInfo field of an X.509 certificate, the key usage
# certificate extension MUST only contain `keyEncipherment`.


def validate_pq_allowed_key_usages(cert: rfc9480.CMPCertificate, must_be_present: bool = False) -> None:
    """Validate the key usage of a certificate with a PQ public key.

    :param cert: The certificate to validate.
    :param must_be_present: If the key usage must be present.
    :return: None
    """
    public_key: PQPublicKey = load_public_key_from_cert(cert)  # type: ignore
    key_usage = get_field_from_certificate(cert, extension="key_usage")

    if key_usage is None and not must_be_present:
        return

    key_usage = asn1utils.get_set_bitstring_names(key_usage).split(", ")  # type: ignore

    if isinstance(public_key, PQSignaturePublicKey):
        ml_dsa_allowed = {"digitalSignature", "nonRepudiation", "keyCertSign", "cRLSign"}
        ml_dsa_disallowed = {"keyEncipherment", "dataEncipherment", "keyAgreement", "encipherOnly", "decipherOnly"}

        if not set(key_usage).issubset(ml_dsa_allowed):
            raise ValueError(f"ML-DSA keyUsage must be one of: {ml_dsa_allowed}")
        if set(key_usage) & ml_dsa_disallowed:
            raise ValueError(f"ML-DSA keyUsage must not include: {ml_dsa_disallowed}")

    else:
        ml_kem_allowed = {"keyEncipherment"}
        if set(key_usage) != ml_kem_allowed:
            raise ValueError(f"ML-KEM keyUsage must only contain: {ml_kem_allowed}")


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


SLH_DSA_OID = {
    id_SLH_DSA_SHA2_128S,
    id_SLH_DSA_SHA2_128F,
    id_SLH_DSA_SHA2_192S,
    id_SLH_DSA_SHA2_192F,
    id_SLH_DSA_SHA2_256S,
    id_SLH_DSA_SHA2_256F,
    id_SLH_DSA_SHAKE_128S,
    id_SLH_DSA_SHAKE_128F,
    id_SLH_DSA_SHAKE_192S,
    id_SLH_DSA_SHAKE_192F,
    id_SLH_DSA_SHAKE_256S,
    id_SLH_DSA_SHAKE_256F,
}


def validate_slh_dsa_alg_id(alg_id: rfc9480.AlgorithmIdentifier) -> None:
    """Validate the SLH-DSA signature algorithm identifier.

    :param alg_id: The SLH-DSA `AlgorithmIdentifier`.
    :raises ValueError: If the `parameters` field must be absent.
    """
    if alg_id["parameters"] in SLH_DSA_OID:
        if alg_id["algorithm"].isValue:
            raise ValueError(
                f"The 'parameters' field is not allowed to " f"be set for algorithm OID: {alg_id['parameters']}"
            )
