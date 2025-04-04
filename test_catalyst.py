# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0


"""Try all combinations of alternative signature data and verify the signature of a catalyst certificate."""
import glob
from itertools import product

import oqs
from pyasn1_alt_modules import rfc9480

from pq_logic.fips.fips204 import ML_DSA
from pq_logic.hybrid_sig.catalyst_logic import (
    prepare_alt_signature_data,
    validate_catalyst_extension,
)
from pq_logic.keys.abstract_pq import PQPrivateKey, PQPublicKey
from pq_logic.keys.sig_keys import MLDSAPublicKey
from resources.certutils import parse_certificate
from resources.oid_mapping import KEY_CLASS_MAPPING, may_return_oid_to_name
from unit_tests.utils_for_test import get_subject_and_issuer


def get_catalyst_certs() -> list[str]:
    """Get paths of all catalyst certificates from the test directory."""
    pem_files = []
    for file in glob.iglob("./data/pqc-certificates/providers/**", recursive=True):
        if file.endswith(".der") and "catalyst" in file:
            pem_files.append(file)

    if pem_files == []:
        raise FileNotFoundError("No catalyst certificates found in the specified directory.")
    return pem_files



def get_key_name(key) -> str:
    """Get a human-readable name of an asymmetric key."""
    if isinstance(key, (PQPublicKey, PQPrivateKey)):
        return key.key_name
    else:
        return str(KEY_CLASS_MAPPING.get(type(key).__name__, key))


def log_cert_infos(asn1cert: rfc9480.CMPCertificate):
    """Retrieve basic information about a Catalyst certificate"""
    tmp = get_subject_and_issuer(asn1cert)
    tmp += "\nSignature algorithm: " + may_return_oid_to_name(asn1cert['tbsCertificate']['signature']['algorithm'])
    tmp += "\nPublic key algorithm: " + may_return_oid_to_name(
        asn1cert['tbsCertificate']['subjectPublicKeyInfo']['algorithm']['algorithm'])
    tmp += "\nCatalyst Extension: \n"
    extension = validate_catalyst_extension(asn1cert)
    tmp += "Catalyst AltPubKey: " + may_return_oid_to_name(extension['spki']["algorithm"]["algorithm"])
    tmp += "\nCatalyst AltSigAlg: " + may_return_oid_to_name(extension['alg_id']["algorithm"])

    pub_key = extension['spki']["subjectPublicKey"].asOctets()


    name = may_return_oid_to_name(extension['spki']["algorithm"]["algorithm"])
    #print(tmp)
    return pub_key, name, extension["signature"]





def _try2(asn1cert: rfc9480.CMPCertificate,
          pub_key: bytes, name: str, signature: bytes) -> bool:
    """Try all possible combinations of alternative signature data and verify the signature.

    :param asn1cert: The certificate to be verified.
    :param pub_key: The public key of the certificate.
    :param name: The name of the public key algorithm.
    :param signature: The signature to be verified.
    :return: Whether the verification was successful.
    """
    # verify the key size.
    MLDSAPublicKey.from_public_bytes(pub_key, name)

    for exclude_alt_extensions, only_tbs_cert, exclude_signature_field, exclude_spki \
            in product([True, False], repeat=4):
        # Prepare alternative signature data with the current combination
        alt_sig_data = prepare_alt_signature_data(
            cert=asn1cert,
            exclude_alt_extensions=exclude_alt_extensions,
            only_tbs_cert=only_tbs_cert,
            exclude_signature_field=exclude_signature_field, #means the signature field inside tbsCertificate,
            # which is the signature algorithm.
            exclude_first_spki=exclude_spki,
        )



        out = ML_DSA(name).verify(pk=pub_key,
                                  m=alt_sig_data,
                                  sig=signature,
                                  ctx=b"")


        for sigalg in oqs.get_enabled_sig_mechanisms():
            if sigalg.startswith("Dilithium") or sigalg.startswith("ML-D"):
                with oqs.Signature(sigalg) as verifier:
                    try:
                         is_valid = verifier.verify(alt_sig_data, signature, pub_key)

                         if is_valid:
                           print(f"Verification successful with {sigalg} with: "
                                 f"exclude_alt_extensions={exclude_alt_extensions}, "
                                 f"only_tbs_cert={only_tbs_cert}, "
                                 f"exclude_signature_field={exclude_signature_field}"
                                 f"exclude_spki={exclude_spki}")
                           return True
                    except Exception:
                        #print(f"Verification failed for {sigalg}:", e)
                        continue



        if out:
            print(f"Verification successful with {name} with: "
                  f"exclude_alt_extensions={exclude_alt_extensions}, "
                  f"only_tbs_cert={only_tbs_cert}, "
                  f"exclude_signature_field={exclude_signature_field}"
                  f"exclude_spki={exclude_spki}")
            return True

    print("Verification failed for all options for ", name)
    return False


pem_files = get_catalyst_certs()

for pem_file in pem_files:
    with open(pem_file, 'rb') as file:
        cert = parse_certificate(file.read())
        pub_key, name, signature = log_cert_infos(cert)
        _try2(cert, pub_key, name, signature)
