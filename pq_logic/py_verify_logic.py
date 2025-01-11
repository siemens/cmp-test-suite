
"""Contains logic to perform all kind of verification tasks.

Either has functionality to verify signatures of PKIMessages or certificates.


"""
from typing import Optional

from pq_logic.hybrid_sig.sun_lamps_hybrid_scheme_00 import validate_alt_pub_key_extn, validate_alt_sig_extn
from pq_logic.pq_compute_utils import verify_signature_with_alg_id
from resources.certutils import load_public_key_from_cert
from resources.typingutils import PublicKeySig


# TODO fix to include CRL-Verification
# currently only works for PQ and traditional signatures.
# But in the next update will be Completely support CRL-Verification.

# TODO fix to either extract

def verify_sun_hybrid_cert(
    cert: rfc9480.CMPCertificate,
    issuer_cert: rfc9480.CMPCertificate,
    alt_issuer_key: Optional[PublicKeySig] = None,
    check_alt_sig: bool = True,
):
    """Verify a Sun hybrid certificate.

    Validates the primary and alternative signatures in a certificate.

    :param cert: The SUN hybrid certificate to verify.
    :param issuer_cert: The issuer's certificate for verifying the main signature.
    :param check_alt_sig: Whether to validate the alternative signature (default: True).
    :raises ValueError: If validation fails for the certificate or its extensions.
    """
    alt_pub_key = validate_alt_pub_key_extn(cert)
    if check_alt_sig:
        validate_alt_sig_extn(cert, alt_pub_key, alt_issuer_key)

    public_key = load_public_key_from_cert(issuer_cert)
    data = encoder.encode(cert["tbsCertificate"])
    alg_id = cert["tbsCertificate"]["signature"]
    signature = cert["signature"].asOctets()
    verify_signature_with_alg_id(public_key=public_key, data=data, signature=signature, alg_id=alg_id)
