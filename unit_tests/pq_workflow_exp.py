from typing import Optional

from pq_logic.hybrid_sig.sun_lamps_hybrid_scheme_00 import prepare_sun_hybrid_csr_attributes
from pq_logic.keys.comp_sig_cms03 import CompositeSigCMSPrivateKey, get_oid_cms_composite_signature
from pq_logic.pq_compute_utils import sign_data_with_alg_id
from resources.certbuildutils import build_csr

from pyasn1_alt_modules import rfc6402

###################
# Example Workflow
###################

def build_sun_hybrid_composite_csr(
    signing_key: Optional[CompositeSigCMSPrivateKey] = None,
    common_name: str = "CN=Hans Mustermann",
    pub_key_hash_alg: Optional[str] = None,
    pub_key_location: Optional[str] = None,
    sig_hash_alg: Optional[str] = None,
    sig_value_location: Optional[str] = None,
    use_rsa_pss: bool = True,
) -> rfc6402.CertificationRequest:
    """
    Create a CSR with composite signatures, supporting two public keys and multiple CSR attributes.

    :param signing_key: CompositeSigCMSPrivateKey, which holds both traditional and post-quantum keys.
    :param common_name: The subject common name for the CSR.
    :param pub_key_hash_alg: Hash algorithm for the alternative public key.
    :param pub_key_location: URI for the alternative public key.
    :param sig_hash_alg: Hash algorithm for the alternative signature.
    :param sig_value_location: URI for the alternative signature.
    :param use_rsa_pss: Whether to use RSA-PSS for traditional keys.
    :return: CertificationRequest object with composite signature.
    """
    signing_key = signing_key or CompositeSigCMSPrivateKey.generate(pq_name="ml-dsa-44", trad_param="ec")

    csr = build_csr(signing_key, common_name=common_name, exclude_signature=True, use_rsa_pss=use_rsa_pss)
    sig_alg_id = rfc5280.AlgorithmIdentifier()

    domain_oid = get_oid_cms_composite_signature(
        signing_key.pq_key.name,
        signing_key.trad_key,  # type: ignore
        use_pss=use_rsa_pss,
        pre_hash=False,
    )

    # Step 4 and 5
    # Currently is always the PQ-Key the firsts key to
    # it is assumed to be the first key, and the alternative key is the traditional key.
    attributes = prepare_sun_hybrid_csr_attributes(
        pub_key_hash_alg=pub_key_hash_alg,
        sig_value_location=sig_value_location,
        pub_key_location=pub_key_location,
        sig_hash_alg=sig_hash_alg,
    )

    sig_alg_id["algorithm"] = domain_oid

    csr["certificationRequestInfo"]["attributes"].extend(attributes)

    der_data = encoder.encode(csr["certificationRequestInfo"])
    signature = sign_data_with_alg_id(key=signing_key, alg_id=sig_alg_id, data=der_data)

    csr["signatureAlgorithm"] = sig_alg_id
    csr["signature"] = univ.BitString.fromOctetString(signature)

    csr, _ = decoder.decode(encoder.encode(csr), rfc6402.CertificationRequest())
    return csr
