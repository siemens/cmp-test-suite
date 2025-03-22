# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.combined_factory import CombinedKeyFactory
from unit_tests.pq_workflow_exp import build_sun_hybrid_composite_csr
from pq_logic.keys.comp_sig_cms03 import CompositeSigCMSPrivateKey, get_names_from_oid
from pq_logic.pq_compute_utils import verify_csr_signature
from pq_logic.tmp_oids import PREHASH_OID_2_HASH
from pyasn1.codec.der import encoder
from pyasn1_alt_modules import rfc9480
from resources.certbuildutils import generate_certificate


def _generate_composite_cert(
        key: CompositeSigCMSPrivateKey,
        common_name: str = "CN=Hans Mustermann",
        pre_hash: bool = False,
        use_pss: bool = False):

    if pre_hash:
        raise NotImplementedError("Prehashing not supported for composite keys")

    return generate_certificate(private_key=key,
                                common_name=common_name,
                                use_rsa_pss=use_pss)



def _verify_cert_signature(cert: rfc9480.Certificate, issuer_pubkey=None):
    """Verify the signature of a certificate.

    :param cert: The certificate to verify.
    :param issuer_pubkey: The public key of the issuer of the certificate.
    :return: None
    """
    spki = cert["tbsCertificate"]["subjectPublicKeyInfo"]

    oid = cert["tbsCertificate"]["signature"]["algorithm"]
    _, trad_name = get_names_from_oid(oid)
    public_key = issuer_pubkey or CombinedKeyFactory.load_public_key_from_spki(spki=spki)
    pre_hash = PREHASH_OID_2_HASH.get(oid, False)
    use_pss = trad_name.endswith("-pss")

    public_key.verify(signature=cert["signature"].asOctets(),
                      data=encoder.encode(cert["tbsCertificate"]),
                      use_pss=use_pss,
                      pre_hash=pre_hash
                      )


class TestCompositeSignature(unittest.TestCase):

    def test_cert_comp_sig_pure_rsa_with_pk(self):
        """
        GIVEN a composite rsa signature key.
        WHEN generating a certificate,
        THEN the signature is valid.
        """
        key = CompositeSigCMSPrivateKey.generate()
        cert = _generate_composite_cert(key)
        _verify_cert_signature(cert, key.public_key())


    def test_cert_comp_sig_pure_rsa(self):
        """
        GIVEN a composite rsa signature key.
        WHEN generating a certificate,
        THEN the signature is valid.
        """
        key = CompositeSigCMSPrivateKey.generate()
        cert = _generate_composite_cert(key)
        _verify_cert_signature(cert)


    def test_sign_csr(self):
        """
        GIVEN a composite signature key.
        WHEN signing a CSR,
        THEN the signature is valid.
        """
        csr = build_sun_hybrid_composite_csr()
        verify_csr_signature(csr)

