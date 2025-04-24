# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pq_logic.hybrid_sig.sun_lamps_hybrid_scheme_00 import (
    convert_sun_hybrid_cert_to_target_form,
    sun_csr_to_cert,
    validate_alt_pub_key_extn,
    validate_alt_sig_extn,
)
from resources.keyutils import generate_key
from pq_logic.tmp_oids import id_altSubPubKeyExt, id_altSignatureExt
from pq_logic.hybrid_structures import AltSignatureExt
from pq_logic.keys.composite_sig03 import CompositeSig03PrivateKey
from resources.certutils import verify_csr_signature
from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc6402, rfc9480
from resources.certextractutils import get_extension

from unit_tests.utils_for_test import compare_pyasn1_objects, build_sun_hybrid_composite_csr


def _extract_alt_sig(cert: rfc9480.CMPCertificate) -> bytes:
    """Extract the alt signature from the certificate.

    :param cert: The certificate to extract the alt signature from.
    :return: The alt signature as bytes.
    :raises ValueError: If the alt signature extension is not found.
    """
    for x in cert['tbsCertificate']["extensions"]:
        if x['extnID'] == id_altSignatureExt:
            decoded_ext, _ = decoder.decode(x['extnValue'].asOctets(), AltSignatureExt())
            return decoded_ext["plainOrHash"].asOctets()

    raise ValueError("No alt signature extension found.")

class TestSunHybridScheme(unittest.TestCase):
    """Unit tests for the hybrid certificate scheme."""

    def setUp(self):
        """Set up keys and other reusable components for testing."""

        self.composite_key = generate_key("composite-sig-ml-dsa-44-rsa2048",
                                          by_name=True)

        self.issuer_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        self.alt_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        self.common_name = "CN=Hans Mustermann"

        # Currently uses the trad-key as key for the extension.
        self.public_key_bytes = self.composite_key.pq_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.csr = build_sun_hybrid_composite_csr(
            signing_key=self.composite_key,
            common_name=self.common_name,
            pub_key_hash_alg="sha256",
            pub_key_location="https://example.com/pubkey",
            sig_hash_alg="sha256",
            sig_value_location="https://example.com/sig"
        )


    def test_validate_cert_signature(self):
        """
        GIVEN a certificate with an alt signature extension.
        WHEN the extension is validated.
        THEN the extension is correctly validated.
        """
        csr = build_sun_hybrid_composite_csr(
            signing_key=self.composite_key,
            common_name=self.common_name,
            pub_key_hash_alg="sha256",
            pub_key_location="https://example.com/pubkey",
            sig_hash_alg="sha384",
            sig_value_location="https://example.com/sig"
        )

        cert, cert_1 = sun_csr_to_cert(
            csr=csr,
            issuer_private_key=self.issuer_private_key,
            alt_private_key=self.alt_private_key,
            hash_alg="sha256",
        )

        sig = _extract_alt_sig(cert_1)
        validate_alt_sig_extn(cert=cert,
                              alt_pub_key=self.alt_private_key.public_key(), signature=sig)

    def test_build_csr(self):
        """
        GIVEN a composite key and a common name.
        WHEN a CSR is built with the composite key and arguments for the attributes,
        THEN the CSR is correctly built.
        """
        csr = build_sun_hybrid_composite_csr(
            signing_key=self.composite_key,
            common_name=self.common_name,
            pub_key_hash_alg="sha256",
            pub_key_location="https://example.com/pubkey",
            sig_hash_alg="sha256",
            sig_value_location="https://example.com/sig"
        )

        self.assertIsInstance(csr, rfc6402.CertificationRequest)
        self.assertTrue(csr["certificationRequestInfo"].isValue)
        self.assertTrue(csr["signatureAlgorithm"].isValue)
        self.assertTrue(csr["signature"].isValue)

        attributes = csr["certificationRequestInfo"]["attributes"]
        self.assertEqual(len(attributes), 4)

    def test_verify_csr_signature(self):
        """
        GIVEN a CSR with a composite key.
        WHEN the CSR signature is verified,
        THEN the signature is correctly verified.
        """
        csr = build_sun_hybrid_composite_csr(
            signing_key=self.composite_key,
            common_name=self.common_name,
            pub_key_hash_alg="sha256",
            pub_key_location="https://example.com/pubkey",
            sig_hash_alg="sha256",
            sig_value_location="https://example.com/sig"
        )

        verify_csr_signature(csr)

    def test_issue_certificate_from_csr(self):
        """
        GIVEN a CSR with a composite key.
        WHEN a certificate is issued from the CSR,
        THEN the certificate is correctly issued.
        """
        csr = build_sun_hybrid_composite_csr(
            signing_key=self.composite_key,
            common_name=self.common_name,
            pub_key_hash_alg="sha256",
            pub_key_location="https://example.com/pubkey",
            sig_hash_alg="sha256",
            sig_value_location="https://example.com/sig"
        )

        cert, cert_1 = sun_csr_to_cert(
            csr=csr,
            issuer_private_key=self.issuer_private_key,
            alt_private_key=self.alt_private_key,
            hash_alg="sha256",
        )

        self.assertIsInstance(cert, rfc9480.CMPCertificate)
        self.assertIn("tbsCertificate", cert)
        self.assertIn("signatureAlgorithm", cert)
        self.assertIn("signature", cert)

    @patch("pq_logic.hybrid_sig.sun_lamps_hybrid_scheme_00.utils.fetch_value_from_location")
    def test_validate_pub_key_extn(self, mock_fetch):
        """
        GIVEN a certificate with an alt public key extension.
        WHEN the extension is validated.
        THEN the extension is correctly validated.
        """
        mock_fetch.side_effect = [
            self.public_key_bytes,

        ]
        csr = build_sun_hybrid_composite_csr(
            signing_key=self.composite_key,
            common_name=self.common_name,
            pub_key_hash_alg="sha256",
            pub_key_location="https://example.com/pubkey",
            sig_hash_alg="sha256",
            sig_value_location="https://example.com/sig"
        )


        cert_form4, cert_form1 = sun_csr_to_cert(
            csr=csr,
            issuer_private_key=self.issuer_private_key,
            alt_private_key=self.alt_private_key,
            hash_alg="sha256",
        )
        # needs to be called with the form 4 certificate,
        # otherwise needs to apply the conversion to be in form 4 certificate
        validate_alt_pub_key_extn(cert_form4)

    def test_convert_to_form4(self):
        """
        GIVEN a certificate in form 1.
        WHEN the certificate is converted to form 4,
        THEN the certificate is correctly converted.
        """
        csr = build_sun_hybrid_composite_csr(
            signing_key=self.composite_key,
            common_name=self.common_name,
            pub_key_hash_alg="sha256",
            pub_key_location="https://example.com/pubkey",
            sig_hash_alg="sha256",
            sig_value_location="https://example.com/sig"
        )

        cert_form4, cert_form1 = sun_csr_to_cert(
            csr=csr,
            issuer_private_key=self.issuer_private_key,
            alt_private_key=self.alt_private_key,
            hash_alg="sha256",
        )

        cert_form4_other = convert_sun_hybrid_cert_to_target_form(cert_form1, "Form4")

        extn1 = get_extension(extensions=cert_form4["tbsCertificate"]["extensions"],
                              oid=id_altSubPubKeyExt)

        extn2 = get_extension(extensions=cert_form4_other["tbsCertificate"]["extensions"],
                              oid=id_altSubPubKeyExt)

        self.assertTrue(compare_pyasn1_objects(extn1, extn2))
        extn1 = get_extension(extensions=cert_form4["tbsCertificate"]["extensions"],
                              oid=id_altSignatureExt)

        extn2 = get_extension(extensions=cert_form4_other["tbsCertificate"]["extensions"],
                              oid=id_altSignatureExt)

        self.assertTrue(compare_pyasn1_objects(extn1, extn2))
        self.assertTrue(compare_pyasn1_objects(cert_form4, cert_form4_other))

    @patch("pq_logic.hybrid_sig.sun_lamps_hybrid_scheme_00.utils.fetch_value_from_location")
    def test_convert_from4_to_form1(self, mock_fetch):
        """
        GIVEN a certificate in form 4.
        WHEN the certificate is converted to form 1,
        THEN the certificate is correctly converted.
        """
        cert_form4, cert_form1 = sun_csr_to_cert(
            csr=self.csr,
            issuer_private_key=self.issuer_private_key,
            alt_private_key=self.alt_private_key,
            hash_alg="sha512",
        )
        mock_fetch.side_effect = [
            self.public_key_bytes,
            _extract_alt_sig(cert_form1)
        ]

        cert_form1_other = convert_sun_hybrid_cert_to_target_form(cert_form4, "Form1")
        self.assertTrue(compare_pyasn1_objects(cert_form1_other, cert_form1))


if __name__ == "__main__":
    unittest.main()
