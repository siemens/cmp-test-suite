# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pq_logic.tmp_oids import id_ad_certDiscovery, id_ad_relatedCertificateDescriptor
from pq_logic.hybrid_sig.certdiscovery import (
    extract_related_cert_des_from_sis_extension,
    prepare_subject_info_access_syntax_extension,
)
from pq_logic.hybrid_structures import RelatedCertificateDescriptor
from pyasn1.codec.der import decoder
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280, rfc9481
from resources.certbuildutils import generate_certificate
from resources.keyutils import generate_key


class TestCertDiscovery(unittest.TestCase):

    def setUp(self):
        rsa_public_key = rfc5280.AlgorithmIdentifier()
        rsa_public_key['algorithm'] = rfc9481.rsaEncryption
        rsa_public_key['parameters'] = univ.Null("")
        self.pub_key_alg_id = rsa_public_key

        rsa_with_sha256 = rfc5280.AlgorithmIdentifier()
        rsa_with_sha256['algorithm'] = rfc9481.sha256WithRSAEncryption
        rsa_with_sha256['parameters'] = univ.Null("")
        self.sig_alg_id = rsa_with_sha256

        private_key = generate_key("rsa")
        self.cert = generate_certificate(private_key=private_key, hash_alg="sha256")

        self.url = "https://example.com/secondary_certificate.pem"

    def test_simple_prepare(self):
        """
        GIVEN a URL.
        WHEN preparing a SubjectInfoAccess extension for certificate discovery.
        THEN the extension should be correctly prepared.
        """
        extension = prepare_subject_info_access_syntax_extension(
            url=self.url,
            critical=False,
        )
        encoded_extension = encode(extension)
        decoded_extension, rest = decode(encoded_extension, asn1Spec=rfc5280.Extension())
        self.assertEqual(rest, b"")


    def test_prepare_subject_info_access_syntax_extension(self):
        """
        GIVEN a URL, a signature algorithm and a public key algorithm.
        WHEN preparing a SubjectInfoAccess extension for certificate discovery.
        THEN the extension should be correctly prepared.
        """
        extension = prepare_subject_info_access_syntax_extension(
            url=self.url,
            critical=False,
            signature_algorithm=self.sig_alg_id,
            public_key_algorithm=self.pub_key_alg_id
        )
        encoded_extension = encode(extension)
        decoded_extension, rest = decode(encoded_extension, asn1Spec=rfc5280.Extension())
        self.assertEqual(rest, b"")

        self.assertEqual(decoded_extension['extnID'], rfc5280.id_pe_subjectInfoAccess, "extnID should match id_ad_certDiscovery.")
        self.assertFalse(decoded_extension['critical'], "Critical flag should be False.")

        sia, rest = decoder.decode(decoded_extension['extnValue'].asOctets(), rfc5280.SubjectInfoAccessSyntax())
        self.assertEqual(rest, b"")
        self.assertEqual(len(sia), 1)

        access_description = sia[0]
        self.assertEqual(access_description['accessMethod'], id_ad_certDiscovery, "accessMethod should match id_ad_certDiscovery.")

        other_name = access_description['accessLocation']['otherName']
        self.assertEqual(other_name['type-id'], id_ad_relatedCertificateDescriptor, "type-id should match id_ad_relatedCertificateDescriptor.")

        descriptor, _ = decoder.decode(sia[0]['accessLocation']['otherName']["value"], RelatedCertificateDescriptor())

        self.assertEqual(str(descriptor['uniformResourceIdentifier']), self.url, "URL should match the input value.")
        self.assertEqual(descriptor['signatureAlgorithm']['algorithm'], self.sig_alg_id['algorithm'], "Signature algorithm should match.")
        self.assertEqual(descriptor['publicKeyAlgorithm']['algorithm'], self.pub_key_alg_id['algorithm'], "Public key algorithm should match.")

    def test_parse_sia_extension_for_cert_discovery(self):
        """
        GIVEN a SubjectInfoAccess extension with a single access description.
        WHEN extracting the descriptor for certificate discovery.
        THEN the descriptor should be correctly extracted.
        """
        extension = prepare_subject_info_access_syntax_extension(
            url=self.url,
            critical=False,
            signature_algorithm=self.sig_alg_id,
            public_key_algorithm=self.pub_key_alg_id
        )

        descriptor = extract_related_cert_des_from_sis_extension(extension, index=0)

        self.assertEqual(str(descriptor['uniformResourceIdentifier']), self.url, "URL should match the input value.")
        self.assertEqual(descriptor['signatureAlgorithm']['algorithm'], self.sig_alg_id['algorithm'], "Signature algorithm should match.")
        self.assertEqual(descriptor['publicKeyAlgorithm']['algorithm'], self.pub_key_alg_id['algorithm'], "Public key algorithm should match.")


    def test_prepare_with_cert(self):
        """
        GIVEN a certificate and a URL.
        WHEN preparing a SubjectInfoAccess extension for certificate discovery.
        THEN the extension should be correctly prepared.
        """
        extension = prepare_subject_info_access_syntax_extension(
            url=self.url,
            critical=False,
            other_cert=self.cert,
        )
        encoded_extension = encode(extension)
        decoded_extension, rest = decode(encoded_extension, asn1Spec=rfc5280.Extension())
        self.assertEqual(rest, b"")

        self.assertEqual(decoded_extension['extnID'], rfc5280.id_pe_subjectInfoAccess, "extnID should match id_ad_certDiscovery.")
        self.assertFalse(decoded_extension['critical'], "Critical flag should be False.")

        sia, rest = decoder.decode(decoded_extension['extnValue'].asOctets(), rfc5280.SubjectInfoAccessSyntax())
        self.assertEqual(rest, b"")

        descriptor, _ = decoder.decode(sia[0]['accessLocation']['otherName']["value"], RelatedCertificateDescriptor())

        self.assertEqual(str(descriptor['uniformResourceIdentifier']), self.url, "URL should match the input value.")
        self.assertEqual(descriptor['signatureAlgorithm']['algorithm'], self.sig_alg_id['algorithm'], "Signature algorithm should match.")
        self.assertEqual(descriptor['publicKeyAlgorithm']['algorithm'], self.pub_key_alg_id['algorithm'], "Public key algorithm should match.")


if __name__ == "__main__":
    unittest.main()
