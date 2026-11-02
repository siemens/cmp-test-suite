# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.codec.der import decoder
from pyasn1.codec.der.encoder import encode
from pyasn1_alt_modules import rfc4211, rfc9480
from resources.certbuildutils import build_certificate, prepare_cert_template
from resources.convertutils import pyasn1_time_obj_to_py_datetime


class TestPrepareCertTemplate(unittest.TestCase):
    def test_prepare_rr_cert_template_basic(self):
        """
        GIVEN a `pyasn1` `rfc9480.CMPCertificate` with the Subject Key Identifier extension
        WHEN prepare_cert_template is called, excluding serialNumber, publicKey, and validity.
        THEN the returned CertTemplate should have the extensions, issuer, and subject fields populated,
        and DER encoding/decoding should succeed without leftover data.
        """
        cert, key = build_certificate(include_ski=True)
        cert_template = prepare_cert_template(cert=cert, exclude_fields="serialNumber,publicKey, validity")
        self.assertTrue(cert_template["extensions"].isValue)
        self.assertTrue(cert_template["issuer"].isValue)
        self.assertTrue(cert_template["subject"].isValue)

        der_data = encode(cert_template)
        new_object, rest = decoder.decode(der_data, rfc4211.CertTemplate())
        self.assertEqual(rest, b"")

    def test_prepare_rr_cert_template_basic_without_extensions(self):
        """
        GIVEN a `pyasn1` `rfc9480.CMPCertificate`.
        WHEN prepare_cert_template is called, excluding serialNumber, publicKey, and validity.
        THEN the returned CertTemplate should not have the `extensions` field set,
        but the issuer and subject fields should be populated, and DER encoding/decoding should succeed.
        """
        cert, key = build_certificate()
        cert_template = prepare_cert_template(cert=cert, exclude_fields="serialNumber,publicKey, validity")
        self.assertFalse(cert_template["extensions"].isValue)
        self.assertTrue(cert_template["issuer"].isValue)
        self.assertTrue(cert_template["subject"].isValue)

        der_data = encode(cert_template)
        new_object, rest = decoder.decode(der_data, rfc4211.CertTemplate())
        self.assertEqual(rest, b"")

    def test_prepare_rr_cert_template_num(self):
        """
        GIVEN a `pyasn1` `rfc9480.CMPCertificate`.
        WHEN prepare_cert_template is called, excluding extensions, publicKey, and validity.
        THEN the returned CertTemplate should have the serialNumber, issuer, and subject fields populated,
        and DER encoding/decoding should succeed without leftover data.
        """
        cert, key = build_certificate()
        cert_template = prepare_cert_template(cert=cert, exclude_fields="extensions, publicKey,validity")
        self.assertTrue(cert_template["serialNumber"].isValue)
        self.assertTrue(cert_template["issuer"].isValue)
        self.assertTrue(cert_template["subject"].isValue)
        der_data = encode(cert_template)
        cert_temp_object, rest = decoder.decode(der_data, rfc9480.CertTemplate())
        self.assertEqual(rest, b"")

    def test_prepare_cert_template_validity(self):
        """
        GIVEN a `pyasn1` `rfc9480.CMPCertificate`.
        WHEN prepare_cert_template is called, including only the validity field.
        THEN the returned CertTemplate should only have the validity field populated,
        and the notBefore and notAfter values should match the certificate's validity period.
        """
        cert, key = build_certificate()
        cert_template = prepare_cert_template(cert=cert, include_fields="validity")
        options = set(list(cert_template.keys()))
        sum_up = sum([cert_template[x].isValue for x in options])
        self.assertTrue(sum_up == 1)
        der_data = encode(cert_template)
        cert_temp_object, rest = decoder.decode(der_data, rfc9480.CertTemplate())
        self.assertEqual(rest, b"")
        validity_obj = cert_template["validity"]
        not_valid_before_utc = pyasn1_time_obj_to_py_datetime(cert["tbsCertificate"]["validity"]["notBefore"])
        not_valid_after_utc = pyasn1_time_obj_to_py_datetime(cert["tbsCertificate"]["validity"]["notAfter"])
        self.assertEqual(not_valid_before_utc, pyasn1_time_obj_to_py_datetime(validity_obj["notBefore"]))
        self.assertEqual(not_valid_after_utc, pyasn1_time_obj_to_py_datetime(validity_obj["notAfter"]))

    def test_prepare_cert_template_keeps_multi_rdn_names(self):
        """
        GIVEN a `pyasn1` `rfc9480.CMPCertificate` whose issuer and subject have several RDNs.
        WHEN prepare_cert_template is called with the certificate.
        THEN the issuer and subject of the CertTemplate must be DER-identical to those of the certificate.
        """
        cert, key = build_certificate(common_name="CN=Test CA,O=Test Org,C=DE")
        cert_template = prepare_cert_template(cert=cert, include_fields="issuer,subject")
        for field in ["issuer", "subject"]:
            self.assertEqual(
                encode(cert_template[field]["rdnSequence"]),
                encode(cert["tbsCertificate"][field]["rdnSequence"]),
            )

    def test_prepare_cert_template_does_not_share_names_with_cert(self):
        """
        GIVEN a `pyasn1` `rfc9480.CMPCertificate`.
        WHEN prepare_cert_template is called with the certificate and the issuer of the template is changed.
        THEN the issuer of the certificate must stay unchanged.
        """
        cert, key = build_certificate(common_name="CN=Test CA,O=Test Org,C=DE")
        issuer_der = encode(cert["tbsCertificate"]["issuer"]["rdnSequence"])
        cert_template = prepare_cert_template(cert=cert, include_fields="issuer,serialNumber")
        cert_template["issuer"]["rdnSequence"].clear()
        self.assertEqual(encode(cert["tbsCertificate"]["issuer"]["rdnSequence"]), issuer_der)


if __name__ == "__main__":
    unittest.main()
