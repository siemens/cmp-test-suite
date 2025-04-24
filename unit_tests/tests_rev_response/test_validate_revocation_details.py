# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.asn1utils import is_bit_set
from resources.ca_ra_utils import validate_rev_details
from resources.certbuildutils import prepare_cert_template, build_certificate
from resources.cmputils import prepare_rev_details
from resources.certutils import parse_certificate
from resources.exceptions import AddInfoNotAvailable, BadRequest, CertRevoked, BadCertId
from resources.keyutils import load_private_key_from_file
from resources.utils import load_and_decode_pem_file

class TestValidateRevocationDetails(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.cert = parse_certificate(load_and_decode_pem_file("data/unittest/ca1_cert_ecdsa.pem"))
        cls.private_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")

    def test_valid_rev_details(self):
        """
        GIVEN a valid revocation details.
        WHEN validate_rev_details is called,
        THEN the status must be 'accepted'.
        """
        rev_details = prepare_rev_details(
            cert=self.cert,
            reason="keyCompromise",
        )
        status, data = validate_rev_details(rev_details,
                                            issued_certs=[self.cert],
                                            )
        self.assertEqual(str(status["status"]), "accepted")
        self.assertEqual(data["reason"], "keyCompromise")

    def test_rev_details_invalid_version_in_cert_template(self):
        """
        GIVEN a revocation details with an invalid version in the cert template.
        WHEN validate_rev_details is called,
        THEN a BadRequest exception must be raised.
        """
        cert_template = prepare_cert_template(cert=self.cert,
                                              version=0,
                                              include_fields="version,issuer,serialNumber"
                                              )

        rev_details = prepare_rev_details(
            cert_template=cert_template,
            reason="affiliationChanged",
        )

        with self.assertRaises(BadRequest):
            validate_rev_details(rev_details, issued_certs=[self.cert])


    def test_rev_details_missing_issuer(self):
        """
        GIVEN a revocation details with a missing issuer in the cert template.
        WHEN validate_rev_details is called,
        THEN a BadRequest exception must be raised.
        """
        cert_template = prepare_cert_template(cert=self.cert,
                                              include_fields="serialNumber"

                                              )

        rev_details = prepare_rev_details(
            cert_template=cert_template,
            reason="affiliationChanged",
        )

        with self.assertRaises(AddInfoNotAvailable):
            validate_rev_details(rev_details, issued_certs=[self.cert])


    def test_rev_details_missing_serial_number(self):
        """
        GIVEN a revocation details with a missing serial number in the cert template.
        WHEN validate_rev_details is called,
        THEN a BadRequest exception must be raised.
        """
        cert_template = prepare_cert_template(cert=self.cert,
                                              include_fields="issuer"

                                              )

        rev_details = prepare_rev_details(
            cert_template=cert_template,
            reason="affiliationChanged",
        )

        with self.assertRaises(AddInfoNotAvailable):
            validate_rev_details(rev_details, issued_certs=[self.cert])


    def test_rev_details_cert_revoked(self):
        """
        GIVEN a revocation details with a certificate that is already revoked.
        WHEN validate_rev_details is called,
        THEN the status must be 'rejection' and the failinfo must be 'badRequest'.
        """
        rev_details = prepare_rev_details(
            cert=self.cert,
            reason="keyCompromise",
        )
        with self.assertRaises(CertRevoked):
            validate_rev_details(rev_details,
                                 issued_certs=[self.cert],
                                 revoked_certs=[self.cert]
                                 )

    def test_revive_non_revoked_cert(self):
        """
        GIVEN a revocation details with a certificate that is not revoked.
        WHEN validate_rev_details is called,
        THEN a BadCertId exception must be raised.
        """
        rev_details = prepare_rev_details(
            cert=self.cert,
            reason="removeFromCRL",
        )
        with self.assertRaises(BadCertId):
            validate_rev_details(rev_details,
                                 issued_certs=[self.cert],
                                 revoked_certs=[]
                                 )

    def test_rev_details_unknown_cert(self):
        """
        GIVEN a revocation details with an unknown certificate.
        WHEN validate_rev_details is called,
        THEN a BadCertId exception must be raised.
        """
        cert, _ = build_certificate()
        rev_details = prepare_rev_details(
            cert=cert,
            reason="removeFromCRL",
        )
        with self.assertRaises(BadCertId):
            validate_rev_details(rev_details,
                                 issued_certs=[self.cert],
                                 revoked_certs=[]
                                 )