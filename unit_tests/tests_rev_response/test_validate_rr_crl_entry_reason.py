# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1_alt_modules import rfc5280

from resources.ca_ra_utils import validate_rr_crl_entry_details_reason
from resources.certbuildutils import prepare_extensions
from resources.cmputils import prepare_crl_reason_extensions
from resources.exceptions import BadRequest, BadAsn1Data

class TestValidateRRCrlEntryDetailsReason(unittest.TestCase):
    def test_valid_extension_without_must_be(self):
        """
        GIVEN a valid CRL reason extension for "keyCompromise".
        WHEN the extension is validated without specifying a must_be value,
        THEN the function returns the pretty printed CRL reason "keyCompromise"
        """
        ext = prepare_crl_reason_extensions("keyCompromise")
        result = validate_rr_crl_entry_details_reason(ext)
        self.assertEqual(result, rfc5280.CRLReason("keyCompromise").prettyPrint())

    def test_valid_extension_with_matching_must_be(self):
        """
        GIVEN a valid CRL reason extension for "affiliationChanged".
        WHEN the extension is validated with must_be set to "affiliationChanged",
        THEN the function returns "affiliationChanged"
        """
        ext = prepare_crl_reason_extensions("affiliationChanged")
        result = validate_rr_crl_entry_details_reason(ext, must_be="affiliationChanged")
        self.assertEqual(result, "affiliationChanged")

    def test_valid_extension_with_mismatched_must_be_raises_value_error(self):
        """
        GIVEN a valid CRL reason extension for "keyCompromise".
        WHEN the extension is validated with must_be set to a mismatching value "removeFromCRL",
        THEN a ValueError is raised indicating the mismatch
        """
        ext = prepare_crl_reason_extensions("keyCompromise")
        wrong_expected = "removeFromCRL"
        with self.assertRaises(ValueError) as cm:
            validate_rr_crl_entry_details_reason(ext, must_be=wrong_expected)
        self.assertIn("Invalid CRL reason. Expected:", str(cm.exception))

    def test_invalid_number_of_entries_raises_bad_request(self):
        """
        GIVEN an Extensions object with more than one CRL reason entry
        (e.g. "keyCompromise,removeFromCRL").
        WHEN the extension is validated,
        THEN a BadRequest exception is raised indicating an invalid number of entries
        """
        extensions = prepare_crl_reason_extensions("keyCompromise,removeFromCRL")
        with self.assertRaises(BadRequest) as cm:
            validate_rr_crl_entry_details_reason(extensions)
        self.assertIn("Invalid number of entries", str(cm.exception))

    def test_invalid_extnID_raises_bad_request(self):
        """
        GIVEN an Extensions object with an invalid extension ID (generated via prepare_extensions with invalid_extension flag)
        WHEN the extension is validated
        THEN a BadRequest exception is raised indicating an invalid extension ID
        """
        ext = prepare_extensions(invalid_extension=True)
        with self.assertRaises(BadRequest) as cm:
            validate_rr_crl_entry_details_reason(ext)
        self.assertIn("Invalid extension ID", str(cm.exception))

    def test_decode_failure_raises_bad_asn1data(self):
        """
        GIVEN an Extensions object with an extnValue that is not valid DER encoding for a
        CRLReason.
        WHEN the extension is validated,
        THEN a BadAsn1Data exception is raised indicating failure to decode the CRLReason
        """
        ext = prepare_crl_reason_extensions(invalid_der=True)
        with self.assertRaises(BadAsn1Data) as cm:
            validate_rr_crl_entry_details_reason(ext)
        self.assertIn("Failed to decode", str(cm.exception))

    def test_non_empty_decoding_remainder_raises_bad_asn1data(self):
        """
        GIVEN an Extensions object with extra trailing bytes appended to a valid CRLReason.
        WHEN the extension is validated,
        THEN a BadAsn1Data exception is raised due to a non-empty decoding remainder
        """
        ext = prepare_crl_reason_extensions("keyCompromise", add_bytes=True)
        with self.assertRaises(BadAsn1Data) as cm:
            validate_rr_crl_entry_details_reason(ext)
        self.assertIn("CRLReason", str(cm.exception))

    def test_invalid_reason_value_raises_bad_request(self):
        """
        GIVEN an Extensions object with a CRLReason value that is not defined in RFC5280.
        WHEN the extension is validated,
        THEN a BadRequest exception is raised indicating an invalid CRL reason value
        """
        ext = prepare_crl_reason_extensions(invalid_reason=True)
        with self.assertRaises(BadAsn1Data) as cm:
            validate_rr_crl_entry_details_reason(ext)
        self.assertIn("Invalid CRL reason value", str(cm.exception))

    def test_missing_crl_entry_details_raises_bad_request(self):
        """
        GIVEN an empty Extensions object (i.e. no CRL entry details are present)
        WHEN the extension is validated,
        THEN a BadRequest exception is raised indicating that CRL entry details are missing.
        """
        empty_ext = rfc5280.Extensions()
        with self.assertRaises(BadRequest) as cm:
            validate_rr_crl_entry_details_reason(empty_ext)
        self.assertIn("CRL entry details are missing", str(cm.exception))