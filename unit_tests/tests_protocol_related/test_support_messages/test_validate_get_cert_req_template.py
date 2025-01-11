# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import datetime
import unittest

from pyasn1.codec.der import encoder
from pyasn1.codec.der.decoder import decode
from pyasn1_alt_modules import rfc5480, rfc6664, rfc9480, rfc9481
from resources.certbuildutils import prepare_cert_template, prepare_validity
from resources.general_msg_utils import check_controls_for_cert_temp, validate_get_certificate_request_template

from unit_tests.prepare_support_message_structures import (
    build_genp_cert_req_template_content,
    prepare_cert_req_template_content,
    prepare_genp_controls,
)


def _prepare_ec_param():
    """Prepare EC parameter with namedCurve for testing."""
    alg_id = rfc9480.AlgorithmIdentifier()
    alg_id["algorithm"] = rfc6664.id_ecPublicKey
    ec_param = rfc5480.ECParameters()
    ec_param["namedCurve"] = rfc5480.secp256r1
    alg_id["parameters"] = ec_param
    return alg_id


class TestValidateGetCertificateRequestTemplate(unittest.TestCase):

    def test_valid_controls_structure_only_ec(self):
        """
        GIVEN a Controls structure containing only an EC algorithm identifier
        WHEN `check_controls_for_cert_temp` is called
        THEN no errors should be raised, confirming the validity of the structure.
        """
        alg_id = _prepare_ec_param()
        controls = prepare_genp_controls(alg_id=alg_id)
        der_data = encoder.encode(controls)
        controls, rest = decode(der_data, rfc9480.Controls())
        self.assertEqual(rest, b"")
        check_controls_for_cert_temp(controls, rsa_length_min=512)

    def test_invalid_controls_contains_both_ec_and_rsa_key_length(self):
        """
        GIVEN a Controls structure containing both EC algorithm identifier and RSA key length
        WHEN `check_controls_for_cert_temp` is called
        THEN a ValueError should be raised, indicating both cannot coexist.
        """
        alg_id = _prepare_ec_param()
        controls = prepare_genp_controls(alg_id=alg_id, rsa_key_len=512)
        der_data = encoder.encode(controls)
        controls, rest = decode(der_data, rfc9480.Controls())
        self.assertEqual(rest, b"")
        with self.assertRaises(ValueError):
            check_controls_for_cert_temp(controls, rsa_length_min=512)

    def test_invalid_alg_id_inside_controls_structure(self):
        """
        GIVEN a Controls structure containing an invalid algorithm identifier (RSA)
        WHEN `check_controls_for_cert_temp` is called
        THEN a ValueError should be raised, indicating RSA is not allowed.
        """
        alg_id = rfc9480.AlgorithmIdentifier()
        alg_id["algorithm"] = rfc9481.rsaEncryption
        controls = prepare_genp_controls(alg_id=alg_id)
        der_data = encoder.encode(controls)
        controls, rest = decode(der_data, rfc9480.Controls())
        self.assertEqual(rest, b"")
        with self.assertRaises(ValueError):
            check_controls_for_cert_temp(controls)

    def test_complete_correct_genp(self):
        """
        GIVEN a complete and correct CertReqTemplateValue with EC parameters and validity
        WHEN `validate_get_certificate_request_template` is called
        THEN no errors should be raised, indicating a valid certificate request template.
        """
        validity = prepare_validity(datetime.datetime.now(),
                                    datetime.datetime.now() + datetime.timedelta(days=365))
        cert_template = prepare_cert_template(validity=validity, include_fields="validity")
        cert_req_template_value = prepare_cert_req_template_content(
            cert_template=cert_template, key_spec=prepare_genp_controls(alg_id=_prepare_ec_param())
        )
        genp = build_genp_cert_req_template_content(cert_req_template_value)
        validate_get_certificate_request_template(genp)

    def test_missing_controls_must_be_present(self):
        """
        GIVEN a CertReqTemplateValue with controls expected to be present
        WHEN `validate_get_certificate_request_template` is called without controls
        THEN a ValueError should be raised, indicating that controls are missing.
        """
        cert_template = prepare_cert_template(include_fields="subject")
        cert_req_template_value = prepare_cert_req_template_content(cert_template=cert_template, key_spec=None)
        genp = build_genp_cert_req_template_content(cert_req_template_value)
        with self.assertRaises(ValueError):
            validate_get_certificate_request_template(genp, must_be_present=True, control_presents=True)

    def test_invalid_ec_curve_in_controls(self):
        """
        GIVEN a Controls structure with an EC algorithm identifier and an invalid curve
        WHEN `check_controls_for_cert_temp` is called
        THEN a ValueError should be raised, indicating that the curve is unsupported.
        """
        alg_id = rfc9480.AlgorithmIdentifier()
        alg_id["algorithm"] = rfc6664.id_ecPublicKey
        ec_param = rfc5480.ECParameters()
        ec_param["namedCurve"] = rfc5480.rsaEncryption
        alg_id["parameters"] = ec_param
        controls = prepare_genp_controls(alg_id=alg_id)
        der_data = encoder.encode(controls)
        controls, rest = decode(der_data, rfc9480.Controls())
        self.assertEqual(rest, b"")
        with self.assertRaises(ValueError):
            check_controls_for_cert_temp(controls, rsa_length_min=512)


if __name__ == "__main__":
    unittest.main()
