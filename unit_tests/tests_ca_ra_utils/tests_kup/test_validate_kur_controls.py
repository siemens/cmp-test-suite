# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from resources.asn1_structures import PKIMessageTMP
from resources.ca_ra_utils import validate_kur_controls
from resources.certutils import parse_certificate
from resources.cmputils import build_key_update_request, prepare_controls_structure, prepare_old_cert_id_control
from resources.exceptions import BadRequest, BadCertId
from resources.keyutils import load_private_key_from_file
from resources.utils import load_and_decode_pem_file
from unit_tests.utils_for_test import try_encode_pyasn1
from resources.asn1utils import try_decode_pyasn1


class TestValidateKurControls(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ca_cert = parse_certificate(load_and_decode_pem_file("data/unittest/ca1_cert_ecdsa.pem"))
        cls.private_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        cls.new_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
        cls.cert = parse_certificate(load_and_decode_pem_file("data/unittest/ca2_cert_rsa.pem"))

    def _generate_kur(self, controls) -> PKIMessageTMP:
        kur = build_key_update_request(
            self.new_key,
            cert=self.cert,
            controls=controls,
            exclude_fields=None,
        )
        kur["extraCerts"].extend([self.cert, self.ca_cert])
        der_data = try_encode_pyasn1(kur)
        obj, rest = try_decode_pyasn1(der_data, PKIMessageTMP())
        self.assertEqual(rest, b"")
        return obj # type: ignore

    def test_valid_validate_kur_controls(self):
        """
        GIVEN a valid KUR PKIMessage, with valid controls.
        WHEN the PKIMessage is processed, and a response is built,
        THEN must a PKIMessage with a status of 'accepted' be returned.
        """
        controls = prepare_controls_structure(
            cert=self.cert,
        )
        kur = self._generate_kur(controls)

        validate_kur_controls(
            kur,
            ca_cert=self.ca_cert,
            must_be_present=True,
        )

    def test_invalid_ser_num_validate_kur_controls(self):
        """
        GIVEN a valid KUR PKIMessage with invalid serial number in the OldCertId control.
        WHEN the PKIMessage is processed, and a response is built,
        THEN a BadCertId exception must be raised.
        """
        controls = prepare_old_cert_id_control(
            cert=self.cert,
            bad_issuer=False,
            inc_serial_number=True,
        )
        controls = prepare_controls_structure(
            controls=controls,
        )

        kur = self._generate_kur(controls)

        with self.assertRaises(BadCertId):
            validate_kur_controls(
                kur,
                ca_cert=self.ca_cert,
                must_be_present=True,
            )

    def test_invalid_issuer_validate_kur_controls(self):
        """
        GIVEN a valid KUR PKIMessage with invalid issuer in the OldCertId control.
        WHEN the PKIMessage is processed, and a response is built,
        THEN a BadCertId exception must be raised.
        """
        controls = prepare_old_cert_id_control(
            cert=self.cert,
            bad_issuer=True,
            inc_serial_number=False,
        )
        controls = prepare_controls_structure(
            controls=controls,
        )

        kur = self._generate_kur(controls)

        with self.assertRaises(BadCertId):
            validate_kur_controls(
                kur,
                ca_cert=self.ca_cert,
                must_be_present=True,
            )

