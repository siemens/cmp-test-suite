# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest
from datetime import datetime

from pq_logic.hybrid_sig.chameleon_logic import prepare_dcd_extension_from_delta
from resources.asn1utils import encode_to_der
from resources.certbuildutils import (
    build_certificate,
    compare_ski_value,
    prepare_authority_key_identifier_extension,
    prepare_crl_distribution_point_extension,
    prepare_issuing_distribution_point_extension,
    prepare_ski_extension,
    prepare_validity,
)
from resources.compareutils import compare_pyasn1_names
from resources.convertutils import pyasn1_time_obj_to_py_datetime
from resources.keyutils import load_private_key_from_file
from resources.utils import get_openssl_name_notation
from unit_tests.utils_for_test import load_ca_cert_and_key


class TestPrepareDCDExtensionFromDelta(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ec_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        cls.mldsa_key = load_private_key_from_file("data/keys/private-key-ml-dsa-44-seed.pem")
        cls.ca_cert, cls.ca_key = load_ca_cert_and_key()

    def test_prepare_dcd_extension_from_delta_with_dif_validity(self):
        """
        GIVEN a delta certificate with a different validity period than the base certificate.
        WHEN preparing the DCD extension,
        THEN the validity period is correctly set.
        """
        not_before = datetime(2023, 1, 1)
        not_after = datetime(2023, 1, 2)
        not_after_delta = datetime(2023, 1, 20)
        validity = prepare_validity(not_before=not_before, not_after=not_after)
        validity_delta = prepare_validity(
            not_before=not_before,
            not_after=not_after_delta,
        )
        base_cert, _ = build_certificate(
            self.ec_key,
            common_name="CN=Hans the Tester",
            validity=validity,
            serial_number=1,
        )
        delta_cert, _ = build_certificate(
            self.mldsa_key,
            common_name="CN=Hans the Tester",
            base_cert=base_cert,
            validity=validity_delta,
            serial_number=3,
        )

        self.assertEqual(
            pyasn1_time_obj_to_py_datetime(
                delta_cert["tbsCertificate"]["validity"]["notBefore"],
            ).date(),
            not_before.date(),
        )
        self.assertEqual(
            pyasn1_time_obj_to_py_datetime(
                delta_cert["tbsCertificate"]["validity"]["notAfter"],
            ).date(),
            not_after_delta.date(),
        )

        delta_cert_des = prepare_dcd_extension_from_delta(delta_cert=delta_cert, base_cert=base_cert)
        self.assertEqual(
            3,
            int(delta_cert_des["serialNumber"]),
        )

        val1 = encode_to_der(delta_cert["tbsCertificate"]["validity"])
        val2 = encode_to_der(base_cert["tbsCertificate"]["validity"])
        self.assertFalse(
            val1 == val2,
            "Validity should be different.",
        )

        self.assertTrue(
            delta_cert_des["validity"].isValue,
            "Validity should be set.",
        )
        self.assertEqual(
            pyasn1_time_obj_to_py_datetime(
                delta_cert_des["validity"]["notBefore"],
            ).date(),
            not_before.date(),
        )
        self.assertEqual(
            pyasn1_time_obj_to_py_datetime(
                delta_cert_des["validity"]["notAfter"],
            ).date(),
            not_after_delta.date(),
        )

    def test_prepare_dcd_extension_from_delta_with_dif_issuer_and_subject(self):
        """
        GIVEN a delta certificate with a different issuer and subject than the base certificate.
        WHEN preparing the DCD extension,
        THEN the extension is correctly prepared.
        """
        not_before = datetime(2023, 1, 1)
        not_after = datetime(2023, 1, 2)
        validity = prepare_validity(not_before, not_after)

        base_issuer_cert, _ = build_certificate("rsa", common_name="CN=Base Issuer")
        delta_issuer_cert, _ = build_certificate(
            "rsa",
            common_name="CN=Delta Issuer",
        )
        base_cert, _ = build_certificate(
            self.ec_key, common_name="CN=Base Cert", validity=validity, serial_number=1, ca_cert=base_issuer_cert
        )
        delta_cert, _ = build_certificate(
            self.mldsa_key,
            common_name="CN=Delta Cert",
            base_cert=base_cert,
            serial_number=3,
            validity=validity,
            ca_cert=delta_issuer_cert,
        )
        delta_cert_des = prepare_dcd_extension_from_delta(delta_cert=delta_cert, base_cert=base_cert)
        self.assertEqual(
            3,
            int(delta_cert_des["serialNumber"]),
        )
        self.assertFalse(
            delta_cert_des["validity"].isValue,
            "Validity should be absent.",
        )
        self.assertTrue(
            compare_pyasn1_names(
                delta_cert["tbsCertificate"]["subject"],
                delta_cert_des["subject"],
                "without_tag",
            ),
            "Subject should be equal.",
        )
        self.assertEqual(get_openssl_name_notation(delta_cert["tbsCertificate"]["subject"]), "CN=Delta Cert")

        self.assertTrue(
            compare_pyasn1_names(
                delta_cert["tbsCertificate"]["issuer"],
                delta_cert_des["issuer"],
                "without_tag",
            ),
            "Subject should be equal.",
        )
        self.assertEqual(get_openssl_name_notation(delta_cert["tbsCertificate"]["issuer"]), "CN=Delta Issuer")

    def test_prepare_dcd_extension_from_delta_with_diff_extensions(self):
        """
        GIVEN a delta certificate with a ski extension than the base certificate.
        WHEN preparing the DCD extension,
        THEN the extension is correctly prepared.
        """
        base_cert, _ = build_certificate(
            self.ec_key,
            common_name="CN=Base Cert",
            serial_number=1,
            include_ski=True,
        )
        delta_cert, _ = build_certificate(
            self.mldsa_key,
            common_name="CN=Delta Cert",
            base_cert=base_cert,
            serial_number=3,
            include_ski=True,
        )
        delta_cert_des = prepare_dcd_extension_from_delta(delta_cert=delta_cert, base_cert=base_cert)
        self.assertEqual(
            3,
            int(delta_cert_des["serialNumber"]),
        )
        self.assertEqual(1, len(delta_cert_des["extensions"]))
        self.assertTrue(compare_ski_value(delta_cert_des["extensions"], self.mldsa_key))

    def test_prepare_dcd_extension_from_delta_with_more_extensions(self):
        """
        GIVEN a delta certificate with different extensions than the base certificate.
        WHEN preparing the DCD extension,
        THEN the extensions are correctly prepared.
        """
        unique_extn = prepare_issuing_distribution_point_extension(
            full_name="CN=Issuer",
        )

        cdp1 = prepare_crl_distribution_point_extension(
            full_name="https://example.com/crl",
            critical=False,
        )
        cdp2 = prepare_crl_distribution_point_extension(
            full_name="https://example.com/crl2",
            critical=False,
        )

        aki1 = prepare_authority_key_identifier_extension(
            ca_cert=self.ca_cert,
            ca_key=self.ca_key.public_key(),
            critical=False,
        )
        aki2 = prepare_authority_key_identifier_extension(
            ca_cert=self.ca_cert,
            ca_key=self.ca_key.public_key(),
            critical=True,
        )

        ski1 = prepare_ski_extension(
            key=self.ec_key.public_key(),
            critical=False,
        )

        ski2 = prepare_ski_extension(
            key=self.mldsa_key.public_key(),
            critical=False,
        )

        base_cert, _ = build_certificate(
            self.ec_key,
            common_name="CN=Base Cert",
            serial_number=1,
            extensions=[cdp1, unique_extn, aki1, ski1],
        )
        delta_cert, _ = build_certificate(
            self.mldsa_key,
            common_name="CN=Delta Cert",
            base_cert=base_cert,
            serial_number=3,
            extensions=[cdp2, aki2, ski2],
        )
        delta_cert_des = prepare_dcd_extension_from_delta(delta_cert=delta_cert, base_cert=base_cert)
        self.assertEqual(
            3,
            int(delta_cert_des["serialNumber"]),
        )
        self.assertEqual(3, len(delta_cert_des["extensions"]))
        self.assertTrue(compare_ski_value(delta_cert_des["extensions"], self.mldsa_key))
