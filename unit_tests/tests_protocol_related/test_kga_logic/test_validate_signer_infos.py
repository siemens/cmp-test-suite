# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1_alt_modules import rfc5652
from resources.ca_kga_logic import check_signer_infos
from resources.certutils import parse_certificate
from resources.envdatautils import prepare_signer_infos
from resources.keyutils import load_private_key_from_file
from resources.oid_mapping import compute_hash, sha_alg_name_to_oid
from resources.utils import load_and_decode_pem_file


class TestCheckSignerInfos(unittest.TestCase):
    def setUp(self):
        self.kga_certificate = parse_certificate(load_and_decode_pem_file("data/unittest/ecc_cert_ski.pem"))
        self.key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
        self.eContent = bytes.fromhex("AA" * 32)
        self.dig_alg_id = rfc5652.DigestAlgorithmIdentifier()
        self.dig_alg_id["algorithm"] = sha_alg_name_to_oid("sha256")
        self.signer_infos = prepare_signer_infos(
            signing_key=self.key, cert=self.kga_certificate, e_content=self.eContent, sig_hash_name="sha256"
        )

    def test_valid_signer_info(self):
        """
        GIVEN a valid SignerInfos structure and a digest algorithm identifier.
        WHEN check_signer_infos is called.
        THEN it should return the digest of the eContent and confirm it matches the expected SHA-256 hash.
        """
        result = check_signer_infos(self.signer_infos, self.dig_alg_id, self.kga_certificate)
        self.assertIn("digest_eContent", result)
        self.assertEqual(result["digest_eContent"], compute_hash("sha256", self.eContent))

    def test_invalid_signer_infos_size(self):
        """
        GIVEN a SignerInfos structure with an incorrect size.
        WHEN check_signer_infos is called.
        THEN it should raise a ValueError due to invalid size in the signer information.
        """
        signer_infos_invalid = prepare_signer_infos(
            signing_key=self.key,
            cert=self.kga_certificate,
            e_content=self.eContent,
            sig_hash_name="sha256",
            negative_size=True,
        )

        with self.assertRaises(ValueError):
            check_signer_infos(signer_infos_invalid, self.dig_alg_id, self.kga_certificate)

    def test_invalid_signer_info_version(self):
        """
        GIVEN a SignerInfos structure with an invalid version number
        WHEN check_signer_infos is called.
        THEN it should raise a ValueError because the version must be 3 for valid SignerInfos.
        """
        self.signer_infos[0].setComponentByName("version", 2)
        with self.assertRaises(ValueError):
            check_signer_infos(self.signer_infos, self.dig_alg_id, self.kga_certificate)

    def test_mismatched_signature_digest_algorithms(self):
        """
        GIVEN a SignerInfos structure with mismatched signature and digest algorithms
        WHEN check_signer_infos is called.
        THEN it should raise a ValueError due to the algorithm mismatch between the signature and digest.
        """
        signer_infos = prepare_signer_infos(
            signing_key=self.key,
            cert=self.kga_certificate,
            e_content=self.eContent,
            digest_hash_name="sha256",
            sig_hash_name="sha512",
        )

        with self.assertRaises(ValueError):
            check_signer_infos(signer_infos, self.dig_alg_id, self.kga_certificate)


if __name__ == "__main__":
    unittest.main()
