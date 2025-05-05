# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from mock_ca.mock_fun import CertRevStateDB, RevokedEntry, RevokedEntryList

from resources.certbuildutils import build_csr, prepare_cert_template
from resources.certutils import parse_certificate
from resources.cmputils import build_ir_from_key, build_p10cr_from_csr
from resources.keyutils import generate_key, load_private_key_from_file
from resources.utils import load_and_decode_pem_file


class TestCompromisedKeyLogic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert = parse_certificate(load_and_decode_pem_file("data/unittest/bare_certificate.pem"))
        cls.key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)

    def test_check_compromised_key_with_no_entries(self):
        """
        GIVEN an empty entry list.
        WHEN checking if the key is compromised,
        THEN the result should be False.
        """
        entry_list = RevokedEntryList()
        result = entry_list.contains_key(self.cert)
        self.assertFalse(result)

    def test_check_compromised_key(self):
        """
        GIVEN a certificate and a key.
        WHEN checking if the key is compromised,
        THEN the result should be True.
        """
        entry = RevokedEntry(reason="unspecified", cert=self.cert)
        entry_list = RevokedEntryList([entry])

        result = entry_list.contains_key(self.cert)
        self.assertTrue(result)

        cert_template = prepare_cert_template(
            key=self.key,
        )
        result = entry_list.contains_key(cert_template)
        self.assertTrue(result)

    def test_check_compromised_key_composite_sig(self):
        """
        GIVEN a certificate and a composite signature key.
        WHEN checking if the key is compromised,
        THEN the result should be True.
        """
        pq_key = generate_key("ml-dsa-44")
        comp_key = generate_key("composite-sig", trad_key=self.key, pq_key=pq_key)

        rev_entry_list = RevokedEntryList()
        rev_entry_list.add_entry({"reason": "keyCompromise", "cert": self.cert})

        result = rev_entry_list.contains_key(comp_key.public_key())
        self.assertTrue(result)

    def test_check_compromised_key_from_ir(self):
        """
        GIVEN a certificate and an ir.
        WHEN checking if the key is compromised,
        THEN the result should be True.
        """
        ir = build_ir_from_key(self.key)
        cert_rev_db = CertRevStateDB()
        cert_rev_db.add_compromised_key({"reason": "keyCompromise", "cert": self.cert})
        result = cert_rev_db.check_request_for_compromised_key(ir)
        self.assertTrue(result)

    def test_check_compromised_comp_key_from_p10cr(self):
        """
        GIVEN a composite-sig certificate and a p10cr.
        WHEN checking if the key is compromised,
        THEN the result should be True.
        """
        comp_key = generate_key("composite-sig", trad_key=self.key, pq_key=generate_key("ml-dsa-44"))
        csr = build_csr(comp_key)
        cert_rev_db = CertRevStateDB()
        cert_rev_db.add_compromised_key({"reason": "keyCompromise", "cert": self.cert})
        p10cr = build_p10cr_from_csr(csr=csr)
        result = cert_rev_db.check_request_for_compromised_key(p10cr)
        self.assertTrue(result)

    def test_check_compromised_key_from_p10cr(self):
        """
        GIVEN a certificate and a p10cr.
        WHEN checking if the key is compromised,
        THEN the result should be True.
        """
        csr = build_csr(self.key)
        cert_rev_db = CertRevStateDB()
        cert_rev_db.add_compromised_key({"reason": "keyCompromise", "cert": self.cert})
        p10cr = build_p10cr_from_csr(csr=csr)
        result = cert_rev_db.check_request_for_compromised_key(p10cr)
        self.assertTrue(result)

    def test_check_valid_ir(self):
        """
        GIVEN a certificate and a fresh ir.
        WHEN checking if the key is compromised,
        THEN the result should be False.
        """
        for _ in range(10):
            key = generate_key("rsa")
            if key.public_key() != self.key.public_key():
                break

        ir = build_ir_from_key(key)
        cert_rev_db = CertRevStateDB()
        cert_rev_db.add_compromised_key({"reason": "keyCompromise", "cert": self.cert})
        result = cert_rev_db.check_request_for_compromised_key(ir)
        self.assertFalse(result)

    def test_check_valid_p10cr(self):
        """
        GIVEN a certificate and a fresh p10cr.
        WHEN checking if the key is compromised,
        THEN the result should be False.
        """
        for _ in range(10):
            key = generate_key("rsa")
            if key.public_key() != self.key.public_key():
                break

        csr = build_csr(key)
        cert_rev_db = CertRevStateDB()
        cert_rev_db.add_compromised_key({"reason": "keyCompromise", "cert": self.cert})
        p10cr = build_p10cr_from_csr(csr=csr)
        result = cert_rev_db.check_request_for_compromised_key(p10cr)
        self.assertFalse(result)
