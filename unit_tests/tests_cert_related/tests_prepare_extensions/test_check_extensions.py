# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import unittest

from pyasn1.type import univ
from pyasn1_alt_modules import rfc9480, rfc5280

from resources.asn1utils import try_decode_pyasn1
from resources.certbuildutils import prepare_extensions, prepare_cert_template, check_extensions, prepare_ski_extension, \
    prepare_key_usage_extension, prepare_subject_alt_name_extension
from resources.certextractutils import get_extension
from resources.exceptions import BadCertTemplate
from resources.keyutils import load_private_key_from_file

def _check_extensions_are_unique(extensions: rfc9480.Extensions) -> bool:
    """Check that the extensions are unique."""
    seen = set()
    for ext in extensions:
        if ext["extnID"] in seen:
            return False
        seen.add(ext["extnID"])
    return True

class TestCheckExtensions(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)

    def _prepare_template(self, extn: rfc9480.Extensions):
        """Prepare a certificate template."""
        return prepare_cert_template(
            subject="CN=Hans the Tester",
            key=self.key,
            extensions=extn,
        )

    def test_check_extensions_are_correctly_parsed(self):
        """
        GIVEN a certificate template with extensions and other extensions.
        WHEN the extensions are checked.
        THEN the extensions should be correctly parsed.
        """
        extn = prepare_extensions(is_ca=True, critical=True, key=self.key, ca_key=self.key.public_key())
        other_extn = prepare_extensions(is_ca=True, critical=True, key=self.key, ca_key=self.key.public_key())
        cert_template = self._prepare_template(extn)
        out_extn = check_extensions(cert_template,
                                    ca_public_key=self.key.public_key(),
                                    allow_basic_con_non_crit=False,
                                    other_extensions=other_extn,
                                    )
        self.assertTrue(_check_extensions_are_unique(out_extn))

    def test_valid_extensions_no_other_extensions(self):
        """
        GIVEN a certificate template with valid extensions and no other_extensions provided.
        WHEN check_extensions is called.
        THEN all required (non-None) extensions are returned and are unique.
        """
        extn = prepare_extensions(is_ca=True, critical=True, key=self.key, ca_key=self.key.public_key())
        cert_template = self._prepare_template(extn)
        out_extn = check_extensions(
            cert_template,
            ca_public_key=self.key.public_key(),
            allow_basic_con_non_crit=False,
            other_extensions=None,
        )
        self.assertTrue(len(out_extn) > 0, "Expected validated extensions to be returned.")
        self.assertTrue(_check_extensions_are_unique(out_extn), "Returned extensions are not unique.")

    def test_with_other_extensions_partial(self):
        """
        GIVEN a certificate template with valid extensions and an other_extensions list
              that already contains some of the required extensions.
        WHEN check_extensions is called.
        THEN only the missing extensions are added.
        """
        # has size 3, BasicConstraints, SubjectKeyIdentifier, AuthorityKeyIdentifier
        extn = prepare_extensions(is_ca=True, critical=True,
                                  ca_key=self.key.public_key(),
                                  key=self.key,
                                  )
        self.assertEqual(len(extn), 3, "Expected 3 extensions to be present.")
        cert_template = self._prepare_template(extn)


        ski_extn = prepare_ski_extension(self.key.public_key())
        key_usage_ext = prepare_key_usage_extension(key_usage="digitalSignature")

        other_extns = [key_usage_ext, ski_extn]

        out_extn = check_extensions(
            cert_template,
            ca_public_key=self.key.public_key(),
            allow_basic_con_non_crit=False,
            other_extensions=other_extns,
        )
        self.assertEqual(len(out_extn), 4)
        self.assertTrue(_check_extensions_are_unique(out_extn))

    def test_unknown_extensions_not_allowed(self):
        """
        GIVEN a certificate template that includes an unknown extension.
        WHEN check_extensions is called with allow_unknown_extns set to False.
        THEN a BadCertTemplate exception is raised.
        """
        extn = prepare_extensions(is_ca=True, critical=True, key=self.key, ca_key=self.key.public_key(), invalid_extension=True)
        cert_template = self._prepare_template(extn)
        with self.assertRaises(BadCertTemplate):
            check_extensions(
                cert_template,
                ca_public_key=self.key.public_key(),
                allow_unknown_extns=False,
                allow_basic_con_non_crit=False,
            )

    def test_unknown_extensions_allowed(self):
        """
        GIVEN a certificate template that includes an unknown extension.
        WHEN check_extensions is called with allow_unknown_extns set to True.
        THEN the unknown extension is ignored and the validated extensions are returned.
        """
        unknown_ext = rfc5280.Extension()
        unknown_ext["extnID"] = univ.ObjectIdentifier("1.2.3.4.5.6")
        unknown_ext["critical"] = True
        unknown_ext["extnValue"] = univ.OctetString(b"dummy")
        extn = prepare_extensions(is_ca=True, critical=True, key=self.key, ca_key=self.key.public_key())
        extn.append(unknown_ext)
        cert_template = self._prepare_template(extn)
        out_extn = check_extensions(
            cert_template,
            ca_public_key=self.key.public_key(),
            allow_unknown_extns=True,
            allow_basic_con_non_crit=False,
        )
        self.assertTrue(_check_extensions_are_unique(out_extn), "Returned extensions are not unique.")

    def test_no_validated_extensions(self):
        """
        GIVEN a certificate template with an empty Extensions structure.
        WHEN check_extensions is called.
        THEN an empty Extensions structure is returned.
        """
        empty_ext = rfc5280.Extensions()
        cert_template = self._prepare_template(empty_ext)
        out_extn = check_extensions(
            cert_template,
            ca_public_key=self.key.public_key(),
            allow_basic_con_non_crit=False,
            other_extensions=None,
        )
        self.assertEqual(len(out_extn), 0, "Expected no validated extensions when template is empty.")

    def test_basic_constraints_non_critical_not_allowed(self):
        """
        GIVEN a certificate template with a basicConstraints extension that is not marked critical.
        WHEN check_extensions is called with allow_basic_con_non_crit set to False.
        THEN a BadCertTemplate exception is raised.
        """
        extn = prepare_extensions(is_ca=True, critical=True, key=self.key, ca_key=self.key.public_key())
        # Modify the basicConstraints extension to be non-critical.
        basic_con_oid = rfc5280.id_ce_basicConstraints
        basic_con_ext = get_extension(extn, basic_con_oid)
        if basic_con_ext is not None:
            basic_con_ext["critical"] = False
        cert_template = self._prepare_template(extn)
        with self.assertRaises(BadCertTemplate):
            check_extensions(
                cert_template,
                ca_public_key=self.key.public_key(),
                allow_basic_con_non_crit=False,
            )

    def test_empty_other_extensions_list(self):
        """
        GIVEN a certificate template with valid extensions and an empty list provided as other_extensions.
        WHEN check_extensions is called,
        THEN the validated extensions from the template are returned.
        """
        extn = prepare_extensions(is_ca=True, critical=True, key=self.key, ca_key=self.key.public_key())
        cert_template = self._prepare_template(extn)
        out_extn = check_extensions(
            cert_template,
            ca_public_key=self.key.public_key(),
            other_extensions=[],
        )
        self.assertTrue(len(out_extn) > 0, "Expected validated extensions when other_extensions is an empty list.")
        self.assertTrue(_check_extensions_are_unique(out_extn), "Returned extensions are not unique.")

    def test_subject_null_dn_and_san_not_present(self):
        """
        GIVEN a certificate template with a null subject DN and no SAN extension.
        WHEN check_extensions is called,
        THEN a BadCertTemplate exception is raised.
        """
        extn = prepare_extensions(is_ca=True, critical=True, key=self.key,
                                  ca_key=self.key.public_key())

        cert_template = prepare_cert_template(
            subject="Null-DN",
            key=self.key,
            extensions=extn,
        )

        with self.assertRaises(BadCertTemplate):
            check_extensions(
                cert_template,
                ca_public_key=self.key.public_key(),
            )

    def test_subject_null_dn_and_san_present(self):
        """
        GIVEN a certificate template with a null subject DN and a SAN extension.
        WHEN check_extensions is called,
        THEN the validated extensions and corrected SAN extension is returned.
        """
        # MUST be critical if the subject is Null-DN.
        san_extn = prepare_subject_alt_name_extension("example.com", critical=True)

        cert_template = prepare_cert_template(
            subject="Null-DN",
            key=self.key,
            extensions=[san_extn],
        )

        out_extn = check_extensions(
            cert_template,
            ca_public_key=self.key.public_key(),
        )
        extn = get_extension(out_extn, rfc5280.id_ce_subjectAltName)
        self.assertIsNotNone(extn, "Expected a SAN extension to be present.")
        self.assertTrue(bool(extn["critical"]), "Expected the SAN extension to be non-critical.")

    def test_subject_null_dn_and_san_present_correct(self):
        """
        GIVEN a certificate template with a null subject DN and a SAN extension.
        WHEN check_extensions is called,
        THEN the validated extensions and corrected SAN extension is returned.
        """
        # MUST be critical if the subject is Null-DN.
        san_extn = prepare_subject_alt_name_extension("example.com", critical=False)

        cert_template = prepare_cert_template(
            subject="Null-DN",
            key=self.key,
            extensions=[san_extn],
        )

        out_extn = check_extensions(
            cert_template,
            ca_public_key=self.key.public_key(),
        )
        extn = get_extension(out_extn, rfc5280.id_ce_subjectAltName)
        self.assertIsNotNone(extn, "Expected a SAN extension to be present.")
        der_data = extn["extnValue"].asOctets()
        san, rest = try_decode_pyasn1(der_data, rfc5280.GeneralNames())
        san: rfc5280.GeneralNames
        self.assertEqual(rest, b"")
        self.assertEqual(str(san[0]["dNSName"]), "example.com")
        self.assertTrue(bool(extn["critical"]), "Expected the SAN extension to be critical.")

    def test_subject_null_dn_and_san_present_correct_non_null(self):
        """
        GIVEN a certificate template with a non-null subject DN and a SAN extension.
        WHEN check_extensions is called,
        THEN the validated extensions and corrected SAN extension is returned.
        """
        # MUST be not critical if the subject is a non-Null DN.
        san_extn = prepare_subject_alt_name_extension("example.com", critical=True)

        cert_template = prepare_cert_template(
            subject="CN=Hans the Tester",
            key=self.key,
            extensions=[san_extn],
        )

        out_extn = check_extensions(
            cert_template,
            ca_public_key=self.key.public_key(),
        )
        extn = get_extension(out_extn, rfc5280.id_ce_subjectAltName)
        self.assertIsNotNone(extn, "Expected a SAN extension to be present.")
        der_data = extn["extnValue"].asOctets()
        san, rest = try_decode_pyasn1(der_data, rfc5280.GeneralNames())
        san: rfc5280.GeneralNames
        self.assertEqual(rest, b"")
        self.assertEqual(str(san[0]["dNSName"]), "example.com")
        self.assertFalse(bool(extn["critical"]), "Expected the SAN extension to be not critical.")


if __name__ == "__main__":
    unittest.main()
