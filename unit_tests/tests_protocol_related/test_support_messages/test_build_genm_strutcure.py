# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import datetime
import logging
import os
import unittest
from typing import Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc9480
from resources.certutils import parse_certificate
from resources.general_msg_utils import build_general_message
from resources.utils import load_and_decode_pem_file
from unit_tests.utils_for_test import de_and_encode_pkimessage


def convert_to_asn1cert(cert: Union[rfc9480.CMPCertificate, x509.Certificate]) -> rfc9480.CMPCertificate:  # noqa D417 undocumented-param
    """Ensure the function calling this method, can work with pyasn1 certificates."""
    if isinstance(cert, rfc9480.CMPCertificate):
        return cert
    if isinstance(cert, x509.Certificate):
        data = cert.public_bytes(serialization.Encoding.DER)
        cert, _rest = decoder.decode(data, asn1Spec=rfc9480.CMPCertificate())
        return cert  # type: ignore

    raise ValueError(f"Expected the type of the input to be CertObject not: {type(cert)}")



def generate_certificate_with_idp():
    """Generate a self-signed X.509 certificate with Issuing Distribution Point extension.

    Containing a distinguished name.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
            x509.NameAttribute(NameOID.COMMON_NAME, "TEST_issuing_dp.com"),
        ]
    )
    issuer = subject

    # Define the distinguished name for the Issuing Distribution Point
    issuing_distinguished_name = x509.RelativeDistinguishedName(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "TEST Issuing Distribution Point"),
        ]
    )

    # Build the certificate
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now())
        .not_valid_after(datetime.datetime.now() + datetime.timedelta(days=1))
    )

    idp_extension = x509.IssuingDistributionPoint(
        full_name=None,
        relative_name=issuing_distinguished_name,
        only_contains_user_certs=False,
        only_contains_ca_certs=False,
        only_some_reasons=None,
        indirect_crl=False,
        only_contains_attribute_certs=False,
    )
    cert_builder = cert_builder.add_extension(idp_extension, critical=True)

    certificate = cert_builder.sign(private_key=private_key, algorithm=hashes.SHA256())
    with open("data/unittest/cert_issuing_dp.pem", "wb") as cert_file:
        cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))


def generate_certificate_with_crl_dp():
    """Generate a file to test the Get CRL Update Retrieval."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name.from_rfc4514_string("CN=TEST_issuing_dp.com")
    issuer = subject

    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now())
        .not_valid_after(datetime.datetime.now() + datetime.timedelta(days=1))
    )

    crl_distribution_points = x509.DistributionPoint(
        full_name=[x509.UniformResourceIdentifier("http://crl.testcompany.com/testcompany.crl")],
        relative_name=None,
        reasons=None,
        crl_issuer=None,
    )

    cert_builder = cert_builder.add_extension(x509.CRLDistributionPoints([crl_distribution_points]), critical=False)

    certificate = cert_builder.sign(private_key=private_key, algorithm=hashes.SHA256())

    with open("data/unittest/cert_crl_dp.pem", "wb") as cert_file:
        cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))


def generate_crl():
    """Generate a CRL for the unittest.

    To check if the time can be correctly extracted and set for genm CRL Retrieval message.
    """
    crl_builder = x509.CertificateRevocationListBuilder()

    ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name.from_rfc4514_string("CN=TEST_issuing_dp.com")
    issuer = subject

    crl_builder = crl_builder.issuer_name(issuer)

    revoked_certs = [{"serialNumber": 1, "revocation_date": datetime.datetime.now()}]

    crl_builder = crl_builder.last_update(datetime.datetime.now())
    crl_builder = crl_builder.next_update(datetime.datetime.now() + datetime.timedelta(days=7))

    for cert in revoked_certs:
        revoked_certificate = (
            x509.RevokedCertificateBuilder()
            .serial_number(cert["serialNumber"])
            .revocation_date(cert["revocation_date"])
            .build()
        )

        crl_builder = crl_builder.add_revoked_certificate(revoked_certificate)

    crl = crl_builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    with open("data/unittest/crl_filepath.crl", "wb") as crl_file:
        crl_file.write(crl.public_bytes(serialization.Encoding.PEM))


class TestBuildGeneralMessage(unittest.TestCase):
    def setUp(self):
        if not os.path.isfile("data/unittest/cert_crl_dp.pem"):
            generate_certificate_with_idp()
            generate_certificate_with_crl_dp()
            generate_crl()
        self.sender, self.recipient = "sender", "recipient"
        der_data = load_and_decode_pem_file("data/unittest/cert_crl_dp.pem")
        self.cert = parse_certificate(der_data)
        der_data = load_and_decode_pem_file("data/unittest/cert_issuing_dp.pem")
        self.cert_issuing_dp = parse_certificate(der_data)
        self.crl_filepath = "data/unittest/crl_filepath.crl"

    def test_genm_encode_decode_get_ca_certs(self):
        """
        GIVEN a general message for retrieving CA certificates.
        WHEN the message is encoded using DER and then decoded.
        THEN the decoded message should correctly contain the CA certificates information type.
        """
        add_messages = "get_ca_certs"
        genm = build_general_message(add_messages=add_messages, sender=self.sender, recipient=self.recipient)
        dec_pki_msg = de_and_encode_pkimessage(genm)
        self.assertTrue(dec_pki_msg["body"].getName() == "genm")
        self.assertTrue(
            len(dec_pki_msg["body"]["genm"]) == 1, f"Decoded body looks like: {dec_pki_msg['body'].prettyPrint()}"
        )

        self.assertTrue(
            dec_pki_msg["body"]["genm"][0]["infoType"] == rfc9480.id_it_caCerts,
            f"Decoded body looks like: {dec_pki_msg['body'].prettyPrint()}",
        )

    def test_genm_encode_negative_decode_get_ca_certs(self):
        """
        GIVEN a negative general message for retrieving CA certificates.
        WHEN the message is encoded and decoded.
        THEN the decoded message should still contain the correct CA certificates information type.
        """
        add_messages = "get_ca_certs"
        genm = build_general_message(
            add_messages=add_messages,
            negative=True, sender=self.sender, recipient=self.recipient
        )
        dec_pki_msg = de_and_encode_pkimessage(genm)

        self.assertTrue(dec_pki_msg["body"].getName() == "genm")
        self.assertTrue(
            len(dec_pki_msg["body"]["genm"]) == 1, f"Decoded body looks like: {dec_pki_msg['body'].prettyPrint()}"
        )

        self.assertTrue(
            dec_pki_msg["body"]["genm"][0]["infoType"] == rfc9480.id_it_caCerts,
            f"Decoded body looks like: {dec_pki_msg['body'].prettyPrint()}",
        )

    def test_genm_encode_decode_get_root_ca_cert_update(self):
        """
        GIVEN a general message for retrieving Root CA certificate updates.
        WHEN the message is encoded and decoded.
        THEN the decoded message should correctly contain the Root CA certificate information type.
        """
        add_messages = "get_root_ca_cert_update"
        genm = build_general_message(add_messages=add_messages, sender=self.sender, recipient=self.recipient)
        dec_pki_msg = de_and_encode_pkimessage(genm)
        self.assertTrue(dec_pki_msg["body"].getName() == "genm")
        self.assertTrue(
            len(dec_pki_msg["body"]["genm"]) == 1, f"Decoded body looks like: {dec_pki_msg['body'].prettyPrint()}"
        )

        self.assertTrue(
            dec_pki_msg["body"]["genm"][0]["infoType"] == rfc9480.id_it_rootCaCert,
            f"Decoded body looks like: {dec_pki_msg['body'].prettyPrint()}",
        )

    def test_genm_encode_decode_get_root_ca_cert_update_with_cert(self):
        """
        GIVEN a general message for retrieving Root CA certificate updates with a certificate.
        WHEN the message is encoded and decoded.
        THEN the decoded message should correctly contain the Root CA certificate information type.
        """
        add_messages = "get_root_ca_cert_update"
        genm = build_general_message(
            add_messages=add_messages, ca_cert=self.cert, sender=self.sender, recipient=self.recipient
        )
        dec_pki_msg = de_and_encode_pkimessage(genm)
        self.assertTrue(dec_pki_msg["body"].getName() == "genm")
        self.assertTrue(
            len(dec_pki_msg["body"]["genm"]) == 1, f"Decoded body looks like: {dec_pki_msg['body'].prettyPrint()}"
        )

        self.assertTrue(
            dec_pki_msg["body"]["genm"][0]["infoType"] == rfc9480.id_it_rootCaCert,
            f"Decoded body looks like: {dec_pki_msg['body'].prettyPrint()}",
        )

    def test_genm_encode_decode_get_cert_req_template(self):
        """
        GIVEN a general message for retrieving certificate request templates.
        WHEN the message is encoded and decoded.
        THEN the decoded message should correctly contain the certificate request template information type.
        """
        genm = build_general_message(add_messages="get_cert_template", sender=self.sender, recipient=self.recipient)
        dec_pki_msg = de_and_encode_pkimessage(genm)
        self.assertTrue(dec_pki_msg["body"].getName() == "genm")
        self.assertTrue(
            len(dec_pki_msg["body"]["genm"]) == 1, f"Decoded body looks like: {dec_pki_msg['body'].prettyPrint()}"
        )
        self.assertTrue(
            dec_pki_msg["body"]["genm"][0]["infoType"] == rfc9480.id_it_certReqTemplate,
            f"Decoded body looks like: {dec_pki_msg['body'].prettyPrint()}",
        )
        self.assertFalse(dec_pki_msg["body"]["genm"][0]["infoValue"].isValue)

    def test_genm_encode_decode_get_cert_req_template_neg(self):
        """
        GIVEN a negative general message for retrieving certificate request templates.
        WHEN the message is encoded and decoded.
        THEN the decoded message should still contain the correct certificate request template information type.
        """
        genm = build_general_message(
            add_messages="get_cert_template", negative=True, sender=self.sender, recipient=self.recipient
        )
        dec_pki_msg = de_and_encode_pkimessage(genm)
        self.assertTrue(dec_pki_msg["body"].getName() == "genm")
        self.assertTrue(
            len(dec_pki_msg["body"]["genm"]) == 1, f"Decoded body looks like: {dec_pki_msg['body'].prettyPrint()}"
        )

        self.assertTrue(
            dec_pki_msg["body"]["genm"][0]["infoType"] == rfc9480.id_it_certReqTemplate,
            f"Decoded body looks like: {dec_pki_msg['body'].prettyPrint()}",
        )
        self.assertTrue(dec_pki_msg["body"]["genm"][0]["infoValue"].isValue)

    def test_genm_encode_decode_current_crl(self):
        """
        GIVEN a general message for retrieving the current CRL (Certificate Revocation List).
        WHEN the message is encoded and decoded.
        THEN the decoded message should correctly contain the current CRL information type.
        """
        genm = build_general_message(add_messages="current_crl", sender=self.sender, recipient=self.recipient)
        dec_pki_msg = de_and_encode_pkimessage(genm)
        self.assertTrue(dec_pki_msg["body"].getName() == "genm")
        self.assertTrue(
            len(dec_pki_msg["body"]["genm"]) == 1, f"Decoded body looks like: {dec_pki_msg['body'].prettyPrint()}"
        )
        self.assertTrue(
            dec_pki_msg["body"]["genm"][0]["infoType"] == rfc9480.id_it_currentCRL,
            f"Decoded body looks like: {dec_pki_msg['body'].prettyPrint()}",
        )

    def test_genm_encode_decode_current_crl_neg(self):
        """
        GIVEN a negative general message for retrieving the current CRL.
        WHEN the message is encoded and decoded.
        THEN the decoded message should still contain the correct current CRL information type.
        """
        genm = build_general_message(
            add_messages="current_crl", negative=True, sender=self.sender, recipient=self.recipient
        )
        dec_pki_msg = de_and_encode_pkimessage(genm)
        self.assertTrue(dec_pki_msg["body"].getName() == "genm")
        self.assertTrue(
            len(dec_pki_msg["body"]["genm"]) == 1, f"Decoded body looks like: {dec_pki_msg['body'].prettyPrint()}"
        )
        self.assertTrue(
            dec_pki_msg["body"]["genm"][0]["infoType"] == rfc9480.id_it_currentCRL,
            f"Decoded body looks like: {dec_pki_msg['body'].prettyPrint()}",
        )

    def test_genm_encode_decode_get_crl_update_retrival(self):
        """
        GIVEN a general message for retrieving CRL updates.
        WHEN the message is encoded and decoded.
        THEN the decoded message should correctly contain the CRL status list information type.
        """
        add_messages = "crl_update_ret"
        genm = build_general_message(
            add_messages=add_messages, crl_cert=self.cert, sender=self.sender, recipient=self.recipient
        )
        dec_pki_msg = de_and_encode_pkimessage(genm)
        self.assertTrue(dec_pki_msg["body"].getName() == "genm")
        self.assertTrue(
            len(dec_pki_msg["body"]["genm"]) == 1, f"Decoded body looks like: {dec_pki_msg['body'].prettyPrint()}"
        )
        self.assertTrue(
            dec_pki_msg["body"]["genm"][0]["infoType"] == rfc9480.id_it_crlStatusList,
            f"Decoded body looks like: {dec_pki_msg['body'].prettyPrint()}",
        )

    def test_genm_encode_decode_get_crl_update_retrival_with_idp_extension(self):
        """
        GIVEN a general message for retrieving CRL updates with an Issuing Distribution Point (IDP) extension.
        WHEN the message is encoded and decoded.
        THEN the decoded message should correctly contain the CRL status list information type.
        """
        add_messages = "crl_update_ret"
        genm = build_general_message(
            add_messages=add_messages, crl_cert=self.cert_issuing_dp, sender=self.sender, recipient=self.recipient
        )
        dec_pki_msg = de_and_encode_pkimessage(genm)
        self.assertTrue(dec_pki_msg["body"].getName() == "genm")
        self.assertTrue(
            len(dec_pki_msg["body"]["genm"]) == 1, f"Decoded body looks like: {dec_pki_msg['body'].prettyPrint()}"
        )
        self.assertTrue(
            dec_pki_msg["body"]["genm"][0]["infoType"] == rfc9480.id_it_crlStatusList,
            f"Decoded body looks like: {dec_pki_msg['body'].prettyPrint()}",
        )

    def test_genm_encode_decode_get_crl_update_retrival_with_crl_filepath(self):
        """
        GIVEN a general message for retrieving CRL updates with a CRL file path.
        WHEN the message is encoded and decoded.
        THEN the decoded message should correctly contain the CRL status list information type.
        """
        add_messages = "crl_update_ret"
        genm = build_general_message(
            add_messages=add_messages,
            crl_cert=self.cert,
            crl_filepath=self.crl_filepath,
            sender=self.sender,
            recipient=self.recipient,
        )
        dec_pki_msg = de_and_encode_pkimessage(genm)
        self.assertTrue(dec_pki_msg["body"].getName() == "genm")
        self.assertTrue(
            len(dec_pki_msg["body"]["genm"]) == 1, f"Decoded body looks like: {dec_pki_msg['body'].prettyPrint()}"
        )
        self.assertTrue(
            dec_pki_msg["body"]["genm"][0]["infoType"] == rfc9480.id_it_crlStatusList,
            f"Decoded body looks like: {dec_pki_msg['body'].prettyPrint()}",
        )

    def test_genm_encode_decode_get_crl_update_retrival_neg(self):
        """
        GIVEN a negative general message for retrieving CRL updates.
        WHEN the message is encoded and decoded.
        THEN the decoded message should correctly contain the CRL status list information
        type even with negative updates.
        """
        add_messages = "crl_update_ret"
        genm = build_general_message(
            add_messages=add_messages, crl_cert=self.cert, negative=True, sender=self.sender, recipient=self.recipient
        )
        dec_pki_msg = de_and_encode_pkimessage(genm)
        self.assertTrue(dec_pki_msg["body"].getName() == "genm")
        self.assertTrue(
            len(dec_pki_msg["body"]["genm"]) == 1, f"Decoded body looks like: {dec_pki_msg['body'].prettyPrint()}"
        )
        self.assertTrue(
            dec_pki_msg["body"]["genm"][0]["infoType"] == rfc9480.id_it_crlStatusList,
            f"Decoded body looks like: {dec_pki_msg['body'].prettyPrint()}",
        )

    def test_genm_encode_decode_get_crl_update_ret_with_crl(self):
        """
        GIVEN a general message for retrieving CRL updates with a CRL file.
        WHEN the message is encoded and decoded.
        THEN the decoded message should correctly contain the CRL status list information type.
        """
        add_messages = "crl_update_ret"
        crl_filepath = None
        if crl_filepath is None:
            logging.info("To test genm CRL Retrieval, a `crl_filepath` needs to be provided.")
            return

        genm = build_general_message(
            add_messages=add_messages,
            crl_filepath=crl_filepath,
            crl_cert=self.cert,
            sender=self.sender,
            recipient=self.recipient,
        )
        dec_pki_msg = de_and_encode_pkimessage(genm)
        self.assertTrue(dec_pki_msg["body"].getName() == "genm")
        self.assertTrue(
            len(dec_pki_msg["body"]["genm"]) == 1, f"Decoded body looks like: {dec_pki_msg['body'].prettyPrint()}"
        )
        self.assertTrue(
            dec_pki_msg["body"]["genm"][0]["infoType"] == rfc9480.id_it_crlStatusList,
            f"Decoded body looks like: {dec_pki_msg['body'].prettyPrint()}",
        )

    def test_genm_encode_decode_get_crl_update_retrival_with_cm(self):
        """
        GIVEN a general message for retrieving CRL updates with a custom certificate manager.
        WHEN the message is encoded and decoded.
        THEN the decoded message should correctly contain the CRL status list information type.
        """
        return
        genm = build_general_message(add_messages="crl_update_ret",
                                     ca_crl_url="http://crl.testcompany.com/testcompany.crl",
                                     sender=self.sender, recipient=self.recipient)


        dec_pki_msg = de_and_encode_pkimessage(genm)
        self.assertTrue(dec_pki_msg["body"].getName() == "genm")
        self.assertTrue(len(dec_pki_msg["body"]["genm"]) == 1,
                        f"Decoded body looks like: {dec_pki_msg['body'].prettyPrint()}")
        self.assertTrue(dec_pki_msg["body"]["genm"][0]["infoType"] == rfc9480.id_it_crlStatusList,
                        f"Decoded body looks like: {dec_pki_msg['body'].prettyPrint()}")



if __name__ == "__main__":
    unittest.main()
