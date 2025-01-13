# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Help Utility to build pki message structures or other stuff for the unittests and debugging."""

import datetime
import os.path
from typing import List, Optional, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.extensions import ExtensionOID
from pq_logic.tmp_oids import FRODOKEM_NAME_2_OID
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import base, tag, univ
from pyasn1.type.tag import Tag, tagClassContext, tagFormatSimple
from pyasn1_alt_modules import rfc2459, rfc5280, rfc5652, rfc9480
from resources import certutils, cmputils, utils
from resources.certbuildutils import build_certificate
from resources.certutils import parse_certificate
from resources.cmputils import parse_csr
from resources.cryptoutils import verify_signature
from resources.envdatautils import (
    _prepare_pbkdf2,
    prepare_enveloped_data,
    prepare_pwri_structure,
    wrap_key_password_based_key_management_technique,
)
from resources.keyutils import generate_key, load_private_key_from_file, save_key
from resources.typingutils import PrivateKey, PrivateKeySig
from resources.utils import (
    get_openssl_name_notation,
    load_and_decode_pem_file,
    load_certificate_chain,
    write_cmp_certificate_to_pem,
)
from robot.api.deco import not_keyword


def build_pkimessage(body_type="p10cr", **params):
    """Build a PKIMessage for test cases."""
    if body_type == "p10cr":
        parsed_csr = parse_csr(utils.load_and_decode_pem_file("data/example-csr.pem"))
        params["implicit_confirm"] = False
        if params.get("sender") is None:
            params["sender"] = "CN=Hans the Tester"

        if params.get("recipient") is None:
            params["recipient"] = "CN=Hans the Tester"

        pki_message = cmputils.build_p10cr_from_csr(
            csr=parsed_csr,
            **params,
        )
        return pki_message

    if body_type == "error":
        return cmputils.build_cmp_error_message(**params)

    if body_type == "cr":
        params["signing_key"] = params.get("signing_key", params.get("key")) or generate_key()
        return cmputils.build_cr_from_key(**params)

    if body_type == "ir":
        params["signing_key"] = params.get("signing_key", params.get("key")) or generate_key()
        return cmputils.build_cr_from_key(**params)

    raise NotImplementedError("Only used for building the `p10cr` PKIBody.")


def de_and_encode_pkimessage(pki_message: rfc9480.PKIMessage) -> rfc9480.PKIMessage:
    """Encode and decode a given PKIMessage, to simulate getting a message over the wire.

    :param pki_message: The `PKIMessage` object to encode and decode.
    :returns: The decoded `PKIMessage` object.
    :raises ValueError: If the decoded data has leftover bytes,
                        indicating an incomplete or malformed message.
    """
    der_data = encoder.encode(pki_message)
    decoded_message, rest = decoder.decode(der_data, rfc9480.PKIMessage())
    if rest != b"":
        raise ValueError("Decoded message contains unused bytes, indicating incomplete or incorrect decoding.")

    return decoded_message


@not_keyword
def prepare_pki_header(
    sender: Union[str, rfc5280.GeneralName] = "CN=Hans the Tester",
    recipient: str = "CN=Hans the Tester",
    pvno: int = 2,
    sender_kid: Optional[bytes] = None,
) -> rfc9480.PKIHeader:
    """Prepare the PKIHeader for a PKIMessage.

    :param sender_kid: senderKID of the PKIHeader.
    :param sender: the sender of the PKIMessage.
    :param recipient: a str or a pyasn1 `GeneralName` object. the recipient of the PKIMessage.
    :param pvno: the version of the PKIMessage.
    :return: the build PKIHeader object.
    """
    if isinstance(sender, str):
        sender = rfc2459.GeneralName().setComponentByName("rfc822Name", sender)

    recipient = rfc2459.GeneralName().setComponentByName("rfc822Name", recipient)

    pki_header = rfc9480.PKIHeader()
    pki_header.setComponentByName("pvno", univ.Integer(pvno))  # cmp2000
    pki_header.setComponentByName("sender", sender)
    pki_header.setComponentByName("recipient", recipient)

    if sender_kid is not None:
        pki_header["senderKID"] = rfc9480.KeyIdentifier(sender_kid).subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, 2)
        )

    return pki_header


def get_ski_extension(cert: x509.Certificate) -> Union[None, bytes]:
    """Extract the SubjectKeyIdentifier extension from a certificate, if present.

    :param cert: The certificate the extract the extension from.
    :return: None if not present or DER-encoded bytes.
    """
    try:
        ski: x509.Extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)  # type: ignore
        value: x509.SubjectKeyIdentifier = ski.value
        return value.key_identifier

    except x509.ExtensionNotFound:
        return None


def build_certificate_chain(
    length: int = 3, keys: Optional[List[PrivateKeySig]] = None
) -> Tuple[List[rfc9480.CMPCertificate], List[PrivateKeySig]]:
    """Build a certificate chain of specified length.

    :param length: The desired length of the certificate chain.
    :param keys: Optional keys to provided, if to less, new ones will be generated.
    :return: A tuple containing a list of certificates and a list of corresponding private keys.
    """
    certificates = []
    keys = keys if keys is not None else []

    tmp = [generate_key() for _ in range(length)]
    keys += tmp

    root_cert, _ = build_certificate(
        private_key=keys[0],
        common_name="CN=Root CA",
        is_ca=True,  # needed for OpenSSL validation
        key_usage="digitalSignature,keyCertSign",  # not needed, but if a newer version makes it mandatory.
        path_length=length - 2,
        ski=True,
    )
    certificates.append(root_cert)
    previous_cert = root_cert
    previous_key = keys[0]

    for i in range(1, length):
        common_name = f"CN=Intermediate CA {i}" if i < length - 1 else "CN=End Entity"
        is_ca = i < length - 1
        path_length = (length - i - 1) if is_ca else None

        cert, _ = build_certificate(
            private_key=keys[i],
            issuer_cert=previous_cert,
            signing_key=previous_key,
            common_name=common_name,
            key_usage="digitalSignature,keyCertSign",
            is_ca=is_ca,  # needed for OpenSSL validation
            path_length=path_length,
            ski=True,
        )

        certificates.append(cert)
        previous_cert = cert
        previous_key = keys[i]

    return certificates, keys[:length]


def _gen_new_certs() -> None:
    """Generate a certificate chain of six certificates with a specific key configuration and saves them.

    Load the predefined private keys inside the data/keys-directory of the suite.
    Root Key: "private-key-ed25519.pem",
    CA1 Key: "private-key-ecdsa.pem",
    CA2 Key: "private-key-rsa.pem"
    CA3-EE: "private-key-ecdsa.pem"

    The generated files are:
      - `data/unittest/test_cert_chain_len6.pem`: A PEM file containing the entire certificate chain.
      - `data/unittest/root_cert_ed25519.pem`: The root certificate saved as PEM.
      - `data/unittest/ca1_cert_ecdsa.pem`: The next intermediate certificate in the chain saved as PEM.
      - `data/unittest/ca2_cert_rsa.pem`: The following intermediate certificate in the chain saved as PEM.
    """
    root_key = load_private_key_from_file("data/keys/private-key-ed25519.pem", key_type="ed25519")
    ca1_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
    ca2_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
    cert_chain, _ = build_certificate_chain(length=6, keys=[root_key, ca1_key, ca2_key, ca1_key, ca1_key, ca1_key])
    certutils._cert_chain_to_file(cert_chain=cert_chain, path="data/unittest/test_cert_chain_len6.pem")
    utils.write_cmp_certificate_to_pem(cert_chain[0], "data/unittest/root_cert_ed25519.pem")
    utils.write_cmp_certificate_to_pem(cert_chain[1], "data/unittest/ca1_cert_ecdsa.pem")
    utils.write_cmp_certificate_to_pem(cert_chain[2], "data/unittest/ca2_cert_rsa.pem")
    # does also have an invalid time.
    _build_kga_cert_signed_by_root()
    # needs to be valid during OpenSSL verification.
    _generate_crl()


def _generate_crl()-> None:
    """Generate a valid CRL for testing.

    Updates: `crl_sign_cert_ecdsa.pem` and `test_verify_crl.crl`.

    :return: None.
    """
    root_key: ed25519.Ed25519PrivateKey = load_private_key_from_file("data/keys/private-key-ed25519.pem", key_type="ed25519")
    root_cert = parse_certificate(load_and_decode_pem_file("data/unittest/root_cert_ed25519.pem"))
    builder = x509.CertificateRevocationListBuilder()


    ca1_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
    crl_sign_cert, _ = build_certificate(
        private_key=ca1_key,
        issuer_cert=root_cert,
        signing_key=root_key,
        common_name="CN=CA1 CRL Signer",
        key_usage="cRLSign,keyCertSign",
        is_ca=True,
        path_length=None,
        ski=True,
    )
    utils.write_cmp_certificate_to_pem(crl_sign_cert, "data/unittest/crl_sign_cert_ecdsa.pem")

    ca_cert = convert_to_crypto_lib_cert(crl_sign_cert)
    builder = builder.issuer_name(ca_cert.subject)


    builder = builder.last_update(datetime.datetime.now())
    builder = builder.next_update(datetime.datetime.now() + datetime.timedelta(days=30))

    revoked_cert = x509.RevokedCertificateBuilder().serial_number(1234567890).revocation_date(
        datetime.datetime.now()
    ).build()

    builder = builder.add_revoked_certificate(revoked_cert)
    crl = builder.sign(private_key=ca1_key, algorithm=hashes.SHA256())

    with open("data/unittest/test_verify_crl.crl", "wb") as crl_file:
        crl_file.write(crl.public_bytes(Encoding.PEM))


def load_or_generate_cert_chain() -> Tuple[List[Union[rfc9480.CMPCertificate, x509.Certificate]], List[PrivateKeySig]]:
    """Load an existing certificate chain of size six, for testing.

    Filepath: "data/unittest/test_cert_chain_len6.pem".
    If the time is invalid of the certificate chain, a new one is automatically generated and
    written to a file.

    :return: Tuple list of certificates and list of keys.
    """
    ca2_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
    root_key = load_private_key_from_file("data/keys/private-key-ed25519.pem", key_type="ed25519")
    ca1_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")

    if not os.path.isfile("data/unittest/test_cert_chain_len6.pem"):
        _gen_new_certs()

    keys = [root_key, ca1_key, ca2_key, ca1_key, ca1_key, ca1_key]
    cert_chain = load_certificate_chain("data/unittest/test_cert_chain_len6.pem")

    cert: x509.Certificate = convert_to_crypto_lib_cert(cert_chain[0])
    if cert.not_valid_after_utc <= datetime.datetime.now(datetime.timezone.utc):
        _gen_new_certs()

    cert_chain = load_certificate_chain("data/unittest/test_cert_chain_len6.pem")

    return cert_chain, keys


def verify_csr_signature(csr: x509.CertificateSigningRequest):
    """Verify the signature of an X509 CSR using the public key extracted from the CSR.

    :param csr: `cryptography.x509.CertificateSigningRequest` representing the CSR to verify.
    :raises InvalidSignature: If the CSR's signature is not valid.
    """
    verify_signature(
        public_key=csr.public_key(),
        signature=csr.signature,
        data=csr.tbs_certrequest_bytes,
        hash_alg=csr.signature_hash_algorithm,
    )


def compare_certificate_extensions(
    crypto_lib_obj: Union[x509.Certificate, x509.CertificateSigningRequest], asn1_extensions: rfc9480.Extensions
) -> bool:
    """Compare the extensions of a `pyasn1` structure and the extensions of a certificate.

    :param crypto_lib_obj: A certificate or certificate signing request (CSR) from the `cryptography` library.
    :param asn1_extensions: A set of extensions in ASN.1 format (`rfc9480.Extensions`) from pyasn1_alt_modules.
    :return: True if the extensions match, False otherwise.
    """
    cryptography_extensions = crypto_lib_obj.extensions

    if len(cryptography_extensions) != len(asn1_extensions):
        return False

    for ext in cryptography_extensions:
        ext_oid = ext.oid.dotted_string
        match_found = False

        for asn1_ext in asn1_extensions:
            asn1_ext_oid = asn1_ext["extnID"].prettyPrint()

            if ext_oid == asn1_ext_oid:
                if ext.critical != asn1_ext["critical"]:
                    return False

                asn1_ext_value = asn1_ext["extnValue"].asOctets()
                cryptography_ext_value = ext.value.public_bytes()

                if asn1_ext_value != cryptography_ext_value:
                    return False

                match_found = True
                break

        if not match_found:
            return False

    return True


def prepare_cert_for_extensions(extensions: rfc5280.Extensions) -> rfc9480.CMPCertificate:
    """Prepare a CMPCertificate with specified extensions, but nothing more.

    This function creates a `CMPCertificate` object and sets the provided extensions.

    :param extensions: `rfc5280.Extensions` to add to the `CMPCertificate`.
    :return: A populated `rfc9480.CMPCertificate` object.
    """
    # Create the CMPCertificate object
    cert = rfc9480.CMPCertificate()

    tbs_cert = rfc5280.TBSCertificate()
    exts = rfc5280.Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))

    for ext in extensions:
        exts.append(ext)

    tbs_cert["extensions"] = exts
    cert["tbsCertificate"] = tbs_cert

    return cert


def get_subject_and_issuer(cert: rfc9480.CMPCertificate) -> str:
    """Return a concatenated string fo the issuer and subject of a certificate.

    :param cert: object to extract the values from.
    :return: "issuer=%s, subject=%s"
    """
    issuer_name = get_openssl_name_notation(cert["tbsCertificate"]["issuer"])
    subject_name = get_openssl_name_notation(cert["tbsCertificate"]["subject"])
    return f"subject={subject_name}, issuer={issuer_name}"


def print_chain_subject_and_issuer(cert_or_chain: Union[rfc9480.CMPCertificate, List[rfc9480.CMPCertificate]]):
    """Log the subject and issuer details of a certificate or a chain of certificates.

    Used for Debugging. Accepts a single `CMPCertificate` or a list of `CMPCertificate` objects. For each
    certificate in the chain, it retrieves and prints the subject and issuer information.

    :param cert_or_chain: A single `rfc9480.CMPCertificate` or a list of `rfc9480.CMPCertificate` objects representing
                          the certificate chain to print.
    """
    if isinstance(cert_or_chain, rfc9480.CMPCertificate):
        cert_or_chain = [cert_or_chain]

    for cert in cert_or_chain:
        print(get_subject_and_issuer(cert))


def compare_pyasn1_objects(first: base.Asn1Type, second: base.Asn1Type) -> bool:
    """Compare if two pyasn1 structures, by first encoding them and then compare the bytes.

    :param first: The first object to compare.
    :param second: The second object to compare.
    :return: True if the structures are identical; False otherwise.
    """
    return encoder.encode(first) == encoder.encode(second)


@not_keyword
def convert_to_crypto_lib_cert(cert: Union[rfc9480.CMPCertificate, x509.Certificate]) -> x509.Certificate:
    """Ensure the function calling this method, can work with certificates from the 'cryptography' library."""
    if isinstance(cert, Union[rfc9480.CMPCertificate, rfc5280.Certificate]):
        return x509.load_der_x509_certificate(encoder.encode(cert))
    if isinstance(cert, x509.Certificate):
        return cert

    raise ValueError(f"Expected the type of the input to be CertObject not: {type(cert)}")


def _build_certs_root_ca_key_update_content():
    """Generate and save a set of certificates for Root CA key updates.

    This function creates a series of certificates to simulate Root CA key updates:
    - Old Root CA certificate
    - New Root CA certificate signed with its own key
    - New Root CA certificate signed by the old Root CA
    - Old Root CA certificate signed by the new Root CA
    Contains extension to be able to be verified by `pkilint`.
    """
    old_cert, old_key = build_certificate(
        common_name="CN=OldRootCA", is_ca=True, key_usage="digitalSignature,keyCertSign", ski=True
    )
    new_with_new_cert, new_key = build_certificate(
        common_name="CN=NewRootCA", is_ca=True, key_usage="digitalSignature,keyCertSign", ski=True
    )
    new_with_old_cert, _ = build_certificate(
        private_key=new_key,
        common_name="CN=NewRootCA_with_Old",
        issuer_cert=old_cert,
        signing_key=old_key,
    )
    old_with_new_cert, _ = build_certificate(
        private_key=old_key,
        common_name="CN=OldRootCA",
        issuer_cert=new_with_new_cert,
        signing_key=new_key,
    )

    write_cmp_certificate_to_pem(old_cert, "data/unittest/old_root_ca.pem")
    write_cmp_certificate_to_pem(new_with_new_cert, "data/unittest/new_root_ca.pem")
    write_cmp_certificate_to_pem(new_with_old_cert, "data/unittest/new_with_old.pem")
    write_cmp_certificate_to_pem(old_with_new_cert, "data/unittest/old_with_new.pem")


def _build_kga_cert_signed_by_root():
    """Generate and save a KGA certificate signed by a trusted Root CA.

    The KGA certificate is used for key agreement and validation.
    The certificate is saved to the `data/unittest/kga_cert_kari_ecdsa.pem` file.
    """
    # are not time independent, because verified with OpenSSL

    # because the verify cert chain is already test creates a minimal chain.
    root_key = load_private_key_from_file("data/keys/private-key-ed25519.pem", key_type="ed25519")
    root_cert = parse_certificate(load_and_decode_pem_file("data/unittest/root_cert_ed25519.pem"))

    ca1_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
    # This certificate is needed to unwrap the Content-encryption-key.
    # Does not need to be to issue a certificate, is just used for key agreement.
    kga_cert, _ = build_certificate(
        private_key=ca1_key,
        issuer_cert=root_cert,
        signing_key=root_key,
        common_name="CN=KGA EC KARI",
        key_usage="keyAgreement,digitalSignature",  # as in the specification described.
        is_ca=True,
        ski=True,
        path_length=None,
        eku="cmKGA",
    )
    # Remember, this certificate is only used to show that the Other Party is allowed to generate keys
    # for the client, because this certificate has a valid certificate chain, which was
    # signed ba a trust anchor.
    write_cmp_certificate_to_pem(kga_cert, "data/unittest/kga_cert_kari_ecdsa.pem")


def _build_time_indepeneded_certs():
    """Generate time-independent certificates and save them for testing.

    This function prepares various certificates used for testing scenarios:
    - Calls `_build_certs_root_ca_key_update_content` to generate Root CA key update certificates.
    - Generates a KGA certificate for X25519-based key agreement.
    - Ensures certificates are suitable for testing with time-independent checks.
    Which means that the validity period of the certificate can be over.

    Generated certificates are saved to the `data/unittest/` directory.
    """
    _build_certs_root_ca_key_update_content()

    root_key = load_private_key_from_file("data/keys/private-key-ed25519.pem", key_type="ed25519")
    root_cert = parse_certificate(load_and_decode_pem_file("data/unittest/root_cert_ed25519.pem"))
    # used for kari.
    private_key = load_private_key_from_file("data/keys/server-key-x25519.pem", key_type="x25519")
    # cannot be self-signed, because x25519, but otherwise does not need to be signed, by a
    # valid trusted anchor, because it is used for validation of the envelopeData structure,
    # which does not include that check.
    kga_cert, _ = build_certificate(
        private_key=private_key,
        issuer_cert=root_cert,
        signing_key=root_key,
        common_name="CN=CMP Protection Cert For KARI X25519",
        key_usage="keyAgreement",
        is_ca=True,
        ski=True,
        eku="cmKGA,cmcCA",
    )
    write_cmp_certificate_to_pem(kga_cert, "data/unittest/cmp_prot_kari_x25519.pem")
    _build_pq_certs()

def _build_pq_certs():
    mldsa_key = load_private_key_from_file("data/keys/private-key-ml-dsa-65.pem", key_type="ml-dsa-65")
    mlkem_key = load_private_key_from_file("data/keys/private-key-ml-kem-768.pem", key_type="ml-kem-768")
    slh_dsa_key = load_private_key_from_file("data/keys/private-key-slh-dsa-sha2-256f.pem", key_type="slh-dsa")
    mcelliece_key = load_private_key_from_file("data/keys/private-key-mceliece-6960119.pem", key_type="mceliece-6960119")
    composite_sig_rsa = load_private_key_from_file("data/keys/private-key-composite-sig-rsa.pem", key_type="composite-sig")

    cert, key = build_certificate(signing_key=mldsa_key, common_name="CN=PQ Root CA",
                      is_ca=True, path_length=None, ski=True)

    write_cmp_certificate_to_pem(cert, "data/unittest/pq_root_ca_ml_dsa_65.pem")
    cert, key = build_certificate(private_key=mlkem_key,
                                  signing_key=mldsa_key, common_name="CN=PQ ML-KEM 768",
                                  is_ca=False, path_length=None, ski=True)
    write_cmp_certificate_to_pem(cert, "data/unittest/pq_cert_ml_kem_768.pem")
    cert, key = build_certificate(private_key=slh_dsa_key,
                                  signing_key=mldsa_key, common_name="CN=PQ SLH-DSA-SHA2-256f",
                                  is_ca=False, path_length=None, ski=True)
    write_cmp_certificate_to_pem(cert, "data/unittest/pq_root_ca_slh_dsa_sha2_256f.pem")
    cert, key = build_certificate(private_key=mcelliece_key,
                                  signing_key=mldsa_key, common_name="CN=PQ McEliece 6960119",
                                  is_ca=False, path_length=None, ski=True)
    write_cmp_certificate_to_pem(cert, "data/unittest/pq_cert_mceliece_6960119.pem")
    cert, key = build_certificate(private_key=composite_sig_rsa,
                                  signing_key=mldsa_key, common_name="CN=PQ Composite Signature RSA",
                                  is_ca=False, path_length=None, ski=True)
    write_cmp_certificate_to_pem(cert, "data/unittest/pq_root_ca_composite_sig_rsa.pem")


def private_key_to_pkcs8(key: Union[ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey]) -> bytes:
    """Convert a private key to PKCS#8 format and return it as a PEM-encoded byte string.

    Used to compare keys, before and after extracting from the asym. key package.

    :param key: The private key to convert.
    :return: The private key in PKCS#8 PEM format as bytes.
    """
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def compare_cert_chain(chain1: List[rfc9480.CMPCertificate], chain2: List[rfc9480.CMPCertificate]) -> bool:
    """Compare two `pyasn1` certificate chains for equality.

    :param chain1: The first certificate chain.
    :param chain2: The second certificate chain.
    :return: True if the chains are identical; False otherwise.
    """
    for x, y in zip(chain2, chain1):
        if not compare_pyasn1_objects(x, y):
            return False
    return True


def setup_test_data():
    """Prepare test data by generating or loading certificate chains and dependent resources."""
    load_or_generate_cert_chain()
    _build_time_indepeneded_certs()



def _gen_and_save_keys():
    # Generate ML-KEM keys
    save_key(generate_key("ml-kem-1024"), "data/keys/private-key-ml-kem-1024.pem")
    save_key(generate_key("ml-kem-768"), "data/keys/private-key-ml-kem-768.pem")
    save_key(generate_key("ml-kem-512"), "data/keys/private-key-ml-kem-512.pem")
    # Generate ML-DSA keys
    save_key(generate_key("ml-dsa-44"), "data/keys/private-key-ml-dsa-44.pem")
    save_key(generate_key("ml-dsa-65"), "data/keys/private-key-ml-dsa-65.pem")
    save_key(generate_key("ml-dsa-87"), "data/keys/private-key-ml-dsa-87.pem")
    # Generate SLH-DSA keys
    save_key(generate_key("slh-dsa-sha2-256f"), "data/keys/private-key-slh-dsa-sha2-256f.pem")
    save_key(generate_key("slh-dsa-sha2-192s"), "data/keys/private-key-slh-dsa-sha2-192s.pem")
    save_key(generate_key("slh-dsa-sha2-192f"), "data/keys/private-key-slh-dsa-sha2-192f.pem")
    save_key(generate_key("slh-dsa-sha2-128s"), "data/keys/private-key-slh-dsa-sha2-128s.pem")
    save_key(generate_key("slh-dsa-sha2-128f"), "data/keys/private-key-slh-dsa-sha2-128f.pem")
    save_key(generate_key("slh-dsa-shake-256s"), "data/keys/private-key-slh-dsa-shake-256s.pem")
    save_key(generate_key("slh-dsa-shake-256f"), "data/keys/private-key-slh-dsa-shake-256f.pem")
    save_key(generate_key("slh-dsa-shake-192s"), "data/keys/private-key-slh-dsa-shake-192s.pem")
    save_key(generate_key("slh-dsa-shake-192f"), "data/keys/private-key-slh-dsa-shake-192f.pem")
    save_key(generate_key("slh-dsa-shake-128s"), "data/keys/private-key-slh-dsa-shake-128s.pem")
    save_key(generate_key("slh-dsa-shake-128f"), "data/keys/private-key-slh-dsa-shake-128f.pem")







def _save_tmp_kem_pq_certs():
    """Generate and save a set of certificates for PQ algorithms.

    Which have not finalized OIDs yet.
    FrodoKEM, sntrup761 and McEliece.
    """

    mldsa_key = load_private_key_from_file("data/keys/private-key-ml-dsa-44.pem")
    mldsa_cert = parse_certificate(load_and_decode_pem_file("data/unittest/pq_root_ca_ml_dsa_44.pem"))


    # Generate McEliece keys
    save_key(generate_key("mceliece-348864"), "data/keys/private-key-mceliece-348864.pem")
    save_key(generate_key("mceliece-6960119"), "data/keys/private-key-mceliece-6960119.pem")
    save_key(generate_key("mceliece-8192128"), "data/keys/private-key-mceliece-8192128.pem")


    # Generate NTRU key:
    save_key(generate_key("sntrup761"), "data/keys/private-key-sntrup761.pem")

    cert, _ = build_certificate(private_key=load_private_key_from_file("data/keys/private-key-sntrup761.pem"),
                                signing_key=mldsa_key, common_name="CN=PQ KEM SNTRUP761", issuer_cert=mldsa_cert)

    write_cmp_certificate_to_pem(cert, "data/unittest/pq_cert_sntrup761.pem")

    # Generate FrodoKEM keys
    for x in FRODOKEM_NAME_2_OID:
        save_key(generate_key(x), f"data/keys/private-key-{x}.pem")

    frodo_cert, _ = build_certificate(private_key=load_private_key_from_file("data/keys/private-key-frodokem-976-aes.pem"),
                                      signing_key=mldsa_key, common_name="CN=PQ KEM FrodoKEM 976 AES", issuer_cert=mldsa_cert)
    write_cmp_certificate_to_pem(frodo_cert, "data/unittest/pq_cert_frodokem_976_aes.pem")



    mc_key = load_private_key_from_file("data/keys/private-key-mceliece-6960119.pem", key_type="mceliece-6960119")
    mc_cert, _ = build_certificate(private_key=mc_key, signing_key=mldsa_key,
                                   common_name="CN=PQ KEM McEliece 6960119", issuer_cert=mldsa_cert)
    write_cmp_certificate_to_pem(mc_cert, "data/unittest/pq_cert_mceliece_6960119.pem")




def _generate_pq_certs():

    _gen_and_save_keys()

    # Generate PQ Signature certs:
    mldsa_key = load_private_key_from_file("data/keys/private-key-ml-dsa-65.pem", key_type="ml-dsa-65")
    mldsa_cert, _ = build_certificate(private_key=mldsa_key, common_name="CN=PQ Root CA MLDSA 65")
    write_cmp_certificate_to_pem(mldsa_cert, "data/unittest/pq_root_ca_ml_dsa_65.pem")

    mldsa_key44 = load_private_key_from_file("data/keys/private-key-ml-dsa-44.pem")
    mldsa_cert44, _ = build_certificate(private_key=mldsa_key44, common_name="CN=PQ Root CA MLDSA 44")
    write_cmp_certificate_to_pem(mldsa_cert44, "data/unittest/pq_root_ca_ml_dsa_44.pem")

    slh_dsa_key = load_private_key_from_file("data/keys/private-key-slh-dsa-sha2-256f.pem", key_type="slh-dsa")
    slh_dsa_cert, _ = build_certificate(private_key=slh_dsa_key, common_name="CN=PQ Root CA SLH-DSA-SHA2-256f")
    write_cmp_certificate_to_pem(slh_dsa_cert, "data/unittest/pq_root_ca_slh_dsa_sha2_256f.pem")

    # Generate PQ KEM certs:
    mlkem_key = load_private_key_from_file("data/keys/private-key-ml-kem-768.pem", key_type="ml-kem-768")
    mlkem_cert, _ = build_certificate(private_key=mlkem_key, signing_key=mldsa_key,
                                      common_name="CN=MLKEM 768", issuer_cert=mldsa_cert)
    write_cmp_certificate_to_pem(mlkem_cert, "data/unittest/pq_cert_ml_kem_768.pem")


    _save_composite_sig()
    _save_xwing()
    _save_composite_kem()


def _save_composite_sig():
    """Generate a self-signed Composite signature Key."""
    key = generate_key("composite-sig", trad_name="rsa", length="2048", pq_name="ml-dsa-44")
    save_key(key, "data/keys/private-key-composite-sig-rsa2048-ml-dsa-44.pem")
    cert, _ = build_certificate(private_key=key, common_name="CN=Hybrid Root CompositeSig RSA2048 ML-DSA-44")
    write_cmp_certificate_to_pem(cert, "data/unittest/pq_root_ca_composite_sig_rsa2048_ml_dsa_44.pem")

    key = generate_key("composite-sig", trad_name="ed448", pq_name="ml-dsa-87")
    save_key(key, "data/keys/private-key-composite-sig-ed448-ml-dsa-87.pem")
    cert, _ = build_certificate(private_key=key, common_name="CN=Hybrid Root CompositeSig ED448 ML-DSA-87")
    write_cmp_certificate_to_pem(cert, "data/unittest/pq_root_ca_composite_sig_ed448_ml_dsa_87.pem")

def _save_xwing():
    """Generate and save two X-Wing keys and certificates for testing."""

    mldsa_key = load_private_key_from_file("data/keys/private-key-ml-dsa-44.pem")
    ml_dsa_cert = parse_certificate(load_and_decode_pem_file("data/unittest/pq_root_ca_ml_dsa_44.pem"))

    # xwing
    key = generate_key("xwing")
    save_key(key, "data/keys/private-key-xwing.pem")

    xwing_key = key
    xwing_cert, _ = build_certificate(private_key=xwing_key, signing_key=mldsa_key, issuer_cert=ml_dsa_cert,
                                      common_name="CN=Hybrid Key X-Wing")
    write_cmp_certificate_to_pem(xwing_cert, "data/unittest/hybrid_cert_xwing.pem")

    key2 = generate_key("xwing")
    save_key(key2, "data/keys/private-key-xwing-other.pem")
    xwing_cert2, _ = build_certificate(private_key=key2,
                                       signing_key=mldsa_key,
                                       issuer_cert=ml_dsa_cert,
                                       common_name="CN=Hybrid Key X-Wing Other")

    write_cmp_certificate_to_pem(xwing_cert2, "data/unittest/hybrid_cert_xwing_other.pem")


def _save_composite_kem():
    """Generate and save Composite-KEM keys and certificates for testing."""

    mldsa_key = load_private_key_from_file("data/keys/private-key-ml-dsa-44.pem")
    ml_dsa_cert = parse_certificate(load_and_decode_pem_file("data/unittest/pq_root_ca_ml_dsa_44.pem"))


    key = generate_key("composite-kem", trad_name="rsa", length="2048", pq_name="ml-kem-768")
    save_key(key, "data/keys/private-key-composite-kem-ml-kem-768-rsa2048.pem")
    cert, _ = build_certificate(private_key=key,
                                signing_key=mldsa_key,
                                issuer_cert=ml_dsa_cert,
                                common_name="CN=PQ CompositeKEM ML-KEM-768 RSA2048"

                                )
    write_cmp_certificate_to_pem(cert, "data/unittest/hybrid_cert_composite_kem_ml_kem_768_rsa2048.pem")

    key = generate_key("composite-kem", trad_name="x25519", pq_name="ml-kem-768")
    save_key(key, "data/keys/private-key-composite-kem-ml-kem-1024-x25519.pem")
    cert, _ = build_certificate(private_key=key,
                                signing_key=mldsa_key,
                                issuer_cert=ml_dsa_cert,
                                common_name="CN=Hybrid CompositeKEM ML-KEM-1024 x25519")

    key = generate_key("composite-kem", trad_name="x448", pq_name="ml-kem-1024")
    save_key(key, "data/keys/private-key-composite-kem-ml-kem-1024-x448.pem")
    cert, _ = build_certificate(private_key=key,
                                signing_key=mldsa_key,
                                issuer_cert=ml_dsa_cert,
                                common_name="CN=Hybrid CompositeKEM ML-KEM-1024 X448")

    write_cmp_certificate_to_pem(cert, "data/unittest/hybrid_cert_composite_kem_ml_kem_1024_x448.pem")

    key = generate_key(algorithm="composite-kem", pq_name="frodokem-976-aes",  trad_name="rsa", length="2048")
    save_key(key, "data/keys/private-key-composite-kem-frodokem-976-aes-rsa2048.pem")
    cert, _ = build_certificate(private_key=key,
                                signing_key=mldsa_key,
                                issuer_cert=ml_dsa_cert,
                                common_name="CN=Hybrid CompositeKEM FrodoKEM-976-AES RSA2048")
    write_cmp_certificate_to_pem(cert, "data/unittest/hybrid_cert_composite_kem_frodokem_976_aes_rsa2048.pem")

    key = generate_key(algorithm="composite-kem", pq_name="frodokem-976-aes",  trad_name="x25519")
    save_key(key, "data/keys/private-key-composite-kem-frodokem-976-aes-x25519.pem")
    cert, _ = build_certificate(private_key=key,
                                signing_key=mldsa_key,
                                issuer_cert=ml_dsa_cert,
                                common_name="CN=Hybrid CompositeKEM FrodoKEM-976-AES x25519")
    write_cmp_certificate_to_pem(cert, "data/unittest/hybrid_cert_composite_kem_frodokem_976_aes_x25519.pem")

    key = generate_key(algorithm="composite-kem", pq_name="frodokem-976-shake",  trad_name="x25519")
    save_key(key, "data/keys/private-key-composite-kem-frodokem-976-shake-x25519.pem")
    cert, _ = build_certificate(private_key=key,
                                signing_key=mldsa_key,
                                issuer_cert=ml_dsa_cert,
                                common_name="CN=Hybrid CompositeKEM FrodoKEM-976-SHAKE x25519")
    write_cmp_certificate_to_pem(cert, "data/unittest/hybrid_cert_composite_kem_frodokem_976_shake_x25519.pem")


    # Chempat




def crypto_lib_private_key_to_der(private_key: PrivateKey):
    """Convert a private key to DER-encoded bytes.

    :param private_key: The `PrivateKey` to encode.
    :return: The DER-encoded bytes representing the private key.
    """
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return private_key_bytes


def der_to_crypto_lib_private_key(private_key_bytes: bytes):
    """Convert DER-encoded bytes to a cryptographic library private key.

    Loads a private key from DER-encoded bytes into a usable `PrivateKey` format.

    :param private_key_bytes: The DER-encoded bytes representing the private key.
    :return: The `PrivateKey` object initialized from the DER encoding.
    """
    private_key = serialization.load_der_private_key(private_key_bytes, password=None)
    return private_key


def prepare_default_pwri_env_data(
    password: str = "TEST_PASSWORD",
    content_encryption_key: bytes = b"CCCCCCCCCCCCCCCC",
    signed_data: bytes = b"SSSSSSSSSSSSSSSS",
) -> rfc5652.EnvelopedData:
    """Prepare default `EnvelopedData` structure with password recipient information.

    This structure is only created if an `envelopedData` structure is needed.

    :param password: The password used to encrypt the content encryption key. Default to "TEST_PASSWORD".
    :param content_encryption_key: The content encryption key which is saved as
    an encrypted key inside the envelopeData structure. Default to b"CCCCCCCCCCCCCCCC".
    :param signed_data: The signed data structure as bytes. Default to b"SSSSSSSSSSSSSSSS".
    :return:
    """
    encrypted_key = wrap_key_password_based_key_management_technique(
        password=password, key_to_wrap=content_encryption_key, parameters=_prepare_pbkdf2()
    )

    pwri = prepare_pwri_structure(encrypted_key=encrypted_key)
    recip_info = rfc5652.RecipientInfo()
    recip_info = recip_info.setComponentByName("pwri", pwri)
    return prepare_enveloped_data(
        recipient_infos=[recip_info], version=0, cek=content_encryption_key, data_to_protect=signed_data
    )


def update_cert_and_keys():
    """Generate new PQ and Hybrid keys and certificates."""
    _save_composite_sig()
    _save_xwing()
    _save_composite_kem()
