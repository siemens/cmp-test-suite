# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Help Utility to build pki message structures or other stuff for the unittests and debugging."""

import base64
import importlib.util
import os
import os.path
import textwrap
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa, x448, x25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import AuthorityKeyIdentifier
from cryptography.x509.extensions import ExtensionOID
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import base, tag, univ
from pyasn1.type.tag import Tag, tagClassContext, tagFormatSimple
from pyasn1_alt_modules import rfc2459, rfc5280, rfc5652, rfc6402, rfc8018, rfc9480, rfc9481, rfc9629
from robot.api.deco import not_keyword

from pq_logic.hybrid_sig.sun_lamps_hybrid_scheme_00 import prepare_sun_hybrid_csr_attributes
from pq_logic.keys.composite_sig import CompositeSigPrivateKey
from pq_logic.keys.pq_stateful_sig_factory import PQStatefulSigFactory
from pq_logic.tmp_oids import FRODOKEM_NAME_2_OID
from resources import certutils, cmputils, utils
from resources.asn1_structures import PKIMessageTMP
from resources.asn1utils import try_decode_pyasn1, encode_to_der
from resources.certbuildutils import build_certificate, build_csr, prepare_extensions, \
    prepare_basic_constraints_extension, prepare_ski_extension, prepare_authority_key_identifier_extension, \
    prepare_key_usage_extension, sign_csr
from resources.certutils import parse_certificate, build_cert_chain_from_dir, \
    load_public_key_from_cert, write_cert_chain_to_file
from resources.cmputils import parse_csr
from resources.convertutils import str_to_bytes
from resources.cryptoutils import verify_signature
from resources.envdatautils import (
    prepare_enveloped_data,
    wrap_key_password_based_key_management_technique,
)
from resources.exceptions import BadAsn1Data, MismatchingKey
from resources.keyutils import generate_key, load_private_key_from_file, save_key
from resources.oid_mapping import may_return_oid_to_name
from resources.oidutils import EXTENSION_OID_2_NAME
from resources.prepare_alg_ids import prepare_pbkdf2_alg_id
from resources.typingutils import PrivateKey, SignKey
from resources.utils import (
    get_openssl_name_notation,
    load_and_decode_pem_file,
    load_certificate_chain,
    write_cmp_certificate_to_pem,
)

if importlib.util.find_spec("oqs") is not None:
    import oqs  # pylint: disable=import-error
else:
    oqs = None  # pylint: disable=invalid-name


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


def try_encode_pyasn1(data, exclude_pretty_print: bool = False) -> bytes:
    """Try to encode a pyasn1 object and raise a BadAsn1Data exception if it fails.

    :param data: The pyasn1 object to encode.
    :param exclude_pretty_print: If True, the exception message will not include the pretty-printed data.
    :return: The encoded data.
    """
    try:
        return encoder.encode(data)
    except Exception:
        data = data.prettyPrint() if not exclude_pretty_print else str(type(data))
        raise BadAsn1Data(f"Error encoding data: \n{data}", overwrite=True)


def de_and_encode_pkimessage(pki_message: PKIMessageTMP) -> PKIMessageTMP:
    """Encode and decode a given PKIMessage, to simulate getting a message over the wire.

    :param pki_message: The `PKIMessage` object to encode and decode.
    :returns: The decoded `PKIMessage` object.
    :raises ValueError: If the decoded data has leftover bytes,
                        indicating an incomplete or malformed message.
    """
    der_data = try_encode_pyasn1(pki_message, exclude_pretty_print=True)
    decoded_message, rest = try_decode_pyasn1(der_data, asn1_spec=PKIMessageTMP())
    if rest != b"":
        raise ValueError("Decoded message contains unused bytes, indicating incomplete or incorrect decoding.")

    return decoded_message  # type: ignore


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
    length: int = 3, keys: Optional[List[SignKey]] = None
) -> Tuple[List[rfc9480.CMPCertificate], List[SignKey]]:
    """Build a certificate chain of specified length.

    :param length: The desired length of the certificate chain.
    :param keys: Optional keys to provided, if to less, new ones will be generated.
    :return: A tuple containing a list of certificates and a list of corresponding private keys.
    """
    certificates = []
    keys = keys if keys is not None else []

    tmp = [generate_key() for _ in range(length)]
    keys += tmp

    # Is CA is needed for OpenSSL validation.
    extensions = _prepare_root_ca_extensions(keys[0])

    root_cert, _ = build_certificate(
        private_key=keys[0],
        common_name="CN=Root CA",
        extensions=extensions,
    )
    certificates.append(root_cert)
    previous_cert = root_cert
    previous_key = keys[0]

    for i in range(1, length):
        common_name = f"CN=Intermediate CA {i}" if i < length - 1 else "CN=End Entity"
        # is_ca = i < length - 1
        # path_length = (length - i - 1) if is_ca else None

        extensions = _prepare_ca_ra_extensions(issuer_key=previous_key, key=keys[i], for_ca=True)

        cert, _ = build_certificate(
            private_key=keys[i],
            ca_cert=previous_cert,
            ca_key=previous_key,
            common_name=common_name,
            extensions=extensions,
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
    root_key = load_private_key_from_file("data/keys/private-key-ed25519.pem")
    ca1_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
    ca2_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
    cert_chain, _ = build_certificate_chain(length=6, keys=[root_key, ca1_key, ca2_key, ca1_key, ca1_key, ca1_key])
    certutils.write_cert_chain_to_file(cert_chain=cert_chain, path="data/unittest/test_cert_chain_len6.pem")
    utils.write_cmp_certificate_to_pem(cert_chain[0], "data/unittest/root_cert_ed25519.pem")
    utils.write_cmp_certificate_to_pem(cert_chain[1], "data/unittest/ca1_cert_ecdsa.pem")
    utils.write_cmp_certificate_to_pem(cert_chain[2], "data/unittest/ca2_cert_rsa.pem")
    # does also have an invalid time.
    _build_kga_cert_signed_by_root()
    # needs to be valid during OpenSSL verification.
    _generate_crl()
    _generate_other_trusted_pki_certs()


def _generate_crl() -> None:
    """Generate a valid CRL for testing.

    Updates: `crl_sign_cert_ecdsa.pem` and `test_verify_crl.crl`.

    :return: None.
    """
    root_key: ed25519.Ed25519PrivateKey = load_private_key_from_file("data/keys/private-key-ed25519.pem")
    root_cert = parse_certificate(load_and_decode_pem_file("data/unittest/root_cert_ed25519.pem"))
    builder = x509.CertificateRevocationListBuilder()

    ca1_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
    crl_sign_cert, _ = build_certificate(
        private_key=ca1_key,
        ca_cert=root_cert,
        ca_key=root_key,
        common_name="CN=CA1 CRL Signer",
        key_usage="cRLSign,keyCertSign",
        is_ca=True,
        path_length=None,
        include_ski=True,
    )
    utils.write_cmp_certificate_to_pem(crl_sign_cert, "data/unittest/crl_sign_cert_ecdsa.pem")

    ca_cert = convert_to_crypto_lib_cert(crl_sign_cert)
    builder = builder.issuer_name(ca_cert.subject)

    builder = builder.last_update(datetime.now())
    builder = builder.next_update(datetime.now() + timedelta(days=30))

    revoked_cert = x509.RevokedCertificateBuilder().serial_number(1234567890).revocation_date(datetime.now()).build()

    builder = builder.add_revoked_certificate(revoked_cert)
    crl = builder.sign(private_key=ca1_key, algorithm=hashes.SHA256())

    with open("data/unittest/test_verify_crl.crl", "wb") as crl_file:
        crl_file.write(crl.public_bytes(Encoding.PEM))


def load_or_generate_cert_chain() -> Tuple[List[rfc9480.CMPCertificate], List[SignKey]]:
    """Load an existing certificate chain of size six, for testing.

    Filepath: "data/unittest/test_cert_chain_len6.pem".
    If the time is invalid of the certificate chain, a new one is automatically generated and
    written to a file.

    :return: Tuple list of certificates and list of keys.
    """
    ca2_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
    root_key = load_private_key_from_file("data/keys/private-key-ed25519.pem")
    ca1_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")

    if not os.path.isfile("data/unittest/test_cert_chain_len6.pem"):
        _gen_new_certs()

    keys = [root_key, ca1_key, ca2_key, ca1_key, ca1_key, ca1_key]
    cert_chain = load_certificate_chain("data/unittest/test_cert_chain_len6.pem")

    cert: x509.Certificate = convert_to_crypto_lib_cert(cert_chain[0])
    if cert.not_valid_after_utc <= datetime.now(timezone.utc):
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


def get_subject_and_issuer(cert: Union[rfc9480.CMPCertificate, rfc5652.CertificateChoices]) -> str:
    """Return a concatenated string of the issuer and subject of a certificate.

    :param cert: The certificate to extract the issuer and subject from.
    :return: "issuer=%s, subject=%s"
    """
    if isinstance(cert, rfc5652.CertificateChoices):
        cert = cert["certificate"]

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

def print_extensions(extensions: rfc9480.Extensions) -> None:
    """Print the extensions in a human-readable format.

    :param extensions: The `Extensions` object to print.
    """
    for ext in extensions:
        extn_id = ext["extnID"]
        name = EXTENSION_OID_2_NAME.get(extn_id)
        critical = ext["critical"]
        extn_value = ext["extnValue"].prettyPrint()
        print(f"Extension {name} ID: {extn_id}, Critical: {critical}, Value: {extn_value}")

def compare_pyasn1_objects(first: base.Asn1Type, second: base.Asn1Type) -> bool:
    """Compare if two pyasn1 structures, by first encoding them and then compare the bytes.

    :param first: The first object to compare.
    :param second: The second object to compare.
    :return: True if the structures are identical; False otherwise.
    """
    result = encoder.encode(first) == encoder.encode(second)
    if not result:
        for field in first.keys():  # type: ignore
            if encoder.encode(first[field]) != encoder.encode(first[field]):  # type: ignore
                print(f"{field}: {first[field].prettyPrint()} != {second[field].prettyPrint()}")  # type: ignore

    return result


@not_keyword
def convert_to_crypto_lib_cert(cert: Union[rfc9480.CMPCertificate, x509.Certificate]) -> x509.Certificate:
    """Ensure the function calling this method, can work with certificates from the 'cryptography' library."""
    if isinstance(cert, Union[rfc9480.CMPCertificate, rfc5280.Certificate]):
        return x509.load_der_x509_certificate(encoder.encode(cert))
    if isinstance(cert, x509.Certificate):
        return cert

    raise ValueError(f"Expected the type of the input to be CertObject not: {type(cert)}")


def _prepare_ca_ra_extensions(
    issuer_key: PrivateKey,
    key: PrivateKey,
    eku: Optional[str] = None,
    eku_critical: bool = False,
    for_ca: bool = True,
    key_usage: Optional[str] = None,
    key_usage_critical: bool = True,
) -> rfc9480.Extensions:
    """Prepare the extensions for a intermediate CA certificate.

    :param issuer_key: The key of the issuer.
    :param key: The key of the intermediate CA.
    :param eku: The extended key usage for the intermediate CA certificate.
    :param eku_critical: The critical flag for the extended key usage.
    :param for_ca: Whether the certificate is for a CA or RA.
    :param key_usage: The key usage for the intermediate CA certificate. Defaults to "keyCertSign,cRLSign" for CAs.
    and "digitalSignature" for RAs.
    :return: The extensions for the intermediate CA certificate.
    """
    basic_constraints = prepare_basic_constraints_extension(
        ca=True,
        critical=for_ca,
    )

    ski = prepare_ski_extension(
        key=key.public_key(),
        critical=False,
    )

    aia = prepare_authority_key_identifier_extension(
        ca_key=issuer_key.public_key(),
        critical=False,
    )

    if key_usage is None:
        key_usage = "digitalSignature" if not for_ca else "keyCertSign,cRLSign"

    key_usage = prepare_extensions(
        key_usage=key_usage,
        critical=key_usage_critical,
    )

    key_usage.extend([basic_constraints, ski, aia])
    if eku is not None:
        eku_ext = prepare_extensions(
            eku=eku,
            critical=eku_critical,
        )
        key_usage.extend(eku_ext)
    return key_usage


def _prepare_root_ca_extensions(
    ca_key: PrivateKey,
) -> rfc9480.Extensions:
    """Prepare the extensions for a Root-CA certificate."""
    return _prepare_ca_ra_extensions(
        issuer_key=ca_key,
        key=ca_key,
    )


def _build_certs_root_ca_key_update_content():
    """Generate and save a set of certificates for Root CA key updates.

    This function creates a series of certificates to simulate Root CA key updates:
    - Old Root CA certificate
    - New Root CA certificate signed with its own key
    - New Root CA certificate signed by the old Root CA
    - Old Root CA certificate signed by the new Root CA
    Contains extension to be able to be verified by `pkilint`.
    """
    rsa_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
    new_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")

    new_extn = _prepare_root_ca_extensions(new_key)
    old_extn = _prepare_root_ca_extensions(rsa_key)

    old_cert, old_key = build_certificate(
        common_name="CN=OldRootCA",
        extensions=old_extn,
    )
    new_with_new_cert, new_key = build_certificate(
        common_name="CN=NewRootCA",
        extensions=new_extn,
    )
    new_with_old_cert, _ = build_certificate(
        private_key=new_key,
        common_name="CN=NewRootCA_with_Old",
        ca_cert=old_cert,
        ca_key=old_key,
        include_ski=False,
    )
    old_with_new_cert, _ = build_certificate(
        private_key=old_key,
        common_name="CN=OldRootCA",
        ca_cert=new_with_new_cert,
        ca_key=new_key,
        include_ski=False,
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
    root_key = load_private_key_from_file("data/keys/private-key-ed25519.pem")
    root_cert = parse_certificate(load_and_decode_pem_file("data/unittest/root_cert_ed25519.pem"))

    ca1_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
    # This certificate is needed to unwrap the Content-encryption-key.
    # Does not need to be to issue a certificate, is just used for key agreement.

    extensions = _prepare_ca_ra_extensions(
        issuer_key=root_key,
        key=ca1_key,
        for_ca=True,
        eku="cmKGA",
        key_usage="keyAgreement,digitalSignature",
    )

    kga_cert, _ = build_certificate(
        private_key=ca1_key,
        ca_cert=root_cert,
        ca_key=root_key,
        common_name="CN=KGA EC KARI",
        extensions=extensions,
    )
    # Remember, this certificate is only used to show that the Other Party is allowed to generate keys
    # for the client, because this certificate has a valid certificate chain, which was
    # signed ba a trust anchor.
    write_cmp_certificate_to_pem(kga_cert, "data/unittest/kga_cert_kari_ecdsa.pem")


def _build_time_independent_certs():
    """Generate time-independent certificates and save them for testing.

    This function prepares various certificates used for testing scenarios:
    - Calls `_build_certs_root_ca_key_update_content` to generate Root CA key update certificates.
    - Generates a KGA certificate for X25519-based key agreement.
    - Ensures certificates are suitable for testing with time-independent checks.
    Which means that the validity period of the certificate can be over.

    Generated certificates are saved to the `data/unittest/` directory.
    """
    _build_certs_root_ca_key_update_content()

    root_key = load_private_key_from_file("data/keys/private-key-ed25519.pem")
    root_cert = parse_certificate(load_and_decode_pem_file("data/unittest/root_cert_ed25519.pem"))
    # used for kari.
    private_key = load_private_key_from_file("data/keys/private-key-x25519.pem")
    # cannot be self-signed, because x25519, but otherwise does not need to be signed, by a
    # valid trusted anchor, because it is used for validation of the envelopeData structure,
    # which does not include that check.
    kga_cert, _ = build_certificate(
        private_key=private_key,
        ca_cert=root_cert,
        ca_key=root_key,
        common_name="CN=CMP Protection Cert For KARI X25519",
        key_usage="keyAgreement",
        is_ca=True,
        include_ski=True,
        eku="cmKGA,cmcCA",
    )
    write_cmp_certificate_to_pem(kga_cert, "data/unittest/cmp_prot_kari_x25519.pem")
    _build_pq_certs()


def _build_pq_certs():
    mldsa_key = load_private_key_from_file("data/keys/private-key-ml-dsa-65-seed.pem")
    mlkem_key = load_private_key_from_file("data/keys/private-key-ml-kem-768-seed.pem")
    slh_dsa_key = load_private_key_from_file("data/keys/private-key-slh-dsa-sha2-256f-seed.pem")
    mcelliece_key = load_private_key_from_file("data/keys/private-key-mceliece-6960119-raw.pem")
    composite_sig_rsa = load_private_key_from_file("data/keys/private-key-composite-sig-rsa2048-ml-dsa-44.pem")

    cert, key = build_certificate(ca_key=mldsa_key, common_name="CN=PQ Root CA", is_ca=True, path_length=None, ski=True)

    write_cmp_certificate_to_pem(cert, "data/unittest/pq_root_ca_ml_dsa_65.pem")
    cert, key = build_certificate(
        private_key=mlkem_key, ca_key=mldsa_key, common_name="CN=PQ ML-KEM 768", is_ca=False, path_length=None, ski=True
    )
    write_cmp_certificate_to_pem(cert, "data/unittest/pq_cert_ml_kem_768.pem")
    cert, key = build_certificate(
        private_key=slh_dsa_key,
        ca_key=mldsa_key,
        common_name="CN=PQ SLH-DSA-SHA2-256f",
        is_ca=False,
        path_length=None,
        ski=True,
    )
    write_cmp_certificate_to_pem(cert, "data/unittest/pq_root_ca_slh_dsa_sha2_256f.pem")
    cert, key = build_certificate(
        private_key=mcelliece_key,
        ca_key=mldsa_key,
        common_name="CN=PQ McEliece 6960119",
        is_ca=False,
        path_length=None,
        include_ski=True,
    )
    write_cmp_certificate_to_pem(cert, "data/unittest/pq_cert_mceliece_6960119.pem")
    cert, key = build_certificate(
        private_key=composite_sig_rsa,
        ca_key=mldsa_key,
        common_name="CN=PQ Composite Signature RSA",
        is_ca=False,
        path_length=None,
        include_ski=True,
    )
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
    _generate_update_pq_certs()
    os.makedirs("data/mock_ca", exist_ok=True)
    load_or_generate_cert_chain()
    cert = parse_certificate(utils.load_and_decode_pem_file("data/unittest/root_cert_ed25519.pem"))
    write_cmp_certificate_to_pem(cert, "data/mock_ca/root_cert_ed25519.pem")
    _build_time_independent_certs()
    _generate_other_trusted_ca_and_device_certs()
    _generate_mock_ca_certs()
    _generate_other_trusted_pki_certs()


def _gen_and_save_keys():
    # Generate ML-KEM and ML-DSA keys

    keys = ["ml-kem-1024", "ml-kem-768", "ml-kem-512", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87"]

    for key_name in keys:
        key = generate_key(key_name)
        save_key(
            key,
            f"data/keys/private-key-{key_name}-seed.pem",
            save_type="seed",
        )
        save_key(
            key,
            f"data/keys/private-key-{key_name}-raw.pem",
            save_type="raw",
        )

    slh_names = ["slh-dsa-sha2-256f", "slh-dsa-sha2-192f", "slh-dsa-sha2-128f"]

    for slh_name in slh_names:
        slh_key = generate_key(slh_name)
        save_key(
            slh_key,
            f"data/keys/private-key-{slh_name}-seed.pem",
            save_type="seed",
        )
        save_key(
            slh_key,
            f"data/keys/private-key-{slh_name}-raw.pem",
            save_type="raw",
        )

    # Generate other SLH-DSA keys
    save_key(
        generate_key("slh-dsa-sha2-192s"),
        "data/keys/private-key-slh-dsa-sha2-192s-seed.pem",
        save_type="seed",
    )
    save_key(
        generate_key("slh-dsa-sha2-128s"),
        "data/keys/private-key-slh-dsa-sha2-128s-seed.pem",
        save_type="seed",
    )
    save_key(
        generate_key("slh-dsa-shake-256s"),
        "data/keys/private-key-slh-dsa-shake-256s-seed.pem",
        save_type="seed",
    )
    save_key(
        generate_key("slh-dsa-shake-256f"),
        "data/keys/private-key-slh-dsa-shake-256f-seed.pem",
        save_type="seed",
    )
    save_key(
        generate_key("slh-dsa-shake-192s"),
        "data/keys/private-key-slh-dsa-shake-192s-seed.pem",
        save_type="seed",
    )
    save_key(
        generate_key("slh-dsa-shake-192f"),
        "data/keys/private-key-slh-dsa-shake-192f-seed.pem",
        save_type="seed",
    )
    save_key(
        generate_key("slh-dsa-shake-128s"),
        "data/keys/private-key-slh-dsa-shake-128s-seed.pem",
        save_type="seed",
    )
    save_key(
        generate_key("slh-dsa-shake-128f"),
        "data/keys/private-key-slh-dsa-shake-128f-seed.pem",
        save_type="seed",
    )
    print("Finished generating PQ signature and ML-KEM keys")


def _save_tmp_kem_pq_certs():
    """Generate and save a set of certificates for PQ algorithms.

    Which have not finalized OIDs yet: FrodoKEM, sntrup761 and McEliece.
    """
    mldsa_key = load_private_key_from_file("data/keys/private-key-ml-dsa-44-seed.pem")
    mldsa_cert = parse_certificate(load_and_decode_pem_file("data/unittest/pq_root_ca_ml_dsa_44.pem"))

    mc_eliece_keys = ["mceliece-348864", "mceliece-6960119", "mceliece-8192128"]

    for mc_eliece_name in mc_eliece_keys:
        save_key(
            generate_key(mc_eliece_name),
            f"data/keys/private-key-{mc_eliece_name}-raw.pem",
            save_type="raw",
        )

    # Generate NTRU key:
    save_key(generate_key("sntrup761"), "data/keys/private-key-sntrup761-raw.pem", save_type="raw")

    cert, _ = build_certificate(
        private_key=load_private_key_from_file("data/keys/private-key-sntrup761-raw.pem"),
        ca_key=mldsa_key,
        common_name="CN=PQ KEM SNTRUP761",
        ca_cert=mldsa_cert,
    )

    write_cmp_certificate_to_pem(cert, "data/unittest/pq_cert_sntrup761.pem")

    # Generate FrodoKEM keys
    for x in FRODOKEM_NAME_2_OID:
        save_key(generate_key(x), f"data/keys/private-key-{x}-raw.pem", save_type="raw")

    frodo_cert, _ = build_certificate(
        private_key=load_private_key_from_file("data/keys/private-key-frodokem-976-aes-raw.pem"),
        ca_key=mldsa_key,
        common_name="CN=PQ KEM FrodoKEM 976 AES",
        ca_cert=mldsa_cert,
    )
    write_cmp_certificate_to_pem(frodo_cert, "data/unittest/pq_cert_frodokem_976_aes.pem")

    mc_key = load_private_key_from_file("data/keys/private-key-mceliece-6960119-raw.pem")
    mc_cert, _ = build_certificate(
        private_key=mc_key, ca_key=mldsa_key, common_name="CN=PQ KEM McEliece 6960119", ca_cert=mldsa_cert
    )
    write_cmp_certificate_to_pem(mc_cert, "data/unittest/pq_cert_mceliece_6960119.pem")


def _generate_update_pq_certs():
    """Generate and save a set of certificates for PQ and Composite algorithms."""
    _gen_and_save_keys()

    # Generate PQ Signature certs:
    mldsa_key = load_private_key_from_file("data/keys/private-key-ml-dsa-65-seed.pem")
    mldsa_cert, _ = build_certificate(private_key=mldsa_key, common_name="CN=PQ Root CA MLDSA 65")
    write_cmp_certificate_to_pem(mldsa_cert, "data/unittest/pq_root_ca_ml_dsa_65.pem")

    mldsa_key44 = load_private_key_from_file("data/keys/private-key-ml-dsa-44-seed.pem")
    mldsa_cert44, _ = build_certificate(private_key=mldsa_key44, common_name="CN=PQ Root CA MLDSA 44")
    write_cmp_certificate_to_pem(mldsa_cert44, "data/unittest/pq_root_ca_ml_dsa_44.pem")

    slh_dsa_key = load_private_key_from_file("data/keys/private-key-slh-dsa-sha2-256f-seed.pem")
    slh_dsa_cert, _ = build_certificate(private_key=slh_dsa_key, common_name="CN=PQ Root CA SLH-DSA-SHA2-256f")
    write_cmp_certificate_to_pem(slh_dsa_cert, "data/unittest/pq_root_ca_slh_dsa_sha2_256f.pem")

    # Generate PQ KEM certs:
    mlkem_key = load_private_key_from_file("data/keys/private-key-ml-kem-768-seed.pem")
    mlkem_cert, _ = build_certificate(
        private_key=mlkem_key, ca_key=mldsa_key, common_name="CN=MLKEM 768", ca_cert=mldsa_cert
    )
    write_cmp_certificate_to_pem(mlkem_cert, "data/unittest/pq_cert_ml_kem_768.pem")

    _save_tmp_kem_pq_certs()
    _save_composite_sig()
    _save_xwing()
    _save_composite_kem()
    _generate_mock_ca_kem_certs()
    _save_migration_csrs()


def _save_composite_sig():
    """Generate a self-signed Composite signature Key."""
    key = generate_key("composite-sig", trad_name="rsa", length="2048", pq_name="ml-dsa-44")
    save_key(key, "data/keys/private-key-composite-sig-rsa2048-ml-dsa-44.pem", save_type="seed")
    cert, _ = build_certificate(private_key=key, common_name="CN=Hybrid Root CompositeSig RSA2048 ML-DSA-44")
    write_cmp_certificate_to_pem(cert, "data/unittest/pq_root_ca_composite_sig_rsa2048_ml_dsa_44.pem")

    key = generate_key("composite-sig", trad_name="ed448", pq_name="ml-dsa-87")
    save_key(key, "data/keys/private-key-composite-sig-ed448-ml-dsa-87.pem", save_type="seed")
    cert, _ = build_certificate(private_key=key, common_name="CN=Hybrid Root CompositeSig ED448 ML-DSA-87")
    write_cmp_certificate_to_pem(cert, "data/unittest/pq_root_ca_composite_sig_ed448_ml_dsa_87.pem")

    # Composite Signature CSR's
    key = load_private_key_from_file("data/keys/private-key-composite-sig-rsa2048-ml-dsa-44.pem")
    csr = build_csr(signing_key=key, common_name="CN=Hybrid CSR CompositeSig RSA2048 ML-DSA-44")
    save_csr(csr, "data/csrs/hybrid_csr_composite_sig_rsa2048_ml_dsa_44.pem", save_as_pem=True, add_pretty_print=True)
    print("Generated Composite Signature keys, certificates and CSR.")


def _save_xwing():
    """Generate and save two X-Wing keys and certificates for testing."""
    mldsa_key = load_private_key_from_file("data/keys/private-key-ml-dsa-44-seed.pem")
    ml_dsa_cert = parse_certificate(load_and_decode_pem_file("data/unittest/pq_root_ca_ml_dsa_44.pem"))

    # xwing
    key = generate_key("xwing")
    save_key(key, "data/keys/private-key-xwing-seed.pem", save_type="seed")
    save_key(key, "data/keys/private-key-xwing-raw.pem", save_type="raw")

    xwing_key = key
    xwing_cert, _ = build_certificate(
        private_key=xwing_key, ca_key=mldsa_key, ca_cert=ml_dsa_cert, common_name="CN=Hybrid Key X-Wing"
    )
    write_cmp_certificate_to_pem(xwing_cert, "data/unittest/hybrid_cert_xwing.pem")

    key2 = generate_key("xwing")
    save_key(key2, "data/keys/private-key-xwing-other-seed.pem", save_type="seed")
    save_key(key2, "data/keys/private-key-xwing-other-raw.pem", save_type="raw")

    xwing_cert2, _ = build_certificate(
        private_key=key2, ca_key=mldsa_key, ca_cert=ml_dsa_cert, common_name="CN=Hybrid Key X-Wing Other"
    )

    write_cmp_certificate_to_pem(xwing_cert2, "data/unittest/hybrid_cert_xwing_other.pem")
    print("Finished generating xwing keys and certificates.")


def _save_composite_kem():
    """Generate and save Composite-KEM keys and certificates for testing."""
    mldsa_key = load_private_key_from_file("data/keys/private-key-ml-dsa-44-seed.pem")
    ml_dsa_cert = parse_certificate(load_and_decode_pem_file("data/unittest/pq_root_ca_ml_dsa_44.pem"))

    key = generate_key("composite-kem", trad_name="rsa", length="2048", pq_name="ml-kem-768")
    save_key(key, "data/keys/private-key-composite-kem-ml-kem-768-rsa2048-seed.pem", save_type="seed")
    cert, _ = build_certificate(
        private_key=key, ca_key=mldsa_key, ca_cert=ml_dsa_cert, common_name="CN=PQ CompositeKEM ML-KEM-768 RSA2048"
    )
    write_cmp_certificate_to_pem(cert, "data/unittest/hybrid_cert_composite_kem_ml_kem_768_rsa2048.pem")

    key = generate_key("composite-kem", trad_name="x25519", pq_name="ml-kem-768")
    save_key(key, "data/keys/private-key-composite-kem-ml-kem-1024-x25519-seed.pem", save_type="seed")
    cert, _ = build_certificate(
        private_key=key, ca_key=mldsa_key, ca_cert=ml_dsa_cert, common_name="CN=Hybrid CompositeKEM ML-KEM-1024 x25519"
    )

    key = generate_key("composite-kem", trad_name="x448", pq_name="ml-kem-1024")
    save_key(key, "data/keys/private-key-composite-kem-ml-kem-1024-x448-seed.pem", save_type="seed")
    cert, _ = build_certificate(
        private_key=key, ca_key=mldsa_key, ca_cert=ml_dsa_cert, common_name="CN=Hybrid CompositeKEM ML-KEM-1024 X448"
    )

    write_cmp_certificate_to_pem(cert, "data/unittest/hybrid_cert_composite_kem_ml_kem_1024_x448.pem")

    key = generate_key(algorithm="composite-kem", pq_name="frodokem-976-aes", trad_name="rsa", length="2048")
    save_key(key, "data/keys/private-key-composite-kem-frodokem-976-aes-rsa2048-seed.pem", save_type="seed")
    cert, _ = build_certificate(
        private_key=key,
        ca_key=mldsa_key,
        ca_cert=ml_dsa_cert,
        common_name="CN=Hybrid CompositeKEM FrodoKEM-976-AES RSA2048",
    )
    write_cmp_certificate_to_pem(cert, "data/unittest/hybrid_cert_composite_kem_frodokem_976_aes_rsa2048.pem")

    key = generate_key(algorithm="composite-kem", pq_name="frodokem-976-aes", trad_name="x25519")
    save_key(key, "data/keys/private-key-composite-kem-frodokem-976-aes-x25519-seed.pem", save_type="seed")
    cert, _ = build_certificate(
        private_key=key,
        ca_key=mldsa_key,
        ca_cert=ml_dsa_cert,
        common_name="CN=Hybrid CompositeKEM FrodoKEM-976-AES x25519",
    )
    write_cmp_certificate_to_pem(cert, "data/unittest/hybrid_cert_composite_kem_frodokem_976_aes_x25519.pem")

    key = generate_key(algorithm="composite-kem", pq_name="frodokem-976-shake", trad_name="x25519")
    save_key(key, "data/keys/private-key-composite-kem-frodokem-976-shake-x25519-seed.pem", save_type="seed")
    cert, _ = build_certificate(
        private_key=key,
        ca_key=mldsa_key,
        ca_cert=ml_dsa_cert,
        common_name="CN=Hybrid CompositeKEM FrodoKEM-976-SHAKE x25519",
    )
    write_cmp_certificate_to_pem(cert, "data/unittest/hybrid_cert_composite_kem_frodokem_976_shake_x25519.pem")

    print("Finished generating composite keys and certificates.")

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


def _save_migration_csrs():
    """Generate and save CSRs for PQ/Hybrid testing.

    Might change, due different key encodings.
    """
    os.makedirs("data/csrs", exist_ok=True)

    # PQ CSR's
    #
    ## ML-DSA CSR's
    key = load_private_key_from_file("data/keys/private-key-ml-dsa-44-seed.pem")
    csr = build_csr(signing_key=key, common_name="CN=PQ CSR ML-DSA-44")
    save_csr(csr, "data/csrs/pq_csr_ml_dsa_44.pem", save_as_pem=True, add_pretty_print=True)

    ## SLH-DSA CSR's
    key = load_private_key_from_file("data/keys/private-key-slh-dsa-shake-256s-seed.pem")
    csr = build_csr(signing_key=key, common_name="CN=PQ CSR SLH-DSA-SHAKE-256s")
    save_csr(csr, "data/csrs/pq_csr_slh_dsa_shake_256s.pem", save_as_pem=True, add_pretty_print=True)




def _update_ed_x_trad_keys():
    path = "data/keys/private-key-x25519.pem"
    key = x25519.X25519PrivateKey.generate()
    save_key(key, path)
    loaded_key = load_private_key_from_file(path)

    if not isinstance(loaded_key, x25519.X25519PrivateKey):
        raise ValueError(f"The loaded key is not of the correct type. Expected: {type(key)}\nGot: {type(loaded_key)}")

    if key.public_key() != loaded_key.public_key():
        raise ValueError("The public keys of the loaded and the generated key are the same.")

    path = "data/keys/client-key-x25519.pem"
    key = x25519.X25519PrivateKey.generate()
    save_key(key, path)
    loaded_key = load_private_key_from_file(path)

    if not isinstance(loaded_key, x25519.X25519PrivateKey):
        raise ValueError(f"The loaded key is not of the correct type. Expected: {type(key)}\nGot: {type(loaded_key)}")

    if key.public_key() != loaded_key.public_key():
        raise ValueError("The public keys of the loaded and the generated key are the same.")

    path = "data/keys/private-key-x448.pem"
    key = x448.X448PrivateKey.generate()
    save_key(key, path)
    loaded_key = load_private_key_from_file(path)
    if key.public_key() != loaded_key.public_key():
        raise ValueError("The public keys of the loaded and the generated key are the same.")

    path = "data/keys/client-x448-key.pem"
    key = x448.X448PrivateKey.generate()
    save_key(key, path)
    loaded_key = load_private_key_from_file(path)
    if key.public_key() != loaded_key.public_key():
        raise ValueError("The public keys of the loaded and the generated key are the same.")

    path = "data/keys/private-key-ed448.pem"
    key = ed448.Ed448PrivateKey.generate()
    save_key(key, path)
    loaded_key = load_private_key_from_file(path)
    if key.public_key() != loaded_key.public_key():
        raise ValueError("The public keys of the loaded and the generated key are the same.")

    path = "data/keys/private-key-ed25519.pem"
    key = ed25519.Ed25519PrivateKey.generate()
    save_key(key, path)
    loaded_key = load_private_key_from_file(path)
    if key.public_key() != loaded_key.public_key():
        raise ValueError("The public keys of the loaded and the generated key are the same.")


def update_cert_and_keys():
    """Generate new PQ and Hybrid keys and certificates.

    Update the certificates/CRS and keys used for testing with new ones.
    """
    _gen_new_certs()
    _generate_update_pq_certs()


def _prepare_pbkdf2() -> rfc8018.PBKDF2_params:
    """Prepare a `PBKDF2_params` structure used in the `PasswordRecipientInfo` structure.

    Used to encrypt a content encryption key.

    :return: The populated structure with the Default salt b"AAAAAAAAAAAAAAAA"
    """
    pbkdf2_params = rfc8018.PBKDF2_params()
    pbkdf2_params["salt"]["specified"] = univ.OctetString(b"AAAAAAAAAAAAAAAA")
    pbkdf2_params["iterationCount"] = 1000
    pbkdf2_params["keyLength"] = 32
    pbkdf2_params["prf"] = rfc8018.AlgorithmIdentifier()
    pbkdf2_params["prf"]["algorithm"] = rfc9481.id_hmacWithSHA256
    pbkdf2_params["prf"]["parameters"] = univ.Null()
    return pbkdf2_params


@not_keyword
def prepare_pwri_structure(
    version: int = 3,
    kdf_oid: univ.ObjectIdentifier = rfc9481.id_PBKDF2,
    key_enc_alg_id: univ.ObjectIdentifier = rfc9481.id_aes256_wrap,
    enc_key: bool = True,
    encrypted_key: Optional[bytes] = None,
    **kwargs,
) -> rfc5652.PasswordRecipientInfo:
    """Create a `PasswordRecipientInfo` (`pwri`) used to encrypt a content encryption key.

    Prepares a default `PBKDF2_params` structure with the fixed salt b"AAAAAAAAAAAAAAAA".

    :param version: The version number for the `PasswordRecipientInfo` structure. Defaults to 3.
    :param kdf_oid: The Object Identifier (OID) for the key derivation algorithm.
    :param key_enc_alg_id: The OID for the key encryption algorithm.
    :param enc_key:  Flag indicating whether to include the encrypted key in the `PasswordRecipientInfo`.
    If `True`, the `encryptedKey` field is populated. Defaults to `True`.
    :param encrypted_key:The encrypted key bytes to include in the `PasswordRecipientInfo`.
    If not provided and `enc_key` is `True`, a random 32-byte key is generated.
    :param kwargs: Additional parameters to pass to the key derivation algorithm.
    (salt, iteration_count, key_length, hash_alg, kdf_alg_id).
    :return: The populated `PasswordRecipientInfo` structure.
    """
    salt = kwargs.get("salt", os.urandom(32))
    salt = str_to_bytes(salt)

    alg_id = kwargs.get("kdf_alg_id") or prepare_pbkdf2_alg_id(
        salt=salt,
        iterations=int(kwargs.get("iterations", 100000)),
        key_length=int(kwargs.get("key_length", 32)),
        hash_alg=kwargs.get("hash_alg", "sha256"),
    )

    alg_id["algorithm"] = kdf_oid

    pwri = rfc5652.PasswordRecipientInfo().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)
    )
    pwri["version"] = version
    pwri["keyDerivationAlgorithm"] = alg_id.subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0), cloneValueFlag=True
    )
    # must be of type KM_KW_ALG
    pwri["keyEncryptionAlgorithm"]["algorithm"] = key_enc_alg_id
    if enc_key:
        pwri["encryptedKey"] = rfc5652.EncryptedKey(encrypted_key or os.urandom(32))

    return pwri


def build_crl_crypto_lib(
    ca_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
    ca_cert: x509.Certificate,
    revoked_cert: x509.Certificate,
):
    """Build a CRL with the given CA key, CA certificate, and revoked certificate."""
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.last_update(datetime.now())
    builder = builder.next_update(datetime.now() + timedelta(days=30))

    revoked_cert_entry = (
        x509.RevokedCertificateBuilder()
        .serial_number(revoked_cert.serial_number)
        .revocation_date(datetime.now())
        .build()
    )
    builder = builder.add_revoked_certificate(revoked_cert_entry)
    builder.add_extension(
        AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
        critical=False,
    )

    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return crl.public_bytes(encoding=Encoding.DER)


def _generate_other_trusted_pki_certs():
    """Generate and save certificates for other trusted PKIs.

    Generates other trusted RA certificates for testing purposes.
    Also used by the Mock-CA to test the LwCMP Section 5 test cases.

    Uses:
    ----
    - `load_ca_cert_and_key()` as issuer cert and key.

    Generated files:
    ---------------
    - data/unittest/ra_kga_cert_ecdsa.pem
    - data/unittest/ra_cms_cert_ecdsa.pem

    """

    root_cert, root_key = load_ca_cert_and_key()
    kga_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")

    pub_key = load_public_key_from_cert(root_cert)
    if pub_key != root_key.public_key():
        raise ValueError("The public key extracted from the root certificate does not match the root key.")

    extn = _prepare_ca_ra_extensions(
        issuer_key=root_key,
        key=kga_key,
        eku="cmKGA",
        eku_critical=False,
    )

    kga_ra_cert, _ = build_certificate(
        private_key=kga_key,
        common_name="CN=KGA RA",
        ca_cert=root_cert,
        ca_key=root_key,
        extensions=extn,
        for_ca=False,
    )

    write_cmp_certificate_to_pem(kga_ra_cert, "data/unittest/ra_kga_cert_ecdsa.pem")
    cert_chain = build_cert_chain_from_dir(
        ee_cert=kga_ra_cert,
        cert_chain_dir="data/unittest/",
    )
    if len(cert_chain) != 2:
        raise ValueError("Failed to create the certificate chain for the KGA RA certificate.")

    # TODO lookup if the RA is-allowed/must have the basic constraints extension.
    extn = _prepare_ca_ra_extensions(
        issuer_key=root_key,
        key=kga_key,
        eku="cmcRA",
        eku_critical=False,
        for_ca=False,
    )

    kga_ra_cert, _ = build_certificate(
        private_key=kga_key,
        common_name="CN=CMC RA",
        ca_cert=root_cert,
        ca_key=root_key,
        extensions=extn,
    )
    write_cmp_certificate_to_pem(kga_ra_cert, "data/trusted_ras/ra_cms_cert_ecdsa.pem")

    cert_chain = build_cert_chain_from_dir(
        ee_cert=kga_ra_cert,
        cert_chain_dir="data/unittest/",
    )
    if len(cert_chain) != 2:
        raise ValueError("Failed to create the certificate chain for the CMC RA certificate.")


def parse_cms_env_data(der_data: bytes) -> rfc5652.EnvelopedData:
    """Parse a CMS EnvelopedData structure."""
    content_info, _ = decoder.decode(der_data, asn1Spec=rfc5652.ContentInfo())

    if content_info["contentType"] != rfc5652.id_envelopedData:
        raise ValueError(f"ContentInfo not of type EnvelopedData. Got: {content_info['contentType']}")

    env_data, _ = decoder.decode(content_info["content"], asn1Spec=rfc5652.EnvelopedData())
    return env_data


def parse_cms_kemri(der_data: bytes) -> Tuple[rfc9629.KEMRecipientInfo, bytes, rfc9480.AlgorithmIdentifier]:
    """Parse a CMS EnvelopedData structure with a KEMRecipientInfo recipient.

    :param der_data: The (DER) data corresponding to the CMS EnvelopedData.
    :return: The parsed KEMRecipientInfo structure, the encrypted content, and the content encryption algorithm.
    """
    env_data = parse_cms_env_data(der_data)

    enc_content = env_data["encryptedContentInfo"]["encryptedContent"].asOctets()
    cek_alg_id = env_data["encryptedContentInfo"]["contentEncryptionAlgorithm"]

    _name = env_data["recipientInfos"][0].getName()
    if _name != "ori":
        print(env_data["recipientInfos"][0].prettyPrint())
        raise ValueError(f"RecipientInfo not of type KEM. Got: {_name}")

    recip_info = env_data["recipientInfos"][0]["ori"]
    if recip_info["oriType"] != rfc9629.id_ori_kem:
        raise ValueError("RecipientInfo not of type KEM")

    kem_recip_info, _ = decoder.decode(recip_info["oriValue"], asn1Spec=rfc9629.KEMRecipientInfo())

    return kem_recip_info, enc_content, cek_alg_id


def print_alg_id(alg_id: rfc9480.AlgorithmIdentifier) -> None:
    """Print the details of an algorithm identifier."""
    _name = may_return_oid_to_name(alg_id["algorithm"])
    print("Algorithm Identifier:\n  Algorithm: ", _name)
    if alg_id["parameters"].isValue:
        print("  Parameters: ", alg_id["parameters"].prettyPrint())


def load_ca_cert_and_key() -> Tuple[rfc9480.CMPCertificate, Ed25519PrivateKey]:
    """Load a valid Root CA key and certificate for testing."""
    root_key = load_private_key_from_file("data/keys/private-key-ed25519.pem")
    root_cert = parse_certificate(load_and_decode_pem_file("data/unittest/root_cert_ed25519.pem"))
    return root_cert, root_key


def build_sun_hybrid_composite_csr(
    signing_key: Optional[CompositeSigPrivateKey] = None,
    common_name: str = "CN=Hans Mustermann",
    pub_key_hash_alg: Optional[str] = None,
    pub_key_location: Optional[str] = None,
    sig_hash_alg: Optional[str] = None,
    sig_value_location: Optional[str] = None,
    use_rsa_pss: bool = True,
) -> rfc6402.CertificationRequest:
    """Create a CSR with composite signatures, supporting two public keys and multiple CSR attributes.

    :param signing_key: CompositeSigCMSPrivateKey, which holds both traditional and post-quantum keys.
    :param common_name: The subject common name for the CSR.
    :param pub_key_hash_alg: Hash algorithm for the alternative public key.
    :param pub_key_location: URI for the alternative public key.
    :param sig_hash_alg: Hash algorithm for the alternative signature.
    :param sig_value_location: URI for the alternative signature.
    :param use_rsa_pss: Whether to use RSA-PSS for traditional keys.
    :return: CertificationRequest object with composite signature.
    """
    csr = build_csr(signing_key, common_name=common_name,
                    exclude_signature=True, use_rsa_pss=use_rsa_pss)
    sig_alg_id = rfc5280.AlgorithmIdentifier()

    domain_oid = signing_key.get_oid(
        use_pss=use_rsa_pss,
    )

    # Step 4 and 5
    # Currently is always the PQ-Key the firsts key to
    # it is assumed to be the first key, and the alternative key is the traditional key.
    attributes = prepare_sun_hybrid_csr_attributes(
        pub_key_hash_alg=pub_key_hash_alg,
        sig_value_location=sig_value_location,
        pub_key_location=pub_key_location,
        sig_hash_alg=sig_hash_alg,
    )

    sig_alg_id["algorithm"] = domain_oid

    csr["certificationRequestInfo"]["attributes"].extend(attributes)

    csr = sign_csr(
        csr=csr,
        signing_key=signing_key,
        sig_alg_id=sig_alg_id,
        use_rsa_pss=use_rsa_pss,
    )
    csr, _ = decoder.decode(encoder.encode(csr), rfc6402.CertificationRequest())
    return csr


def save_csr(
    csr: rfc6402.CertificationRequest, path: str, save_as_pem: bool = False, add_pretty_print: bool = False
) -> None:
    """Save a CSR to a file.

    :param csr: The CSR to save.
    :param path: The path to save the CSR to.
    :param save_as_pem: If True, the CSR is saved as PEM-; otherwise, it is saved as DER-encoded.

    """
    der_data = encoder.encode(csr)
    if save_as_pem:
        b64_encoded = base64.b64encode(der_data).decode("utf-8")
        b64_encoded = "\n".join(textwrap.wrap(b64_encoded, width=64))
        pem_csr = "-----BEGIN CERTIFICATE REQUEST-----\n" + b64_encoded + "\n-----END CERTIFICATE REQUEST-----\n"
        if add_pretty_print:
            pem_csr += "\n"
            pem_csr += csr.prettyPrint()
            pem_csr += "\n"
        der_data = pem_csr.encode("utf-8")

    with open(path, "wb") as file:
        file.write(der_data)


def _build_key_encipherment_cert(
    ca_key: PrivateKey, ca_cert: rfc9480.CMPCertificate, kem_key: PrivateKey, common_name: str
) -> Tuple[rfc9480.CMPCertificate, PrivateKey]:
    """Build a keyEncipherment certificate."""
    exts = _prepare_ca_ra_extensions(
        issuer_key=ca_key,
        key=kem_key,
        eku=None,
        eku_critical=False,
        key_usage="keyEncipherment",
        key_usage_critical=False,
    )

    return build_certificate(
        private_key=kem_key,
        common_name=common_name,
        extensions=exts,
        ca_cert=ca_cert,
        ca_key=ca_key,
    )


def _build_key_agreement_cert(
    ca_key: PrivateKey, ca_cert: rfc9480.CMPCertificate, agree_key: PrivateKey, common_name: str
) -> Tuple[rfc9480.CMPCertificate, PrivateKey]:
    """Build a keyAgreement certificate."""
    exts = _prepare_ca_ra_extensions(
        issuer_key=ca_key,
        key=agree_key,
        eku=None,
        eku_critical=False,
        key_usage="keyAgreement",
        key_usage_critical=False,
    )
    return build_certificate(
        private_key=agree_key,
        common_name=common_name,
        extensions=exts,
        ca_cert=ca_cert,
        ca_key=ca_key,
    )


def _generate_mock_ca_kem_certs():
    """Generate and save mock CA KEM certificates for testing."""
    ca_cert, ca_key = load_ca_cert_and_key()
    mlkem_key = load_private_key_from_file("data/keys/private-key-ml-kem-768-seed.pem")

    cert, _ = _build_key_encipherment_cert(
        ca_key=ca_key,
        ca_cert=ca_cert,
        kem_key=mlkem_key,
        common_name="CN=ML-KEM-768 CA Encr Cert",
    )
    write_cmp_certificate_to_pem(cert, "data/unittest/ca_encr_cert_ml_kem_768.pem")
    print("Updated ML-KEM-768 CA Encr Cert")

    # Generate X-Wing
    xwing_key = load_private_key_from_file("data/keys/private-key-xwing-seed.pem")
    cert, _ = _build_key_encipherment_cert(
        ca_key=ca_key,
        ca_cert=ca_cert,
        kem_key=xwing_key,
        common_name="CN=X-Wing CA Encr Cert",
    )
    write_cmp_certificate_to_pem(cert, "data/unittest/ca_encr_cert_xwing.pem")
    print("Updated X-Wing CA Encr Cert")
    # Generate FrodoKEM
    frodo_key = load_private_key_from_file("data/keys/private-key-frodokem-976-aes-raw.pem")
    cert, _ = _build_key_encipherment_cert(
        ca_key=ca_key,
        ca_cert=ca_cert,
        kem_key=frodo_key,
        common_name="CN=FrodoKEM-976-AES CA Encr Cert",
    )
    write_cmp_certificate_to_pem(cert, "data/unittest/ca_encr_cert_frodokem_976_aes.pem")
    print("Updated FrodoKEM-976-AES CA Encr Cert")

def _generate_other_trusted_ca_and_device_certs():
    """Build another trusted CA certificate for testing."""
    os.makedirs("data/mock_ca", exist_ok=True)
    os.makedirs("data/mock_ca/trustanchors", exist_ok=True)
    key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)

    extensions = _prepare_root_ca_extensions(key)

    root_cert, _ = build_certificate(
        private_key=key,
        common_name="CN=Other Trusted Root CA RSA",
        extensions=extensions,
        hash_alg="sha512",
    )
    write_cmp_certificate_to_pem(root_cert, "data/mock_ca/trustanchors/root_ca_cert_rsa.pem")

    device_cert, _ = build_certificate(
        private_key=key,
        common_name="CN=Other Trusted Device",
        extensions=extensions,
    )

    device_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")

    device_extn = _prepare_ca_ra_extensions(
        issuer_key=key,
        key=device_key,
        eku=None,
        eku_critical=False,
        key_usage="keyAgreement, digitalSignature",
        key_usage_critical=False,
    )

    device_cert, _ = build_certificate(
        private_key=device_key,
        ca_cert=root_cert,
        ca_key=key,
        common_name="CN=Device Cert ECDSA",
        extensions=extensions,
        hash_alg="sha512",
        device_extn=device_extn,
    )
    device_chain = [device_cert, root_cert]
    write_cert_chain_to_file(device_chain, "data/mock_ca/device_cert_ecdsa_cert_chain.pem")
    print("Updated Other Trusted Device Cert Chain")

def _generate_mock_ca_issued_dsa_cert():
    """Generate and save a mock CA-issued DSA certificate for testing purposes.

    This certificate is intended for use in a test that verifies the CA correctly
    rejects PKIMessages signed with a DSA certificate, as DSA is not supported
    by Lightweight CMP (LwCMP) according to RFC 9483.
    """
    ca_cert, ca_key = load_ca_cert_and_key()
    dsa_key = load_private_key_from_file("data/keys/private-key-dsa.pem")

    from mock_ca.ca_handler import CAHandler
    ca_handler = CAHandler()
    exts = ca_handler._prepare_extensions(
        ca_cert=ca_cert,
    )

    key_usage_extn = prepare_key_usage_extension("digitalSignature", critical=False)
    exts.append(key_usage_extn)

    dsa_cert, _ = build_certificate(
        private_key=dsa_key,
        common_name="CN=DSA Certificate",
        extensions=exts,
        ca_cert=ca_cert,
        ca_key=ca_key,
    )
    write_cmp_certificate_to_pem(dsa_cert, "data/unittest/dsa_certificate.pem")
    print("Updated DSA certificate")

def _generate_mock_ca_certs():
    """Generate and save mock CA certificates for testing."""
    ca_cert, ca_key = load_ca_cert_and_key()
    rsa_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)

    exts = _prepare_ca_ra_extensions(
        issuer_key=ca_key,
        key=rsa_key,
        eku=None,
        eku_critical=False,
        key_usage="digitalSignature, keyEncipherment",
        key_usage_critical=False,
    )

    ca_encr_cert, _ = build_certificate(
        rsa_key,
        common_name="CN=CA Encr Cert RSA",
        extensions=exts,
        ca_cert=ca_cert,
        ca_key=ca_key,
    )
    write_cmp_certificate_to_pem(ca_encr_cert, "data/unittest/ca_encr_cert_rsa.pem")
    print("Updated RSA CA Encr Cert")

    ecc_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
    exts = _prepare_ca_ra_extensions(
        issuer_key=ca_key,
        key=ecc_key,
        eku=None,
        eku_critical=False,
        key_usage="digitalSignature, keyAgreement",
        key_usage_critical=False,
    )
    ca_encr_cert, _ = build_certificate(
        ecc_key,
        common_name="CN=CA Encr Cert ECC",
        extensions=exts,
        ca_cert=ca_cert,
        ca_key=ca_key,
    )
    write_cmp_certificate_to_pem(ca_encr_cert, "data/unittest/ca_encr_cert_ecc.pem")
    print("Updated ECC CA Encr Cert")

    # Generate x25519 and x448 Kari certs.
    x25519_key = load_private_key_from_file("data/keys/private-key-x25519.pem")
    x448_key = load_private_key_from_file("data/keys/private-key-x448.pem")

    x25519_cert, _ = _build_key_agreement_cert(
        ca_key=ca_key,
        ca_cert=ca_cert,
        agree_key=x25519_key,
        common_name="CN=CA Encr Cert X25519",
    )
    write_cmp_certificate_to_pem(x25519_cert, "data/unittest/ca_encr_cert_x25519.pem")
    print("Updated X25519 CA Encr Cert")

    x448_cert, _ = _build_key_agreement_cert(
        ca_key=ca_key,
        ca_cert=ca_cert,
        agree_key=x448_key,
        common_name="CN=CA Encr Cert X448",
    )
    write_cmp_certificate_to_pem(ca_encr_cert, "data/unittest/ca_encr_cert_x448.pem")
    print("Updated X448 CA Encr Cert")

    _generate_mock_ca_kem_certs()
    # For DSA test case.
    _generate_mock_ca_issued_dsa_cert()



def load_kari_certs() -> Dict:
    """Load the KARI certificate for Mock CA or testing."""
    ecc_cert = parse_certificate(load_and_decode_pem_file("data/unittest/ca_encr_cert_ecc.pem"))
    ecc_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
    x25519_cert = parse_certificate(load_and_decode_pem_file("data/unittest/ca_encr_cert_x25519.pem"))
    x25519_key = load_private_key_from_file("data/keys/private-key-x25519.pem")
    x448_cert = parse_certificate(load_and_decode_pem_file("data/unittest/ca_encr_cert_x448.pem"))
    x448_key = load_private_key_from_file("data/keys/private-key-x448.pem")
    return {
        "ecc_cert": ecc_cert,
        "ecc_key": ecc_key,
        "x25519_cert": x25519_cert,
        "x25519_key": x25519_key,
        "x448_cert": x448_cert,
        "x448_key": x448_key,
    }


def load_kem_certs():
    """Load the KEM certificate for Mock CA or testing."""
    data = {}
    cert = parse_certificate(load_and_decode_pem_file("data/unittest/ca_encr_cert_ml_kem_768.pem"))
    ml_kem_key = load_private_key_from_file("data/keys/private-key-ml-kem-768-seed.pem")
    data["kem_cert"] = cert
    data["kem_key"] = ml_kem_key
    cert = parse_certificate(load_and_decode_pem_file("data/unittest/ca_encr_cert_xwing.pem"))
    xwing_key = load_private_key_from_file("data/keys/private-key-xwing-seed.pem")
    data["hybrid_kem_cert"] = cert
    data["hybrid_kem_key"] = xwing_key
    return data


def load_env_data_certs():
    """Load the CA encryption certificate and key for testing."""
    data = load_kari_certs()
    cert = parse_certificate(load_and_decode_pem_file("data/unittest/ca_encr_cert_rsa.pem"))
    rsa_key = load_private_key_from_file("data/keys/private-key-rsa.pem", password=None)
    data["encr_rsa_cert"] = cert
    data["encr_rsa_key"] = rsa_key
    data.update(load_kem_certs())
    return data


def load_kga_cert_chain_and_key() -> Tuple[List[rfc9480.CMPCertificate], SignKey]:
    """Load the KGA certificate chain and key for testing."""
    ca_cert = parse_certificate(load_and_decode_pem_file("data/unittest/root_cert_ed25519.pem"))
    kga_cert = parse_certificate(load_and_decode_pem_file("data/unittest/ra_kga_cert_ecdsa.pem"))
    kga_key = load_private_key_from_file("data/keys/private-key-ecdsa.pem")
    if not isinstance(kga_key, SignKey):
        raise ValueError(f"Expected SignKey, got {type(kga_key)}, for the KGA key.")
    return [kga_cert, ca_cert], kga_key


def _safety_pq_cert_check():
    """Check the safety of the certificates and keys.

    By ensuring that the public key in the certificate matches the private key.
    """
    cert_dir = "data/unittest"
    key_dir = "data/keys"

    # Check ML-DSA-44
    mldsa44_path = "pq_root_ca_ml_dsa_44.pem"
    mldsa44_cert = parse_certificate(utils.load_and_decode_pem_file(f"{cert_dir}/{mldsa44_path}"))
    mldsa44_pub_key = load_public_key_from_cert(mldsa44_cert)

    for key_path in [
        "private-key-ml-dsa-44-seed.pem",
        "private-key-ml-dsa-44-raw.pem",
        "private-key-ml-dsa-44-seed-old.pem",
        "private-key-ml-dsa-44-raw-old.pem",
    ]:
        loaded_mldsa44 = load_private_key_from_file(f"{key_dir}/{key_path}")
        if mldsa44_pub_key != loaded_mldsa44.public_key():
            raise MismatchingKey("ML-DSA-44 private key file does not match the public key in the certificate.")

    # Check ML-DSA-65
    mldsa65_path = "pq_root_ca_ml_dsa_65.pem"
    mldsa65_cert = parse_certificate(utils.load_and_decode_pem_file(f"{cert_dir}/{mldsa65_path}"))
    mldsa65_pub_key = load_public_key_from_cert(mldsa65_cert)

    for key_path in ["private-key-ml-dsa-65-seed.pem", "private-key-ml-dsa-65-raw.pem"]:
        loaded_mldsa65 = load_private_key_from_file(f"{key_dir}/{key_path}")
        if mldsa65_pub_key != loaded_mldsa65.public_key():
            raise MismatchingKey("ML-DSA-65 private key file does not match the public key in the certificate.")

    # Check ML-KEM-768
    mlkem768_path = "pq_cert_ml_kem_768.pem"
    mlkem768_cert = parse_certificate(utils.load_and_decode_pem_file(f"{cert_dir}/{mlkem768_path}"))
    mlkem768_pub_key = load_public_key_from_cert(mlkem768_cert)

    for key_path in [
        "private-key-ml-kem-768-seed.pem",
        "private-key-ml-kem-768-raw.pem",
        "private-key-ml-kem-768-seed-old.pem",
        "private-key-ml-kem-768-raw-old.pem",
    ]:
        loaded_mlkem768 = load_private_key_from_file(f"{key_dir}/{key_path}")
        if mlkem768_pub_key != loaded_mlkem768.public_key():
            raise MismatchingKey("ML-KEM-768 private key file does not match the public key in the certificate.")


def _neither_val_is_set(val1: univ.Sequence, val2: univ.Sequence, field_name: str) -> Tuple[int, str]:
    """Check if neither value is set."""
    if not val1[field_name].isValue and not val2[field_name].isValue:
        return 0, f"Field '{field_name}' is not set in neither objects set."

    if not val1[field_name].isValue and val2[field_name].isValue:
        return -1, f"Field '{field_name}' has only set a value in object 2: {val2[field_name].prettyPrint()}"

    if val1[field_name].isValue and not val2[field_name].isValue:
        return -1, f"Field '{field_name}' has only set a value in object 1: {val1[field_name].prettyPrint()}"

    return 1, "Both values are set"


def verbose_pyasn1_compare(obj1: univ.Sequence, obj2: univ.Sequence, exclude_fields: List[str] = None) -> Tuple[list, list]:
    """Compare two pyasn1 objects and print their differences.

    :param obj1: The first object to compare.
    :param obj2: The second object to compare.
    :param exclude_fields: A list of field names to exclude from the comparison.
    """
    eq_fields = []
    non_eq_fields = []

    field_names = list(obj1.keys())
    exclude_fields = exclude_fields or []

    for field_name in field_names:

        if field_name in exclude_fields:
            continue

        val, msg = _neither_val_is_set(obj1, obj2, field_name)
        if val == 0:
            eq_fields.append(msg)
            continue
        elif val == -1:
            non_eq_fields.append(msg)
            continue

        if encode_to_der(obj1[field_name]) == encode_to_der(obj2[field_name]):
            eq_fields.append(field_name)
            continue
        else:
            msg = f"Field '{field_name}' is not equal: {obj1[field_name].prettyPrint()} vs {obj2[field_name].prettyPrint()}"
            non_eq_fields.append(msg)

    return eq_fields, non_eq_fields

def generate_all_xmss_xmssmt_keys() -> None:
    """Generate all XMSS and XMSSMT keys.

    Generates enabled keys for XMSS and XMSSMT algorithms,
    in the OQS library and saves them to the specified directory.
    The keys are saved in PEM format with filenames based on the algorithm name.
    Directory structure:
    data/keys/xmss_xmssmt_keys/
        ├── private-key-xmss-sha_10_256.pem
        ├── private-key-xmssmt_shake_60_layers_12_256.pem
        └── ...
    """
    dir_path = "data/keys/xmss_xmssmt_keys"
    os.makedirs(dir_path, exist_ok=True)

    if oqs is None:
        raise ImportError("The 'oqs' library is not installed. Please install it to generate XMSS/XMSSMT keys.")

    for alg_name in oqs.get_enabled_stateful_sig_mechanisms():
        alg_name = alg_name.lower()
        if alg_name.startswith("xmss-") or alg_name.startswith("xmssmt-"):
            print(f"Testing algorithm: {alg_name}")
            # XMSS (e.g XMSS-SHA_10_256)
            # XMSSMT (e.g XMSSMT-SHAKE_60/12_256)
            key_name = alg_name.lower().replace("/", "_layers_", 1)
            path = os.path.join(dir_path, f"private-key-{key_name}.pem")
            if os.path.exists(path):
                print(f"Key already exists at {path}, skipping generation.")
                continue
            key = generate_key(alg_name)
            save_key(key, path)

def generate_all_hss_keys() -> None:
    """Generate all HSS keys.

    Generates enabled keys for HSS algorithms and saves them to the specified directory.
    The keys are saved in PEM format with filenames based on the algorithm name and the level as _l<num>.
    """
    dir_path = "data/keys/hss_keys"
    os.makedirs(dir_path, exist_ok=True)
    for alg_name in PQStatefulSigFactory.get_algorithms_by_family()["hss"]:
        print(f"Testing algorithm: {alg_name}")





def get_all_xmss_xmssmt_keys() -> dict[str, str]:
    """Get all XMSS and XMSSMT keys.

    :return: Dictionary of algorithm names and their key file paths.
    """
    dir_path = "./data/keys/xmss_xmssmt_keys"
    keys = {}
    # here importing, if not enabled, it will raise an ImportError,
    # but the file does not exist, so it is safe to import here.

    if oqs is None:
        raise ImportError("The 'oqs' library is not installed. Please install it to load XMSS/XMSSMT keys.")

    for alg_name in oqs.get_enabled_stateful_sig_mechanisms():
        alg_name = alg_name.lower()
        if alg_name.startswith("xmss-") or alg_name.startswith("xmssmt-"):
            key_name = alg_name.lower().replace("/", "_layers_", 1)
            path = os.path.join(dir_path, f"private-key-{key_name}.pem")
            if os.path.exists(path):
                keys[alg_name] = path
            else:
                raise FileNotFoundError(f"Key file for {alg_name} not found at {path}")

    return keys
