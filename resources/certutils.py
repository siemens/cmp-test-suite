"""Some wrapper-tools for validating an X509 cert by invoking other software, e.g., OpenSSL, pkilint."""

import logging
from typing import Optional

from cryptography import x509
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, padding, rsa, x448, x25519
from pkilint import loader, report
from pkilint.pkix import certificate, extension, name
from pkilint.validation import ValidationFindingSeverity
from pyasn1.codec.der import decoder
from pyasn1_alt_modules import rfc9480
from robot.api.deco import not_keyword

from oid_mapping import hash_name_to_instance
from typingutils import PublicKeySig

# TODO for these to integrate smoothly into RF, they have to raise exceptions in case of failure, rather than
# return False


@not_keyword
def parse_certificate(data: bytes) -> rfc9480.CMPCertificate:
    """Parse a DER-encoded X509 certificate into a pyasn1 object.

    :param data: bytes, DER-encoded X509 certificate.
    :returns: pyasn1 object, the parsed `rfc9480.CMPCertificate`.
    """
    cert, _rest = decoder.decode(data, asn1Spec=rfc9480.CMPCertificate())
    return cert


def validate_certificate_openssl(data):
    """Validate a certificate by attempting to load it with the cryptography library, which invokes OpenSSL underneath.

    :param data: bytes, DER-encoded X509 certificate.
    :returns bool: True if loading was without errors, otherwise False
    """
    try:
        _certificate = x509.load_der_x509_certificate(data, backends.default_backend())
    except Exception as e:
        message = f"Certificate validation with openssl failed: {e}"
        logging.error(message)
        raise ValueError(message) from e


def validate_certificate_pkilint(data):
    """Validate a certificate using the pkilint tool.

    :param data: bytes, DER-encoded X509 certificate.
    :returns None: Will raise an exception if issues were found
    """
    doc_validator = certificate.create_pkix_certificate_validator_container(
        certificate.create_decoding_validators(name.ATTRIBUTE_TYPE_MAPPINGS, extension.EXTENSION_MAPPINGS),
        [
            certificate.create_issuer_validator_container([]),
            certificate.create_validity_validator_container(),
            certificate.create_subject_validator_container([]),
            certificate.create_extensions_validator_container([]),
        ],
    )

    cert = loader.load_certificate(data, "dynamic-cert")
    results = doc_validator.validate(cert.root)

    findings_count = report.get_findings_count(results, ValidationFindingSeverity.WARNING)
    if findings_count > 0:
        issues = report.ReportGeneratorPlaintext(results, ValidationFindingSeverity.WARNING).generate()
        raise ValueError(issues)


def verify_signature(public_key: PublicKeySig, signature: bytes, data: bytes, hash_alg: str = None) -> None:  # noqa: D417
    """Verify a digital signature using the provided public key, data and hash algorithm.

    Supports: (ECDSA, ED448, ED25519, RSA, DSA).

    Arguments:
    ---------
        - `public_key`: The public key used to verify the signature.
        - `signature`: signature data.
        - `data`: The original data that was signed.
        - `hash_alg`: Name of the hash algorithm used for verification (e.g., "sha256"). If not specified, the default
                      algorithm for the given key type is used.

    Key Types and Verification:
        - `RSAPublicKey`: Verifies using PKCS1v15 padding and the provided hash algorithm.
        - `EllipticCurvePublicKey`: Verifies using ECDSA with the provided hash algorithm.
        - `Ed25519PublicKey` and `Ed448PublicKey`: Verifies without a hash algorithm.
        - `DSAPublicKey`: Verifies using the provided hash algorithm.
        - Unsupported key types (e.g., `X25519PublicKey`, `X448PublicKey`): Raises an error.

    Raises:
    ------
        - InvalidSignature: If the signature is invalid.
        - ValueError: If an unsupported key type is provided.

    Example:
    -------
        | Verify Signature | ${public_key} | ${signature} | ${data} | sha256 |

    """
    if isinstance(hash_alg, hashes.HashAlgorithm):
        pass
    elif hash_alg is not None:
        hash_alg = hash_name_to_instance(hash_alg)

    # isinstance(ed448.Ed448PrivateKey.generate(), EllipticCurvePrivateKey) → False
    # so can check in this Order.
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(signature, data, padding=padding.PKCS1v15(), algorithm=hash_alg)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, data, ec.ECDSA(hash_alg))
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        public_key.verify(signature, data)
    elif isinstance(public_key, ed448.Ed448PublicKey):
        public_key.verify(signature, data)
    elif isinstance(public_key, dsa.DSAPublicKey):
        public_key.verify(signature, data, hash_alg)
    elif isinstance(public_key, (x25519.X25519PublicKey, x448.X448PublicKey)):
        raise ValueError(
            f"Key type '{type(public_key).__name__}' is not used for signing or verifying signatures."
            f"It is used for key exchange."
        )
    else:
        raise ValueError(f"Unsupported public key type: {type(public_key).__name__}.")


@not_keyword
def verify_cert_signature(cert: x509.Certificate, issuer_pub_key: Optional[PublicKeySig] = None):
    """Verify the signature of an X.509 certificate.

    Uses the issuer's public key, or the certificate's own public key if it is self-signed.

    :param cert: `cryptography.x509.Certificate` which is verified.
    :param issuer_pub_key: optional PublicKeySig used for verification.

    :raises InvalidSignature: If the certificate's signature is not valid.
    """
    pub_key = issuer_pub_key or cert.public_key()

    verify_signature(
        public_key=pub_key,
        signature=cert.signature,
        data=cert.tbs_certificate_bytes,
        hash_alg=cert.signature_hash_algorithm,
    )


@not_keyword
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
