from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, dsa, x25519, x448, rsa, padding
from robot.api.deco import not_keyword

from oid_mapping import hash_name_to_instance
from typingutils import PublicKeySig


def verify_signature(public_key: PublicKeySig, signature: bytes, data: bytes, hash_alg: str = None) -> None:
    """""Verify a digital signature using the provided public key, data and hash algorithm.
    Supports: (ECDSA, ED448, ED25519, RSA, DSA).

    Args:
        `public_key` (cryptography.hazmat.primitives.asymmetric): The public key object used to verify the signature.
        `signature` (bytes): The digital signature to be verified, provided as a byte sequence.
        `data` (bytes): The original data that was signed, provided as a byte sequence.
        `hash_alg` (Optional str ): An optional string representing the name of the hash algorithm to be used for verification
                                  (e.g., "sha256"). If not specified, the default algorithm for the given key type is used.

    Key Types and Verification:
        - `RSAPublicKey`: Verifies using PKCS1v15 padding and the provided hash algorithm.
        - `EllipticCurvePublicKey`: Verifies using ECDSA with the provided hash algorithm.
        - `Ed25519PublicKey` and `Ed448PublicKey`: Verifies without a hash algorithm.
        - `DSAPublicKey`: Verifies using the provided hash algorithm.
        - Unsupported key types (e.g., `X25519PublicKey`, `X448PublicKey`): Raises an error.

    Raises:
        InvalidSignature: If the signature is invalid.
        ValueError: If an unsupported key type is provided.

    Example:
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
            f"Key type '{type(public_key).__name__}' is not used for signing or verifying signatures. It is used for key exchange."
        )
    else:
        raise ValueError(f"Unsupported public key type: {type(public_key).__name__}.")


@not_keyword
def verify_cert_signature(certificate: x509.Certificate):
    """Verify the digital signature of an X.509 certificate using the provided or extracted public key.

    :param certificate:
        The certificate to verify, represented in a type that can be cast to an X.509 certificate object.
        It should be in a DER-encoded form compatible with the `x509.Certificate` type.

    :raises InvalidSignature:
        If the certificate's signature is not valid when verified against the provided or extracted public key.
    """

    verify_signature(
        public_key=certificate.public_key(),
        signature=certificate.signature,
        data=certificate.tbs_certificate_bytes,
        hash_alg=certificate.signature_hash_algorithm,
    )


@not_keyword
def verify_csr_signature(csr: x509.CertificateSigningRequest):
    """Verify the digital signature of an X.509 CSR using the provided or extracted public key.

    :param csr:
        The Certificate Signing Request to verify, represented in a type that can be cast to an X.509 CSR object.
        It should be in a DER-encoded form compatible with the `x509.Certificate` type.

    :raises InvalidSignature:
        If the csr's signature is not valid when verified against the provided or extracted public key.
    """

    verify_signature(
        public_key=csr.public_key(),
        signature=csr.signature,
        data=csr.tbs_certrequest_bytes,
        hash_alg=csr.signature_hash_algorithm,
    )
