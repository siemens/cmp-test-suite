# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Utility functions for serializing keys."""

import base64
import textwrap

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pyasn1.codec.der import encoder
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc5915, rfc8017
from robot.api.deco import not_keyword

from resources.oidutils import CURVE_NAME_2_OID


def prepare_enc_key_pem(password: str, one_asym_key: bytes, key_name: bytes) -> bytes:
    """Prepare PEM formatted encrypted key.

    :param password: Password for encryption.
    :param one_asym_key: Key to encrypt.
    :param key_name: Name of the key.
    :return: PEM formatted encrypted key.
    """
    from pq_logic.keys.key_pyasn1_utils import derive_and_encrypt_key

    enc_data, iv = derive_and_encrypt_key(password=password, data=one_asym_key, decrypt=False)

    pem_lines = []
    pem_lines.append(b"-----BEGIN " + key_name + b" PRIVATE KEY-----")
    pem_lines.append(b"Proc-Type: 4,ENCRYPTED")
    pem_lines.append(b"DEK-Info: AES-256-CBC," + iv.hex().upper().encode("ascii"))
    pem_lines.append(b"")

    b64 = base64.b64encode(enc_data).decode("ascii")
    wrapped = "\n".join(textwrap.wrap(b64, width=64))

    pem_lines.extend(line.encode("ascii") for line in wrapped.split("\n"))
    pem_lines.append(b"-----END " + key_name + b" PRIVATE KEY-----")
    pem_lines.append(b"")

    return b"\n".join(pem_lines)


@not_keyword
def prepare_rsa_private_key(rsa_key: rsa.RSAPrivateKey) -> bytes:
    """Prepare an RSA private key for encoding.

    :param rsa_key: The RSA private key to prepare.
    :return: The RSA private key as DER-encoded `RSAPrivateKey`.
    """
    private_nums = rsa_key.private_numbers()

    rsa_asn1_key = rfc8017.RSAPrivateKey()
    rsa_asn1_key["version"] = 0
    rsa_asn1_key["modulus"] = private_nums.public_numbers.n
    rsa_asn1_key["publicExponent"] = private_nums.public_numbers.e
    rsa_asn1_key["privateExponent"] = private_nums.d
    rsa_asn1_key["prime1"] = private_nums.p
    rsa_asn1_key["prime2"] = private_nums.q
    rsa_asn1_key["exponent1"] = private_nums.dmp1
    rsa_asn1_key["exponent2"] = private_nums.dmq1
    rsa_asn1_key["coefficient"] = private_nums.iqmp
    der_data = encoder.encode(rsa_asn1_key)
    return der_data


@not_keyword
def prepare_ec_private_key(ec_key: ec.EllipticCurvePrivateKey) -> rfc5915.ECPrivateKey:
    """Prepare an EC private key for encoding in ASN.1."""
    private_nums = ec_key.private_numbers()
    ec_private_key = rfc5915.ECPrivateKey()
    ec_private_key["version"] = 1
    ec_private_key["privateKey"] = private_nums.private_value.to_bytes(
        (private_nums.private_value.bit_length() + 7) // 8, "big"
    )
    curve_oid = CURVE_NAME_2_OID[ec_key.curve.name.lower()]
    ec_private_key["parameters"]["namedCurve"] = curve_oid

    public_key = ec_key.public_key()
    public_bytes = public_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)

    ec_private_key["publicKey"] = univ.BitString(hexValue=public_bytes.hex()).subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
    )

    return ec_private_key
