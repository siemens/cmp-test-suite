# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Contains functionally which is only needed to test a client CMP-implementation."""

import logging
import os
import random
from typing import Dict, List, Optional, Sequence, Tuple, Union

import pyasn1.error
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, padding, x448, x25519
from cryptography.hazmat.primitives.asymmetric.dh import DHPublicKey
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc4211, rfc5280, rfc5480, rfc5652, rfc5958, rfc6664, rfc9480, rfc9481
from robot.api.deco import keyword, not_keyword

from pq_logic import pq_verify_logic
from pq_logic.combined_factory import CombinedKeyFactory
from pq_logic.keys.abstract_pq import PQKEMPublicKey
from pq_logic.keys.abstract_stateful_hash_sig import PQHashStatefulSigPublicKey
from pq_logic.keys.abstract_wrapper_keys import (
    HybridKEMPrivateKey,
    HybridKEMPublicKey,
    HybridPublicKey,
    KEMPrivateKey,
    KEMPublicKey,
    PQPublicKey,
)
from pq_logic.pq_utils import get_kem_oid_from_key, is_kem_public_key
from resources import (
    ca_kga_logic,
    certbuildutils,
    certutils,
    cmputils,
    compareutils,
    convertutils,
    cryptoutils,
    envdatautils,
    keyutils,
    prepare_alg_ids,
    prepareutils,
    protectionutils,
    utils,
)
from resources.asn1_structures import CertResponseTMP, ChallengeASN1, PKIBodyTMP, PKIMessageTMP
from resources.asn1utils import get_set_bitstring_names, try_decode_pyasn1
from resources.ca_kga_logic import get_digest_hash_alg_from_alg_id
from resources.certextractutils import get_extension
from resources.convertutils import (
    copy_asn1_certificate,
    ensure_is_kem_pub_key,
    ensure_is_verify_key,
    str_to_bytes,
    subject_public_key_info_from_pubkey,
)
from resources.data_objects import ExtraIssuingData, KARICertsAndKeys
from resources.exceptions import (
    AddInfoNotAvailable,
    BadAlg,
    BadAsn1Data,
    BadCertId,
    BadCertTemplate,
    BadDataFormat,
    BadMessageCheck,
    BadPOP,
    BadRequest,
    BadSigAlgID,
    CertRevoked,
    CMPTestSuiteError,
    InvalidAltSignature,
    InvalidKeyData,
    NotAuthorized,
    SignerNotTrusted,
    UnsupportedVersion,
)
from resources.oid_mapping import compute_hash, get_hash_from_oid, may_return_oid_to_name, sha_alg_name_to_oid
from resources.oidutils import CURVE_OID_2_NAME, id_KemBasedMac
from resources.suiteenums import InvalidOneAsymKeyType, KeySaveType
from resources.typingutils import (
    CAResponse,
    CertOrCerts,
    ECDHPrivateKey,
    ECDHPublicKey,
    EnvDataPrivateKey,
    ExtensionsParseType,
    PrivateKey,
    PublicKey,
    SignKey,
    Strint,
)


def _prepare_rand(
    sender: Optional[Union[rfc9480.GeneralName, str]],
    rand_int: Optional[int] = None,
    cert: Optional[rfc9480.CMPCertificate] = None,
) -> rfc9480.Rand:
    """Prepare the `Rand` structure for the challenge.

    :param sender: The sender of the message.
    :param rand_int: The random number to use. Defaults to `None`.
    :param cert: The certificate to use to populate the `Rand` sender field. Defaults to `None`.
    :return: The populated `Rand` structure.
    :raises ValueError: If neither `sender` nor `cert` is provided.
    """
    if sender is None and cert is None:
        raise ValueError("Either `sender` or `cert` must be provided.")

    rand_obj = rfc9480.Rand()
    if rand_int is None:
        rand_int = int.from_bytes(os.urandom(4), "big")

    if isinstance(sender, str):
        sender = prepareutils.prepare_general_name("directoryName", sender)

    if cert:
        tmp = cert["tbsCertificate"]["subject"]
        sender = rfc9480.GeneralName()
        sender["directoryName"]["rdnSequence"] = tmp["rdnSequence"]

    rand_obj["sender"] = sender
    rand_obj["int"] = rand_int
    return rand_obj


def _prepare_witness_val(
    challenge_obj: ChallengeASN1, hash_alg: Optional[str], rand: rfc9480.Rand, bad_witness: bool
) -> ChallengeASN1:
    """Get the witness value for the challenge.

    :param challenge_obj: The challenge object.
    :param hash_alg: The hash algorithm to use. Defaults to `None`.
    :param rand: The random number to use.
    :param bad_witness: Whether to manipulate the witness value. Defaults to `False`.
    (witness is the hash of the integer.)
    :return: The updated challenge object.
    """
    witness = b""
    if hash_alg:
        challenge_obj["owf"] = prepare_alg_ids.prepare_sha_alg_id(hash_alg or "sha256")
        num_bytes = (int(rand["int"])).to_bytes(4, "big")
        witness = compute_hash(hash_alg, num_bytes)
        logging.info("valid witness value: %s", witness.hex())

    if bad_witness:
        if not hash_alg:
            witness = os.urandom(32)
        else:
            witness = utils.manipulate_first_byte(witness)

    challenge_obj["witness"] = univ.OctetString(witness)
    return challenge_obj


@not_keyword
def prepare_challenge(
    public_key: PublicKey,
    ca_key: Optional[PrivateKey] = None,
    bad_witness: bool = False,
    hash_alg: Optional[str] = None,
    rand_sender: Optional[str] = "CN=CMP-Test-Suite CA",
    rand_int: Optional[int] = None,
    iv: Union[str, bytes] = b"AAAAAAAAAAAAAAAA",
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
) -> Tuple[ChallengeASN1, Optional[bytes], Optional[rfc9480.InfoTypeAndValue]]:
    """Prepare a challenge for the PKIMessage.

    :param public_key: The public key of the end-entity (EE).
    :param ca_key: The private key of the CA/RA.
    :param bad_witness: Whether to manipulate the witness value. Defaults to `False`.
    :param hash_alg: The hash algorithm to use. Defaults to `None`.
    :param rand_sender: The sender inside the Rand structure. Defaults to "CN=CMP-Test-Suite CA".
    :param rand_int: The random number to use. Defaults to `None`.
    :param iv: The initialization vector to use, for AES-CBC. Defaults to `b"AAAAAAAAAAAAAAAA"`.
    :param ca_cert: The CA certificate to use to populate the `Rand` sender field. Defaults to `None`.
    :return: The populated `Challenge` structure, the shared secret, and the info value (for KEMs/HybridKEMs).
    :raises ValueError: If the public key type is invalid. Must be either EC or KEM key.
    If neither `sender` nor `cert` is provided.
    """
    challenge_obj = ChallengeASN1()
    info_val: Optional[rfc9480.InfoTypeAndValue] = None

    rand = _prepare_rand(sender=rand_sender, rand_int=rand_int, cert=ca_cert)
    data = encoder.encode(rand)
    challenge_obj = _prepare_witness_val(
        challenge_obj=challenge_obj, rand=rand, hash_alg=hash_alg, bad_witness=bad_witness
    )

    if isinstance(public_key, RSAPublicKey):
        enc_data = public_key.encrypt(data, padding=padding.PKCS1v15())
        challenge_obj["challenge"] = univ.OctetString(enc_data)
        return challenge_obj, None, None

    if isinstance(public_key, ECDHPublicKey):
        if not isinstance(ca_key, ECDHPrivateKey):
            raise ValueError("ECDH private key is required for ECDH public key challenge.")
        shared_secret = cryptoutils.perform_ecdh(ca_key, public_key)
        shared_secret = protectionutils.dh_based_mac_derive_key(shared_secret, desired_length=32, owf="sha256")

    elif is_kem_public_key(public_key):
        public_key = convertutils.ensure_is_kem_pub_key(public_key)
        shared_secret, ct = public_key.encaps()
        info_val = protectionutils.prepare_kem_ciphertextinfo(key=public_key, ct=ct)
    else:
        raise ValueError(f"Invalid public key type, to prepare a challenge: {type(public_key).__name__}")

    enc_data = cryptoutils.compute_aes_cbc(key=shared_secret, data=data, iv=str_to_bytes(iv), decrypt=False)

    challenge_obj["challenge"] = univ.OctetString(enc_data)
    return challenge_obj, shared_secret, info_val


@keyword(name="Prepare Challenge Encrypted Rand")
def prepare_challenge_enc_rand(  # noqa: D417 Missing argument descriptions in the docstring
    public_key: PublicKey,
    rand_sender: Optional[Union[rfc9480.GeneralName, str]] = None,
    rand_int: Optional[int] = None,
    hash_alg: Optional[str] = None,
    bad_witness: bool = False,
    cert_req_id: int = 0,
    private_key: Optional[ECDHPrivateKey] = None,
    hybrid_kem_key: Optional[HybridKEMPrivateKey] = None,
    challenge: Optional[Union[str, bytes]] = None,
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
) -> ChallengeASN1:
    """Prepare a `Challenge` structure with an encrypted random number.

    Arguments:
    ---------
        - `public_key`: The public key of the end-entity (EE), used to create the `EnvelopedData` structure.
        - `sender`: The sender of the message, to set in the `Rand` structure.
        Either a `GeneralName` or a string.
        - `rand_int`: The random number to be encrypted. Defaults to `None`.
        (a random number is generated if not provided)
        - `private_key`: The private key of the server (CA/RA). Defaults to `None`.
        - `hash_alg`: The hash algorithm to use to hash the random number (e.g., "sha256"). Defaults to `None`.
        - `bad_witness`: The hash of the challenge. Defaults to an empty byte string.
        - `cert_req_id`: The certificate request ID , used in the `rid` field. Defaults to `0`.
        - `hybrid_kem_key`: The hybrid KEM key to use. Defaults to `None`.
        - `challenge`: The challenge to use. Defaults to an empty byte string.
        - `ca_cert`: The CA certificate to use to populate the `Rand` sender field. Defaults to `None`.

    Returns:
    -------
        - The populated `Challenge` structure.

    Raises:
    ------
        - `ValueError`: If the public key type is invalid.
        - `ValueError`: If neither `sender` nor `ca_cert` is provided.

    Examples:
    --------
    | ${challenge}= | Prepare Challenge Encrypted Rand | ${public_key} | ${sender} |
    | ${challenge}= | Prepare Challenge Encrypted Rand | ${public_key} | ${sender} | rand_int=1 | bad_witness=True |

    """
    challenge_obj = ChallengeASN1()

    rand_obj = _prepare_rand(sender=rand_sender, rand_int=rand_int, cert=ca_cert)

    env_data = rfc9480.EnvelopedData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
    issuer_and_ser = certbuildutils.prepare_issuer_and_serial_number(serial_number=cert_req_id, issuer="Null-DN")

    trad_key: Optional[ECDHPrivateKey]
    if isinstance(hybrid_kem_key, HybridKEMPrivateKey):
        trad_key = hybrid_kem_key.trad_key  # type: ignore
    else:
        trad_key = None

    env_data = envdatautils.build_env_data_for_exchange(
        public_key_recip=public_key,
        data=encoder.encode(rand_obj),
        private_key=private_key,
        target=env_data,
        issuer_and_ser=issuer_and_ser,
        hybrid_key_recip=trad_key,
        enc_oid=rfc5652.id_data,
    )

    challenge_obj = _prepare_witness_val(
        challenge_obj=challenge_obj, rand=rand_obj, hash_alg=hash_alg, bad_witness=bad_witness
    )

    challenge = challenge or b""
    challenge = str_to_bytes(challenge)

    challenge_obj["encryptedRand"] = env_data
    challenge_obj["challenge"] = univ.OctetString(challenge)
    return challenge_obj


def prepare_oob_cert_hash(  # noqa: D417 Missing argument descriptions in the docstring
    ca_cert: rfc9480.CMPCertificate, hash_alg: str = "sha256"
) -> rfc9480.OOBCertHash:
    """Prepare an `OOBCertHash` from a CA certificate.

    Arguments:
    ---------
        - `ca_cert`: The OOB CA certificate.
        - `hash_alg`: The hash algorithm to use (e.g., "sha256"). Defaults to "sha256".

    Returns:
    -------
        - The populated `OOBCertHash` structure.

    Examples:
    --------
    | ${oob_cert_hash}= | Prepare OOBCertHash | ${ca_cert} |
    | ${oob_cert_hash}= | Prepare OOBCertHash | ${ca_cert} | sha256 |

    """
    sig = compute_hash(hash_alg, encoder.encode(ca_cert))

    oob_cert_hash = rfc9480.OOBCertHash()
    oob_cert_hash["hashAlg"]["algorithm"] = sha_alg_name_to_oid(hash_alg)
    oob_cert_hash["certId"] = rfc9480.CertId()
    oob_cert_hash["certId"]["issuer"] = ca_cert["tbsCertificate"]["issuer"]
    oob_cert_hash["certId"]["serialNumber"] = ca_cert["tbsCertificate"]["serialNumber"]

    oob_cert_hash["hashVal"] = univ.BitString.fromOctetString(sig)

    return oob_cert_hash


# TODO add unit test for this function


@keyword(name="Validate OOBCertHash")
def validate_oob_cert_hash(  # noqa: D417 Missing argument descriptions in the docstring
    ca_cert: rfc9480.OOBCert, oob_cert_hash: rfc9480.OOBCertHash
) -> None:
    """Validate an `OOBCertHash` against a CA certificate.

    Arguments:
    ---------
        - `ca_cert`: The OOB CA certificate.
        - `oob_cert_hash`: The OOB cert hash to validate.

    Raises:
    ------
        - ValueError: If the OOB cert hash is invalid.
        - `BadAlg`: If the hash algorithm is invalid.

    Examples:
    --------
    | Validate OOBCertHash | ${ca_cert} | ${oob_cert_hash} |

    """
    hash_name = get_hash_from_oid(oob_cert_hash["hashAlg"]["algorithm"])

    if hash_name is None:
        raise BadAlg("Invalid hash algorithm inside the `OOBCertHash`")

    sig = compute_hash(hash_name, encoder.encode(oob_cert_hash))

    if sig != oob_cert_hash["hashVal"].asOctets():
        raise ValueError("Invalid OOB cert hash")

    if ca_cert["tbsCertificate"]["issuer"] != oob_cert_hash["certId"]["issuer"]:
        raise ValueError("Invalid OOB cert issuer")

    if ca_cert["tbsCertificate"]["serialNumber"] != oob_cert_hash["certId"]["serialNumber"]:
        raise ValueError("Invalid OOB cert serial number")

    # Validate as of rfc4210bis-15 Section 5.2.5. Out-of-band root CA Public Key:
    #
    # 1. MUST be self-signed
    # 2. MUST have the same issuer and subject.
    if not certutils.check_is_cert_signer(ca_cert, ca_cert):
        raise ValueError("CA cert is not self-signed")

    # 3. If the subject field contains a "NULL-DN", then both subjectAltNames and issuerAltNames
    # extensions MUST be present and have exactly the same value

    if compareutils.is_null_dn(ca_cert["tbsCertificate"]["subject"]):
        logging.info("Subject is NULL-DN")
        extn_san = get_extension(ca_cert["tbsCertificate"]["extensions"], rfc5280.id_ce_subjectAltName)
        extn_ian = get_extension(ca_cert["tbsCertificate"]["extensions"], rfc5280.id_ce_issuerAltName)

        if extn_ian is None:
            raise ValueError("IssuerAltName missing")
        if extn_san is None:
            raise ValueError("SubjectAltName missing")

        logging.info("SubjectAltName: %s", extn_san.prettyPrint())
        logging.info("IssuerAltName: %s", extn_ian.prettyPrint())

        if extn_san["critical"] != extn_ian["critical"]:
            raise ValueError("SubjectAltName and IssuerAltName must have same criticality.")

        if extn_san["extnValue"].asOctets() != extn_ian["extnValue"].asOctets():
            raise ValueError("SubjectAltName and IssuerAltName must have same value")

    # Validate other self-signed features.
    # 4. The values of all other extensions must be suitable for a self-signed certificate
    # (e.g., key identifiers for subject and issuer must be the same).
    certutils.validate_certificate_pkilint(ca_cert)


@keyword("Get CertReqMsg From PKIMessage")
def get_cert_req_msg_from_pkimessage(  # noqa: D417 Missing argument descriptions in the docstring
    pki_message: PKIMessageTMP, index: Strint = 0
) -> rfc4211.CertReqMsg:
    """Extract the certificate request from a PKIMessage.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage to extract the certificate request from.
        - `index`: The index of the certificate request to extract. Defaults to `0`.

    Returns:
    -------
        - The certificate request message.

    Raises:
    ------
        - ValueError: If the body type is not one of `ir`, `cr`, `kur`, or `crr`.
        - IndexError: If the index is out of range.

    Examples:
    --------
    | ${cert_req_msg}= | Get CertReqMsg From PKIMessage | ${pki_message} |
    | ${cert_req_msg}= | Get CertReqMsg From PKIMessage | ${pki_message} | index=0 |

    """
    body_name = pki_message["body"].getName()
    if body_name in {"ir", "cr", "kur", "ccr"}:
        return pki_message["body"][body_name][int(index)]

    raise ValueError(f"Invalid PKIMessage body: {body_name} Expected: ir, cr, kur, ccr")


@keyword(name="Validate certReqId")
def validate_cert_req_id(  # noqa: D417 Missing argument descriptions in the docstring
    pki_message: PKIMessageTMP, cert_req_id: Strint = 0
) -> None:
    """Validate the certificate request certificate ID.

    Used for LwCMP to ensure the certReqId in the PKIMessage matches
    either one or minus one for p10cr.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage to validate.
        - `cert_req_id`: The index of the certificate request to validate. Defaults to `0`.

    Raises:
    ------
        - `BadRequest`: If the certificate request ID in the PKIMessage is invalid.
        - `ValueError`: If the body was not of the expected type.

    Examples:
    --------
    | Validate certReqId | ${pki_message} | 0 |

    """
    cert_req_id = int(cert_req_id)
    body_name = pki_message["body"].getName()

    if body_name in {"ir", "cr", "kur", "ccr"}:
        cert_req_msg = get_cert_req_msg_from_pkimessage(pki_message)
        cert_id = cert_req_msg["certReq"]["certReqId"]
        if cert_id != cert_req_id:
            raise BadRequest("Invalid certReqId in PKIMessage.")
    else:
        raise ValueError(f"Invalid PKIMessage body: {body_name} Expected: ir, cr, kur, crr or p10cr")


@not_keyword
def get_public_key_from_cert_req_msg(cert_req_msg: rfc4211.CertReqMsg, must_be_present: bool = True) -> PublicKey:
    """Extract the public key from a certificate request message.

    :param cert_req_msg: The certificate request message.
    :param must_be_present: Whether the public key must be present. Defaults to `True`.
    :return: The extracted public key.
    :raises ValueError: If the public key type is invalid.
    """
    return keyutils.load_public_key_from_cert_template(
        cert_req_msg["certReq"]["certTemplate"],  # type: ignore
        must_be_present=must_be_present,
    )


def _prepare_recip_info_for_kga(
    cek: bytes,
    password: Optional[Union[bytes, str]] = None,
    public_key: Optional[PublicKey] = None,
    cert: Optional[rfc9480.CMPCertificate] = None,
    ec_priv_key: Optional[ECDHPrivateKey] = None,
    hash_alg: Optional[str] = None,
    **kwargs,  # pylint: disable=unused-argument
) -> rfc5652.RecipientInfo:
    """Prepare the recipient info for the key generation action.

    :param cek: The content encryption key to use.
    :param password: The password to use for encrypting the private key. Defaults to `None`.
    :param public_key: The public key to use for encrypting the private key. Defaults to `None`.
    :param cert: The CMP protection certificate to use for `KARI`, `KTRI`
    or the recipient cert for `KEMRI`. Defaults to `None`.
    :param ec_priv_key: The ECDH private key to use for `KARI`. Defaults to `None`.
    :param hash_alg: The hash algorithm to use for `KARI` or `KEMRI`. Defaults to "sha256".
    :return: The public key of the newly generated private key and the enveloped data containing the private key.
    :raises ValueError: If neither `password` nor `public_key` is provided or
    if the public key type is invalid.
    """
    if password is None and public_key is None:
        raise ValueError("Either `password` or `public_key` must be provided.")

    if public_key is not None:
        if isinstance(public_key, RSAPublicKey):
            recip_info = envdatautils.prepare_ktri(ee_key=public_key, cek=cek, cmp_protection_cert=cert)

        elif isinstance(public_key, ECDHPublicKey):
            if ec_priv_key is None:
                raise ValueError("ECDH private key is required for KARI.")

            recip_info = envdatautils.prepare_kari(
                public_key=public_key,
                sender_private_key=ec_priv_key,
                cek=cek,
                cmp_protection_cert=cert,
                hash_alg=hash_alg or "sha256",
            )
        elif is_kem_public_key(public_key):
            recip_info = envdatautils.prepare_kem_recip_info(
                public_key_recip=public_key,  # type: ignore
                cek=cek,
                recip_cert=cert,
                hash_alg=hash_alg or "sha256",
            )
        else:
            raise ValueError(f"Invalid public key type: {type(public_key).__name__}")
    else:
        pwd = str_to_bytes(password)  # type: ignore
        recip_info = envdatautils.prepare_password_recipient_info(password=pwd, cek=cek)

    return recip_info  # type: ignore


def _generate_ec_key_from_alg_id(alg_id: rfc9480.AlgorithmIdentifier) -> ec.EllipticCurvePrivateKey:
    """Generate an elliptic curve key from an algorithm identifier.

    :param alg_id: The algorithm identifier to generate the key from.
    :return: The generated elliptic curve key.
    :raises ValueError: If the algorithm is not supported.
    """
    if not alg_id["parameters"].isValue:
        raise BadDataFormat(
            "Parameters are missing in the algorithm identifier.For ECC, the `parameters` must be present."
        )

    ec_params, rest = decoder.decode(alg_id["parameters"].asOctets(), asn1Spec=rfc5480.ECParameters())
    if rest:
        raise BadDataFormat("`ECParameters`")

    curve_name = CURVE_OID_2_NAME.get(ec_params["namedCurve"])

    if curve_name is None:
        raise BadAlg(ec_params["namedCurve"], failinfo="badAlg, badCertTemplate")

    return keyutils.generate_key("ecc", curve=curve_name)  # type: ignore


def _get_kga_key_from_cert_template(
    cert_template: rfc4211.CertTemplate, default_key_type: Optional[str] = "rsa"
) -> PrivateKey:
    """Get the key for the key generation action.

    :param cert_template: The certificate template to get the key from.
    :param default_key_type: The default key type to generate. Defaults to "rsa".
    :return: The generated key.
    :raises BadCertTemplate: If the key OID is not recognized or if the public key value is set,
    but not the OID.
    """
    alg_name = default_key_type or "rsa"

    oid = cert_template["publicKey"]["algorithm"]["algorithm"]

    if cert_template["publicKey"].isValue:
        if not cert_template["publicKey"]["algorithm"].isValue:
            raise BadCertTemplate("Public key algorithm is missing in the certificate template.")
        if not cert_template["publicKey"]["subjectPublicKey"].isValue:
            raise BadCertTemplate("Public key value is missing in the certificate template.")
        if cert_template["publicKey"]["subjectPublicKey"].asOctets() != b"":
            raise BadPOP("Public key value is set, but not the `POPO`.")

        alg_name = may_return_oid_to_name(oid)

        if oid == rfc6664.id_ecPublicKey:
            return _generate_ec_key_from_alg_id(cert_template["publicKey"]["algorithm"])

        if "." in alg_name:
            raise BadCertTemplate(f"Unknown KGA Public key OID: {alg_name}", failinfo="badAlg, badCertTemplate")

    return keyutils.generate_key(alg_name, by_name=True)


@not_keyword
def prepare_invalid_kga_private_key(
    invalid_operation: Optional[Union[str, InvalidOneAsymKeyType]],
    new_private_key: PrivateKey,
    key_export_version: Union[str, int] = "v2",
    key_save_type: KeySaveType = KeySaveType.RAW,
) -> rfc5958.OneAsymmetricKey:
    """Prepare an invalid KGA private key.

    :param invalid_operation: The invalid operation to perform. Defaults to `None`.
    :param new_private_key: The private key to prepare.
    :param key_export_version: The key export version to use. Defaults to "v2".
    :param key_save_type: The key save type to use. Defaults to "KeySaveType.RAW".
    :return: The prepared `OneAsymmetricKey` structure.
    :raises ValueError: If an invalid operation is provided.

    """
    if isinstance(invalid_operation, str):
        invalid_operation = InvalidOneAsymKeyType(invalid_operation)

    version = key_export_version
    invalid_pub_key = False
    invalid_priv_key = False
    mis_matching_key = False
    public_key = None

    if invalid_operation is None:
        return keyutils.prepare_one_asymmetric_key(
            private_key=new_private_key,
            version=version,
            key_save_type=KeySaveType.get(key_save_type).value,
        )

    if invalid_operation == InvalidOneAsymKeyType.INVALID_VERSION_V1:
        version = "v1"
        public_key = new_private_key.public_key()

    elif invalid_operation == InvalidOneAsymKeyType.INVALID_PUBLIC_KEY_SIZE:
        invalid_pub_key = True

    elif invalid_operation == InvalidOneAsymKeyType.INVALID_KEY_PAIR:
        mis_matching_key = True

    elif invalid_operation == InvalidOneAsymKeyType.INVALID_KEY_PAIR_CERT:
        pass

    elif invalid_operation == InvalidOneAsymKeyType.INVALID_PRIVATE_KEY_SIZE:
        invalid_priv_key = True

    elif invalid_operation == InvalidOneAsymKeyType.INVALID_VERSION:
        version = 4

    else:
        raise ValueError(f"Invalid operation: {invalid_operation}")

    return_value = keyutils.prepare_one_asymmetric_key(
        private_key=new_private_key,
        public_key=public_key,
        version=version,
        key_save_type=key_save_type,
        invalid_pub_key_size=invalid_pub_key,
        mis_matching_key=mis_matching_key,
        invalid_priv_key_size=invalid_priv_key,
    )
    return return_value


@not_keyword
def prepare_private_key_for_kga(
    new_private_key: PrivateKey,
    request: PKIMessageTMP,
    kga_key: SignKey,
    kga_cert_chain: List[rfc9480.CMPCertificate],
    password: Optional[Union[bytes, str]] = None,
    hash_alg: str = "sha256",
    key_save_type: Optional[Union[str, KeySaveType]] = KeySaveType.RAW,
    invalid_kga_operation: Optional[Union[str, InvalidOneAsymKeyType]] = None,
    new_private_keys: Optional[Union[List[rfc5958.OneAsymmetricKey], rfc5958.OneAsymmetricKey]] = None,
    **kwargs,
) -> rfc5652.EnvelopedData:
    """Prepare the private key for the key generation action.

    :param new_private_key: The private key to securely exchange with the Client.
    :param request: The PKIMessage to prepare the private key for.
    :param password: The password to use for encrypting the private key. Defaults to `None`.
    :param kga_cert_chain: The KGA certificate chain to use. Defaults to `None`.
    :param hash_alg: The hash algorithm to use. Defaults to "sha256".
    :param kga_key: The key generation authority key to use. Defaults to `None`.
    :param key_save_type: Whether to save the PQ-key as `seed`, `raw` or `seed_and_raw`. Defaults to `KeySaveType.RAW`.
    :param invalid_kga_operation: The invalid operation to perform. Defaults to `None`.
    :param new_private_keys: The new private keys to use. Defaults to `None`.
    :raises BadCertTemplate: If the key OID is not recognized.
    """
    recip_type = _get_kga_recipient_type(pki_message=request)
    logging.debug("Recipient type used for the KGA response: %s", recip_type)
    print("Recipient type used for the KGA response: %s", recip_type)

    cek = os.urandom(32)
    client_cert = request["extraCerts"][0]
    recip_info = _prepare_recip_info_for_kga_request(
        recip_type=recip_type,
        cek=cek,
        password=password,
        kga_cert_chain=kga_cert_chain,
        hash_alg=hash_alg,
        client_cert=client_cert,
        **kwargs,
    )

    version_num = kwargs.get("key_export_version", "v2")

    if isinstance(version_num, str) and not version_num.isdigit():
        if version_num not in ["v1", "v2"]:
            raise ValueError("Invalid key export version. Must be `v1`, `v2`. Else please provide a integer.")
    elif version_num.isdigit():
        version_num = int(version_num)

    if new_private_keys is None:
        new_private_keys = prepare_invalid_kga_private_key(
            new_private_key=new_private_key,
            invalid_operation=invalid_kga_operation,
            key_save_type=KeySaveType.get(key_save_type or KeySaveType.RAW),
            key_export_version=version_num,
        )

    signed_data = envdatautils.prepare_signed_data(
        signing_key=kga_key,
        sig_hash_name=None,  # will automatically be set to the hash algorithm used for the KGA key.
        cert=kga_cert_chain[0],
        private_keys=new_private_keys,
        cert_chain=kga_cert_chain,
    )
    signed_data_der = encoder.encode(signed_data)
    enveloped_data = envdatautils.prepare_enveloped_data(
        recipient_infos=[recip_info],
        data_to_protect=signed_data_der,
        cek=cek,
    )
    return enveloped_data


def _get_encrypted_key_recipient_type(
    env_data: rfc9480.EnvelopedData,
    index: int = 0,
) -> str:
    """Get the recipient type from the PKIMessage.

    :param env_data: The EnvelopedData to get the recipient type from.
    :return: The recipient type.
    """
    recip_info = env_data["recipientInfos"][index]
    if not recip_info.isValue:
        raise ValueError("Recipient Info is missing in the EnvelopedData.")

    recip_type = recip_info.getName()

    # TODO fix this to use the correct recipient type.
    # now only supports kemri, so the quick solution is to return kemri.
    if recip_type == "ori":
        return "kemri"

    return recip_type


def _get_kga_recipient_type(pki_message: PKIMessageTMP) -> str:
    """Get the recipient type from the PKIMessage.

    :param pki_message: The PKIMessage to get the recipient type from.
    :return: The recipient type.
    """
    if protectionutils.get_protection_type_from_pkimessage(pki_message) == "mac":
        oid = pki_message["header"]["protectionAlg"]["algorithm"]
        if oid == rfc9480.id_DHBasedMac:
            return "kari"
        if oid == id_KemBasedMac:
            return "kemri"
        return "pwri"

    cert = pki_message["extraCerts"][0]
    public_key = keyutils.load_public_key_from_spki(cert["tbsCertificate"]["subjectPublicKeyInfo"])

    expected_usage = None
    try:
        if isinstance(public_key, RSAPublicKey):
            expected_usage = "keyEncipherment"
            # MUST be present in the certificate, as described in RFC 9483, Section 4.1.6.1
            certutils.validate_key_usage(cert, key_usages=expected_usage, strictness="STRICT")
            return "ktri"

        if isinstance(public_key, ECDHPublicKey):
            expected_usage = "keyAgreement"
            # MUST be present in the certificate, as described in RFC 9483, Section 4.1.6.2
            certutils.validate_key_usage(cert, key_usages=expected_usage, strictness="STRICT")
            return "kari"

        if is_kem_public_key(public_key):
            expected_usage = "keyEncipherment"
            # MUST be present in the certificate.
            certutils.validate_key_usage(cert, key_usages=expected_usage, strictness="STRICT")
            return "kemri"

        raise ValueError(f"Invalid public key type: {type(public_key).__name__}")

    except ValueError as e:
        raise NotAuthorized(
            f"The recipient certificate is not authorized for the KGA action.Expected key usage: {expected_usage}"
        ) from e


def _get_kari_matching_cert_key_pair(
    client_pub_key: ECDHPublicKey,
    ecc_cert: Optional[rfc9480.CMPCertificate] = None,
    ecc_key: Optional[EllipticCurvePrivateKey] = None,
    x25519_cert: Optional[rfc9480.CMPCertificate] = None,
    x25519_key: Optional[X25519PrivateKey] = None,
    x448_cert: Optional[rfc9480.CMPCertificate] = None,
    x448_key: Optional[X448PrivateKey] = None,
) -> Tuple[rfc9480.CMPCertificate, ECDHPrivateKey]:
    """Prepare the matching certificate and key pair for the KGA."""
    out_cert, out_key = None, None
    key_name = keyutils.get_key_name(client_pub_key).replace("ecdsa", "ecc").upper()

    if isinstance(client_pub_key, EllipticCurvePublicKey):
        if ecc_cert is not None and ecc_key is not None:
            out_cert, out_key = ecc_cert, ecc_key

        if out_cert is None or out_key is None:
            raise ValueError(
                "The client wanted to use `KARI`, but the CA key is not set. "
                f"Expected to provide a {key_name} key and certificate."
            )

    elif isinstance(client_pub_key, x25519.X25519PublicKey):
        if x25519_cert is None or x25519_key is None:
            raise ValueError(
                "The client wanted to use `KARI`, but the CA key is not set. "
                f"Expected to provide a {key_name} key and certificate."
            )
        out_cert, out_key = x25519_cert, x25519_key

    elif isinstance(client_pub_key, x448.X448PublicKey):
        if x448_cert is None or x448_key is None:
            raise ValueError(
                "The client wanted to use `KARI`, but the CA key is not set. "
                f"Expected to provide a {key_name} key and certificate."
            )
        out_cert, out_key = x448_cert, x448_key

    else:
        raise ValueError(f"The client key was not a ECDH key, but a {key_name} key.")

    # Just to verify that the keys are of the matching type.
    cryptoutils.perform_ecdh(out_key, client_pub_key)
    return out_cert, out_key


def _get_kga_matching_kari_cert_key_pair(
    client_pub_key: ECDHPublicKey,
    cmp_protection_cert: rfc9480.CMPCertificate,
    cmp_protection_key: Optional[SignKey] = None,
    ecc_cert: Optional[rfc9480.CMPCertificate] = None,
    ecc_key: Optional[EllipticCurvePrivateKey] = None,
    x25519_cert: Optional[rfc9480.CMPCertificate] = None,
    x25519_key: Optional[X25519PrivateKey] = None,
    x448_cert: Optional[rfc9480.CMPCertificate] = None,
    x448_key: Optional[X448PrivateKey] = None,
    **kwargs,  # pylint: disable=unused-argument
) -> Tuple[rfc9480.CMPCertificate, ECDHPrivateKey]:
    """Prepare the matching certificate and key pair for the KGA."""
    out_cert, out_key = None, None

    key_name = keyutils.get_key_name(client_pub_key).replace("ecdsa", "ecc").upper()

    if isinstance(client_pub_key, EllipticCurvePublicKey):
        if ecc_cert is not None and ecc_key is not None:
            out_cert, out_key = ecc_cert, ecc_key

        elif cmp_protection_cert is not None and cmp_protection_key is not None:
            if isinstance(cmp_protection_key, EllipticCurvePrivateKey):
                out_cert, out_key = cmp_protection_cert, cmp_protection_key

        if out_cert is None or out_key is None:
            raise ValueError(
                "The client wanted to use `KARI`, but the CA key is not set. "
                f"Expected to provide a {key_name} key and certificate."
            )

    elif isinstance(client_pub_key, x25519.X25519PublicKey):
        if x25519_cert is None or x25519_key is None:
            raise ValueError(
                "The client wanted to use `KARI`, but the CA key is not set. "
                f"Expected to provide a {key_name} key and certificate."
            )
        out_cert, out_key = x25519_cert, x25519_key

    elif isinstance(client_pub_key, x448.X448PublicKey):
        if x448_cert is None or x448_key is None:
            raise ValueError(
                "The client wanted to use `KARI`, but the CA key is not set. "
                f"Expected to provide a {key_name} key and certificate."
            )

        out_cert, out_key = x448_cert, x448_key

    else:
        raise ValueError(f"The client key was not a ECDH key, but a {key_name} key.")

    # Just to verify that the keys are of the matching type.
    cryptoutils.perform_ecdh(out_key, client_pub_key)
    return out_cert, out_key


def _prepare_recip_info_for_kga_request(
    recip_type: str,
    cek: bytes,
    password: Optional[Union[bytes, str]] = None,
    **kwargs,
):
    """Prepare the recipient info for the key generation action.

    :param recip_type: The recipient type to use.
    :param cek: The content encryption key to use.
    :param newly_generated_key: The newly generated key to use.
    :return: The recipient info.
    """
    if recip_type == "pwri":
        return _prepare_recip_info_for_kga(
            cek=cek,
            password=password,
            hash_alg=kwargs.get("hash_alg", "sha256"),
        )

    client_cert = kwargs.get("client_cert")
    if client_cert is None:
        raise ValueError("The client certificate must be provided.")

    client_pub_key = keyutils.load_public_key_from_spki(client_cert["tbsCertificate"]["subjectPublicKeyInfo"])

    if recip_type == "kemri":
        client_pub_key = ensure_is_kem_pub_key(client_pub_key)
        return _prepare_recip_info_for_kga(
            cek=cek,
            cert=client_cert,
            public_key=client_pub_key,
            **kwargs,
        )

    if recip_type == "ktri":
        if not isinstance(client_pub_key, RSAPublicKey):
            raise ValueError("The recipient certificate must contain an RSA key for KGA `KTRI`.")

        kwargs["cert"] = kwargs.get("cmp_protection_cert")
        return _prepare_recip_info_for_kga(
            cek=cek,
            public_key=client_pub_key,
            **kwargs,
        )

    if recip_type == "kari":
        if not isinstance(client_pub_key, ECDHPublicKey):
            raise ValueError("The recipient certificate must contain an ECDH key for KGA `KARI`.")

        kwargs["client_pub_key"] = client_pub_key
        ca_cert, ca_key = _get_kga_matching_kari_cert_key_pair(
            **kwargs,
        )

        return _prepare_recip_info_for_kga(
            cek=cek,
            cert=ca_cert,
            public_key=client_pub_key,
            ec_priv_key=ca_key,
        )

    raise ValueError(f"Invalid recipient type for KGA: {recip_type}")


def _get_kga_private_key_and_update_template(
    cert_template: rfc4211.CertTemplate,
    invalid_kga_operation: Optional[Union[str, InvalidOneAsymKeyType]] = None,
    default_key_type: Optional[str] = "rsa",
) -> Tuple[PrivateKey, rfc9480.CertTemplate]:
    """Prepare the private key and subject public key info for KGA.

    :param cert_template: The certificate template to get the key type from.
    :param invalid_kga_operation: The invalid operation to perform. Defaults to `None`.
    :param default_key_type: The default key type to generate. Defaults to "rsa".
    :return: The generated private key and the updated certificate template.
    """
    private_key = _get_kga_key_from_cert_template(cert_template, default_key_type=default_key_type)
    public_key = private_key.public_key()
    if invalid_kga_operation is not None:
        invalid_kga_operation = InvalidOneAsymKeyType.get(invalid_kga_operation)
        if invalid_kga_operation == InvalidOneAsymKeyType.INVALID_KEY_PAIR_CERT:
            public_key = keyutils.generate_different_public_key(private_key)

    spki = subject_public_key_info_from_pubkey(public_key)
    cert_template["publicKey"]["subjectPublicKey"] = spki["subjectPublicKey"]
    if not cert_template["publicKey"]["algorithm"].isValue:
        cert_template["publicKey"]["algorithm"] = spki["algorithm"]

    return private_key, cert_template


@not_keyword
def prepare_cert_and_private_key_for_kga(
    cert_template: rfc4211.CertTemplate,
    request: PKIMessageTMP,
    ca_cert: rfc9480.CMPCertificate,
    ca_key: SignKey,
    kga_cert_chain: Optional[List[rfc9480.CMPCertificate]],
    kga_key: Optional[SignKey],
    password: Optional[Union[bytes, str]] = None,
    cmp_protection_cert: Optional[rfc9480.CMPCertificate] = None,
    key_save_type: Optional[str] = None,
    invalid_kga_operation: Optional[Union[str, InvalidOneAsymKeyType]] = None,
    **kwargs,
) -> Tuple[rfc9480.CMPCertificate, rfc9480.EnvelopedData]:
    """Prepare a certified key pair for the key generation action.

    :param cert_template: The certificate template to get the key from.
    :param request: The PKIMessage to prepare the private key for.
    :param ca_cert: The CA certificate to matching the private key.
    :param ca_key:  The CA key to sign the certificate with.
    :param password: The password to use for encrypting the private key. Defaults to `None`.
    :param kga_cert_chain: The KGA certificate chain to use. Defaults to `None`.
    :param kga_key: The key generation authority key to sign the signed data with. Defaults to `None`.
    :param cmp_protection_cert: The CMP protection certificate to use for `KARI`, `KTRI`
    :param key_save_type: Whether to save the PQ-key as `seed`, `raw` or `seed_and_raw`. Defaults to `raw`.
    or the recipient cert for `KEMRI`. Defaults to `None`.
    :param invalid_kga_operation: The invalid operation to perform. Defaults to `None`.
    :return: The populated `CertifiedKeyPair` structure.
    """
    prot_type = protectionutils.get_protection_type_from_pkimessage(request)
    alg_name = may_return_oid_to_name(request["header"]["protectionAlg"]["algorithm"])

    if prot_type == "mac" and password is None and alg_name not in ["dh_based_mac", "kem_based_mac"]:
        raise ValueError("The password must be provided for KGA `PWRI`.")

    if kga_cert_chain is None:
        raise ValueError("`kga_cert_chain` must be provided.")

    if kga_key is None:
        raise ValueError("`kga_key` must be provided.")

    private_key, cert_template = _get_kga_private_key_and_update_template(
        cert_template=cert_template,
        invalid_kga_operation=invalid_kga_operation,
        default_key_type=kwargs.get("default_key_type", "rsa"),
    )

    cert = certbuildutils.build_cert_from_cert_template(
        cert_template=cert_template,
        ca_cert=ca_cert,
        ca_key=ca_key,
        extensions=kwargs.get("extensions"),
        hash_alg=kwargs.get("hash_alg", "sha256"),
        use_rsa_pss=kwargs.get("use_rsa_pss", False),
    )

    env_data = prepare_private_key_for_kga(
        new_private_key=private_key,
        request=request,
        password=password,
        kga_cert_chain=kga_cert_chain,
        kga_key=kga_key,
        cmp_protection_cert=cmp_protection_cert,
        key_save_type=key_save_type or "raw",
        invalid_kga_operation=invalid_kga_operation,
        **kwargs,
    )
    return cert, env_data


@keyword(name="Check If Request Is For KGA")
def check_if_request_is_for_kga(  # noqa: D417 undocumented-params
    pki_message: PKIMessageTMP, index: Strint = 0
) -> bool:
    """Check if the request is for key generation authority (KGA).

    Arguments:
    ---------
        - `pki_message`: The PKIMessage to check.
        - `index`: The index of the certificate request to check. Defaults to `0`.

    Returns:
    -------
        - `True` if the request is for key generation action, `False` otherwise.

    Raises:
    ------
        - ValueError: If the body type is not one of `ir`, `cr`, `kur`, or `crr`.
        - BadCertTemplate: If the key OID is not recognized.

    Examples:
    --------
    | ${is_kga}= | Check If Request Is For KGA | ${pki_message} | 0 |

    """
    cert_req_msg = get_cert_req_msg_from_pkimessage(pki_message, index)
    if not cert_req_msg["popo"].isValue:
        _get_kga_key_from_cert_template(cert_req_msg["certReq"]["certTemplate"])
        return True
    return False


def _verify_pop_signature(
    pki_message: PKIMessageTMP,
    request_index: int = 0,
) -> None:
    """Verify the POP signature in the PKIMessage.

    :param pki_message: The PKIMessage to verify the POP signature for.
    :param request_index: The index of the certificate request to verify the POP for. Defaults to `0`.
    :raises BadAsn1Data: If the CertRequest encoding fails.
    :raises BadPOP: If the POP verification fails.
    :raises InvalidSignature: If the signature verification fails.
    """
    body_name = pki_message["body"].getName()

    try:
        cert_req_msg = get_cert_req_msg_from_pkimessage(pki_message, index=request_index)
        popo: rfc4211.ProofOfPossession = cert_req_msg["popo"]
        if not popo["signature"].isValue:
            raise BadPOP("POP signature is missing in the PKIMessage.")

        popo_sig = popo["signature"]
        public_key = get_public_key_from_cert_req_msg(cert_req_msg)
        if not public_key:
            raise BadPOP("Public key is missing in the certificate request.Can not verify the POP signature.")
        try:
            public_key = convertutils.ensure_is_verify_key(public_key)

            if isinstance(public_key, DSAPublicKey):
                raise BadPOP("The DSA keys are not supported", failinfo="badPOP,badCertTemplate,badAlg")

        except ValueError as err:
            raise BadPOP("Public key is not a valid verify key.", failinfo="badPOP,badCertTemplate,badAlg") from err

        protectionutils.verify_signature_with_alg_id(
            public_key=public_key,
            alg_id=popo_sig["algorithmIdentifier"],
            data=encoder.encode(cert_req_msg["certReq"]),
            signature=popo_sig["signature"].asOctets(),
        )

        if cert_req_msg["regInfo"].isValue:
            logging.debug("regInfo is present in the CertReqMsg,but server logic is not supported yet.")

    except BadSigAlgID as err:
        raise BadPOP(
            "Invalid signature algorithm identifier.", error_details=[err.message] + err.error_details
        ) from err

    except pyasn1.error.PyAsn1Error as err:
        raise BadAsn1Data("Failed to encode the CertRequest.", overwrite=True) from err

    except InvalidSignature as err:
        raise BadPOP(f"Signature POP verification for `{body_name}` failed.") from err


def _verify_ra_verified(
    pki_message: PKIMessageTMP,
    allowed_ra_dir: str = "data/trusted_ras",
    strict_eku: bool = True,
    strict_ku: bool = True,
    verify_ra_verified: bool = True,
    verify_cert_chain: bool = True,
) -> None:
    """Verify the raVerified in the PKIMessage.

    :param pki_message: The PKIMessage to verify the raVerified for.
    :param allowed_ra_dir: The allowed RA directory. Defaults to `None`.
    :param strict_eku: Whether the RA certificate must have the `cmcRA` EKU bit set. Defaults to `True`.
    :param strict_ku: Whether the RA certificate must have the `digitalSignature` KeyUsage bit set. Defaults to `True`.
    :param verify_ra_verified: Whether to verify the `raVerified` or let it pass. Defaults to `True`.
    :param verify_cert_chain: Whether to verify the certificate chain. Defaults to `True`.
    """
    if not verify_ra_verified:
        logging.info("Skipping `raVerified` verification.")
        return

    ra_certs = certutils.load_certificates_from_dir(allowed_ra_dir)

    if len(ra_certs) is None:
        raise ValueError("No RA certificates found in the allowed RA directory.")

    logging.debug("Loaded RA certificates: %d", len(ra_certs))

    if not pki_message["extraCerts"].isValue:
        raise NotAuthorized("RA certificate is missing in the PKIMessage (no `extraCerts`).")

    may_ra_cert = pki_message["extraCerts"][0]
    result = certutils.cert_in_list(may_ra_cert, ra_certs)

    if not result:
        raise NotAuthorized("RA certificate not in allowed RA directory.")

    try:
        certutils.validate_cmp_extended_key_usage(
            cert=may_ra_cert, ext_key_usages="cmcRA", strictness="STRICT" if strict_eku else "LAX"
        )
    except ValueError as err:
        raise NotAuthorized("RA certificate does not have the `cmcRA` EKU bit set.") from err

    try:
        certutils.validate_key_usage(
            cert=may_ra_cert, key_usages="digitalSignature", strictness="STRICT" if strict_ku else "LAX"
        )
    except ValueError as err:
        raise NotAuthorized("RA certificate does not have the `digitalSignature` KeyUsage bit set.") from err

    cert_chain = certutils.build_cmp_chain_from_pkimessage(
        pki_message,
        ee_cert=may_ra_cert,
    )

    if len(cert_chain) == 1 and not certutils.check_is_cert_signer(cert_chain[0], cert_chain[0]):
        raise NotAuthorized("RA certificate is not self-signed, but the certificate chain could not be build.")

    logging.debug("RA certificate chain length: %d", len(cert_chain))
    print("RA certificate chain length:", len(cert_chain))

    if verify_cert_chain:
        try:
            certutils.verify_cert_chain_openssl(
                cert_chain=cert_chain,
                crl_check=False,
                verbose=True,
                timeout=60,
            )
        except SignerNotTrusted as err:
            error_details = [err.message] + err.get_error_details()
            raise NotAuthorized(
                "RA certificate is not trusted, verification with OpenSSL failed.", error_details=error_details
            ) from err


def verify_popo_for_cert_request(  # noqa: D417 Missing argument descriptions in the docstring
    pki_message: PKIMessageTMP,
    allowed_ra_dir: str = "data/trusted_ras",
    cert_req_index: Union[int, str] = 0,
    must_have_ra_eku_set: bool = True,
    verify_ra_verified: bool = True,
    verify_cert_chain: bool = True,
) -> None:
    """Verify the Proof-of-Possession (POP) for a certificate request.

    Arguments:
    ---------
       - `pki_message`: The pki message to verify the POP for.
       - `allowed_ra_dir`: The allowed RA directory, filed with trusted RA certificates.
         Defaults to `data/trusted_ras`.
       - `allow_os_store`: Whether to allow the OS store. Defaults to `False`.
       - `cert_req_index`: The index of the certificate request to verify the POP for. Defaults to `0`.
       - `must_have_ra_eku_set`: Whether Extended Key Usage (EKU) CMP-RA bit must be set. Defaults to `True`.
       - `verify_ra_verified`: Whether to verify the `raVerified` or let it pass. Defaults to `True`.
       - `verify_cert_chain`: Whether to verify the certificate chain. Defaults to `True`.

    Raises:
    ------
        - ValueError: If the body type is not one of `ir`, `cr`, `kur`, or `crr`.
        - ValueError: If the POP structure is invalid
        - ValueError: If the public key type is invalid.
        - NotImplementedError: If the request is for key agreement.
        - BadPOP: If the POP verification fails.
        - NotAuthorized: If the RA certificate is not trusted.

    Examples:
    --------
    | Verify POP Signature For PKI Request | ${pki_message} | ${allowed_ra_dir} | ./data/trustanchors | True |
    | Verify POP Signature For PKI Request | ${pki_message} | verify_ra_verified=False |

    """
    body_name = pki_message["body"].getName()
    if body_name not in {"ir", "cr", "kur", "crr"}:
        raise ValueError(f"Invalid PKIMessage body: {pki_message['body'].getName()} Expected: ir, cr, kur, crr")

    cert_req_msg = get_cert_req_msg_from_pkimessage(pki_message, index=cert_req_index)

    if check_if_request_is_for_kga(pki_message=pki_message, index=cert_req_index):
        return

    if not cert_req_msg["popo"].isValue:
        raise BadPOP(f"POP structure is missing in the PKIMessage, for {body_name}")

    name = cert_req_msg["popo"].getName()

    if name == "raVerified":
        _verify_ra_verified(
            pki_message,
            allowed_ra_dir=allowed_ra_dir,
            verify_cert_chain=verify_cert_chain,
            strict_eku=must_have_ra_eku_set,
            verify_ra_verified=verify_ra_verified,
        )

    elif name == "signature":
        verify_sig_pop_for_pki_request(pki_message)
    elif name == "keyEncipherment":
        public_key = get_public_key_from_cert_req_msg(cert_req_msg=cert_req_msg)

        if not is_kem_public_key(public_key):
            raise ValueError("Invalid public key type, for `keyEncipherment`.")

    elif name == "keyAgreement":
        public_key = get_public_key_from_cert_req_msg(cert_req_msg=cert_req_msg)
        if not isinstance(public_key, ECDHPublicKey):
            raise ValueError("Invalid public key type, for `keyAgreement`.")

    else:
        raise ValueError(
            f"Invalid POP structure: {name}. Expected: raVerified, signature, keyEncipherment, keyAgreement"
        )


@not_keyword
def validate_cert_request_controls(
    cert_request: rfc4211.CertRequest,
    request: Optional[PKIMessageTMP] = None,
    extra_issuing_data: Optional[ExtraIssuingData] = None,
    archive_options_must_be_present: bool = False,
    **kwargs,
) -> None:
    """Validate the certificate request controls.

    :param cert_request: The certificate request to validate.
    :param request: The PKIMessage to validate the controls for. Defaults to `None`.
    :param extra_issuing_data: The extra issuing data to use for setting the `regToken` and `authenticator` values.
    Defaults to `None`.
    :param archive_options_must_be_present: Whether the archive options must be present. Defaults to `False`.
    :raises ValueError: If the controls are not set or if the `regToken` is not set.
    """
    controls = cert_request["controls"]
    if not controls.isValue:
        return

    if request is not None:
        if request["body"].getName() == "kur":
            validate_kur_controls(request=request, ca_cert=kwargs.get("ca_cert"))

    cmputils.validate_archive_options(
        controls=controls,
        must_be_present=archive_options_must_be_present,
        cert_template=cert_request["certTemplate"],
    )
    cmputils.validate_pki_publication_information(
        controls=controls,
        must_be_present=kwargs.get("pki_publication_information_must_be_present", False),
    )

    found_token = kwargs.get("found_regToken", False)
    if extra_issuing_data is not None:
        reg_token = extra_issuing_data.regToken
        found_token = extra_issuing_data.found_regToken

    elif kwargs.get("regToken") is not None:
        reg_token = kwargs.get("regToken")
    else:
        reg_token = None

    if reg_token is not None:
        reg_token_out = cmputils.validate_reg_token_control(
            controls=controls,
            expected_token=reg_token,
            must_be_present=kwargs.get("regToken_must_be_present", False),
        )
        if reg_token_out is not None:
            if found_token:
                raise BadRequest("The `regToken` control was found and the token was already used.")
            if extra_issuing_data is not None:
                extra_issuing_data.found_regToken = True

    expected_auth_info = kwargs.get("authenticator_control")
    if expected_auth_info is None and extra_issuing_data is not None:
        expected_auth_info = extra_issuing_data.authenticator

    cmputils.validate_authenticator_control(
        controls=controls,
        must_be_present=kwargs.get("authenticator_control_must_be_present", False),
        expected_auth_info=expected_auth_info,
    )


@not_keyword
def validate_cert_template_public_key(
    cert_template: rfc9480.CertTemplate,
    sig_popo_alg_id: Optional[rfc9480.AlgorithmIdentifier] = None,
    max_key_size: Optional[int] = None,
):
    """Validate that the certificate template has set the correct fields.

    :param cert_template: The certificate template to validate.
    :param sig_popo_alg_id: The signature POP algorithm identifier to validate against. Defaults to `None`.
    :param max_key_size: The maximum key size for RSA, to validate against, skipped if `None`. Defaults to `None`.
    """
    if compareutils.is_null_dn(cert_template["subject"]):
        if get_extension(cert_template["extensions"], rfc5280.id_ce_subjectAltName) is None:
            raise BadCertTemplate("The `subject` field is not set inside the certificate template.")

    try:
        public_key = keyutils.load_public_key_from_cert_template(cert_template=cert_template, must_be_present=False)
    except (BadCertTemplate, InvalidKeyData, ValueError) as err:
        raise BadCertTemplate(
            "Failed to load the public key from the `CertTemplate`.", failinfo="badCertTemplate,badDataFormat"
        ) from err

    if isinstance(public_key, DHPublicKey):
        raise BadCertTemplate(
            "The `publicKey` inside the certificate template was a `DH` key, which is not allowed.",
            failinfo="badAlg,badCertTemplate",
        )

    if isinstance(public_key, DSAPublicKey):
        raise BadAlg(
            "The `publicKey` inside the certificate template was a `DSA` key, which is not allowed.",
            failinfo="badAlg,badCertTemplate",
        )

    if isinstance(public_key, RSAPublicKey):
        if public_key.key_size < 2048:
            raise BadCertTemplate("The RSA public key was shorter then 2048 bits")

        if max_key_size is not None and public_key.key_size > max_key_size:
            raise BadCertTemplate(f"The RSA public key was longer then {max_key_size} bits")

    if sig_popo_alg_id is not None:
        if public_key is None:
            raise BadCertTemplate(
                "The public key was not set inside the `CertTemplate`.But a signature POP algorithm was set."
            )
        try:
            public_key = convertutils.ensure_is_verify_key(public_key)
            keyutils.check_consistency_sig_alg_id_and_key(sig_popo_alg_id, public_key)
        except ValueError as e:
            raise BadCertTemplate(
                "The public key was not a valid verify key.", failinfo="badAlg,badCertTemplate"
            ) from e
        except BadSigAlgID as e:
            raise BadCertTemplate(
                "The public key and the signature algorithm identifier did not match.",
                failinfo="badPOP,badCertTemplate",
                error_details=[e.message] + e.error_details,
            ) from e

    if cert_template["publicKey"].isValue:
        if cert_template["publicKey"]["subjectPublicKey"].asOctets() != b"":
            alg_id = cert_template["publicKey"]["algorithm"]

            if isinstance(public_key, PQHashStatefulSigPublicKey):
                raise NotImplementedError("PQHashStatefulSigPublicKey is not supported yet, to be validated.")

            if isinstance(public_key, (PQPublicKey, HybridPublicKey)):
                if alg_id["parameters"].isValue:
                    raise BadCertTemplate("The `parameters` field is not allowed for PQ public keys.")


def _process_agree_mac_key_agreement(
    cert_req_msg: rfc4211.CertReqMsg,
    ca_key: SignKey,
    ca_cert: rfc9480.CMPCertificate,
    ca_ecc_key: Optional[ECDHPrivateKey] = None,
    **kwargs,
) -> rfc9480.CMPCertificate:
    """Process the certificate request message for key agreement.

    :param cert_req_msg: The certificate request message to process.
    :param ca_key: The CA key to use for signing the certificate.
    :param ca_cert: The CA certificate to use for signing the certificate.
    :param ca_ecc_key: The CA ECC key to use for signing the certificate. Defaults to `None`.
    :return: The processed certificate.
    """
    cert_template = cert_req_msg["certReq"]["certTemplate"]
    public_key = keyutils.load_public_key_from_cert_template(cert_template=cert_template)

    if not isinstance(public_key, ECDHPublicKey):
        raise ValueError("Invalid public key type, for `keyAgreement`.")

    if ca_ecc_key is None:
        raise ValueError("The CA ECC key was not provided.")

    shared_secret = cryptoutils.perform_ecdh(
        ca_ecc_key,
        public_key,
    )
    alg_id = cert_req_msg["popo"]["keyAgreement"]["agreeMAC"]["algId"]

    der_data = encoder.encode(cert_req_msg["certReq"])
    mac_value = protectionutils.compute_mac_from_alg_id(
        key=shared_secret,
        alg_id=alg_id,
        data=der_data,
    )

    found_mac = cert_req_msg["popo"]["keyAgreement"]["agreeMAC"]["value"].asOctets()

    if mac_value != found_mac:
        raise BadPOP(f"The MAC value does not match the expected value. Expected: {mac_value}, Got: {found_mac}")

    new_ee_cert = certbuildutils.build_cert_from_cert_template(
        cert_template=cert_template,
        ca_key=ca_key,
        ca_cert=ca_cert,
        **kwargs,
    )
    return new_ee_cert


@not_keyword
def validate_enc_key_with_id(
    data: bytes,
    cert_template: rfc9480.CertTemplate,
    allow_identifier_failure: bool = False,
) -> PrivateKey:
    """Validate the `EncKeyWithID` structure.

    :param data: The `EncKeyWithID` structure to validate.
    :param cert_template: The certificate template to use for validation of the `identifier` field.
    :param allow_identifier_failure: Whether to allow the identifier failure. Defaults to `False`.
    (MUST be present.)
    """
    enc_key_with_id, rest = try_decode_pyasn1(data, rfc4211.EncKeyWithID())  # type: ignore
    enc_key_with_id: rfc4211.EncKeyWithID
    if rest:
        raise BadAsn1Data("`EncKeyWithID`")

    if not enc_key_with_id["privateKey"].isValue:
        raise BadAsn1Data("The `privateKey` field is missing in the `EncKeyWithID`.")

    der_data = encoder.encode(enc_key_with_id["privateKey"])
    private_key = CombinedKeyFactory.load_private_key_from_one_asym_key(
        data=der_data,
        must_be_version_2=False,
    )

    public_key = keyutils.load_public_key_from_cert_template(
        cert_template=cert_template,
        must_be_present=True,
    )

    if private_key.public_key() != public_key:
        raise BadPOP("The public key inside the `CertTemplate` did not match the `KEMRI` decrypted key.")

    subject = cert_template["subject"]

    identifier = enc_key_with_id["identifier"]
    if not identifier.isValue:
        raise BadAsn1Data("The `identifier` field is missing in the `EncKeyWithID`.")

    _id_type = identifier.getName()

    subject_name = utils.get_openssl_name_notation(subject)

    if _id_type == "string":
        _id = identifier["string"].prettyPrint()
        out = utils.get_openssl_name_notation(subject)
        if out != _id and not allow_identifier_failure:
            logging.debug("Identifier: %s. Subject: %s", _id, subject_name)
            raise BadCertTemplate(
                "The `EncKeyWithID` identifier (`string`) did not match the `subject` inside the `CertTemplate`."
            )
    elif _id_type == "generalName":
        result = compareutils.compare_general_name_and_name(
            general_name=identifier["generalName"],
            name=subject,
        )

        if result:
            return private_key

        if not allow_identifier_failure:
            gen_name = utils.get_openssl_name_notation(identifier["generalName"]["directoryName"])
            logging.warning("Identifier: %s. Subject: %s", gen_name, subject_name)
            raise BadCertTemplate(
                "The `EncKeyWithID` identifier (`generalName`) did not match the `subject` inside the `CertTemplate`."
            )

    return private_key


@not_keyword
def process_encrypted_key(
    cert_req_msg: rfc4211.CertReqMsg,
    for_agreement: bool,
    request: PKIMessageTMP,
    ca_key: SignKey,
    ca_cert: rfc9480.CMPCertificate,
    password: Optional[Union[bytes, str]] = None,
    **kwargs,
) -> rfc9480.CMPCertificate:
    """Process the encrypted key in the certificate request message.

    :param cert_req_msg: The certificate request message to process.
    :param for_agreement: Whether the key is used for agreement. Defaults to `False`.
    :param request: The PKIMessage to process the encrypted key for.
    :param ca_key: The CA key to use for signing the certificate.
    :param ca_cert: The CA certificate to use for signing the certificate.
    :param password: The shared secret to use for decrypting the private key. Defaults to `None`.
    :param kwargs: Additional certificates and keys to use for the decryption.
    :return: The build certificate.
    """
    cert_template = cert_req_msg["certReq"]["certTemplate"]
    public_key = keyutils.load_public_key_from_cert_template(cert_template=cert_template, must_be_present=False)

    _popo_type = "keyAgreement" if for_agreement else "keyEncipherment"
    if public_key is None:
        raise BadCertTemplate(
            f"The public key was not set inside the `CertTemplate`,for `encryptedKey` for {_popo_type}"
        )

    env_data = cert_req_msg["popo"][_popo_type]["encryptedKey"]
    recip_type = _get_encrypted_key_recipient_type(env_data)
    if recip_type == "pwri" and password is None:
        raise ValueError(f"The password must be provided for the encrypted {_popo_type} private key `PWRI`.")

    if recip_type == "pwri":
        der_data = ca_kga_logic.validate_enveloped_data(
            env_data=env_data,
            password=password,
            pki_message=request,
            expected_raw_data=True,
        )
    elif recip_type == "kemri":
        ca_kem_key = kwargs.get("kem_key")
        ca_hybrid_kem_key = kwargs.get("hybrid_kem_key")

        if ca_kem_key is None and ca_hybrid_kem_key is None:
            raise ValueError("The CA KEM key was not provided, the `encryptedKey` for `KEMRI` is not supported yet.")

        if ca_kem_key is not None and not isinstance(ca_kem_key, KEMPrivateKey):
            raise ValueError("The CA KEM key was not a `KEMPrivateKey`.")

        if ca_hybrid_kem_key is not None and not isinstance(ca_hybrid_kem_key, HybridKEMPrivateKey):
            raise ValueError("The CA hybrid KEM key was not a `HybridPrivateKey`.")

        # TODO fix to choose in a list of KEM keys.
        der_data = ca_kga_logic.validate_kemri_env_data_for_ca(
            env_data=env_data,
            expected_raw_data=True,
            for_pop=False,
            kem_cert=kwargs.get("kem_cert"),  # type: ignore
            hybrid_kem_cert=kwargs.get("hybrid_kem_cert"),  # type: ignore
            kem_key=ca_kem_key,
            hybrid_key=ca_hybrid_kem_key,
        )
    elif recip_type == "ktri":
        if kwargs.get("encr_rsa_key") is None:
            raise ValueError("The CA RSA key was not provided, the `encryptedKey` for `KTRI` can not be decrypted.")

        if not isinstance(kwargs["encr_rsa_key"], RSAPrivateKey):
            raise ValueError("The CA RSA key was not a `RSAPrivateKey`.")

        der_data = ca_kga_logic.validate_enveloped_data(
            env_data=env_data,
            pki_message=request,
            expected_raw_data=True,
            ee_key=kwargs["encr_rsa_key"],
            cmp_protection_cert=request["extraCerts"][0],
        )

    elif recip_type == "kari":
        # TODO decide if the new public key is allowed to be used for this operation.
        cmp_protection_cert = request["extraCerts"][0]
        client_pub_key = keyutils.load_public_key_from_spki(
            cmp_protection_cert["tbsCertificate"]["subjectPublicKeyInfo"]
        )
        if not isinstance(client_pub_key, ECDHPublicKey):
            raise ValueError("The recipient certificate must contain an ECDH key for KGA `KARI`.")

        kari_certs = kwargs.get("kari_cert_and_key") or KARICertsAndKeys.from_kwargs(
            **kwargs,
        )

        _, kari_key = kari_certs.get_cert_and_key(
            public_key=client_pub_key,
        )

        der_data = ca_kga_logic.validate_enveloped_data(
            env_data=env_data,
            pki_message=request,
            expected_raw_data=True,
            ee_key=kari_key,
            cmp_protection_cert=cmp_protection_cert,
        )

    else:
        raise ValueError(f"Invalid recipient type for `encryptedKey`: {recip_type}")

    # TODO decide if it is allowed, if the public key is not set.
    _ = validate_enc_key_with_id(
        data=der_data,
        cert_template=cert_template,
    )

    new_ee_cert = certbuildutils.build_cert_from_cert_template(
        cert_template=cert_template,
        ca_key=ca_key,
        ca_cert=ca_cert,
        **kwargs,
    )
    return new_ee_cert


@keyword(name="Respond To keyAgreement Request")
def respond_to_key_agreement_request(  # noqa: D417 Missing argument descriptions in the docstring
    cert_req_msg: rfc4211.CertReqMsg,
    ca_key: SignKey,
    ca_cert: rfc9480.CMPCertificate,
    cmp_protection_cert: Optional[rfc9480.CMPCertificate] = None,
    ecc_key: Optional[EllipticCurvePublicKey] = None,
    x25519_key: Optional[X25519PrivateKey] = None,
    x448_key: Optional[X448PrivateKey] = None,
    use_ephemeral: bool = False,
    extensions: Optional[rfc9480.Extensions] = None,
    **kwargs,
) -> Tuple[rfc9480.CMPCertificate, Optional[rfc9480.EnvelopedData]]:
    """Respond to a certificate request using key agreement.

    Note:
    ----
       - Assumes that the request includes a public key compatible with key agreement.
       - Requires the CA to have a corresponding private key for key agreement.

    Arguments:
    ---------
       - `cert_req_msg`: The certificate request message containing the key agreement parameters.
       - `ca_key`: The CA private key used to sign the certificate.
       - `ca_cert`: The CA certificate corresponding to the signing key.
       - `cmp_protection_cert`: The CMP protection certificate used in the key agreement. Defaults to `None`.
       - `ca_ecc_key`: The CA’s Elliptic Curve public key for ECDH key agreement. Defaults to `None`.
       - `ca_x25519`: The CA’s X25519 private key for key agreement. Defaults to `None`.
       - `ca_x448`: The CA’s X448 private key for key agreement. Defaults to `None`.
       - `use_ephemeral`: Whether to use an ephemeral key for key agreement. Defaults to `False`.
       - `extensions`: Additional certificate extensions (e.g., OCSP, CRL). Defaults to `None`.

    Returns:
    -------
       - The newly issued certificate and an `EnvelopedData` structure for secure transport.

    Raises:
    ------
       - `ValueError`: If the request contains an invalid public key type.
       - `ValueError`: If no matching CA key is provided for key agreement.

    Examples:
    --------
    | ${cert} | ${env_data} = | Respond To Key Agreement | ${cert_req_msg} | ${ca_key} | ${ca_cert} |
    | ${cert} | ${env_data} = | Respond To Key Agreement | ${cert_req_msg} | ${ca_key} | ${ca_cert} \
    | ${cmp_protection_cert} | ${ca_x25519} | ${use_ephemeral} |

    """
    cert_template = cert_req_msg["certReq"]["certTemplate"]
    public_key = keyutils.load_public_key_from_cert_template(cert_template=cert_template)

    if not isinstance(public_key, ECDHPublicKey):
        raise ValueError(
            f"Invalid public key type, for `keyAgreement`.Expected: ECDHPublicKey, Got: {type(public_key)}"
        )

    popo = cert_req_msg["popo"]["keyAgreement"]
    popo_type = popo.getName()

    if popo_type not in ["agreeMAC", "encryptedKey", "subsequentMessage"]:
        raise ValueError(f"Invalid POP structure: {popo_type}. Expected: agreeMAC, encryptedKey, subsequentMessage")

    if popo_type == "encryptedKey":
        return process_encrypted_key(
            cert_req_msg=cert_req_msg,
            ca_key=ca_key,
            ca_cert=ca_cert,
            cmp_protection_cert=cmp_protection_cert,
            for_agreement=True,
            x448_key=x448_key,
            x25519_key=x25519_key,
            ecc_key=ecc_key,
            **kwargs,
        ), None

    if popo_type == "agreeMAC":
        use_ephemeral = False

    if isinstance(public_key, X25519PublicKey):
        server_key = x25519_key
    elif isinstance(public_key, X448PublicKey):
        server_key = x448_key
    elif use_ephemeral and (ecc_key is None or isinstance(ecc_key, EllipticCurvePrivateKey)):
        server_key = keyutils.generate_key("ec", curve=public_key.curve.name)
    else:
        server_key = ecc_key

    if server_key is None:
        raise ValueError(f"The CA key for the matching public key was not provided. Expected type: {type(public_key)}")

    if popo_type == "agreeMAC":
        return _process_agree_mac_key_agreement(
            cert_req_msg=cert_req_msg,
            ca_key=ca_key,
            ca_cert=ca_cert,
            ca_ecc_key=server_key,  # type: ignore
            **kwargs,
            extensions=extensions,
        ), None

    cek = os.urandom(32)
    kari = envdatautils.prepare_kari(
        public_key=public_key,
        sender_private_key=server_key,  # type: ignore
        cmp_protection_cert=cmp_protection_cert,
        oid=None,
        cek=cek,
    )
    new_ee_cert = certbuildutils.build_cert_from_cert_template(
        cert_template=cert_template,
        ca_key=ca_key,
        ca_cert=ca_cert,
        extensions=extensions,
    )
    data = encoder.encode(new_ee_cert)
    kari = envdatautils.parse_recip_info(kari)
    env_data = envdatautils.prepare_enveloped_data(
        recipient_infos=[kari],
        cek=cek,
        target=None,
        data_to_protect=data,
        enc_oid=rfc5652.id_data,
    )
    return new_ee_cert, env_data


@keyword(name="Respond To keyEncipherment Request")
def respond_to_key_encipherment_request(  # noqa: D417 undocumented-params
    cert_req_msg: rfc4211.CertReqMsg,
    ca_key: SignKey,
    ca_cert: rfc9480.CMPCertificate,
    cmp_protection_cert: Optional[rfc9480.CMPCertificate] = None,
    ecc_key: Optional[EllipticCurvePublicKey] = None,
    x25519_key: Optional[X25519PrivateKey] = None,
    x448_key: Optional[X448PrivateKey] = None,
    extensions: Optional[Sequence[rfc5280.Extension]] = None,
    **kwargs,
) -> Tuple[rfc9480.CMPCertificate, Optional[rfc9480.EnvelopedData]]:
    """Respond to a key encipherment request.

    Arguments:
    ---------
       - `cert_req_msg`: The certificate request message to respond to.
       - `ca_key`: The CA private key to sign the response with.
       - `ca_cert`: The CA certificate matching the CA key.
       - `cmp_protection_cert`: The CMP protection certificate to use for signing the response. Defaults to `None`.
       - `ecc_key`: The ECC key of the CA to use for the encrypted key. Defaults to `None`.
       - `x25519_key`: The X25519 key of the CA to use for the encrypted key. Defaults to `None`.
       - `x448_key`: The X448 key of the CA to use for the encrypted key. Defaults to `None`.
       - `extensions`: The extensions to add to the certificate. Defaults to `None`.
       - `kwargs`: Additional keyword arguments.

    Returns:
    -------
       - The certificate and the encrypted certificate, if encrCert `challenge` is set.

    Raises:
    ------
       - `NotImplementedError`: If the request is for KGA.
       - `ValueError`: If the request contains an invalid public key type.
       - `ValueError`: If the request contains an invalid POP choice.

    Examples:
    --------
    | ${cert} | ${enc_cert}= | Respond To keyEncipherment Request | ${cert_req_msg} | ${ca_key} | ${ca_cert} |

    """
    enc_cert = None
    cert_template = cert_req_msg["certReq"]["certTemplate"]
    cert = certbuildutils.build_cert_from_cert_template(
        cert_template=cert_template,
        ca_key=ca_key,
        ca_cert=ca_cert,
        extensions=extensions,
    )

    if not cert_req_msg["popo"].isValue:
        raise NotImplementedError(
            "The `popo` field is missing in the certificate request. Please use the `build_kga_cmp_response` function"
        )

    if not cert_req_msg["popo"]["keyEncipherment"].isValue:
        raise NotImplementedError("The `keyEncipherment` field is missing in the certificate request.")

    popo = cert_req_msg["popo"]["keyEncipherment"]

    popo_type = popo.getName()

    if popo_type not in ["encryptedKey", "subsequentMessage"]:
        raise ValueError(
            f"Invalid POP for `keyEncipherment` request: {popo_type}. Expected: encryptedKey, subsequentMessage"
        )

    if popo_type == "encryptedKey":
        return process_encrypted_key(
            cert_req_msg=cert_req_msg,
            ca_key=ca_key,
            ca_cert=ca_cert,
            cmp_protection_cert=cmp_protection_cert,
            for_agreement=False,
            x25519_key=x25519_key,
            x448_key=x448_key,
            ecc_key=ecc_key,
            **kwargs,
        ), None

    if popo.getName() == "subsequentMessage":
        enc_cert = prepare_encr_cert_from_request(
            cert_req_msg=cert_req_msg,
            ca_key=ca_key,
            hash_alg=kwargs.get("hash_alg", "sha256"),
            ca_cert=ca_cert,
            new_ee_cert=cert,
        )

    return cert, enc_cert


@keyword(name="Respond To CertReqMsg")
def respond_to_cert_req_msg(  # noqa: D417 Missing argument descriptions in the docstring
    cert_req_msg: rfc4211.CertReqMsg,
    ca_key: SignKey,
    ca_cert: rfc9480.CMPCertificate,
    hybrid_kem_key: Optional[Union[ECDHPrivateKey, HybridKEMPrivateKey]] = None,
    hash_alg: str = "sha256",
    extensions: Optional[Sequence[rfc5280.Extension]] = None,
    **kwargs,
) -> Tuple[rfc9480.CMPCertificate, Optional[rfc9480.EnvelopedData], Optional[rfc9480.EnvelopedData]]:
    """Respond to a certificate request.

    Note:
    ----
       - Assumes that the `POP` was already verified.

    Arguments:
    ---------
       - `cert_req_msg`: The certificate request message to respond to.
       - `ca_key`: The CA private key to sign the response with.
       - `ca_cert`: The CA certificate matching the CA key.
       - `hybrid_kem_key`: The hybrid KEM key of the CA to use. Defaults to `None`.
       - `hash_alg`: The hash algorithm to use, for signing the certificate. Defaults to "sha256".
       - `extensions`: The extensions to add to the certificate. Defaults to `None`.
       (as an example for OCSP, CRL, etc.)

    Returns:
    -------
         - The certificate and the encrypted certificate, if the request is for key encipherment.

    Raises:
    ------
       - `ValueError`: If the request contains an invalid `POPO` choice (structure was updated).
       - `BadPOP`: If the POP verification fails.
       - `BadCertTemplate`: If the certificate template is invalid.
       - `BadAsn1Data`: If the ASN.1 data is invalid.
       - `BadRequest`: If the request is invalid (e.g., missing fields, request greater 1).


    Examples:
    --------
    | ${cert} | ${enc_cert}= | Respond To CertReqMsg | ${cert_req_msg} | ${ca_key} | ${ca_cert} |
    | ${cert} | ${enc_cert}= | Respond To CertReqMsg | ${cert_req_msg} | ${ca_key} | ${ca_cert} \
    | ${hybrid_kem_key} | ${hash_alg} |

    """
    if kwargs.get("alt_cert_template") is not None:
        cert_template = kwargs["alt_cert_template"]
    else:
        cert_template = cert_req_msg["certReq"]["certTemplate"]

    alg_id = None
    if cert_req_msg["popo"].isValue:
        if cert_req_msg["popo"].getName() == "signature":
            alg_id = cert_req_msg["popo"]["signature"]["algorithmIdentifier"]

    validate_cert_template_public_key(
        cert_template,
        max_key_size=4096 * 2,
        sig_popo_alg_id=alg_id,
    )

    if not cert_req_msg["popo"].isValue:
        public_key = keyutils.load_public_key_from_cert_template(cert_template=cert_template, must_be_present=False)

        if public_key:
            raise BadPOP("The public key value is set, but the POPO is missing in the certificate request.")

    if not cert_req_msg["popo"].isValue:
        cert, private_key = prepare_cert_and_private_key_for_kga(
            cert_template=cert_req_msg["certReq"]["certTemplate"],
            ca_cert=ca_cert,
            ca_key=ca_key,
            **kwargs,
        )
        return cert, None, private_key

    name = cert_req_msg["popo"].getName()

    if name in ["raVerified", "signature"]:
        cert = certbuildutils.build_cert_from_cert_template(
            cert_template=cert_template,
            ca_key=ca_key,
            ca_cert=ca_cert,
            extensions=extensions,
        )
        return cert, None, None

    if name == "keyEncipherment":
        cert, enc_cert = respond_to_key_encipherment_request(
            cert_req_msg=cert_req_msg,
            ca_key=ca_key,
            ca_cert=ca_cert,
            hybrid_kem_key=hybrid_kem_key,
            hash_alg=hash_alg,
            extensions=extensions,  # type: ignore
            **kwargs,
        )

        return cert, enc_cert, None

    if name == "keyAgreement":
        cert, enc_cert = respond_to_key_agreement_request(
            ca_key=ca_key,
            ca_cert=ca_cert,
            hash_alg=hash_alg,
            extensions=extensions,  # type: ignore
            cert_req_msg=cert_req_msg,
            hybrid_kem_key=hybrid_kem_key,
            **kwargs,
        )
        return cert, enc_cert, None

    name = cert_req_msg["popo"].getName()
    raise ValueError(f"Invalid POP structure: {name}.")


@keyword(name="Verify Signature POP For PKI Request")
def verify_sig_pop_for_pki_request(  # noqa: D417 Missing argument descriptions in the docstring
    pki_message: PKIMessageTMP, cert_index: Union[int, str] = 0
) -> None:
    """Verify the POP in the PKIMessage.

    Arguments:
    ---------
        - `pki_message`: The PKIMessage to verify the POP for.
        - `cert_index`: The index of the certificate request to verify the POP for. Defaults to `0`.

    Raises:
    ------
        - ValueError: If the body type is not one of `ir`, `cr`, `kur`, or `crr`.
        - IndexError: If the index is out of range.
        - BadAsn1Data: If the ASN.1 data is invalid.
        - BadPOP: If the signature is invalid.

    Examples:
    --------
    | Verify Signature POP For PKI Request | ${pki_message} | ${cert_index} |

    """
    body_name = pki_message["body"].getName()
    if body_name in {"ir", "cr", "kur", "crr"}:
        cert_req_msg = get_cert_req_msg_from_pkimessage(pki_message, index=cert_index)
        popo: rfc4211.ProofOfPossession = cert_req_msg["popo"]
        if not popo["signature"].isValue:
            raise BadPOP("POP signature is missing in the PKIMessage.")
        try:
            _verify_pop_signature(pki_message, request_index=int(cert_index))
        except BadSigAlgID as e:
            raise BadPOP(
                "POP signature is missing in the PKIMessage.", error_details=[e.message] + e.error_details
            ) from e

    elif pki_message["p10cr"]:
        csr = pki_message["p10cr"]
        try:
            certutils.verify_csr_signature(csr)

        except BadSigAlgID as e:
            raise BadPOP(
                "POP signature is missing in the PKIMessage.", error_details=[e.message] + e.error_details
            ) from e

        except InvalidSignature:
            raise BadPOP("POP verification for `p10cr` failed.")  # pylint: disable=raise-missing-from

    else:
        raise ValueError(f"Invalid PKIMessage body: {body_name} Expected: ir, cr, kur, crr or p10cr")


@not_keyword
def prepare_ca_body(
    body_name: str,
    responses: Union[Sequence[CertResponseTMP], CertResponseTMP],
    ca_pubs: Optional[Sequence[rfc9480.CMPCertificate]] = None,
) -> PKIBodyTMP:
    """Prepare the body for a CA `CertResponse` message.

    :return: The prepared body.
    """
    types_to_id = {"ip": 1, "cp": 3, "kup": 8, "ccp": 14}
    if body_name not in types_to_id:
        raise ValueError(f"Unsupported body_type: '{body_name}'. Expected one of {list(types_to_id.keys())}.")

    body = PKIBodyTMP()
    if ca_pubs is not None:
        body[body_name]["caPubs"].extend(ca_pubs)

    if isinstance(responses, CertResponseTMP):
        responses = [responses]

    if responses is None:
        raise ValueError("No responses provided to build the body.")

    body[body_name]["response"].extend(responses)
    return body


@not_keyword
def set_ca_header_fields(request: PKIMessageTMP, kwargs: dict) -> dict:
    """Set header fields for a new PKIMessage, by extracting them from the request.

    Includes the setting of the `recipNonce`, `recipKID`, `senderNonce`, `transactionID`, and
    `recipient`, `pvno` fields.

    :param request: The PKIMessage to extract the header fields from.
    :param kwargs: The additional values to set for the header, values if are
    included in the request will not be overwritten.
    """
    if request["header"]["senderKID"].isValue:
        kwargs["recip_kid"] = kwargs.get("recip_kid") or request["header"]["senderKID"].asOctets()
    else:
        logging.debug("No `senderKID` value set in the request header.")

    kwargs["recip_nonce"] = kwargs.get("recip_nonce") or request["header"]["senderNonce"].asOctets()
    alt_nonce = (
        os.urandom(16) if not request["header"]["recipNonce"].isValue else request["header"]["recipNonce"].asOctets()
    )

    if not kwargs.get("use_fresh_nonce", True):
        alt_nonce = os.urandom(16)

    kwargs["sender_nonce"] = kwargs.get("sender_nonce") or alt_nonce
    kwargs["transaction_id"] = kwargs.get("transaction_id") or request["header"]["transactionID"].asOctets()
    kwargs["recipient"] = kwargs.get("recipient") or request["header"]["sender"]
    kwargs["pvno"] = kwargs.get("pvno") or int(request["header"]["pvno"])
    return kwargs


@keyword(name="Build CP From P10CR")
def build_cp_from_p10cr(  # noqa: D417 Missing argument descriptions in the docstring
    request: PKIMessageTMP,
    cert: Optional[rfc9480.CMPCertificate] = None,
    set_header_fields: bool = True,
    cert_req_id: Strint = -1,
    ca_pubs: Optional[Sequence[rfc9480.CMPCertificate]] = None,
    ca_key: Optional[SignKey] = None,
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
    **kwargs,
) -> Tuple[PKIMessageTMP, rfc9480.CMPCertificate]:
    """Build a CMP message for a certificate request.

    Arguments:
    ---------
        - `request`: The PKIMessage containing the certificate request.
        - `cert`: The certificate to build the response for. Defaults to `None`.
        - `set_header_fields`: Whether to patch the header fields, for the exchange. Defaults to `True`.
        (recipNonce, recipKID)
        - `cert_req_id`: The certificate request ID. Defaults to `-1`.
        - `ca_pubs`: The CA certificates to include in the response. Defaults to `None`.
        - `ca_key`: The CA private key to sign the response with. Defaults to `None`.
        - `ca_cert`: The CA certificate matching the CA key. Defaults to `None`.
        - `kwargs`: Additional values to set for the header.

    **kwargs:
    --------
        - `hash_alg` (str): The hash algorithm to use for signing the certificate. Defaults to "sha256".
        - `extensions` (ExtensionParseType): Additional certificate extensions (e.g., OCSP, CRL). Defaults to `None`.
        - `include_ski` (bool): Whether to include the Subject Key Identifier in the certificate. Defaults to `True`.
        - `include_csr_extensions` (bool): Whether to include the CSR extensions in the certificate. Defaults to `True`.

    Returns:
    -------
        - The built PKIMessage.
        - The certificate built from the request.

    Raises:
    ------
        - ValueError: If the request is not a `p10cr`.
        - ValueError: If the CA key and certificate are not provided and the certificate is not provided.

    Examples:
    --------
    | ${pki_message} | ${cert} = | Build CP From P10CR | ${request} | ${cert} | ${ca_key} | ${ca_cert} |
    | ${pki_message} | ${cert} = | Build CP From P10CR | ${request} | ${cert} | ${ca_key} | ${ca_cert} | cert_req_id=2 |

    """
    if request["body"].getName() != "p10cr":
        raise ValueError("Request must be a p10cr to build a CP message for it.")

    if request and set_header_fields:
        kwargs = set_ca_header_fields(request, kwargs)

    certutils.verify_csr_signature(request["body"]["p10cr"])
    if cert is None and ca_key is None and ca_cert is None:
        raise ValueError("Either `cert` or `ca_key` and `ca_cert` must be provided to build a CA CMP message.")

    cert = cert or certbuildutils.build_cert_from_csr(
        csr=request["body"]["p10cr"],
        ca_key=ca_key,  # type: ignore
        ca_cert=ca_cert,  # type: ignore
        hash_alg=kwargs.get("hash_alg", "sha256"),
        extensions=kwargs.get("extensions"),
        include_ski=kwargs.get("include_ski", True),
        include_csr_extensions=kwargs.get("include_csr_extensions", True),
    )
    responses = prepare_cert_response(cert=cert, cert_req_id=cert_req_id)
    body = prepare_ca_body(body_name="cp", responses=responses, ca_pubs=ca_pubs)
    pki_message = cmputils.prepare_pki_message(**kwargs)
    pki_message["body"] = body
    return pki_message, cert


def _process_one_cert_request(
    ca_key: SignKey,
    ca_cert: rfc9480.CMPCertificate,
    request: PKIMessageTMP,
    cert_index: int,
    eku_strict: bool,
    **kwargs,
) -> Tuple[rfc9480.CMPCertificate, Optional[rfc5652.EnvelopedData], Optional[rfc9480.EnvelopedData]]:
    """Process a single certificate response.

    :param ca_key: The CA private key to sign the certificate with.
    :param ca_cert: The CA certificate matching the CA key.
    :param request: The PKIMessage containing the certificate request.
    :param cert_index: The index of the certificate to respond to.
    :param eku_strict: The strictness of the EKU bits.
    :param kwargs: The additional values to set for the header.
    :return: The certificate and the optional encrypted certificate.
    """
    logging.info("Processing certificate request: %d", cert_index)
    logging.debug("Verify RA verified in _process_one_cert: %s", kwargs.get("verify_ra_verified", True))

    cert_req_msg = get_cert_req_msg_from_pkimessage(pki_message=request, index=cert_index)

    if cert_req_msg["popo"].isValue:
        if cert_req_msg["popo"].getName() == "signature":
            public_key = get_public_key_from_cert_req_msg(cert_req_msg)
            try:
                public_key = convertutils.ensure_is_verify_key(public_key)
            except ValueError as e:
                raise BadPOP(
                    f"Invalid public key type: {type(public_key)}. {e}", failinfo="badPOP,badCertTemplate"
                ) from e
            try:
                keyutils.check_consistency_sig_alg_id_and_key(
                    cert_req_msg["popo"]["signature"]["algorithmIdentifier"], public_key
                )

            except BadSigAlgID as e:
                raise BadPOP("The `signature` POP alg id and the public key are of different types.") from e

    elif not cert_req_msg["popo"].isValue:
        if not check_if_request_is_for_kga(request):
            raise BadCertTemplate(
                "The `popo` structure is missing in the PKIMessage."
                "But the request is not for KGA (key generation authority)."
            )

    alt_cert_req, _ = cmputils.validate_reg_info_field(
        cert_reg_msg=cert_req_msg,
        alt_reg_must_be_present=False,
        utf8_pairs_must_be_present=False,
    )
    alt_cert_template = None
    if alt_cert_req is not None:
        alt_cert_template = alt_cert_req["certTemplate"]

    validate_cert_template_public_key(cert_req_msg["certReq"]["certTemplate"], max_key_size=4096 * 2)
    validate_cert_request_controls(
        cert_request=cert_req_msg["certReq"],
        **kwargs,
    )

    verify_popo_for_cert_request(
        pki_message=request,
        allowed_ra_dir=kwargs.get("allowed_ra_dir", "./data/trusted_ras"),
        cert_req_index=cert_index,
        must_have_ra_eku_set=eku_strict,
        verify_ra_verified=kwargs.get("verify_ra_verified", True),
    )

    cert, enc_cert, private_key = respond_to_cert_req_msg(
        cert_req_msg=cert_req_msg,
        request=request,
        ca_key=ca_key,
        ca_cert=ca_cert,
        alt_cert_template=alt_cert_template,
        **kwargs,
    )
    return cert, enc_cert, private_key


def _process_cert_requests(
    ca_key: SignKey,
    ca_cert: rfc9480.CMPCertificate,
    request: PKIMessageTMP,
    eku_strict: bool,
    **kwargs,
) -> Tuple[List[CertResponseTMP], List[rfc9480.CMPCertificate]]:
    """Process a certificate requests.

    :param ca_key: The CA private key to sign the certificates with.
    :param ca_cert: The CA certificate matching the CA key.
    :param request: The PKIMessage containing the certificate request.
    :param eku_strict: The strictness of the EKU bits.
    :return: The certificate responses and the certificates.
    """
    responses = []
    certs = []

    logging.warning("Verify RA verified in _process_cert_requests: %s", kwargs.get("verify_ra_verified", True))

    body_name = request["body"].getName()

    for i in range(len(request["body"][body_name])):
        cert, enc_cert, private_key = _process_one_cert_request(
            ca_key=ca_key,
            ca_cert=ca_cert,
            request=request,
            cert_index=i,
            eku_strict=eku_strict,
            **kwargs,
        )
        certs.append(cert)
        cert_req_id = int(request["body"][body_name][i]["certReq"]["certReqId"])
        response = prepare_cert_response(cert=cert, enc_cert=enc_cert, private_key=private_key, cert_req_id=cert_req_id)

        responses.append(response)

    return responses, certs


@not_keyword
def get_response_body_type(request: PKIMessageTMP) -> str:
    """Get the response body type.

    :param request: The PKIMessage to get the response body type from.
    :return: The response body type.
    """
    body_name = request["body"].getName()
    if body_name == "ir":
        return "ip"
    if body_name in ["cr", "p10cr"]:
        return "cp"
    if body_name == "kur":
        return "kup"
    if body_name == "crr":
        return "ccp"

    raise ValueError(f"Invalid PKIMessage body: {body_name}. Expected: ir, cr, kur, crr or p10cr.")


def _build_ca_cert_response_body(
    responses: Union[Sequence[CertResponseTMP], CertResponseTMP],
    set_header_fields: bool = True,
    request: Optional[PKIMessageTMP] = None,
    body_name: Optional[str] = None,
    **kwargs,
) -> PKIMessageTMP:
    """Build a CA certificate response body."""
    if request and set_header_fields:
        kwargs = set_ca_header_fields(request, kwargs)

    if request is not None:
        body_name = body_name or get_response_body_type(request)

    if body_name is None:
        raise ValueError("The `body_name` must be set to build a CA certificate response body.")

    kwargs["sender_nonce"] = kwargs.get("sender_nonce") or os.urandom(16)
    body = prepare_ca_body(body_name=body_name, responses=responses, ca_pubs=kwargs.get("ca_pubs"))
    pki_message = cmputils.prepare_pki_message(**kwargs)
    pki_message["body"] = body
    return pki_message


@keyword(name="Build CP CMP Message")
def build_cp_cmp_message(  # noqa: D417 Missing argument descriptions in the docstring
    request: Optional[PKIMessageTMP] = None,
    cert: Optional[rfc9480.CMPCertificate] = None,
    enc_cert: Optional[rfc5652.EnvelopedData] = None,
    ca_key: Optional[SignKey] = None,
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
    cert_req_id: Optional[int] = None,
    responses: Optional[Union[Sequence[CertResponseTMP], CertResponseTMP]] = None,
    cert_index: Optional[int] = None,
    eku_strict: bool = True,
    set_header_fields: bool = True,
    **kwargs,
) -> CAResponse:
    """Build a CMP message for a certificate response.

    Arguments:
    ---------
       - `request`: The PKIMessage containing the certificate request. Defaults to `None`.
       - `cert`: The certificate to build the response for. Defaults to `None`.
       - `enc_cert`: The encrypted certificate to build the response for. Defaults to `None`.
       - `ca_key`: The CA private key to sign the response with. Defaults to `None`.
       - `ca_cert`: The CA certificate matching the CA key. Defaults to `None`.
       - `cert_req_id`: The certificate request ID. Defaults to `None`.
       - `responses`: The certificate responses to include in the response. Defaults to `None`.
       - `cert_index`: The certificate index. Defaults to `None` (if `None`, all requests are processed).
       - `eku_strict`: Whether to strictly enforce the EKU bits, for `raVerified`. Defaults to `True`.
       - `set_header_fields`: Whether to patch the header fields, for the exchange. Defaults to `True`.
       - `kwargs`: Additional values to set for the header.

    Returns:
    -------
        - The built PKIMessage and the certificates.

    Raises:
    ------
        - `ValueError`: If the CA key and certificate are not provided and the encrypted certificate
        or certificate is not provided.
        - `ValueError`: If the body name is invalid.
        - `BadRequest`: If the request is invalid (e.g., missing fields, request greater than 1).
        - `BadCertTemplate`: If the certificate template is invalid.
        - `BadAsn1Data`: If the ASN.1 data is invalid or contains trailing data.
        - `BadPOP`: If the POP verification fails.

    Examples:
    --------
    | ${pki_message} ${certs}= | Build CP CMP Message | ${request} | ${cert} |
    | ${pki_message} ${certs}= | Build CP CMP Message | ${request} | ${enc_cert} |
    | ${pki_message} ${certs}= | Build CP CMP Message | ${request} | ${cert} | ${enc_cert} |



    """
    certs = []

    if enc_cert is None and cert is None and request is None:
        raise ValueError("Either `cert`, `enc_cert`, or `request` must be provided to build a CA CMP message.")

    if responses is not None:
        pass

    elif enc_cert is not None or cert is not None:
        if cert_req_id is None:
            cert_req_id = 0

        responses = prepare_cert_response(cert=cert, enc_cert=enc_cert, cert_req_id=cert_req_id)

        if cert is not None:
            certs.append(cert)

    elif request is not None:
        if ca_key is None or ca_cert is None:
            raise ValueError("Either `cert` or `ca_key` and `ca_cert` must be provided to build a CA CMP message.")

        if cert_index is not None:
            cert, enc_cert, private_key = _process_one_cert_request(
                ca_key=ca_key,
                ca_cert=ca_cert,
                request=request,
                cert_index=cert_index,
                eku_strict=eku_strict,
                **kwargs,
            )
            certs.append(cert)

            if cert_req_id is None:
                cert_req_id = int(request["body"]["cr"][cert_index]["certReq"]["certReqId"])

            responses = prepare_cert_response(
                cert=cert, enc_cert=enc_cert, private_key=private_key, cert_req_id=cert_req_id
            )

        else:
            responses, certs = _process_cert_requests(
                ca_key=ca_key,
                ca_cert=ca_cert,
                request=request,
                eku_strict=eku_strict,
                **kwargs,
            )

    if request and set_header_fields:
        kwargs = set_ca_header_fields(request, kwargs)

    if responses is None:
        raise ValueError("No responses provided to build a CA CMP message.")

    kwargs["sender_nonce"] = kwargs.get("sender_nonce") or os.urandom(16)
    body = prepare_ca_body("cp", responses=responses, ca_pubs=kwargs.get("ca_pubs"))
    pki_message = cmputils.prepare_pki_message(**kwargs)
    pki_message["body"] = body
    return pki_message, certs


@keyword(name="Enforce LwCMP For CA")
def enforce_lwcmp_for_ca(  # noqa: D417 Missing argument descriptions in the docstring
    request: PKIMessageTMP,
) -> None:
    """Enforce the Lightweight CMP (LwCMP) for a CA.

    When the request is "ir", "cr", "kur", or "crr", the `certReqId` **MUST** be `0`,
    and only one **MUST** be present (p10cr does not have a `certReqId`).

    Supported request types:
    -----------------------
    - ir (initialization request)
    - cr (certification request)
    - kur (key update request)
    - crr (cross-certification request)
    - rr (revocation request)
    - certConf (certificate confirmation)

    Arguments:
    ---------
      - `request`: The PKIMessage to enforce the LwCMP for.

    Raises:
    ------
        - BadRequest: If the `certReqId` is invalid.
        - BadRequest: If the request length is invalid.
        - BadRequest: If the request type is invalid.

    Examples:
    --------
    | Enforce LwCMP For CA | ${request} |

    """
    if request["body"].getName() == "p10cr":
        pass
    elif request["body"].getName() in {"ir", "cr", "kur", "crr"}:
        if len(request["body"][request["body"].getName()]) != 1:
            raise BadRequest("Only one certificate request is allowed for LwCMP.")

        if request["body"][request["body"].getName()][0]["certReq"]["certReqId"] != 0:
            raise BadRequest("Invalid certReqId for LwCMP.")

    elif request["body"].getName() == "certConf":
        if len(request["body"]["certConf"]) != 1:
            raise BadRequest("Only one certificate confirmation is allowed for LwCMP.")

    elif request["body"].getName() == "rr":
        if len(request["body"]["rr"]) != 1:
            raise BadRequest("Only one revocation request is allowed for LwCMP.")

    else:
        raise BadRequest(
            "Invalid PKIMessage body for LwCMP. Expected: ir, cr, kur, crr, rr, certConf or p10cr."
            f"Got: {request['body'].getName()}."
        )


@keyword(name="Build IP CMP Message")
def build_ip_cmp_message(  # noqa: D417 Missing argument descriptions in the docstring
    request: Optional[PKIMessageTMP] = None,
    cert: Optional[rfc9480.CMPCertificate] = None,
    enc_cert: Optional[rfc5652.EnvelopedData] = None,
    ca_pubs: Optional[Sequence[rfc9480.CMPCertificate]] = None,
    responses: Optional[Union[Sequence[CertResponseTMP], CertResponseTMP]] = None,
    exclude_fields: Optional[str] = None,
    set_header_fields: bool = True,
    verify_ra_verified: bool = True,
    **kwargs,
) -> CAResponse:
    """Build a CMP message for an initialization response.

    Arguments:
    ---------
        - `cert`: The certificate to build the response for. Defaults to `None`.
        - `enc_cert`: The encrypted certificate to build the response for. Defaults to `None`.
        - `ca_pubs`: The CA certificates to include in the response. Defaults to `None`.
        - `responses`: The certificate responses to include in the response. Defaults to `None`.
        - `exclude_fields`: The fields to exclude from the response. Defaults to `None`.
        - `request`: The PKIMessage containing the certificate request. Defaults to `None`.
        - `set_header_fields`: Whether to patch the header fields, for the exchange. Defaults to `True`.
        - `kwargs`: Additional values to set for the header.

    **kwargs:
    --------
        - additional values to set for the header.
        - `private_key`: The private key securely wrapped in the `EnvelopedData` structure.
        - `enforce_lwcmp`: Whether to enforce the Lightweight CMP (LwCMP) for the CA. Defaults to `True`.
        - `hash_alg`: The hash algorithm to use for signing the certificate. Defaults to `sha256`.
        - `eku_strict`: Whether to strictly enforce the EKU bits. Defaults to `True`.
        (needed for raVerified)
        - `ca_key`: The CA private key to sign the newly issued certificate with.
        - `ca_cert`: The CA certificate matching the CA key.
        - `cert_req_id`: The certificate request ID. Defaults to `0`, if cert is provided.
        (else parsed from the request)
        - `extensions`: The extensions to include in the certificate. Defaults to `None`.
        (as an example for OCSP, CRL, etc.)

    Returns:
    -------
        - The built PKIMessage.
        - The certificates built from the request.

    Raises:
    ------
        - ValueError: If the CA key and certificate are not provided and the certificate is not provided.

    Examples:
    --------
    | ${pki_message} | ${certs} = | Build IP CMP Message | ${cert} | ${enc_cert} | ${ca_pubs} |
    | ${pki_message} | ${certs} = | Build IP CMP Message | ${request} | ca_cert=${ca_cert} |ca_key=${ca_key} |

    """
    if enc_cert is None and cert is None and responses is None and request is None:
        raise ValueError(
            "Either `cert`, `enc_cert`, `responses` or `request` must be provided to build a CA CMP message."
        )

    if request and set_header_fields:
        kwargs = set_ca_header_fields(request, kwargs)

    if responses is not None:
        # TODO think about extracting the certs from the responses.
        certs = [cert] if cert is not None else []

    elif request and cert is None and enc_cert is None:
        kwargs["eku_strict"] = kwargs.get("eku_strict", True)
        if kwargs.get("enforce_lwcmp", True):
            enforce_lwcmp_for_ca(request)
        if request["body"].getName() != "p10cr":
            responses, certs = _process_cert_requests(
                request=request,
                verify_ra_verified=verify_ra_verified,
                **kwargs,
            )
        else:
            logging.warning("Request was a p10cr, this is not allowed for IP messages.")
            certutils.verify_csr_signature(request["body"]["p10cr"])

            ca_key = convertutils.ensure_is_sign_key(kwargs.get("ca_key"))
            ca_cert = kwargs.get("ca_cert")
            if not isinstance(ca_cert, rfc9480.CMPCertificate):
                raise TypeError("The `ca_cert` must be a CMPCertificate object.")

            cert = certbuildutils.build_cert_from_csr(
                csr=request["body"]["p10cr"],
                ca_key=ca_key,
                ca_cert=ca_cert,
                hash_alg=kwargs.get("hash_alg", "sha256"),
                extensions=kwargs.get("extensions"),
            )
            cert_req_id = kwargs.get("cert_req_id") or -1
            certs = [cert]
            responses = prepare_cert_response(cert=cert, enc_cert=enc_cert, cert_req_id=cert_req_id)
    else:
        certs = [cert]
        responses = prepare_cert_response(
            cert=cert,
            enc_cert=enc_cert,
            private_key=kwargs.get("private_key"),
            cert_req_id=int(kwargs.get("cert_req_id", 0)),
        )

    body = prepare_ca_body("ip", responses=responses, ca_pubs=ca_pubs)
    kwargs["sender_nonce"] = kwargs.get("sender_nonce") or os.urandom(16)
    pki_message = cmputils.prepare_pki_message(exclude_fields=exclude_fields, **kwargs)
    pki_message["body"] = body
    return pki_message, certs or []  # type: ignore


@not_keyword
def prepare_enc_key(env_data: rfc5652.EnvelopedData, explicit_tag: int = 0) -> rfc9480.EncryptedKey:
    """Prepare an EncryptedKey structure by encapsulating the provided EnvelopedData.

    :param env_data: The EnvelopedData to wrap in the `EncryptedKey` structure.
    :param explicit_tag: The explicitTag id set for the `EncryptedKey` structure
    :return: An `EncryptedKey` object with encapsulated EnvelopedData.
    """
    enc_key = rfc9480.EncryptedKey().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, explicit_tag)
    )

    enc_key["envelopedData"] = env_data
    return enc_key


def prepare_cert_or_enc_cert(
    cert: Optional[rfc9480.CMPCertificate] = None, enc_cert: Optional[rfc5652.EnvelopedData] = None
) -> rfc9480.CertOrEncCert:
    """Prepare a CertOrEncCert structure containing either a certificate or encrypted certificate.

    :param cert: A certificate object representing the certificate to include.
    :param enc_cert: An optional EnvelopedData object representing an encrypted certificate.
    :return: A populated CertOrEncCert structure.
    """
    cert_or_enc_cert = rfc9480.CertOrEncCert()
    if cert is not None:
        cert2 = rfc9480.CMPCertificate().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
        cert_or_enc_cert["certificate"] = copy_asn1_certificate(cert, cert2)

    if enc_cert is not None:
        enc_key = prepare_enc_key(env_data=enc_cert, explicit_tag=1)
        cert_or_enc_cert["encryptedCert"] = enc_key

    return cert_or_enc_cert


@not_keyword
def prepare_certified_key_pair(
    cert: Optional[rfc9480.CMPCertificate] = None,
    enc_cert: Optional[rfc9480.EnvelopedData] = None,
    private_key: Optional[rfc9480.EnvelopedData] = None,
) -> rfc9480.CertifiedKeyPair:
    """Prepare a CertifiedKeyPair structure containing certificate or encrypted certificate and an optional private key.

    :param cert: An optional certificate representing the certificate.
    :param enc_cert: An optional EnvelopedData object for the encrypted certificate.
    :param private_key: An optional EnvelopedData object representing the private key.
    :raises ValueError: If both cert and enc_cert are not provided.
    :return: A populated CertifiedKeyPair structure.
    """
    if not cert and not enc_cert:
        raise ValueError("At least one of `cert` or `enc_cert` must be provided to prepare a CertifiedKeyPair.")

    certified_key_pair = rfc9480.CertifiedKeyPair()
    certified_key_pair["certOrEncCert"] = prepare_cert_or_enc_cert(cert=cert, enc_cert=enc_cert)

    if private_key is not None:
        certified_key_pair["privateKey"]["envelopedData"] = private_key

    return certified_key_pair


@keyword(name="Prepare CertResponse")
def prepare_cert_response(
    cert_req_id: Strint = 0,
    status: str = "accepted",
    text: Union[List[str], str, None] = None,
    failinfo: Optional[str] = None,
    cert: Optional[rfc9480.CMPCertificate] = None,
    enc_cert: Optional[rfc9480.EnvelopedData] = None,
    private_key: Optional[rfc9480.EnvelopedData] = None,
    **kwargs,
) -> CertResponseTMP:
    """Prepare a CertResponse structure for responding to a certificate request.

    :param cert_req_id: The ID of the certificate request being responded to.
    :param status: The status of the certificate request (e.g., "accepted" or "rejected").
    :param text: Optional status text.
    :param failinfo: Optional failure information.
    :param cert: An optional certificate object.
    :param enc_cert: Optional encrypted certificate as EnvelopedData.
    :param private_key: A private key inside the `EnvelopedData` structure
    :keyword rsp_info (str, bytes): Optional response information. Defaults to `None`.
    :keyword pki_status_info: The PKIStatusInfo structure to include in the response. Defaults to `None`.
    :return: The populated `CertResponse` structure.
    """
    cert_response = CertResponseTMP()
    cert_response["certReqId"] = univ.Integer(int(cert_req_id))

    pki_status_info = kwargs.get("pki_status_info")
    if pki_status_info is None:
        pki_status_info = cmputils.prepare_pkistatusinfo(texts=text, status=status, failinfo=failinfo)

    cert_response["status"] = pki_status_info

    if cert or enc_cert or private_key:
        cert_response["certifiedKeyPair"] = prepare_certified_key_pair(cert, enc_cert, private_key)

    if kwargs.get("rsp_info") is not None:
        cert_response["rspInfo"] = univ.OctetString(str_to_bytes(kwargs["rsp_info"]))

    return cert_response


# TODO add unit tests for this function


@not_keyword
def verify_encrypted_key_popo(
    popo_priv_key: rfc4211.POPOPrivKey,
    client_public_key: PublicKey,
    ca_key: Optional[EnvDataPrivateKey] = None,
    password: Optional[str] = None,
    client_cert: Optional[rfc9480.CMPCertificate] = None,
    cmp_protection_salt: Optional[bytes] = None,
    expected_name: Optional[str] = None,
) -> None:
    """Verify the `keyEncipherment` and `keyAgreement` POPO processing.

    :param popo_priv_key: The POPOPrivKey structure to verify.
    :param client_public_key: The public key of the client.
    :param ca_key: The CA private key used to unwrap the private key.
    :param password: The password to use for decryption the private key.
    :param client_cert: The client certificate. Defaults to `None`.
    :param cmp_protection_salt: The protection salt used to compare to the PWRI protection salt.
    Defaults to `None`.
    :param expected_name: The expected identifier name. Defaults to `None`.
    """
    data = ca_kga_logic.validate_enveloped_data(
        env_data=popo_priv_key["encryptedKey"],
        password=password,
        ee_key=ca_key,
        for_pop=False,
        cmp_protection_cert=client_cert,
        cmp_protection_salt=cmp_protection_salt,
    )
    enc_key, rest = decoder.decode(data, rfc4211.EncKeyWithID())

    if rest:
        raise BadAsn1Data("EncKeyWithID")

    if not enc_key["identifier"].isValue:
        raise ValueError("EncKeyWithID identifier is missing.")

    if expected_name is not None:
        if enc_key["identifier"]["string"].isValue:
            idf_name = str(enc_key["identifier"]["string"])
            if idf_name != expected_name:
                raise ValueError(f"EncKeyWithID identifier name mismatch. Expected: {expected_name}. Got: {idf_name}")
        else:
            result = compareutils.compare_general_name_and_name(
                enc_key["identifier"]["generalName"], prepareutils.prepare_name(expected_name)
            )
            if not result:
                logging.debug(enc_key["identifier"].prettyPrint())
                raise ValueError("EncKeyWithID identifier name mismatch.")

    data = encoder.encode(enc_key["privateKeyInfo"])

    private_key = CombinedKeyFactory.load_private_key_from_one_asym_key(data, must_be_version_2=False)

    if private_key.public_key() != client_public_key:
        raise ValueError("The decrypted key does not match the public key in the certificate request.")


def _perform_encaps_with_keys(
    public_key: KEMPublicKey,
    hybrid_kem_key: Optional[Union[ECDHPrivateKey, HybridKEMPrivateKey]] = None,
) -> Tuple[bytes, bytes, univ.ObjectIdentifier]:
    """Perform encapsulation with the provided keys.

    :param public_key: The public key to encapsulate.
    :param hybrid_kem_key: The hybrid KEM key to use for encapsulation. Defaults to `None`.
    :return: The shared secret and the encapsulated key.
    :raises ValueError: If the public key is not a KEM public key.
    """
    if not is_kem_public_key(public_key):
        raise ValueError(f"Invalid public key for `keyEncipherment`: {type(public_key)}")

    if isinstance(public_key, PQKEMPublicKey):
        ss, ct = public_key.encaps()
        kem_oid = get_kem_oid_from_key(public_key)

    elif isinstance(public_key, HybridKEMPublicKey):
        if isinstance(hybrid_kem_key, HybridKEMPrivateKey):
            hybrid_kem_key = hybrid_kem_key.trad_key  # type: ignore
        ss, ct = public_key.encaps(hybrid_kem_key)  # type: ignore
        kem_oid = get_kem_oid_from_key(public_key)

    else:
        raise ValueError(f"Invalid public key for `keyEncipherment`: {type(public_key)}")

    return ss, ct, kem_oid


# TODO think about also always returning both certificates.


def prepare_encr_cert_from_request(  # noqa: D417 Missing argument descriptions in the docstring
    cert_req_msg: rfc4211.CertReqMsg,
    ca_key: Optional[SignKey],
    ca_cert: rfc9480.CMPCertificate,
    hash_alg: Optional[str],
    new_ee_cert: Optional[rfc9480.CMPCertificate] = None,
    hybrid_kem_key: Optional[Union[HybridKEMPrivateKey, ECDHPrivateKey]] = None,
    client_pub_key: Optional[KEMPublicKey] = None,
    **kwargs,
) -> rfc9480.EnvelopedData:
    """Prepare an encrypted certificate for a request.

    Either used as a challenge for non-signing keys like KEM keys.

    Arguments:
    ---------
       - `cert_req_msg`: The certificate request message.
       - `signing_key`: The CA key to sign the certificate with.
       - `hash_alg`: The hash algorithm to use for signing the certificate (e.g., "sha256").
       - `ca_cert`: The CA certificate matching the CA key.
       - `new_ee_cert`: The new EE certificate to encrypt. Defaults to `None`.
       - `hybrid_kem_key`: The hybrid KEM key to use for encryption. Defaults to `None`.
       - `client_pub_key`: The client public key to use for the RecipientInfo. Defaults to `None`.
       (only used for the newly introduced Catalyst KEM issuing, without using Hybrid KEMs.)

    Returns:
    -------
         - The tagged `EnvelopedData` with the encrypted certificate.

    Raises:
    ------
        - `ValueError`: If the POP type is not `subsequentMessage` with `encrCert`.
        - `ValueError`: If arguments are invalid or missing.

    Examples:
    --------
    | ${enc_cert} | Prepare Encr Cert For Request | ${cert_req_msg} | ${signing_key} | ${hash_alg} | ${ca_cert} |

    """
    if new_ee_cert is None and ca_key is None:
        raise ValueError("Either `new_ee_cert` or `ca_key` must be provided to build an encrypted certificate.")

    if new_ee_cert is None:
        new_ee_cert = certbuildutils.build_cert_from_cert_template(
            cert_template=cert_req_msg["certReq"]["certTemplate"],
            ca_key=ca_key,  # type: ignore
            ca_cert=ca_cert,
            hash_alg=hash_alg,
        )
    popo_type = cert_req_msg["popo"]["keyEncipherment"]

    if popo_type.getName() != "subsequentMessage":
        raise ValueError("Only subsequentMessage is supported for KEM keys")

    if str(popo_type["subsequentMessage"]) != "encrCert":
        raise ValueError("Only encrCert is supported for KEM keys")

    spki = new_ee_cert["tbsCertificate"]["subjectPublicKeyInfo"]
    public_key = client_pub_key or keyutils.load_public_key_from_spki(spki)
    public_key = convertutils.ensure_is_kem_pub_key(public_key)

    target = rfc5652.EnvelopedData().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

    ss, ct, kem_oid = _perform_encaps_with_keys(public_key, hybrid_kem_key)
    cek = kwargs.get("cek") or os.urandom(32)
    kem_recip_info = envdatautils.prepare_kem_recip_info(
        recip_cert=new_ee_cert,
        public_key_recip=public_key,
        cek=cek,
        kemct=ct,
        shared_secret=ss,
        kem_oid=kem_oid,
    )
    data = encoder.encode(new_ee_cert)
    kem_recip_info = envdatautils.parse_recip_info(kem_recip_info)
    return envdatautils.prepare_enveloped_data(
        recipient_infos=[kem_recip_info],
        cek=cek,
        target=target,
        data_to_protect=data,
        enc_oid=rfc5652.id_data,
    )


def _validate_cert_status(
    status: rfc9480.PKIStatusInfo,
) -> None:
    """Validate the certificate status.

    :param status: The certificate status to validate.
    :raises BadRequest: If the certificate status is not `accepted` or `rejection`.
    :raises BadRequest: If the certificate status is `accepted`, but a `failInfo` is present.
    """
    if not status.isValue:
        return

    if str(status["status"]) not in {"accepted", "rejection"}:
        raise BadRequest(
            "Invalid certificate status in CertConf message."
            f"Expected 'accepted' or 'rejection', got {status['status'].getName()}"
        )

    if str(status["status"]) == "accepted" and status["failInfo"].isValue:
        raise BadRequest("Certificate status is accepted, but a fail info is present.")


@keyword(name="Build pkiconf from CertConf")
def build_pki_conf_from_cert_conf(  # noqa: D417 Missing argument descriptions in the docstring
    request: PKIMessageTMP,
    issued_certs: List[rfc9480.CMPCertificate],
    exclude_fields: Optional[str] = None,
    enforce_lwcmp: bool = True,
    set_header_fields: bool = True,
    **kwargs,
) -> PKIMessageTMP:
    """Build a PKI Confirmation message from a Certification Confirmation message.

    Ensures that the client correly received the certificates.

    Arguments:
    ---------
       - `request`: The CertConf message to build the PKIConf message from.
       - `issued_certs`: The certificates that were issued.
       - `exclude_fields`: The fields to exclude from the PKIConf message. Defaults to `None`.
       - `enforce_lwcmp`: Whether to enforce LwCMP rules. Defaults to `True`.
       - `set_header_fields`: Whether to set the header fields. Defaults to `True`.

    **kwargs:
    --------
        - additional values to set for the header.
        - `hash_alg`: The hash algorithm to use for signing the certificate. Defaults to `sha256`.
        - `allow_auto_ed`: Whether to allow automatic ED hash algorithm choice. Defaults to `True`.
        - `use_fresh_nonce`: Whether to use a fresh sender nonce. Defaults to `True`.

    Returns:
    -------
         - The built PKI Confirmation message.

    Raises:
    ------
        - `ValueError`: If the request is not a CertConf message.
        - `ValueError`: If the number of CertConf entries does not match the number of issued certificates.
        - `BadRequest`: If the number of CertStatus's is not one (for LwCMP).
        - `BadRequest`: If the CertReqId is not zero (for LwCMP).
        - `BadRequest`: If the certificate status is not `accepted` or `rejection`.
        - `BadPOP`: If the certificate hash is invalid or not present.

    Examples:
    --------
    | ${pki_conf} | Build PKIConf from CertConf | ${request} | ${issued_certs} |

    """
    if request["body"].getName() != "certConf":
        raise ValueError("Request must be a `certConf` to build a `PKIConf` message from it.")

    cert_conf: rfc9480.CertConfirmContent = request["body"]["certConf"]

    if len(cert_conf) != 1 and enforce_lwcmp:
        raise BadRequest(f"Invalid number of entries in CertConf message.Expected 1 for LwCMP, got {len(cert_conf)}")

    if len(cert_conf) != len(issued_certs):
        raise ValueError("Number of CertConf entries does not match the number of issued certificates.")

    entry: rfc9480.CertStatus
    hash_alg = kwargs.get("hash_alg")
    for entry, issued_cert in zip(cert_conf, issued_certs):
        if entry["certReqId"] != 0 and enforce_lwcmp:
            raise BadRequest(f"Invalid CertReqId in CertConf message. Got: {int(entry['certReqId'])}Expected: 0.")

        if not entry["certHash"].isValue:
            raise BadPOP("Certificate hash is missing in CertConf message.")

        _validate_cert_status(entry["statusInfo"])
        if entry["statusInfo"].isValue:
            if str(entry["statusInfo"]["status"]) == "rejection":
                logging.debug("Certificate status was rejection.")
                continue

        if entry["hashAlg"].isValue:
            logging.warning(entry["hashAlg"])
            if int(request["header"]["pvno"]) != 3:
                raise BadCertId("Hash algorithm is set in CertConf message, but the version is not 3.")
            # expected to be sha256 or similar,
            # is ensured with the flag `only_hash=False`
            hash_alg = get_hash_from_oid(entry["hashAlg"]["algorithm"], only_hash=False)
        else:
            alg_oid = issued_cert["tbsCertificate"]["signature"]["algorithm"]
            hash_alg = get_hash_from_oid(alg_oid, only_hash=True)
            if kwargs.get("allow_auto_ed", False):
                if alg_oid in [rfc9481.id_Ed25519, rfc9481.id_Ed448]:
                    hash_alg = get_digest_hash_alg_from_alg_id(alg_id=issued_cert["tbsCertificate"]["signature"])

        if hash_alg is None:
            raise BadCertId(
                "No hash algorithm found for the certificate signature algorithm,"
                "please use version 3 and set the hash algorithm in the `CertConf` message."
            )

        computed_hash = compute_hash(
            alg_name=hash_alg,
            data=encoder.encode(issued_cert),
        )

        if entry["certHash"].asOctets() != computed_hash:
            raise BadCertId("Invalid certificate hash in CertConf message.")

    if request and set_header_fields:
        kwargs = set_ca_header_fields(request, kwargs)

    pki_message = cmputils.prepare_pki_message(exclude_fields=exclude_fields, **kwargs)
    pki_message["body"]["pkiconf"] = rfc9480.PKIConfirmContent("").subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 19)
    )

    return pki_message


@not_keyword
def get_correct_ca_body_name(request: PKIMessageTMP) -> str:
    """Get the correct body name for the response.

    :param request: The PKIMessage with the request.
    :return: The correct body name for the response.
    :raises ValueError: If the body name is invalid (allowed are `ir`, `cr`, `kur`, `ccr`).
    """
    body_name = request["body"].getName()
    if body_name == "ir":
        return "ip"

    if body_name in ["cr", "p10cr"]:
        return "cp"

    if body_name == "kur":
        return "kup"

    if body_name == "ccr":
        return "ccp"

    raise ValueError(f"Invalid body name: {body_name}")


@not_keyword
def build_ca_message(
    responses: Union[CertResponseTMP, Sequence[CertResponseTMP]],
    request: Optional[PKIMessageTMP] = None,
    set_header_fields: bool = True,
    body_name: Optional[str] = None,
    **pki_header_fields,
) -> PKIMessageTMP:
    """Build a PKIMessage for a CA response.

    :param responses: The responses to include in the message.
    :param request: The PKIMessage containing the certificate request. Defaults to `None`.
    :param set_header_fields: Whether to set patch the header fields, for the exchange. Defaults to `True`.
    :param pki_header_fields: Additional key-value pairs to set in the header.
    :param body_name: The name of the body to use for the response. Defaults to `None`.
    :return: The PKIMessage for the CA response.
    """
    if body_name is None and request is None:
        raise ValueError("Either `body_name` or `request` must be provided to build a CA message.")

    body_type = body_name or get_correct_ca_body_name(request)  # type: ignore

    if request and set_header_fields:
        pki_header_fields = set_ca_header_fields(request, pki_header_fields)

    pki_message = cmputils.prepare_pki_message(**pki_header_fields)
    pki_message["body"] = prepare_ca_body(body_type, responses=responses)
    return pki_message


def _contains_cert_template(cert_template, certs: Sequence[rfc9480.CMPCertificate]) -> Optional[rfc9480.CMPCertificate]:
    """Check if the certificate template is in the list of certificates.

    :param cert_template: The certificate template to check.
    :param certs: The list of certificates to check.
    :return: The certificate if it is in the list, `None` otherwise.
    :raises BadCertId: If the certificate template does not match the certificate or
    If the certificate template does not match any known certificates
    """
    found = False
    for cert in certs:
        found = compareutils.compare_cert_template_and_cert(cert_template, cert, include_fields="serialNumber, issuer")

        if compareutils.compare_cert_template_and_cert(cert_template, cert, strict_subject_validation=True):
            return cert

    if found:
        raise BadCertId("The certificate template did not match the certificate.")

    raise BadCertId("The certificate template did not match any known certificates.")


@keyword(name="Validate RR crlEntryDetails Reason")
def validate_rr_crl_entry_details_reason(  # noqa: D417 Missing argument descriptions in the docstring
    crl_entry_details: rfc9480.Extensions, must_be: Optional[str] = None
) -> str:
    """Validate the extension containing the CRL entry details.

    Arguments:
    ---------
        - `crl_entry_details`: The `Extensions` object containing the CRL entry details.
        - `must_be`: The revocation reason that the CRL entry details must have. Defaults to `None`.

    Returns:
    -------
        - The revocation reason.

    Raises:
    ------
        - `BadRequest`: If the CRL entry details are missing or invalid.
        - `ValueError`: If the revocation reason does not match the expected value.
        - `BadAsn1Data`: If the CRL entry details extension cannot be decoded.

    Examples:
    --------
    | ${reason} | Validate RR crlEntryDetails Reason | ${crl_entry_details} |

    """
    if crl_entry_details.isValue:
        if len(crl_entry_details) != 1:
            raise BadRequest("Invalid number of entries in CRL entry details.")

        if crl_entry_details[0]["extnID"] != rfc5280.id_ce_cRLReasons:
            raise BadRequest("Invalid extension ID in CRL entry details.")

        crl_reasons = crl_entry_details[0]["extnValue"].asOctets()

        try:
            decoded, rest = decoder.decode(crl_reasons, rfc5280.CRLReason())
        except pyasn1.error.PyAsn1Error:
            raise BadAsn1Data("Failed to decode `CRLReason`", overwrite=True)  # pylint: disable=raise-missing-from

        if rest:
            raise BadAsn1Data("CRLReason")

        if int(decoded) not in rfc5280.CRLReason.namedValues.values():
            raise BadAsn1Data("Invalid CRL reason value.")

        _reason = decoded.prettyPrint()
        if must_be is not None and _reason != must_be:
            raise ValueError(f"Invalid CRL reason. Expected: `{must_be}`. Got: `{_reason}`")
        return _reason

    raise BadRequest("CRL entry details are missing.")


def _prepare_cert_id(cert: rfc9480.CMPCertificate) -> rfc4211.CertId:
    """Prepare a CertId structure from a certificate.

    :param cert: The certificate to prepare the CertId for.
    :return: The CertId structure.
    """
    cert_id = rfc4211.CertId()
    cert_id["issuer"] = cert["tbsCertificate"]["issuer"]
    cert_id["serialNumber"] = int(cert["tbsCertificate"]["serialNumber"])
    return cert_id


def _verify_pkimessage_protection_rp(
    request: PKIMessageTMP,
    shared_secret: Optional[bytes],
) -> Tuple[Optional[str], Optional[str]]:
    """Verify the protection of the PKIMessage for the response.

    :param request: The PKIMessage to verify the protection for.
    :param shared_secret: The shared secret to use for the response. Defaults to `None`.
    :return: The failure information and text if the protection is invalid, `None`, `None` otherwise.
    """
    try:
        pq_verify_logic.verify_hybrid_pkimessage_protection(
            request,
        )
    except (InvalidSignature, InvalidAltSignature):
        try:
            protectionutils.verify_pkimessage_protection(request, shared_secret=shared_secret)
        except (ValueError, InvalidSignature):
            logging.debug("Failed to verify the PKIMessage protection.")
            return "badMessageCheck", "Failed to verify the PKIMessage protection."

    return None, None


def _check_rev_details_mandatory_fields(cert_details: rfc9480.CertTemplate) -> None:
    """Check the mandatory fields for a Revocation Request.

    :param cert_details: The certificate details to check.
    :raises AddInfoNotAvailable: If the mandatory fields are missing.
    """
    if not cert_details["issuer"].isValue:
        raise AddInfoNotAvailable("Issuer field is missing in the certificate details.")

    if not cert_details["serialNumber"].isValue:
        raise AddInfoNotAvailable("Serial number field is missing in the certificate details.")

    if cert_details["version"].isValue:
        if int(cert_details["version"]) != int(rfc5280.Version("v2")):
            raise BadRequest("Invalid version inside the `RevDetails` `CertTemplate`.")


def _check_cert_for_revoked(
    cert: rfc9480.CMPCertificate, revoked_certs: Optional[List[rfc9480.CMPCertificate]] = None
) -> None:
    """Check if a certificate is revoked.

    :param cert: The certificate to check.
    :param revoked_certs: The list of revoked certificates. Defaults to `None`.
    :raises BadRequest: If the certificate is not revoked.
    """
    if revoked_certs is not None:
        if certutils.cert_in_list(cert, revoked_certs):
            raise CertRevoked("Certificate is already revoked.")


def _check_cert_for_revive(
    cert: rfc9480.CMPCertificate, revoked_certs: Optional[List[rfc9480.CMPCertificate]] = None
) -> None:
    """Check if a certificate can be revived. Only check if the revoked certificate is not `None`.

    :param cert: The certificate to check.
    :param revoked_certs: The list of revoked certificates. Defaults to `None`.
    :raises BadCertId: If the certificate cannot be revived, because it was not revoked.
    """
    if revoked_certs is not None:
        if certutils.cert_in_list(cert, revoked_certs):
            return
    else:
        return

    raise BadCertId("Certificate can not be revived it was not revoked.")


@keyword(name="Validate Revocation Details")
def validate_rev_details(  # noqa D417 undocumented-param
    rev_details: rfc9480.RevDetails,
    issued_certs: Sequence[rfc9480.CMPCertificate],
    revoked_certs: Optional[List[rfc9480.CMPCertificate]] = None,
) -> Tuple[rfc9480.PKIStatusInfo, Dict]:
    """Process a single Revocation Request entry.

    Arguments:
    ---------
       - `entry`: The RevDetails entry to process.
       - `issued_certs`: The list of certificates to check.
       - `revoked_certs`: The list of revoked certificates. Defaults to `None`.

    Returns:
    -------
        - The PKIStatusInfo for the response.
        - A dictionary containing the reason and the certificate if it was found.
        ({"reason": "removeFromCRL", "cert": `CMPCertificate`})

    Raises:
    ------
        - `AddInfoNotAvailable`: If the mandatory fields are missing (issuer, serial number).
        - `BadRequest`: If the version is set and not 2.
        - `BadCertId`: If the RevDetails entry does not match any of the known certificates.
        - `BadCertID`: If the certificate details are invalid.
        - `BadAsn1Data`: If the CRL entry details extension cannot be decoded or the reason contains
        trailing data or is invalid.
        - `CertRevoked`: If the certificate is already revoked.
        - `BadCertId`: If the certificate cannot be revived, because it was not revoked.

    Examples:
    --------
    | ${response} | Validate Revocation Details | ${entry} | ${issued_certs} |
    | ${response} | Validate Revocation Details | ${entry} | ${issued_certs} | ${revoked_certs} |

    """
    _check_rev_details_mandatory_fields(rev_details["certDetails"])

    cert = _contains_cert_template(
        cert_template=rev_details["certDetails"],
        certs=issued_certs,
    )
    reason = validate_rr_crl_entry_details_reason(rev_details["crlEntryDetails"])
    if cert is not None:
        if reason == "removeFromCRL":
            msg = f"Revive certificate with serial number: {int(cert['tbsCertificate']['serialNumber'])}"
            _check_cert_for_revive(cert, revoked_certs)
        else:
            _check_cert_for_revoked(cert, revoked_certs)
            msg = f"Revoked certificate with reason: {reason}"
        return cmputils.prepare_pkistatusinfo(status="accepted", texts=msg), {"reason": reason, "cert": cert}

    raise BadCertId("The RevDetails entry does not match any of the known certificates.")


# TODO fix for bad order or CertID


def build_rp_from_rr(  # noqa: D417 missing argument descriptions in the docstring
    request: PKIMessageTMP,
    certs: Sequence[rfc9480.CMPCertificate],
    shared_secret: Optional[bytes] = None,
    set_header_fields: bool = True,
    add_another_details: bool = False,
    crls: Optional[Union[rfc5280.CertificateList, Sequence[rfc5280.CertificateList]]] = None,
    verify: bool = True,
    **kwargs,
) -> Tuple[PKIMessageTMP, List[Dict[str, Union[str, rfc9480.CMPCertificate]]]]:
    """Build a PKIMessage for a revocation request.

    Arguments:
    ---------
        - `request`: The Revocation Request message.
        - `shared_secret`: The shared secret to use for the response. Defaults to `None`.
        (experimental used for KEM keys and EC keys)
        - `set_header_fields`: Whether to set the header fields. Defaults to `True`.
        - `certs`: The certificates to use for the response. Defaults to `None`.
        - `add_another_details`: Whether to add another status details. Defaults to `False`.
        - `crls`: The CRLs to include in the response. Defaults to `None`.
        - `verify`: Whether to verify the PKIMessage protection. Defaults to `True`.

    **kwargs:
    --------
        - `enforce_lwcmp` (bool): Whether to enforce LwCMP rules. Defaults to `True`.
        - `cert_id` (CertId): The certificate ID to use for the response. Defaults to `None`.
        - `revoked_certs` (List[rfc9480.CMPCertificate]): The list of revoked certificates. Defaults to `None`.

    Returns:
    -------
        - The built PKIMessage for the revocation response.
        - The data for the revocation response. (reason and certificate) as dict.

    Raises:
    ------
        - `ValueError`: If the request is not a `rr` message.
        - `BadRequest`: If `enforce_lwcmp` is set to `True` and the request size is not 1.
        - `BadRequest`: If the `extraCerts` field is empty in the revocation request message.
        - `BadMessageCheck`: If the PKIMessage protection is invalid.
        - `BadCertTemplate`: If the certificate details are invalid.

    Examples:
    --------
    | ${response} | Build RP from RR | ${request} | ${shared_secret} | ${set_header_fields} | ${certs} |
    | ${response} | Build RP from RR | ${request} | ${certs} | add_another_details=True |

    """
    if kwargs.get("enforce_lwcmp", True):
        enforce_lwcmp_for_ca(request)

    body = rfc9480.PKIBody()
    if set_header_fields:
        kwargs = set_ca_header_fields(request, kwargs)

    fail_info = None
    text = None

    if verify:
        if not request["extraCerts"].isValue:
            fail_info = "addInfoNotAvailable"
            text = "The `extraCerts` field was empty in the revocation request message."
        else:
            fail_info, text = _verify_pkimessage_protection_rp(
                request=request,
                shared_secret=shared_secret,
            )

    if fail_info is not None:
        status_info = cmputils.prepare_pkistatusinfo(
            status="rejection",
            failinfo=fail_info,
            texts=text,
        )
        body["rp"]["status"].append(status_info)
        pki_message = cmputils.prepare_pki_message(**kwargs)
        pki_message["body"] = body
        return pki_message, []

    data = []

    for entry in request["body"]["rr"]:
        try:
            status_info, entry = validate_rev_details(
                rev_details=entry,
                issued_certs=certs,
                revoked_certs=kwargs.get("revoked_certs"),
            )
        except CMPTestSuiteError as e:
            status_info = cmputils.prepare_pkistatusinfo(
                status="rejection",
                failinfo=e.failinfo,
                texts=e.message,
            )
            entry = {}

        if entry:
            data.append(entry)

        body["rp"]["status"].append(status_info)

        if not kwargs.get("enforce_lwcmp", True):
            cert = _contains_cert_template(
                cert_template=entry["certDetails"],
                certs=certs,
            )

            if cert is None:
                raise BadCertId("The certificate template did not match any known certificates.")

            body["rp"]["revCerts"].append(kwargs.get("cert_id") or _prepare_cert_id(cert))

        if add_another_details:
            body["rp"]["status"].append(status_info)

        if crls:
            if isinstance(crls, rfc5280.CertificateList):
                crls = [crls]
            body["rp"]["crls"].extend(crls)

    pki_message = cmputils.prepare_pki_message(**kwargs)
    pki_message["body"] = body

    return pki_message, data


@keyword(name="Build POPDecryptionChallenge From Request")
def build_popdecc_from_request(  # noqa D417 undocumented-param
    request: PKIMessageTMP,
    ca_key: Optional[ECDHPrivateKey] = None,
    rand_int: Optional[int] = None,
    cert_req_id: Optional[int] = None,
    request_index: Union[int, str] = 0,
    expected_size: Union[str, int] = 1,
    set_header_fields: bool = True,
    rand_sender: Optional[str] = "CN=CMP-Test-Suite",
    bad_witness: bool = False,
    for_pvno: Optional[Union[str, int]] = None,
    **kwargs,
) -> Tuple[PKIMessageTMP, int]:
    """Build a PKIMessage for a POPDecryptionChallenge message.

    Arguments:
    ---------
        - `request`: The PKIMessage as raw bytes.
        - `ca_key`: The CA key to use for the challenge. Defaults to `None`.
        - `rand_int`: The random integer to use for the challenge. Defaults to `None`.
        - `cert_req_id`: The certificate request ID. Defaults to `None`.
        - `request_index`: The index of the request. Defaults to `0`.
        - `set_header_fields`: Whether to set the header fields. Defaults to `True`.
        - `rand_sender`: The random sender to use for the challenge. Defaults to `CN=CMP-Test-Suite`.
        - `bad_witness`: Whether manipulate the witness value. Defaults to `False`.
        - `for_pvno`: The protocol version number.
        (decides the challenge type)
        (hash of the random number)
        - `kwargs`: Additional values to set for the header.

    Kwargs:
    -------
        - `hash_alg`: The hash algorithm to use for the random integer. Defaults to `sha256`.
        - `hybrid_kem_key`: The hybrid KEM key to use for the challenge. Defaults to `None`.
        - `iv`: The initialization vector to use for the challenge. Defaults to `A` * 16.
        - `challenge`: The challenge to use for the POPDecryptionChallenge. Defaults to `b""`.
        (only used for negative testing, with version 3)
        - `cmp_protection_cert`: for KARI to populate the RID. Defaults to `None`.

    Returns:
    -------
        - The built PKIMessage for the POPDecryptionChallenge.

    Raises:
    ------
        - ValueError: If the request index is invalid.

    Examples:
    --------
    | ${response} = | Build POPDecryptionChallenge From Request | ${request} | ${ca_key} |
    | ${response} = | Build POPDecryptionChallenge From Request | ${request} | ${ca_key} | rand_int=2 |

    """
    request_index = int(request_index)
    body_name = request["body"].getName()
    if int(expected_size) != len(request["body"][body_name]):
        raise BadRequest(
            f"Invalid number of entries in {body_name} message. "
            f"Expected: {expected_size}. Got: {len(request['body'][body_name])}"
        )

    public_key = get_public_key_from_cert_req_msg(cert_req_msg=request["body"][body_name][request_index])

    cert_req_id = cert_req_id or int(request["body"][body_name][request_index]["certReq"]["certReqId"])

    rand_int = rand_int or random.randint(1, 1000)

    for_pvno = for_pvno or request["header"]["pvno"]
    for_pvno = int(for_pvno)

    if set_header_fields:
        kwargs = set_ca_header_fields(request, kwargs)

    kwargs["pvno"] = kwargs.get("pvno") or for_pvno
    pki_message = cmputils.prepare_pki_message(**kwargs)
    tmp = PKIMessageTMP()
    tmp["header"] = pki_message["header"]

    if for_pvno == 3:
        challenge = prepare_challenge_enc_rand(
            public_key=public_key,
            rand_int=rand_int,
            private_key=ca_key,
            rand_sender=rand_sender,
            bad_witness=bad_witness,
            cert_req_id=cert_req_id,
            challenge=kwargs.get("challenge", b""),
            hash_alg=kwargs.get("hash_alg", None),
            hybrid_kem_key=kwargs.get("hybrid_kem_key"),
            ca_cert=kwargs.get("cmp_protection_cert"),
        )

    else:
        challenge, _, kem_ct_info = prepare_challenge(
            public_key=public_key,
            ca_key=ca_key,
            rand_int=rand_int,
            bad_witness=bad_witness,
            iv=kwargs.get("iv", "A" * 16),
            rand_sender=rand_sender,
            hash_alg=kwargs.get("hash_alg"),
        )
        if kem_ct_info is not None:
            tmp["header"]["generalInfo"].append(kem_ct_info)

    tmp["body"]["popdecc"].append(challenge)

    return tmp, rand_int  # type: ignore


def _validate_old_cert_id(
    control: rfc4211.AttributeTypeAndValue, cert: rfc9480.CMPCertificate, ca_cert: rfc9480.CMPCertificate
) -> None:
    """Validate the old certificate ID inside the KUR message.

    :param control: The control to validate.
    :param cert: The certificate to use for validation.
    :param ca_cert: The CA certificate to use for validation.
    :raises BadRequest: If the old certificate ID is missing.
    :raises BadAsn1Data: If the old certificate ID cannot be decoded or has a remaining part.
    :raises BadCertId: If the old certificate ID does not match the CA certificate.
    """
    if not control["value"].isValue:
        raise BadRequest("Old certificate ID is missing in the KUR message.")

    old_cert_id, rest = try_decode_pyasn1(  # type: ignore
        control["value"].asOctets(),
        rfc4211.OldCertId(),
    )
    old_cert_id: rfc4211.OldCertId

    if rest:
        raise BadAsn1Data("OldCertId")

    if not old_cert_id["serialNumber"].isValue:
        raise BadRequest("Serial number is missing in the old certificate ID.")

    if not old_cert_id["issuer"].isValue:
        raise BadRequest("Issuer is missing in the old certificate ID.")

    if not compareutils.compare_general_name_and_name(
        old_cert_id["issuer"],
        ca_cert["tbsCertificate"]["subject"],
    ):
        name_issuer = utils.get_openssl_name_notation(
            old_cert_id["issuer"]["directoryName"],
        )
        cert_name = utils.get_openssl_name_notation(
            ca_cert["tbsCertificate"]["subject"],
        )

        if name_issuer is None:
            name_issuer = "NULL-DN"

        if cert_name is None:
            cert_name = "NULL-DN"

        msg = "Expected: " + cert_name + " Got: " + name_issuer
        raise BadCertId(f"Issuer in the old certificate ID does not match the CA certificate.{msg}")

    if int(old_cert_id["serialNumber"]) != int(cert["tbsCertificate"]["serialNumber"]):
        raise BadCertId("Serial number in the old certificate ID does not match the CA certificate.")


def validate_kur_controls(  # noqa D417 undocumented-param
    request: PKIMessageTMP,
    ca_cert: Optional[rfc9480.CMPCertificate] = None,  # type: ignore
    request_index: int = 0,
    must_be_present: bool = False,
) -> None:
    """Validate the KUR controls.

    Arguments:
    ---------
        - `request`: The KUR message to validate.
        - `ca_cert`: The CA certificate to use for validation (will be extracted from the \
        `extraCerts` field at position 1) Defaults to `None`.
        - `request_index`: The index of the request. Defaults to `0`.
        - `must_be_present`: Whether the controls must be present. Defaults to `False`.

    Raises:
    ------
        - `BadRequest`: If the controls are missing in the KUR message.
        - `BadMessageCheck`: If the extraCerts are missing in the KUR message.
        - `BadCertId`: If the old certificate ID is invalid.

    Examples:
    --------
    | Validate KUR Controls | ${request} | ${ca_cert} |
    | Validate KUR Controls | ${request} | ${ca_cert} | must_be_present=True |
    | Validate KUR Controls | ${request} | ${ca_cert} | request_index=1 |

    """
    cert_req_msg = get_cert_req_msg_from_pkimessage(pki_message=request, index=request_index)

    controls: rfc4211.Controls = cert_req_msg["certReq"]["controls"]
    if not controls.isValue and must_be_present:
        raise BadRequest("Controls are missing in the KUR message.")
    if not controls.isValue:
        return

    if not request["extraCerts"].isValue:
        raise BadMessageCheck("ExtraCerts are missing in the KUR message.")

    if ca_cert is None:
        try:
            if not request["extraCerts"][1].isValue:
                raise IndexError
            ca_cert = request["extraCerts"][1]
        except IndexError as e:
            raise BadMessageCheck(
                "CA certificate is missing in the KUR message and was not provided as argument."
            ) from e

    cert = request["extraCerts"][0]
    cert: rfc9480.CMPCertificate
    if not cert.isValue:
        raise BadMessageCheck("Certificate to be updated, is missing in the KUR message.")

    control: rfc4211.AttributeTypeAndValue

    for control in controls:
        if control["type"] == rfc4211.id_regCtrl_oldCertID:
            _validate_old_cert_id(control, cert=cert, ca_cert=ca_cert)  # type: ignore
        else:
            logging.debug("Unknown control type: %s", str(control["type"]))


def _validate_popo_kur(request: PKIMessageTMP, index: int = 0) -> None:
    """Validate the Proof-of-Possession structure for the KUR message.

    :param request: The request message.
    :param index: The index of the request.
    """
    popo = get_popo_from_pkimessage(request=request, index=index)
    if not popo.isValue:
        if not check_if_request_is_for_kga(request, index=index):
            raise BadRequest("POP structure is missing in the KUR message.")
        return

    if popo["signature"].isValue:
        _verify_pop_signature(pki_message=request, request_index=index)
        return

    if popo["keyAgreement"].isValue:
        raise NotImplementedError("`keyAgreement` is not supported for KUR messages.")

    if popo["keyEncipherment"].isValue:
        raise NotImplementedError("`keyEncipherment` is not supported for KUR messages.")

    if popo.getName() == "raVerified":
        raise BadPOP("`raVerified` is not supported for KUR messages.")

    raise BadPOP(f"Did got a unknown POP: {popo.getName()}")


# TODO update to check if the certificate is known.


def build_kup_from_kur(  # noqa: D417 undocumented-param
    request: PKIMessageTMP,
    ca_key: SignKey,
    ca_cert: rfc9480.CMPCertificate,
    must_have_controls: bool = False,
    allow_same_key: bool = True,
    **kwargs,
) -> CAResponse:
    """Build a KUP message from a KUR message.

    Arguments:
    ---------
        - `request`: The KUR message to build the KUP message from.
        - `ca_key`: The CA key to use for signing the new certificate.
        - `ca_cert`: The CA certificate to use for signing the new certificate.
        - `must_have_controls`: Whether the KUR message must have control for the old certificate ID.
         Defaults to `False`.
        - `allow_same_key`: Whether to allow the same key for the new certificate. Defaults to `True`.
        - `kwargs`: Additional values to set for the header or issuing process.

    Returns:
    -------
        - The KUP message and the new certificate.
        - The new certificate.

    Raises:
    ------
        - `ValueError`: If the request is not a KUR message.
        - `BadRequest`: If the KUR message does not contain exactly one request.
        - `BadCertTemplate`: If the new certificate has the same key as the old certificate.
        - `BadCertTemplate`: If the certificate template is invalid.
        - `BadCertID`: If the old certificate ID is invalid.
        - `BadAsn1Data`: If decoded data contains trailing data or is invalid.

    Examples:
    --------
    | ${response} | Build Kup From Kur | ${request} | ${ca_key} | ${ca_cert} |

    """
    if request["body"].getName() != "kur":
        raise ValueError("Request must be a `kur` message.")

    enforce_lwcmp_for_ca(request)

    _validate_popo_kur(
        request=request,
        index=0,
    )

    cert_req_msg = get_cert_req_msg_from_pkimessage(pki_message=request)
    if not allow_same_key:
        cert = request["extraCerts"][0]
        # This is a lazy solution, but it works for now.
        pub_key = get_public_key_from_cert_req_msg(cert_req_msg, must_be_present=False)
        if pub_key is not None:
            pub_key_cert = keyutils.load_public_key_from_spki(cert["tbsCertificate"]["subjectPublicKeyInfo"])
            if pub_key == pub_key_cert:
                raise BadCertTemplate("The new certificate must not have the same key as the old certificate.")

    validate_kur_controls(request, must_be_present=must_have_controls)

    if cert_req_msg:
        _num = int(cert_req_msg["certReq"]["certReqId"])
        if _num != 0:
            raise BadRequest(f"Invalid CertReqId in KUR message. Expected 0. Got: {_num}")

    if check_if_request_is_for_kga(pki_message=request):
        return build_kga_cmp_response(
            ca_key=ca_key,
            ca_cert=ca_cert,
            request=request,
            **kwargs,
        )

    cert = certbuildutils.build_cert_from_cert_template(
        cert_template=cert_req_msg["certReq"]["certTemplate"],
        ca_key=ca_key,
        ca_cert=ca_cert,
    )

    if request is not None and set_ca_header_fields:
        kwargs = set_ca_header_fields(request, kwargs)

    responses = prepare_cert_response(cert=cert, cert_req_id=kwargs.get("cert_req_id", 0))
    body = prepare_ca_body(body_name="kup", responses=responses, ca_pubs=kwargs.get("ca_pubs"))

    kwargs["recip_nonce"] = kwargs.get("recip_nonce") or os.urandom(16)
    pki_message = cmputils.prepare_pki_message(**kwargs)
    pki_message["body"] = body
    return pki_message, [cert]


@not_keyword
def get_popo_from_pkimessage(request: PKIMessageTMP, index: int = 0) -> rfc4211.ProofOfPossession:
    """Extract the POPO from a PKIMessage.

    :param request: The PKIMessage to extract the Proof-of-Possession from.
    :param index: The `CertMsgReq` index to extract the Proof-of-Possession from.
    """
    body_name = request["body"].getName()
    if body_name not in ["ir", "cr", "kur", "ccr"]:
        raise ValueError(f"The PKIMessage was not a certification request. Got body name: {body_name}")

    return request["body"][body_name][index]["popo"]


@keyword(name="Prepare New CA Certificate")
def prepare_new_ca_certificate(  # noqa D417 undocumented-param
    old_cert: rfc9480.CMPCertificate,
    new_priv_key: SignKey,
    hash_alg: Optional[str] = "sha256",
    use_rsa_pss: bool = True,
    use_pre_hash: bool = False,
    bad_sig: bool = False,
) -> rfc9480.CMPCertificate:
    """Prepare a new CA certificate.

    Arguments:
    ---------
        - `old_cert`: The old CA certificate.
        - `new_priv_key`: The private key of the new CA certificate.
        - `hash_alg`: The hash algorithm to use for the signature. Defaults to "sha256".
        - `use_rsa_pss`: Whether to use RSA-PSS for the signature. Defaults to `True`.
        - `use_pre_hash`: Whether to use the pre-hash version for a composite signature key. \
        Defaults to `False`.
        - `bad_sig`: Whether to generate a bad signature. Defaults to `False`.

    Returns:
    -------
        - The new CA certificate.

    Raises:
    ------
        - ValueError: If the private key cannot be used for signing.

    Examples:
    --------
    | ${new_ca_cert} | Prepare New CA Certificate | ${old_ca_cert} | ${new_priv_key} |
    | ${new_ca_cert} | Prepare New CA Certificate | ${old_ca_cert} | ${new_priv_key} | sha256 |

    """
    new_cert = rfc9480.CMPCertificate()

    new_cert = copy_asn1_certificate(old_cert, new_cert)

    # Prepare the new certificate
    new_cert["tbsCertificate"]["validity"] = certbuildutils.default_validity()
    new_cert["tbsCertificate"]["serialNumber"] = x509.random_serial_number()
    new_cert["tbsCertificate"]["extensions"] = rfc9480.Extensions().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
    )

    ca_pub_key = convertutils.ensure_is_verify_key(new_priv_key.public_key())
    extn = certbuildutils.prepare_extensions(
        key=ca_pub_key,
        ca_key=ca_pub_key,
        critical=False,
    )
    new_cert["tbsCertificate"]["extensions"].extend(extn)

    new_cert["tbsCertificate"]["subjectPublicKeyInfo"] = subject_public_key_info_from_pubkey(new_priv_key.public_key())

    sig_alg = prepare_alg_ids.prepare_sig_alg_id(
        new_priv_key, hash_alg=hash_alg, use_rsa_pss=use_rsa_pss, use_pre_hash=use_pre_hash
    )

    new_cert["tbsCertificate"]["signature"] = sig_alg
    new_cert["signatureAlgorithm"] = sig_alg
    der_data = encoder.encode(new_cert["tbsCertificate"])

    sig = protectionutils.sign_data_with_alg_id(
        data=der_data,
        key=new_priv_key,
        alg_id=sig_alg,
    )
    if bad_sig:
        sig = utils.manipulate_bytes_based_on_key(sig, key=new_priv_key)

    new_cert["signature"] = univ.BitString.fromOctetString(sig)

    return new_cert


def prepare_old_with_new_cert(  # noqa D417 undocumented-param
    old_cert: rfc9480.CMPCertificate,
    new_cert: rfc9480.CMPCertificate,
    new_priv_key: SignKey,
    hash_alg: str = "sha256",
    use_rsa_pss: bool = True,
    use_pre_hash: bool = True,
    bad_sig: bool = False,
) -> rfc9480.CMPCertificate:
    """Prepare the old certificate signed by the new one.

    Sign the old certificate with the new private key.

    Arguments:
    ---------
        - `old_cert`: The old certificate.
        - `new_cert`: The new certificate.
        - `new_priv_key`: The private key of the new certificate.
        - `hash_alg`: The hash algorithm to use for the signature. Defaults to "sha256".
        - `use_rsa_pss`: Whether to use RSA-PSS for the signature. Defaults to `True`.
        - `use_pre_hash`: Whether to use the pre-hash version for a composite signature key. \
        Defaults to `False`.
        - `bad_sig`: Whether to generate a bad signature. Defaults to `False`.

    Returns:
    -------
        - The old certificate signed by the new one.

    Examples:
    --------
    | ${old_with_new_cert} | Prepare Old With New Cert | ${old_cert} | ${new_cert} | ${new_priv_key} |
    | ${old_with_new_cert} | Prepare Old With New Cert | ${old_cert} | ${new_cert} | ${new_priv_key} | sha256 |

    """
    old_with_new_cert = copy_asn1_certificate(old_cert, rfc9480.CMPCertificate())
    old_with_new_cert["tbsCertificate"]["issuer"] = new_cert["tbsCertificate"]["subject"]
    return certbuildutils.sign_cert(
        cert=old_with_new_cert,
        signing_key=new_priv_key,
        hash_alg=hash_alg,
        use_rsa_pss=use_rsa_pss,
        use_pre_hash=use_pre_hash,
        bad_sig=bad_sig,
    )


def prepare_new_root_ca_certificate(  # noqa D417 undocumented-param
    old_cert: rfc9480.CMPCertificate,
    old_priv_key: SignKey,
    new_priv_key: SignKey,
    hash_alg: str = "sha256",
    use_rsa_pss: bool = True,
    use_pre_hash: bool = True,
    bad_sig: bool = False,
    bad_sig_old: bool = False,
    bad_sig_new: bool = False,
    new_cert: Optional[rfc9480.CMPCertificate] = None,
    include_old_with_new: bool = True,
) -> rfc9480.RootCaKeyUpdateValue:
    """Prepare a new `RootCaKeyUpdateValue` structure containing the new root CA certificate.

    Used to simulate a root CA key update message.

    Arguments:
    ---------
        - `old_cert`: The old root CA certificate.
        - `old_priv_key`: The private key of the old root CA certificate.
        - `new_priv_key`: The private key of the new root CA certificate.
        - `hash_alg`: The hash algorithm to use for the signature. Defaults to "sha256".
        - `use_rsa_pss`: Whether to use RSA-PSS for the signature. Defaults to `True`.
        - `use_pre_hash`: Whether to use the pre-hash version for a composite signature key. \
        Defaults to `False`.
        - `bad_sig`: Whether to generate a bad signature for the new CA certificate. Defaults to `False`.
        - `bad_sig_old`: Whether to generate a bad signature for the old certificate signed by the new one. \
        Defaults to `False`.
        - `bad_sig_new`: Whether to generate a bad signature for the new certificate signed by the old one. \
        Defaults to `False`.
        - `new_cert`: The new root CA certificate. Defaults to `None`.
        - `include_old_with_new`: Whether to include the old certificate signed by the new one. Defaults to `True`.

    Returns:
    -------
        - The populated `RootCaKeyUpdateValue` structure.

    Raises:
    ------
        - ValueError: If the signature algorithm is not supported or the private key is not supported.

    Examples:
    --------
    | ${root_ca}= | Prepare New Root CA Certificate | ${old_cert} | ${old_priv_key} | ${new_priv_key} |
    | ${root_ca}= | Prepare New Root CA Certificate | ${old_cert} | ${old_priv_key} | ${new_priv_key} | sha256 | \
    use_rsa_pss=True |
    | ${root_ca}= | Prepare New Root CA Certificate | ${old_cert} | ${old_priv_key} | ${new_priv_key} | \
    new_cert=${new_cert} |

    """
    new_cert = new_cert or prepare_new_ca_certificate(
        old_cert=old_cert,
        new_priv_key=new_priv_key,
        hash_alg=hash_alg,
        use_rsa_pss=use_rsa_pss,
        use_pre_hash=use_pre_hash,
        bad_sig=bad_sig,
    )

    new_with_old_cert = prepare_old_with_new_cert(
        old_cert=new_cert,
        new_cert=old_cert,
        new_priv_key=old_priv_key,
        hash_alg=hash_alg,
        use_rsa_pss=use_rsa_pss,
        use_pre_hash=use_pre_hash,
        bad_sig=bad_sig_new,
    )
    old_with_new_cert = None
    if include_old_with_new:
        old_with_new_cert = prepare_old_with_new_cert(
            old_cert=old_cert,
            new_cert=new_cert,
            new_priv_key=new_priv_key,
            hash_alg=hash_alg,
            use_rsa_pss=use_rsa_pss,
            use_pre_hash=use_pre_hash,
            bad_sig=bad_sig_old,
        )

    return prepare_root_ca_key_update(
        new_with_new_cert=new_cert,
        new_with_old_cert=new_with_old_cert,
        old_with_new_cert=old_with_new_cert,
    )


@keyword(name="Prepare RootCAKeyUpdateValue")
def prepare_root_ca_key_update(  # noqa D417 undocumented-param
    new_with_new_cert: Optional[rfc9480.CMPCertificate] = None,
    new_with_old_cert: Optional[rfc9480.CMPCertificate] = None,
    old_with_new_cert: Optional[rfc9480.CMPCertificate] = None,
) -> rfc9480.RootCaKeyUpdateValue:
    """Build and return a `RootCaKeyUpdateContent` structure containing the provided certificates.

    Arguments:
    ---------
       - `new_with_new_cert`: The new Root certificate.
       - `new_with_old_cert`: The new CA certificate signed by the old one.
       - `old_with_new_cert`: The old CA certificate signed by the new one.

    Returns:
    -------
        - The populated `RootCaKeyUpdateContent` structure.

    Raises:
    ------
        - `ValueError`: If the provided certificates are not valid.

    Examples:
    --------
    | ${root_ca}= | Build Root CA Key Update Content | ${new_with_new_cert} | ${new_with_old_cert} | \
    ${old_with_new_cert} |

    """
    root_ca_update = rfc9480.RootCaKeyUpdateValue()

    if new_with_new_cert is not None:
        root_ca_update.setComponentByName("newWithNew", new_with_new_cert)

    if new_with_old_cert is not None:
        new_with_old = rfc9480.CMPCertificate().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
        )

        new_with_old_cert = copy_asn1_certificate(new_with_old_cert, new_with_old)
        root_ca_update.setComponentByName("newWithOld", new_with_old_cert)

    if old_with_new_cert is not None:
        old_with_new = rfc9480.CMPCertificate().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
        )

        old_with_new = copy_asn1_certificate(old_with_new_cert, old_with_new)
        root_ca_update.setComponentByName("oldWithNew", old_with_new)

    return root_ca_update


CertsType = Union[rfc9480.CMPCertificate, Sequence[rfc9480.CMPCertificate]]


def _validate_ccr_cert_template(cert_template: rfc9480.CertTemplate) -> rfc9480.CertTemplate:
    """Validate the certificate template for the CCR message.

    :param cert_template: The certificate template to validate.
    :raises BadCertTemplate: If the certificate template is invalid.
    """
    if cert_template["version"].isValue:
        # For now is absent treated as version 3.
        if int(cert_template["version"]) != int(rfc5280.Version("v3")):
            logging.warning("The certificate template version is not v3. But is strongly advised to use v3.")

        if int(cert_template["version"]) == int(rfc5280.Version("v2")):
            raise BadCertTemplate("The certificate template version is allowed to be `v2`.")

    else:
        raise BadCertTemplate("The certificate template must contain a `version`.")

    if not cert_template["validity"]["notBefore"].isValue:
        raise BadCertTemplate("For the CA cross certificate request, the `notBefore` field must be set.")

    if not cert_template["validity"]["notAfter"].isValue:
        raise BadCertTemplate("For the CA cross certificate request, the `notAfter` field must be set.")

    if compareutils.is_null_dn(cert_template["issuer"]):
        if get_extension(cert_template["extensions"], rfc5280.id_ce_issuerAltName) is None:
            raise BadCertTemplate("The certificate template must contain an `issuer` or an `issuerAltName`.")

    if compareutils.is_null_dn(cert_template["subject"]):
        if get_extension(cert_template["extensions"], rfc5280.id_ce_subjectAltName) is None:
            raise BadCertTemplate("The certificate template must contain a `subject` or a `subjectAltName`.")

    if not cert_template["validity"].isValue:
        raise BadCertTemplate("The certificate template must contain a validity period.")

    if cert_template["signingAlg"].isValue:
        logging.debug("The signature algorithm is set in the certificate template.But currently not supported.")

    else:
        raise BadCertTemplate("The signature algorithm is not set in the cross certificate template.")

    return cert_template


def _process_crr_single(
    request: PKIMessageTMP,
    ca_key: SignKey,
    ca_cert: rfc9480.CMPCertificate,
    bad_sig: bool = False,
    extensions: Optional[ExtensionsParseType] = None,
) -> rfc9480.CMPCertificate:
    """Process a single CRR message.

    :param request: The PKIMessage to process.
    :param ca_key: The CA key to use for signing the new certificate.
    :param ca_cert: The CA certificate to use for signing the new certificate.
    :param bad_sig: Whether to generate a bad signature. Defaults to `False`.
    :return: The new issued/signed certificate.
    :raises BadCertTemplate: If the certificate template is invalid.
    """
    popo = get_popo_from_pkimessage(request=request, index=0)

    cert_req_msg = get_cert_req_msg_from_pkimessage(pki_message=request, index=0)

    try:
        public_key = keyutils.load_public_key_from_cert_template(
            cert_req_msg["certReq"]["certTemplate"], must_be_present=True
        )
    except ValueError as e:
        raise BadCertTemplate(
            "The public key in the cross Certificate request could not be loaded.",
            error_details=str(e),
        ) from e

    try:
        _ = ensure_is_verify_key(public_key)
    except ValueError as e:
        raise BadCertTemplate(
            f"The public key in the cross Certificate request is not a signing key.Got: {type(public_key)}",
            error_details=str(e),
        ) from e

    if not popo.isValue:
        raise BadPOP("The CA cross certificate request message must contain a POP structure.")

    if popo.getName() == "raVerified":
        raise BadPOP("The `raVerified` POP structure is not supported for CA cross certification request.")

    if popo["signature"].isValue:
        _verify_pop_signature(pki_message=request, request_index=0)

    else:
        raise BadPOP("The POP structure must contain a signature, for a CA cross certification request.")

    validate_cert_req_id(request, cert_req_id=0)
    cert_request = request["body"]["ccr"][0]["certReq"]

    cert_template = cert_request["certTemplate"]
    result = check_if_request_is_for_kga(pki_message=request, index=0)
    if result:
        raise BadRequest(
            "The `CCR` message can not be for a `KGA` request.The private key must be securely generated by the client."
        )

    _validate_ccr_cert_template(cert_template)

    cert_template = _ensure_key_usage(cert_template)
    cert_template = _ensure_basic_constraints(cert_template)
    cert = certbuildutils.build_cert_from_cert_template(
        cert_template=cert_template, bad_sig=bad_sig, ca_key=ca_key, ca_cert=ca_cert, extensions=extensions
    )
    return cert


@keyword(name="Build CCP From CCR")
def build_ccp_from_ccr(  # noqa D417 undocumented-param
    request: PKIMessageTMP,
    ca_key: Optional[SignKey] = None,
    ca_cert: Optional[rfc9480.CMPCertificate] = None,
    cert: Optional[rfc9480.CMPCertificate] = None,
    **kwargs,
) -> CAResponse:
    """Build a CCP message from a CCR message.

    Build a CA certificate response message from a CA certificate request.
    Validates the `KeyUsage` bits and the `BasicConstraints` extension.

    Arguments:
    ---------
        - `request`: The CCR message.
        - `ca_key`: The CA key used for signing the new certificate.
        - `ca_cert`: The CA certificate matching the CA key.
        - `certs`: The certificates to use for the response. Defaults to `None`.
        - `kwargs`: Additional values to set for the header or issuing process.

    Returns:
    -------
        - The CCP message and the new certificate.
        - The new certificate in a list.

    Raises:
    ------
        - `ValueError`: If the request is not a CCR message.
        - `BadRequest`: If the CCR message does not contain exactly one request.
        - `BadCertTemplate`: If the certificate template is invalid.
        - `BadCertID`: If the certificate ID is invalid.
        - `BadAsn1Data`: If decoded data contains trailing data or is invalid.

    Examples:
    --------
    | ${response} = | Build CCP From CCR | ${request} | ${ca_key} | ${ca_cert} |

    """
    if request["body"].getName() != "ccr":
        raise ValueError("Request must be a `ccr` message.")

    if len(request["body"]["ccr"]) != 1:
        raise BadRequest(f"Invalid number of entries in CCR message. Expected 1. Got: {len(request['body']['ccr'])}")

    if not cert:
        if ca_cert is None or ca_key is None:
            raise ValueError("Either a certificate or the `ca_key` and `ca_cert` must be provided!")
        # ONLY 1 is allowed, please refer to RFC4210bis-18!
        cert = _process_crr_single(
            request, ca_key, ca_cert, extensions=kwargs.get("extensions", None), bad_sig=kwargs.get("bad_sig", False)
        )

    responses = prepare_cert_response(
        cert=cert,
        cert_req_id=kwargs.get("cert_req_id", 0),
        text=kwargs.get("text", "Certificate issued"),
        status=kwargs.get("status", "accepted"),
        rsp_info=kwargs.get("rspInfo", None),
    )

    body = prepare_ca_body(body_name="ccp", responses=responses)

    if kwargs.get("set_header_fields", True):
        kwargs = set_ca_header_fields(request, kwargs)

    pki_message = cmputils.prepare_pki_message(**kwargs)
    pki_message["body"] = body
    return pki_message, [cert]


def _ensure_key_usage(cert_template: rfc9480.CertTemplate) -> rfc9480.CertTemplate:
    """Ensure that the KeyUsage extension is present in the certificate template."""
    extn = get_extension(cert_template["extensions"], rfc5280.id_ce_keyUsage)
    if extn:
        try:
            decoded_extn, _ = decoder.decode(extn["extnValue"], asn1Spec=rfc5280.KeyUsage())
        except pyasn1.error.PyAsn1Error as e:
            raise BadDataFormat("The `KeyUsage` extension could not be decoded.") from e

        required_usages = {"keyCertSign"}
        present_usages = set(get_set_bitstring_names(decoded_extn).split(", "))
        if not required_usages.issubset(present_usages):
            raise BadCertTemplate(
                "KeyUsage extension is present but does not include required key usages."
                f" Got: {present_usages}. Required: {required_usages}."
            )

        if not {"digitalSignature"}.issubset(present_usages):
            logging.warning("Only `keyCertSign` is set not `digitalSignature`")

    else:
        extn = certbuildutils.prepare_key_usage_extension("keyCertSign,digitalSignature", critical=True)
        cert_template["extensions"].append(extn)

    return cert_template


def _ensure_basic_constraints(cert_template: rfc9480.CertTemplate) -> rfc9480.CertTemplate:
    """Ensure that the BasicConstraints extension is present in the certificate template."""
    extn = get_extension(cert_template["extensions"], rfc5280.id_ce_basicConstraints)
    if extn is None:
        extn = certbuildutils.prepare_basic_constraints_extension(ca=True, critical=True)
        cert_template["extensions"].append(extn)
    return cert_template


@keyword(name="Build KGA CMP Response")
def build_kga_cmp_response(  # noqa D417 undocumented-param
    request: PKIMessageTMP,
    ca_cert: rfc9480.CMPCertificate,
    ca_key: SignKey,
    kga_cert_chain: Optional[List[rfc9480.CMPCertificate]],
    kga_key: Optional[SignKey] = None,
    password: Optional[Union[bytes, str]] = None,
    hash_alg: str = "sha256",
    set_header_fields: bool = True,
    **kwargs,
) -> CAResponse:
    """Build a CMP message that responds to a KGA request and returns the newly generated private key to the end entity.

    Arguments:
    ---------
        - `request`: The PKIMessage (e.g., an ir/cr/p10cr) that includes a KGA request (no POP, i.e. no signature).
        - `ca_cert`: The CA certificate used to sign the newly issued certificate.
        - `ca_key`: The CA's private key.
        - `kga_cert_chain`: The full chain for the KGA (including the KGA cert and possibly others).
                          Typically [kga_cert, ca_cert].
        - `kga_key`: The KGA private key if the KGA must sign the "SignedData" that wraps
                     the newly generated private key (optional).
        - `password`: The password used if the KGA uses PWRI instead of KARI/KTRI.
                     (i.e. the client used MAC-based protection on the KGA request.)
        - `hash_alg`: The signature/hash algorithm to use for the newly issued certificate.
        - `set_header_fields`: Whether to set header fields for the response (transactionID, senderNonce, etc.).

    **kwargs:
    ---------
        - `ec_priv_key`: The private key to use for the KGA request. Defaults to `None`.
        - `cmp_protection_cert`: The certificate to use for CMP protection. Defaults to `None`.
        - `extensions`: The extensions to be added to the build certificate. Defaults to `None`.
        - `key_save_type`: Whether to save the PQ-key as `seed`, `raw` or `seed_and_raw`. Defaults to `raw`.
        - `default_key_type`: The default key type to generate for the client request. Defaults to `rsa`.
        - `new_private_key` (List[rfc5958.OneAsymmetricKey], rfc5958.OneAsymmetricKey): The new private key to use \
        for the KGA request. Defaults to `None`.

    Returns:
    -------
        - The PKIMessage that responds to the KGA request and includes the new certificate.
        - The list of newly issued certificates.

    Raises:
    ------
        - `BadRequest`: If the request is not a KGA request or if the body name is invalid.
        - `BadCertTemplate`: If the certificate template is invalid.
        - `BadPOP`: If the Proof-of-Possession structure is invalid.

    Examples:
    --------
    | ${pki_message} ${certs}= | Build KGA CMP Response | ${request} | ${ca_cert} | ${ca_key} | \
    | ${kga_cert_chain} | ${kga_key} |

    """
    body_name = request["body"].getName()

    if int(request["header"]["pvno"]) != 3:
        raise UnsupportedVersion("The KGA request only supports version 3 (EnvelopedData).")

    if len(request["body"][body_name]) != 1:
        raise BadRequest("Invalid number of entries in KGA request. Expected 1.")

    body_name = request["body"].getName()
    if not check_if_request_is_for_kga(request):
        raise BadRequest("This PKIMessage is not a KGA request (the 'popo' is not empty).")

    if body_name not in ("ir", "cr", "p10cr", "kur"):
        raise BadRequest(f"Invalid message body for KGA: {body_name}. Must be one of ir, cr, kur, p10cr, or kur.")

    cert_req_msg = get_cert_req_msg_from_pkimessage(request)

    # Actually generate a new key & build the certificate, plus EnvelopedData for the private key
    # (with PWRI, KARI, or KTRI) using existing KGA logic:

    if "ec_priv_key" in kwargs:
        # For KARI with ephemeral ECDH.
        kwargs["kari_key"] = kwargs["ec_priv_key"]

    cert, enveloped_data = prepare_cert_and_private_key_for_kga(
        cert_template=cert_req_msg["certReq"]["certTemplate"],
        request=request,
        ca_cert=ca_cert,
        ca_key=ca_key,
        kga_cert_chain=kga_cert_chain,
        kga_key=kga_key,
        password=password,
        hash_alg=hash_alg,
        **kwargs,
    )

    cert_req_id = int(cert_req_msg["certReq"]["certReqId"])
    cert_response = prepare_cert_response(
        cert_req_id=cert_req_id,
        cert=cert,
        private_key=enveloped_data,  # Goes in 'CertifiedKeyPair.privateKey'
        status="accepted",
        text="New Key Generation completed.",
    )

    if request is not None and set_ca_header_fields:
        kwargs = set_ca_header_fields(request, kwargs)

    if body_name == "ir":
        pki_message, _ = build_ip_cmp_message(
            request=request, responses=cert_response, set_header_fields=set_header_fields, **kwargs
        )

    elif body_name == "kur":
        pki_message = _build_ca_cert_response_body(
            request=request,
            responses=cert_response,
            set_header_fields=set_header_fields,
            **kwargs,
        )

    else:
        # For CR and P10CR, we need to build a CA response body
        pki_message, _ = build_cp_cmp_message(
            request=request, responses=cert_response, set_header_fields=set_header_fields, **kwargs
        )

    return pki_message, [cert]


def _compare_comp_template(cert_template: rfc9480.CertTemplate, certs: list[rfc9480.CMPCertificate]) -> bool:
    """Check if a `CertTemplate` is already present in a list of certificates.

    :param cert_template: The template to check.
    :param certs: A list of `CMPCertificate` objects to check against.
    """
    for cert in certs:
        if compareutils.compare_cert_template_and_cert(cert_template, cert, strict_subject_validation=True):
            return True
    return False


@not_keyword
def cert_template_exists(
    cert_template: rfc9480.CertTemplate,
    certs: list[rfc9480.CMPCertificate],
    check_only_subject_and_pub_key: bool = True,
) -> bool:
    """Check if a `CertTemplate` is already present in a list of certificates.

    The subject and the public key of the certificate are used for comparison.

    :param cert_template: A CMPCertificate object serving as the reference (template).
    :param certs: A list of CMPCertificate objects to check against.
    :param check_only_subject_and_pub_key: If True, only the subject and public key are compared.
    Defaults to `True`.
    :return: True if a certificate with the same subject and public key
             is found in 'cert_list'. Otherwise, False.
    """
    template_subject = cert_template["subject"]
    pub_key = keyutils.load_public_key_from_cert_template(cert_template, must_be_present=False)
    if not pub_key:
        return False

    if not check_only_subject_and_pub_key:
        return _compare_comp_template(cert_template, certs)

    for cert in certs:
        cert_subject = cert["tbsCertificate"]["subject"]
        cert_spki = cert["tbsCertificate"]["subjectPublicKeyInfo"]
        result = compareutils.compare_pyasn1_names(cert_subject, template_subject, "without_tag")
        result2 = pub_key == keyutils.load_public_key_from_spki(cert_spki)
        if result and result2:
            return True

    return False


def get_cert_template_from_pkimessage(request: PKIMessageTMP, index: Strint = 0) -> rfc4211.CertTemplate:
    """Extract the certificate template from a PKIMessage.

    :param request: The PKIMessage to extract the certificate template from.
    :param index: The `CertMsgReq` index to extract the template from.
    :return: The `CertTemplate` object.
    """
    body_name = request["body"].getName()
    if body_name not in ["ir", "cr", "kur", "crr"]:
        raise ValueError(f"The PKIMessage was not a certification request. Got body name: {body_name}")

    body_name = request["body"].getName()
    return request["body"][body_name][index]["certReq"]["certTemplate"]


@keyword(name="Build CMP Krp Message")
def build_cmp_krp_message(  # noqa D417 undocumented-params
    cert: Optional[rfc9480.CMPCertificate] = None,
    status: str = "accepted",
    ca_certs: Optional[CertOrCerts] = None,
    key_cert_history: Optional[CertOrCerts] = None,
    pki_status_info: Optional[rfc9480.PKIStatusInfo] = None,
    **kwargs,
) -> PKIMessageTMP:
    """Build a CMP Key Recovery Response (KRP) message.

    Arguments:
    ---------
        `cert`: The certificate to be recovered.
        `status`: The status of the certificate. Defaults to `accepted`.
        `ca_certs`: The CA certificates. Defaults to `None`.
        `key_cert_history`: The key certificate history. Defaults to `None`.
        `pki_status_info`: The PKI status information. Defaults to `None`.
        `**kwargs`: Additional keyword arguments for the `PKIHeader`.

    Returns:
    -------
        - The CMP Key Recovery Protocol (KRP) PKIMessage.

    Examples:
    --------
    | krp= | Build CMP KRP Message | ${cert} | status=accepted | ca_certs=${ca_certs} |
    | krp= | Build CMP KRP Message | ${cert} | pki_status_info=${pki_status_info} | \
    key_cert_history=${key_cert_history} |

    """
    krp_con = rfc9480.KeyRecRepContent().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 18))

    if cert is not None:
        new_sig_cert = rfc9480.CMPCertificate().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
        )
        new_sig_cert = copy_asn1_certificate(
            cert=cert,
            target=new_sig_cert,
        )
        krp_con["newSigCert"] = new_sig_cert

    if pki_status_info is None:
        pki_status_info = cmputils.prepare_pkistatusinfo(
            status=status,
            texts="The certificate updated was accepted.",
        )

    krp_con["status"] = pki_status_info

    if ca_certs is not None:
        if isinstance(ca_certs, rfc9480.CMPCertificate):
            ca_certs = [ca_certs]

        krp_con["caCerts"].extend(ca_certs)

    if key_cert_history is not None:
        if isinstance(key_cert_history, rfc9480.CMPCertificate):
            key_cert_history = [key_cert_history]

        krp_con["keyPairHist"].extend(key_cert_history)

    pki_message = cmputils.prepare_pki_message(**kwargs)
    pki_message["body"]["krp"] = krp_con
    return pki_message


@keyword(name="Build Unsuccessful CA Response")
def build_unsuccessful_ca_cert_response(  # noqa D417 undocumented-param
    body_name: Optional[str] = None,
    request: Optional[PKIMessageTMP] = None,
    failinfo: Optional[str] = None,
    text: Optional[Union[str, List[str]]] = None,
    sender: str = "CN=Mock CA",
    **kwargs,
) -> PKIMessageTMP:
    """Build an unsuccessful CA response message.

    Arguments:
    ---------
        - `body_name`: The name of the body to use for the response. Defaults to `None`.
        - `request`: The PKIMessage request to respond to. Defaults to `None`.
        - `failinfo`: The failure information. Defaults to `None`.
        - `text`: The text to include in the `PKIStatusInfo`. Defaults to `None`.
        - `sender`: The sender of the response. Defaults to "CN=Mock CA".

    **kwargs:
    --------
        - `cert_req_id` (str, int): The certificate request ID. Defaults to `None`.
        - `status` (str): The status of the response. Defaults to "rejection".
        - `pki_status_info` (PKISatusInfo): The PKI status information. Defaults to `None`.
        - Additional keyword arguments for the `PKIHeader`.

    Returns:
    -------
        - The PKIMessage that contains the unsuccessful CA response.

    Raises:
    ------
        - `ValueError`: If neither `body_name` nor `request` is provided.
        - `ValueError`: If the body name is invalid or if the request is not a valid PKIMessage.

    Examples:
    --------
    | ${response} = | Build Unsuccessful CA Response | body_name=cr | request=${request} | status=rejection |
    | ${response} = | Build Unsuccessful CA Response | request=${request} | status=accepted | failinfo=badCert |

    """
    if body_name is None and request is None:
        raise ValueError("Either `body_name` or `request` must be provided.")

    if request is not None:
        kwargs = set_ca_header_fields(request, kwargs)

    if body_name is None:
        body_name = request["body"].getName()  # type: ignore

    if kwargs.get("cert_req_id") is None:
        if body_name == "p10cr":
            cert_req_id = -1
        else:
            cert_req_id = 0
    else:
        cert_req_id = int(kwargs["cert_req_id"])

    if kwargs.get("pki_status_info") is None:
        kwargs["pki_status_info"] = cmputils.prepare_pkistatusinfo(
            status=kwargs.get("status", "rejection"),
            failinfo=failinfo,
            texts=text,
        )

    cert_response = prepare_cert_response(cert_req_id=cert_req_id, pki_status_info=kwargs["pki_status_info"])

    body_to_out_name = {"ir": "ip", "cr": "cp", "p10cr": "cp", "kur": "kup", "ccr": "ccp"}

    if body_name not in body_to_out_name:
        raise ValueError(f"Invalid body name: {body_name}. Must be one of {list(body_to_out_name.keys())}.")

    out_name = body_to_out_name[body_name]
    body = prepare_ca_body(out_name, responses=cert_response, ca_pubs=None)
    pki_message = cmputils.prepare_pki_message(sender=sender, **kwargs)
    pki_message["body"] = body
    return pki_message
