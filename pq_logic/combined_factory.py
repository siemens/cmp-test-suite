# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Key factory to create all supported keys."""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x448, x25519
from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc5280, rfc5958
from resources.oid_mapping import get_curve_instance
from resources.oidutils import CMS_COMPOSITE_OID_2_NAME, PQ_OID_2_NAME, XWING_OID_STR

from pq_logic.chempatkem import ChempatPublicKey
from pq_logic.hybrid_key_factory import HybridKeyFactory
from pq_logic.hybrid_structures import (
    CompositeSignaturePublicKeyAsn1,
)
from pq_logic.keys.comp_sig_cms03 import (
    CompositeSigCMSPublicKey,
)
from pq_logic.keys.composite_kem_pki import (
    CompositeDHKEMRFC9180PublicKey,
    parse_public_keys,
)
from pq_logic.keys.kem_keys import FrodoKEMPublicKey, MLKEMPublicKey
from pq_logic.keys.xwing import XWingPublicKey
from pq_logic.pq_key_factory import PQKeyFactory
from pq_logic.tmp_oids import CHEMPAT_OID_2_NAME, COMPOSITE_KEM_OID_2_NAME
from pq_logic.trad_key_factory import generate_trad_key


def _any_string_in_string(string: str, options: list[str]) -> str:
    """Check if any of the options is in the string and return the first match.

    :param string: The string to check.
    :param options: The list of options to check for.
    :return: The first option that is in the string.
    :raises ValueError: If none of the options is in the string.
    """
    for option in options:
        if option in string:
            return option

    raise ValueError(f"Invalid key type: {string}")


# TODO update for Chempat and other Hybrid-KEM keys.
class CombinedKeyFactory:
    """Factory for creating all known key types."""

    @staticmethod
    def generate_key(algorithm: str, **kwargs):
        """Generate a key based on the provided key type, including composite CMS keys.

        :param algorithm: The type of key to generate (e.g., "rsa", "ml-kem-768", "composite", "composite_cms").
        :param kwargs: Additional parameters required by the specific key generator.
        :return: Generated key object.
        :raises ValueError: If the key type is not supported.
        """
        if algorithm in ["rsa", "ecdsa", "ed25519", "ed448", "bad-rsa-key"]:
            return generate_trad_key(algorithm, **kwargs)

        elif PQKeyFactory.may_be_pq_alg(algorithm=algorithm):
            return PQKeyFactory.generate_pq_key(algorithm=algorithm)

        elif algorithm in HybridKeyFactory.supported_algorithms():
            if kwargs.get("pq_key") is not None or kwargs.get("trad_key") is not None:
                return HybridKeyFactory.from_keys(
                    algorithm=algorithm, pq_key=kwargs.get("pq_key"), trad_key=kwargs.get("trad_key")
                )

            return HybridKeyFactory.generate_hybrid_key(algorithm=algorithm, **kwargs)

        else:
            options = ", ".join(CombinedKeyFactory.supported_algorithms())
            raise ValueError(f"Unsupported key type: {algorithm} Supported are {options}")

    @staticmethod
    def load_public_key_from_spki(spki: rfc5280.SubjectPublicKeyInfo):
        """Load a public key from an SPKI structure.

        :param spki: rfc5280.SubjectPublicKeyInfo structure.
        :return: The loaded public key.
        """
        oid = spki["algorithm"]["algorithm"]

        if oid in CMS_COMPOSITE_OID_2_NAME:
            return CompositeSigCMSPublicKey.from_spki(spki)

        if str(oid) in COMPOSITE_KEM_OID_2_NAME:
            return CombinedKeyFactory.load_composite_kem_key(spki)

        if str(oid) in CHEMPAT_OID_2_NAME or oid in CHEMPAT_OID_2_NAME:
            return CombinedKeyFactory.load_chempat_key(spki)

        if oid in PQ_OID_2_NAME or str(oid) in PQ_OID_2_NAME:
            return PQKeyFactory.load_public_key_from_spki(spki=spki)

        if str(oid) == XWING_OID_STR:
            subject_public_key = spki["subjectPublicKey"].asOctets()
            return XWingPublicKey.from_public_bytes(subject_public_key)

        return serialization.load_der_public_key(encoder.encode(spki))

    @staticmethod
    def load_composite_kem_key(spki: rfc5280.SubjectPublicKeyInfo):
        """Load a composite KEM public key from an SPKI structure.

        :param spki: rfc5280.SubjectPublicKeyInfo structure.
        :return: Instance of the appropriate CompositeKEMPublicKey subclass.
        """
        oid = spki["algorithm"]["algorithm"]
        alg_name = COMPOSITE_KEM_OID_2_NAME[str(oid)]

        obj, rest = decoder.decode(spki["subjectPublicKey"].asOctets(), CompositeSignaturePublicKeyAsn1())
        if rest != b"":
            raise ValueError("Extra data after decoding public key")

        pq_pub_bytes = obj[0].asOctets()
        trad_pub_bytes = obj[1].asOctets()

        pq_name = _any_string_in_string(
            alg_name,
            [
                "ml-kem-512",
                "ml-kem-768",
                "ml-kem-1024",
                "frodokem-976-aes",
                "frogokem-1344-aes",
                "frodokem-976-shake",
                "frodokem-1344-shake",
            ],
        )

        if pq_name.startswith("ml"):
            pq_pub = MLKEMPublicKey(
                public_key=pq_pub_bytes,
                kem_alg=pq_name.upper(),
            )
        else:
            pq_pub = FrodoKEMPublicKey(
                public_key=pq_pub_bytes,
                kem_alg=pq_name,
            )

        trad_name = _any_string_in_string(alg_name, ["rsa", "ecdh", "ed25519", "ed448", "x25519", "x448"])

        if trad_name == "x25519":
            trad_pub = x25519.X25519PublicKey.from_public_bytes(trad_pub_bytes)
        elif trad_name == "x448":
            trad_pub = x448.X448PublicKey.from_public_bytes(trad_pub_bytes)
        elif trad_name == "ecdh":
            curve_name = _any_string_in_string(
                alg_name, ["secp256r1", "secp384r1", "brainpoolP256r1", "brainpoolP384r1"]
            )
            curve = get_curve_instance(curve_name)
            trad_pub = ec.EllipticCurvePublicKey.from_encoded_point(curve, trad_pub_bytes)
        elif trad_name.startswith("rsa"):
            trad_pub = serialization.load_der_public_key(trad_pub_bytes)
        else:
            raise ValueError(f"Unsupported traditional public key type: {trad_name}")

        if alg_name.startswith("dhkem"):
            return CompositeDHKEMRFC9180PublicKey(pq_pub, trad_pub)
        return parse_public_keys(pq_pub, trad_pub)

    @staticmethod
    def supported_algorithms():
        """List all supported key types by this factory.

        :return: List of supported key types.
        """
        trad_names = ["rsa", "ecdsa", "ed25519", "ed448", "bad_rsa_key", "x25519", "x448"]
        hybrid_names = HybridKeyFactory.supported_algorithms()
        pq_names = PQKeyFactory.supported_algorithms()
        return trad_names + pq_names + hybrid_names

    @staticmethod
    def load_key_from_one_asym_key(one_asym_key: rfc5958.OneAsymmetricKey):
        """Load a private key from a OneAsymmetricKey structure.

        :param one_asym_key: The OneAsymmetricKey structure.
        :return: The loaded private key.
        """
        from pq_logic.key_pyasn1_utils import parse_key_from_one_asym_key

        der_data = encoder.encode(one_asym_key)
        return parse_key_from_one_asym_key(der_data)

    @staticmethod
    def load_chempat_key(spki: rfc5280.SubjectPublicKeyInfo):
        """Load a Chempat public key from an SPKI structure.

        :param spki: rfc5280.SubjectPublicKeyInfo structure.
        :return: Instance of the appropriate ChempatPublicKey subclass.
        :raises KeyError: If the key OID is invalid.
        """
        oid = spki["algorithm"]["algorithm"]
        alg_name = CHEMPAT_OID_2_NAME.get(oid)
        alg_name = alg_name or CHEMPAT_OID_2_NAME[str(oid)]
        if alg_name is None:
            raise KeyError(f"Invalid Chempat key OID: {oid}")

        raw_bytes = spki["subjectPublicKey"].asOctets()

        return ChempatPublicKey.from_public_bytes(data=raw_bytes, name=alg_name)
