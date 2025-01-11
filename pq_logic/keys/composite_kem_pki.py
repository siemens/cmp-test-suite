# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Composite ML-KEM for use in X.509 Public Key Infrastructure and CMS.

https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-kem/



"""

from abc import abstractmethod
from typing import Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, x448, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from resources.keyutils import generate_key

from pq_logic.hybrid_structures import CompositeCiphertextValue
from pq_logic.kem_mechanism import ECDHKEM, RSAOaepKem
from pq_logic.keys.abstract_composite import AbstractCompositeKEMPrivateKey, AbstractCompositeKEMPublicKey
from pq_logic.keys.kem_keys import MLKEMPrivateKey
from pq_logic.pq_key_factory import PQKeyFactory

#####################################
# OIDs and OID-to-KDF Mappings
#####################################

id_CompKEM = univ.ObjectIdentifier("2.16.840.1.114027.80.5.2.1")

id_MLKEM768_RSA2048 = univ.ObjectIdentifier(f"{id_CompKEM}.21")
id_MLKEM768_RSA3072 = univ.ObjectIdentifier(f"{id_CompKEM}.22")
id_MLKEM768_RSA4096 = univ.ObjectIdentifier(f"{id_CompKEM}.23")
id_MLKEM768_X25519 = univ.ObjectIdentifier(f"{id_CompKEM}.24")
id_MLKEM768_ECDH_P384 = univ.ObjectIdentifier(f"{id_CompKEM}.25")
id_MLKEM768_ECDH_brainpoolP256r1 = univ.ObjectIdentifier(f"{id_CompKEM}.26")
id_MLKEM1024_ECDH_P384 = univ.ObjectIdentifier(f"{id_CompKEM}.27")
id_MLKEM1024_ECDH_brainpoolP384r1 = univ.ObjectIdentifier(f"{id_CompKEM}.28")
id_MLKEM1024_X448 = univ.ObjectIdentifier(f"{id_CompKEM}.29")

oid_to_kdf_mapping = {
    id_MLKEM768_RSA2048: "hkdf-sha256",
    id_MLKEM768_RSA3072: "hkdf-sha256",
    id_MLKEM768_RSA4096: "hkdf-sha256",
    id_MLKEM768_X25519: "sha3-256",
    id_MLKEM768_ECDH_P384: "hkdf-sha256",
    id_MLKEM768_ECDH_brainpoolP256r1: "hkdf-sha256",
    id_MLKEM1024_ECDH_P384: "sha3-256",
    id_MLKEM1024_ECDH_brainpoolP384r1: "sha3-256",
    id_MLKEM1024_X448: "sha3-256",
}


def get_oid_composite(
    ml_kem_name: str,
    trad_key: Union[x25519.X25519PrivateKey, x448.X448PrivateKey, ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey],
):
    """Retrieve the Object Identifier (OID) for a given composite KEM configuration.

    :param ml_kem_name: Name of the post-quantum KEM algorithm, e.g., 'ml-kem-768' or 'ml-kem-1024'.
    :param trad_key: Traditional private key used in the composite KEM.
    :return: The corresponding OID for the composite KEM as defined in the mapping.

    :raises ValueError: If the traditional key type or key parameters are unsupported.
    """
    oid_mapping = {
        ("ml-kem-768", rsa.RSAPrivateKey): {
            2048: id_MLKEM768_RSA2048,
            3072: id_MLKEM768_RSA3072,
            4096: id_MLKEM768_RSA4096,
        },
        ("ml-kem-768", ec.EllipticCurvePrivateKey): {
            "secp384r1": id_MLKEM768_ECDH_P384,
            "brainpoolP256r1": id_MLKEM768_ECDH_brainpoolP256r1,
        },
        ("ml-kem-768", x25519.X25519PrivateKey): id_MLKEM768_X25519,
        ("ml-kem-1024", ec.EllipticCurvePrivateKey): {
            "secp384r1": id_MLKEM1024_ECDH_P384,
            "brainpoolP384r1": id_MLKEM1024_ECDH_brainpoolP384r1,
        },
        ("ml-kem-1024", x448.X448PrivateKey): id_MLKEM1024_X448,
    }

    if isinstance(trad_key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        key_size = trad_key.key_size
        return oid_mapping.get((ml_kem_name, rsa.RSAPrivateKey), {}).get(key_size)
    if isinstance(trad_key, ec.EllipticCurvePrivateKey):
        curve_name = trad_key.curve.name
        return oid_mapping.get((ml_kem_name, ec.EllipticCurvePrivateKey), {}).get(curve_name)
    if isinstance(trad_key, x448.X448PrivateKey):
        return oid_mapping.get((ml_kem_name, x448.X448PrivateKey))

    if isinstance(trad_key, x25519.X25519PrivateKey):
        return oid_mapping.get((ml_kem_name, x25519.X25519PrivateKey))

    else:
        raise ValueError(f"Unsupported traditional key type.: {type(trad_key).__name__}")


def parse_public_keys(pq_key, trad_key) -> "CompositeMLKEMPublicKey":
    """Parse the public keys into a composite ML-KEM public key.

    :param pq_key: The post-quantum public key.
    :param trad_key: The traditional public key.
    :return: The composite ML-KEM public key.
    """
    if isinstance(trad_key, rsa.RSAPublicKey):
        return CompositeMLKEMRSAPublicKey(pq_key, trad_key)
    if isinstance(trad_key, ec.EllipticCurvePublicKey):
        return CompositeMLKEMECPublicKey(pq_key, trad_key)
    if isinstance(trad_key, x25519.X25519PublicKey) or isinstance(trad_key, x448.X448PublicKey):
        return CompositeMLKEMXPublicKey(pq_key, trad_key)
    raise ValueError(f"Unsupported traditional key type.: {type(trad_key).__name__}")


#####################################
# Concrete Class Implementation
#####################################


class CompositeMLKEMPublicKey(AbstractCompositeKEMPublicKey):
    def get_oid(self) -> univ.ObjectIdentifier:
        return get_oid_composite(self.pq_key.name, self.trad_key)


class CompositeMLKEMPrivateKey(AbstractCompositeKEMPrivateKey):
    pq_key: MLKEMPrivateKey

    @abstractmethod
    def _perform_trad_encaps(self, public_key):
        """Perform traditional key encapsulation using the specified KEM mechanism."""
        pass

    @abstractmethod
    def _perform_trad_decaps(self, trad_ct: bytes):
        """Perform traditional key decapsulation using the specified KEM mechanism."""
        pass

    def kem_combiner(self, mlkem_ss: bytes, trad_ss: bytes, trad_ct: bytes, trad_pk: bytes) -> bytes:
        """Combine the shared secrets and encapsulation artifacts into a single shared secret.

        :param mlkem_ss: Shared secret generated from the ML-KEM encapsulation.
        :param trad_ss: Shared secret generated from the traditional KEM encapsulation.
        :param trad_ct: Ciphertext from the traditional KEM encapsulation.
        :param trad_pk: Serialized public key of the traditional KEM.
        :return: A combined shared secret as bytes, derived using a KDF (HKDF or SHA3-256).

        :raises KeyError: If the OID mapping for the specified keys is not found.
        """
        oid = get_oid_composite(self.pq_key.name, self.trad_key)
        concatenated_inputs = mlkem_ss + trad_ss + trad_ct + trad_pk
        kdf_name = oid_to_kdf_mapping[oid]

        if "hkdf" in kdf_name:
            hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=None)
            return hkdf.derive(concatenated_inputs)
        else:
            h = hashes.Hash(hashes.SHA3_256())
            h.update(concatenated_inputs)
            return h.finalize()

    def encaps(self, public_key: CompositeMLKEMPublicKey) -> Tuple[bytes, bytes]:
        """Perform key encapsulation using both ML-KEM and traditional KEM mechanisms.

        :param public_key: The composite public key containing both post-quantum and traditional public keys.
        :return: A tuple containing:
                 - Combined shared secret (bytes)
                 - CompositeCiphertextValue containing ML-KEM and traditional KEM ciphertexts.
        """
        mlkem_ss, mlkem_ct = public_key.pq_key.encaps()
        trad_ss, trad_ct = self._perform_trad_encaps(public_key.trad_key)
        combined_ss = self.kem_combiner(
            mlkem_ss,
            trad_ss,
            trad_ct,
            public_key.trad_key.public_bytes(
                encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
        )

        ct_vals = CompositeCiphertextValue()
        ct_vals.append(univ.OctetString(mlkem_ct))
        ct_vals.append(univ.OctetString(trad_ct))

        return combined_ss, encoder.encode(ct_vals)

    def decaps(self, ct_vals: bytes) -> bytes:
        """Perform key decapsulation to compute the combined shared secret.

        :param ct_vals: The DER-encoded encapsulated composite ciphertext, both ML-KEM and traditional KEM.
        :return: The computed combined shared secret as bytes.
        :raises ValueError: If the ciphertext structure is invalid or cannot be decoded.
        """
        ct_vals, rest = decoder.decode(ct_vals, CompositeCiphertextValue())

        if rest:
            raise ValueError()

        mlkem_ct = ct_vals[0].asOctets()
        trad_ct = ct_vals[1].asOctets()
        mlkem_ss = self.pq_key.decaps(mlkem_ct)

        trad_ss = self._perform_trad_decaps(trad_ct)
        combined_ss = self.kem_combiner(
            mlkem_ss,
            trad_ss,
            trad_ct,
            self.trad_key.public_key().public_bytes(
                encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
        )
        return combined_ss


class CompositeMLKEMRSAPublicKey(AbstractCompositeKEMPublicKey):
    def get_oid(self, *args, **kwargs) -> univ.ObjectIdentifier:
        return get_oid_composite(self.pq_key.name, self.trad_key)


class CompositeMLKEMRSAPrivateKey(CompositeMLKEMPrivateKey):
    """Composite ML-KEM private key with RSA-based traditional KEM.

    This class uses a PQ-based KEM (via RSA-OAEP KEM) and a classical KEM (ECDH),
    each isolated in their own class.
    """

    def _perform_trad_decaps(self, trad_ct: bytes):
        dh_kem_mech = RSAOaepKem()
        trad_ss = dh_kem_mech.decaps(private_key=self.trad_key, ciphertext=trad_ct)
        return trad_ss

    def _perform_trad_encaps(self, trad_key):
        dh_kem_mech = RSAOaepKem()
        trad_ss, trad_ct = dh_kem_mech.encaps(trad_key)
        return trad_ss, trad_ct

    def public_key(self) -> CompositeMLKEMRSAPublicKey:
        """Return the public key of the composite KEM."""
        return CompositeMLKEMRSAPublicKey(self.pq_key.public_key(), self.trad_key.public_key())

    pq_key: MLKEMPrivateKey
    trad_key: rsa.RSAPrivateKey

    @staticmethod
    def generate(pq_name: Optional[str] = None, trad_param: int = 2048):
        if pq_name is None:
            pq_name = "ml-dsa-44"  # default placeholder
        pq_key = PQKeyFactory.generate_pq_key(pq_name)
        trad_key = generate_key("rsa", length=trad_param)
        return CompositeMLKEMRSAPrivateKey(pq_key, trad_key)


class CompositeMLKEMECPublicKey(CompositeMLKEMPublicKey):
    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the OID of the composite KEM."""
        return get_oid_composite(self.pq_key.name, self.trad_key)


class CompositeMLKEMECPrivateKey(CompositeMLKEMPrivateKey):
    @staticmethod
    def generate(pq_name: Optional[str] = None, trad_param: Optional[Union[int, str]] = None):
        """Generate a Composite ML-KEM private key."""
        return CompositeMLKEMECPrivateKey(
            PQKeyFactory.generate_pq_key(pq_name or "ml-kem-768"), generate_key("ec", curve=trad_param or "secp384r1")
        )

    def public_key(self) -> AbstractCompositeKEMPublicKey:
        """Return the public key of the composite KEM."""
        return CompositeMLKEMECPublicKey(self.pq_key.public_key(), self.trad_key.public_key())

    def _perform_trad_encaps(self, trad_pub_key):
        """Perform traditional key encapsulation using the specified KEM mechanism."""
        dh_kem_mech = ECDHKEM(self.trad_key)
        # may use ephemeral key.
        ss, ct = dh_kem_mech.encaps(trad_pub_key)
        self.trad_key = dh_kem_mech.private_key
        return ss, ct

    def _perform_trad_decaps(self, trad_ct: bytes):
        """Perform traditional decapsulation using the specified KEM mechanism."""
        dh_kem_mech = ECDHKEM(self.trad_key)
        return dh_kem_mech.decaps(trad_ct)


class CompositeMLKEMXPublicKey(CompositeMLKEMPublicKey):
    def get_oid(self) -> univ.ObjectIdentifier:
        return get_oid_composite(self.pq_key.name, self.trad_key)


class CompositeMLKEMXPrivateKey(CompositeMLKEMPrivateKey):
    trad_key: Union[x25519.X25519PrivateKey, x448.X448PrivateKey]

    def public_key(self) -> CompositeMLKEMXPublicKey:
        """Return the public key of the composite KEM."""
        return CompositeMLKEMXPublicKey(self.pq_key.public_key(), self.trad_key.public_key())

    @staticmethod
    def generate(pq_name: Optional[str] = None, trad_param: Optional[Union[int, str]] = None):
        """Generate a Composite ML-KEM private key."""
        return CompositeMLKEMXPrivateKey(
            PQKeyFactory.generate_pq_key(pq_name or "ml-kem-768"), generate_key(trad_param or "x25519")
        )

    def _perform_trad_encaps(self, trad_pub_key):
        """Perform traditional key encapsulation using the specified KEM mechanism."""
        dh_kem_mech = ECDHKEM(self.trad_key)
        # may use ephemeral key.
        ss, ct = dh_kem_mech.encaps(trad_pub_key)
        self.trad_key = dh_kem_mech.private_key
        return ss, ct

    def _perform_trad_decaps(self, trad_ct: bytes):
        """Perform traditional decapsulation using the specified KEM mechanism."""
        dh_kem_mech = ECDHKEM(self.trad_key)
        return dh_kem_mech.decaps(trad_ct)
