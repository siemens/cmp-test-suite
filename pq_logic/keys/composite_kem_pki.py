# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Composite ML-KEM for use in X.509 Public Key Infrastructure and CMS.

https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-kem/

If there are changes wanted or changes need to be done,
please contact me on GitHub.

This is a work in progress, which means there is nothing finalized yet.
So changes are incurable to have a better implementation.

Known differences to Draft.

This implementation is currently not testes against test vectors,
but I am working on it, to get some.
For HPKE DKHEM are some available, so as soon as Test vectors are available
this implementation should also be valid for the different implementations.

Issues: Use HPKE DHKEM instead of custom DHKEM #98
Issues: No composite is currently compatible with CNSA 2.0 #102 (Does not support extra OIDs for now.)




"""

from abc import abstractmethod
from typing import Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, x448, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ


from resources.exceptions import InvalidKeyCombination, BadAsn1Data
from resources.keyutils import generate_key

from pq_logic.hybrid_structures import CompositeCiphertextValue
from pq_logic.kem_mechanism import ECDHKEM, RSAOaepKem, DHKEMRFC9180
from pq_logic.keys.abstract_composite import AbstractCompositeKEMPrivateKey, AbstractCompositeKEMPublicKey
from pq_logic.keys.kem_keys import MLKEMPrivateKey
from pq_logic.pq_key_factory import PQKeyFactory

#####################################
# OIDs and OID-to-KDF Mappings
#####################################

from pq_logic.tmp_oids import id_CompKEM, id_frodokem_976_aes_rsa2048, id_frodokem_976_aes_rsa3072, \
    id_frodokem_976_aes_rsa4096, id_frodokem_976_aes_ecdh_p384, id_frodokem_976_aes_x25519, \
    id_frodokem_976_shake_rsa2048, id_frodokem_976_shake_rsa3072, id_frodokem_976_shake_rsa4096, \
    id_frodokem_976_shake_x25519, id_frodokem_976_shake_ecdh_p384, id_frodokem_976_shake_brainpoolP256r1, \
    id_frodokem_1344_aes_ecdh_p384, id_frodokem_1344_aes_x448, id_frodokem_1344_aes_ecdh_brainpoolP384r1, \
    id_frodokem_1344_shake_ecdh_p384, id_frodokem_1344_shake_ecdh_brainpoolP384r1, id_frodokem_1344_shake_x448, \
    id_frodokem_976_aes_brainpoolP256r1, COMPOSITE_KEM_DHKEMRFC9180_MAPPING

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

def get_composite_kem_hash_alg(pq_name: str, trad_key, alternative: bool = False) -> str:
    """Return the hash algorithm for a composite KEM.

    :param pq_name: The name of the post-quantum algorithm.
    :param trad_key: The traditional key algorithm.
    :param alternative: Whether to use an alternative hash algorithm.
    (addresses the issue:  No composite is currently compatible with CNSA 2.0 #102 )
    (to use HKDF-SHA2-512)
    :return: The hash algorithm.
    """

    # TODO maybe do directly by claimed NIST level ?

    if pq_name in ["ml-kem-1024", "frodokem-1344-aes", "frodokem-1344-shake"]:
        return "sha3-256"

    elif (pq_name in ["frodokem-976-aes", "frodokem-976-shake", "ml-kem-768"] and
          isinstance(trad_key, (x25519.X25519PublicKey, x25519.X25519PrivateKey))):

        return "sha3-256"

    elif pq_name in ["frodokem-976-aes", "frodokem-976-shake", "ml-kem-768"]:
        return "hkdf-sha256" if not alternative else "hkdf-sha512"

    raise InvalidKeyCombination(f"Unsupported composite KEM: {pq_name} with {trad_key}")


COMPOSITE_MLKEM_NAME_2_OID = {
    "ml-kem-768-rsa2048": id_MLKEM768_RSA2048,
    "ml-kem-768-rsa3072": id_MLKEM768_RSA3072,
    "ml-kem-768-rsa4096": id_MLKEM768_RSA4096,
    "ml-kem-768-ecdh-secp384r1": id_MLKEM768_ECDH_P384,
    "ml-kem-768-ecdh-brainpoolP256r1": id_MLKEM768_ECDH_brainpoolP256r1,
    "ml-kem-768-x25519": id_MLKEM768_X25519,
    "ml-kem-1024-ecdh-secp384r1": id_MLKEM1024_ECDH_P384,
    "ml-kem-1024-ecdh-brainpoolP384r1": id_MLKEM1024_ECDH_brainpoolP384r1,
    "ml-kem-1024-x448": id_MLKEM1024_X448,
}


COMPOSITE_FRODOKEM_NAME_2_OID = {
    "frodokem-976-aes-rsa2048": id_frodokem_976_aes_rsa2048,
    "frodokem-976-aes-rsa3072": id_frodokem_976_aes_rsa3072,
    "frodokem-976-aes-rsa4096": id_frodokem_976_aes_rsa4096,
    "frodokem-976-aes-x25519": id_frodokem_976_aes_x25519,
    "frodokem-976-aes-ecdh-secp384r1": id_frodokem_976_aes_ecdh_p384,
    "frodokem-976-aes-brainpoolP256r1": id_frodokem_976_aes_brainpoolP256r1,
    "frodokem-976-shake-rsa2048": id_frodokem_976_shake_rsa2048,
    "frodokem-976-shake-rsa3072": id_frodokem_976_shake_rsa3072,
    "frodokem-976-shake-rsa4096": id_frodokem_976_shake_rsa4096,
    "frodokem-976-shake-x25519": id_frodokem_976_shake_x25519,
    "frodokem-976-shake-ecdh-secp384r1": id_frodokem_976_shake_ecdh_p384,
    "frodokem-976-shake-brainpoolP256r1": id_frodokem_976_shake_brainpoolP256r1,
    "frodokem-1344-aes-ecdh-secp384r1": id_frodokem_1344_aes_ecdh_p384,
    "frodokem-1344-aes-ecdh-brainpoolP384r1": id_frodokem_1344_aes_ecdh_brainpoolP384r1,
    "frodokem-1344-aes-x448": id_frodokem_1344_aes_x448,
    "frodokem-1344-shake-ecdh-secp384r1": id_frodokem_1344_shake_ecdh_p384,
    "frodokem-1344-shake-ecdh-brainpoolP384r1": id_frodokem_1344_shake_ecdh_brainpoolP384r1,
    "frodokem-1344-shake-x448": id_frodokem_1344_shake_x448,
}


COMPOSITE_KEM_NAME_2_OID = {}
COMPOSITE_KEM_NAME_2_OID.update(COMPOSITE_MLKEM_NAME_2_OID)
COMPOSITE_KEM_NAME_2_OID.update(COMPOSITE_FRODOKEM_NAME_2_OID)
COMPOSITE_KEM_NAME_2_OID.update(COMPOSITE_KEM_DHKEMRFC9180_MAPPING)

COMPOSITE_KEM_OID_2_NAME = {str(oid): name for name, oid in COMPOSITE_KEM_NAME_2_OID.items()}

def get_oid_composite(
    pq_name: str,
    trad_key: Union[x25519.X25519PrivateKey, x448.X448PrivateKey, ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey],
    length: Optional[int] = None,
    curve_name: Optional[str] = None,
    use_dhkemrfc9180: bool = False,
) -> univ.ObjectIdentifier:
    """Return the OID for a composite KEM combination.

    :param pq_name: The name of the post-quantum algorithm.
    :param trad_key: The traditional key object.
    :param length: The length of the RSA key.
    :param curve_name: The name of the elliptic curve
    (only needed for negative testing)
    :param use_dhkemrfc9180: Whether to use the DHKEMRFC9180 and not ECDH mechanism.
    :return: The Object Identifier.
    """

    if isinstance(trad_key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        trad_name = f"rsa{length or trad_key.key_size}"

    elif isinstance(trad_key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        curve_name = curve_name or trad_key.curve.name
        trad_name = f"ecdh-{curve_name}"

    elif isinstance(trad_key, (x25519.X25519PrivateKey, x25519.X25519PublicKey)):
        trad_name = "x25519"

    elif isinstance(trad_key, (x448.X448PrivateKey, x448.X448PublicKey)):
        trad_name = "x448"
    else:
        raise ValueError(f"Unsupported traditional key type.: {type(trad_key).__name__}")

    prefix = "" if not use_dhkemrfc9180 else "dhkemrfc9180-"

    return COMPOSITE_KEM_NAME_2_OID[f"{prefix}{pq_name}-{trad_name}"]

def parse_public_keys(pq_key, trad_key) -> "CompositeKEMPublicKey":
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

def parse_private_keys(pq_key, trad_key) -> "CompositeMLKEMPrivateKey":
    """Parse the private keys into a composite ML-KEM private key.

    :param pq_key: The post-quantum private key.
    :param trad_key: The traditional private key.
    :return: The composite ML-KEM private key.
    """
    if isinstance(trad_key, rsa.RSAPrivateKey):
        return CompositeMLKEMRSAPrivateKey(pq_key, trad_key)
    if isinstance(trad_key, ec.EllipticCurvePrivateKey):
        return CompositeMLKEMECPrivateKey(pq_key, trad_key)
    if isinstance(trad_key, x25519.X25519PrivateKey) or isinstance(trad_key, x448.X448PrivateKey):
        return CompositeMLKEMXPrivateKey(pq_key, trad_key)
    raise ValueError(f"Unsupported traditional key type.: {type(trad_key).__name__}")

#####################################
# Concrete Class Implementation
#####################################


class CompositeKEMPublicKey(AbstractCompositeKEMPublicKey):
    def get_oid(self) -> univ.ObjectIdentifier:
        return get_oid_composite(self.pq_key.name, self.trad_key)


class CompositeMLKEMPrivateKey(AbstractCompositeKEMPrivateKey):
    pq_key: MLKEMPrivateKey
    _alternative_hash = False

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
        concatenated_inputs = mlkem_ss + trad_ss + trad_ct + trad_pk
        kdf_name = get_composite_kem_hash_alg(self.pq_key.name, self.trad_key)

        if "hkdf" in kdf_name:
            hash_instance = hashes.SHA256()if not self._alternative_hash else hashes.SHA512()
            hkdf = HKDF(algorithm=hash_instance, length=32, salt=None, info=None)
            return hkdf.derive(concatenated_inputs)
        else:
            h = hashes.Hash(hashes.SHA3_256())
            h.update(concatenated_inputs)
            return h.finalize()

    def encaps(self, public_key: CompositeKEMPublicKey) -> Tuple[bytes, bytes]:
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
        :raises BadAsn1Data: If the ciphertext structure is invalid or cannot be decoded.
        """
        ct_vals, rest = decoder.decode(ct_vals, CompositeCiphertextValue())

        if rest:
            raise BadAsn1Data("CompositeCiphertextValue")

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


class CompositeMLKEMECPublicKey(CompositeKEMPublicKey):
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


class CompositeMLKEMXPublicKey(CompositeKEMPublicKey):
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

class CompositeDHKEMRFC9180PublicKey(CompositeKEMPublicKey):

    def get_oid(self) -> univ.ObjectIdentifier:
        return get_oid_composite(self.pq_key.name, self.trad_key, use_dhkemrfc9180=True)


class CompositeDHKEMRFC9180PrivateKey(CompositeMLKEMPrivateKey):

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the OID of the composite KEM."""
        return get_oid_composite(self.pq_key.name, self.trad_key, use_dhkemrfc9180=True)

    def generate(self, pq_name: Optional[str] = None, trad_param: Optional[Union[int, str]] = None):
        raise NotImplementedError("Not implemented yet")

    def public_key(self) -> CompositeDHKEMRFC9180PublicKey:
        """Return the public key of the composite KEM."""
        return CompositeDHKEMRFC9180PublicKey(self.pq_key.public_key(), self.trad_key.public_key())

    def _perform_trad_encaps(self, public_key) -> Tuple[bytes, bytes]:
        """Perform the traditional encapsulation using the specified DHKEMRFC9180 mechanism.

        :param public_key: The peer's public key.
        """
        dh_kem_mech = DHKEMRFC9180(private_key=self.trad_key)
        ss, ct = dh_kem_mech.encaps(public_key)
        return ss, ct

    def _perform_trad_decaps(self, trad_ct: bytes) -> bytes:
        """Perform traditional decapsulation using the specified DHKEMRFC9180 mechanism.

        :param trad_ct: The traditional ciphertext.
        :return: The shared secret.
        """
        dh_kem_mech = DHKEMRFC9180(private_key=self.trad_key)
        return dh_kem_mech.decaps(trad_ct)

