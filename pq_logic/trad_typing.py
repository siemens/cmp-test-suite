"""Includes typing for traditional cryptography keys, to not access `typingutils`."""

from typing import Union

from cryptography.hazmat.primitives.asymmetric import ec, x448, x25519

ECDHPrivateKey = Union[ec.EllipticCurvePrivateKey, x25519.X25519PrivateKey, x448.X448PrivateKey]
ECDHPublicKey = Union[ec.EllipticCurvePublicKey, x25519.X25519PublicKey, x448.X448PublicKey]
