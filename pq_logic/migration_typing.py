# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Defines the keys-typings for newly created wrapper keys."""

from typing import Sequence, Union

from pyasn1_alt_modules import rfc9480

from pq_logic.keys.abstract_composite import (
    AbstractCompositeKEMPrivateKey,
    AbstractCompositeKEMPublicKey,
    AbstractCompositeSigPrivateKey,
    AbstractCompositeSigPublicKey,
)
from pq_logic.keys.abstract_hybrid_raw_kem_key import AbstractHybridRawPrivateKey, AbstractHybridRawPublicKey
from pq_logic.keys.abstract_pq import PQKEMPrivateKey, PQKEMPublicKey

HybridKEMPrivateKey = Union[AbstractCompositeKEMPrivateKey, AbstractHybridRawPrivateKey]
HybridKEMPublicKey = Union[AbstractHybridRawPublicKey, AbstractCompositeKEMPublicKey]


KEMPrivateKey = Union[PQKEMPrivateKey, HybridKEMPrivateKey]
KEMPublicKey = Union[PQKEMPublicKey, HybridKEMPublicKey]

HybridSigPrivKey = Union[AbstractCompositeSigPrivateKey]
HybridSigPubKey = Union[AbstractCompositeSigPublicKey]
CertOrCerts = Union[rfc9480.CMPCertificate, Sequence[rfc9480.CMPCertificate]]
