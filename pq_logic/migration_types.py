# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

from typing import Union

from pq_logic.chempatkem import ChempatPublicKey
from pq_logic.keys.abstract_composite import (
    AbstractCompositeKEMPrivateKey,
    AbstractCompositeKEMPublicKey,
    AbstractCompositeSigPrivateKey,
    AbstractCompositeSigPublicKey,
)
from pq_logic.keys.abstract_hybrid_raw_kem_key import AbstractHybridRawPrivateKey, AbstractHybridRawPublicKey
from pq_logic.keys.abstract_pq import PQKEMPrivateKey, PQKEMPublicKey

HybridKEMPrivateKey = Union[AbstractCompositeKEMPrivateKey, AbstractCompositeKEMPrivateKey, AbstractHybridRawPrivateKey]
HybridKEMPublicKey = Union[AbstractHybridRawPublicKey, AbstractCompositeKEMPublicKey, ChempatPublicKey]


KEMPrivateKey = Union[PQKEMPrivateKey, HybridKEMPrivateKey]
KEMPublicKey = Union[PQKEMPublicKey, HybridKEMPublicKey]

HybridSigPrivKey = Union[AbstractCompositeSigPrivateKey]
HybridSigPubKey = Union[AbstractCompositeSigPublicKey]
