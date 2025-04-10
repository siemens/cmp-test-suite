# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Those are identical function as in the ./resources folder.

Just to avoid import conflicts will be removed in the future.

"""

from cryptography.hazmat.primitives import hashes
from robot.api.deco import not_keyword

from resources.oidutils import ALLOWED_HASH_TYPES


@not_keyword
def hash_name_to_instance(alg: str) -> hashes.HashAlgorithm:
    """Return an instance of a hash algorithm object based on its name.

    :param alg: The name of hashing algorithm, e.g., 'sha256'
    :return: `cryptography.hazmat.primitives.hashes`
    """
    try:
        # to also get the hash function with rsa-sha1 and so on.
        if "-" in alg:
            return ALLOWED_HASH_TYPES[alg.split("-")[1]]

        return ALLOWED_HASH_TYPES[alg]
    except KeyError as err:
        raise ValueError(f"Unsupported hash algorithm: {alg}") from err
