from typing import Optional
from pyasn1.codec.der import encoder
from pyasn1_alt_modules import rfc2986, rfc2459
from pyasn1.type import char

from castutils import cast_csr_to_asn1csr
from typingutils import CSR_TYPE

