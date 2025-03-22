# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
#
# ruff: noqa: D402 First line should not be the function's signature
# ruff: noqa: D401 First line of docstring should be in imperative mood
# ruff: noqa: D205 1 blank line required between summary line and description
# ruff: noqa: D102 Missing docstring in public method

"""SLH-DSA implementation based on FIPS 205."""

import os
from typing import Optional, Tuple, Union

#   fips205.py
#   2023-11-24  Markku-Juhani O. Saarinen < mjos@iki.fi>. See LICENSE
#   === FIPS 205 implementation https://doi.org/10.6028/NIST.FIPS.205
#   SLH-DSA / Stateless Hash-Based Digital Signature Standard
#   test_slhdsa is only used by the unit test in the end
# from test_slhdsa import test_slhdsa
#   hashes
from Crypto.Hash import SHA256, SHA512, SHAKE128, SHAKE256


class ADRS:
    """Class for handling Addresses (Section 4.2)."""

    #   type constants
    WOTS_HASH = 0
    WOTS_PK = 1
    TREE = 2
    FORS_TREE = 3
    FORS_ROOTS = 4
    WOTS_PRF = 5
    FORS_PRF = 6

    a: bytearray

    def __init__(self, a: Union[int, bytearray, bytes] = 32):
        """Initialize."""
        self.a = bytearray(a)

    def copy(self) -> "ADRS":
        """Make a copy of self."""
        return ADRS(self.a)

    def set_layer_address(self, x):
        """Set layer address."""
        self.a[0:4] = x.to_bytes(4, byteorder="big")

    def set_tree_address(self, x):
        """Set tree address."""
        self.a[4:16] = x.to_bytes(12, byteorder="big")

    def set_key_pair_address(self, x):
        """Set key pair Address."""
        self.a[20:24] = x.to_bytes(4, byteorder="big")

    def get_key_pair_address(self):
        """Get key pair Address."""
        return int.from_bytes(self.a[20:24], byteorder="big")

    def set_tree_height(self, x):
        """Set FORS tree height."""
        self.a[24:28] = x.to_bytes(4, byteorder="big")

    def set_chain_address(self, x):
        """Set WOTS+ chain address."""
        self.a[24:28] = x.to_bytes(4, byteorder="big")

    def set_tree_index(self, x):
        """Set FORS tree index."""
        self.a[28:32] = x.to_bytes(4, byteorder="big")

    def get_tree_index(self):
        """Get FORS tree index."""
        return int.from_bytes(self.a[28:32], byteorder="big")

    def set_hash_address(self, x):
        """Set WOTS+ hash address."""
        self.a[28:32] = x.to_bytes(4, byteorder="big")

    def set_type_and_clear(self, t):
        """The member function ADRS.setTypeAndClear(Y) for addresses sets
        the type of the ADRS to Y and sets the fnal 12 bytes of the ADRS
        to zero.
        """
        self.a[16:20] = t.to_bytes(4, byteorder="big")
        for i in range(12):
            self.a[20 + i] = 0

    def adrs(self):
        """Return the ADRS as bytes."""
        return self.a

    def adrsc(self):
        """Compressed address ADRDc used with SHA-2."""
        return self.a[3:4] + self.a[8:16] + self.a[19:20] + self.a[20:32]


#   SLH-DSA Implementation


def integer_to_bytes(x: int, alpha: int) -> bytearray:
    """Convert an integer to a byte array.

    :param x: The integer to convert.
    :param alpha: The number of bytes to return.
    :return: The byte array.
    """
    y = bytearray(alpha)
    for i in range(alpha):
        y[i] = x & 0xFF
        x >>= 8
    return y


class SLH_DSA:
    """SLH-DSA Class."""

    def __init__(self, hashname="SHAKE", n=16, h=66, d=22, hp=3, a=6, k=33, lg_w=4, m=34, rbg=os.urandom):
        """Initialize the SLH-DSA object."""
        self.hashname = hashname
        self.n = n
        self.h = h
        self.d = d
        self.hp = hp
        self.a = a
        self.k = k
        self.lg_w = lg_w
        self.m = m

        #   instantiate hash functions
        if hashname == "SHAKE":
            self.h_msg = self.shake_h_msg
            self.prf = self.shake_prf
            self.prf_msg = self.shake_prf_msg
            self.h_f = self.shake_f
            self.h_h = self.shake_f
            self.h_t = self.shake_f
        elif hashname == "SHA2" and self.n == 16:
            self.h_msg = self.sha256_h_msg
            self.prf = self.sha256_prf
            self.prf_msg = self.sha256_prf_msg
            self.h_f = self.sha256_f
            self.h_h = self.sha256_f
            self.h_t = self.sha256_f
        elif hashname == "SHA2" and self.n > 16:
            self.h_msg = self.sha512_h_msg
            self.prf = self.sha256_prf
            self.prf_msg = self.sha512_prf_msg
            self.h_f = self.sha256_f
            self.h_h = self.sha512_h
            self.h_t = self.sha512_h

        #   equations 5.1 - 5.4
        self.w = 2**self.lg_w
        self.len1 = (8 * self.n + (self.lg_w - 1)) // self.lg_w
        self.len2 = (self.len1 * (self.w - 1)).bit_length() // self.lg_w + 1
        self.len = self.len1 + self.len2

        #   external parameter sizes
        self.pk_sz = 2 * self.n
        self.sk_sz = 4 * self.n
        self.sig_sz = (1 + self.k * (1 + self.a) + self.h + self.d * self.len) * self.n

        #   rbg
        self.rbg = rbg

    #   10.1.   SLH-DSA Using SHAKE
    def shake256(self, x: bytes, length: int) -> bytes:
        """SHAKE256(x, l): Internal hook."""
        return SHAKE256.new(x).read(length)

    def shake_h_msg(self, r, pk_seed, pk_root, m):
        return self.shake256(r + pk_seed + pk_root + m, self.m)

    def shake_prf(self, pk_seed, sk_seed, adrs):
        return self.shake256(pk_seed + adrs.adrs() + sk_seed, self.n)

    def shake_prf_msg(self, sk_prf, opt_rand, m):
        return self.shake256(sk_prf + opt_rand + m, self.n)

    def shake_f(self, pk_seed, adrs, m1):
        return self.shake256(pk_seed + adrs.adrs() + m1, self.n)

    #   Various constructions required for SHA-2 variants.

    def sha256(self, x: bytes, n: int = 32) -> bytes:
        """Tranc_n(SHA2-256(x)).

        :param x: The input data.
        :param n: The number of bytes to return. Defaults to 32.
        :return: The truncated hash.
        """
        return SHA256.new(x).digest()[0:n]

    def sha512(self, x: bytes, n: int = 64) -> bytes:
        """Tranc_n(SHA2-512(x)).

        :param x: The input data.
        :param n: The number of bytes to return. Defaults to 64.
        :return: The truncated hash.
        """
        return SHA512.new(x).digest()[0:n]

    def mgf(self, hash_f, hash_l: int, mgf_seed: bytes, mask_len: int) -> bytes:
        """NIST SP 800-56B REV. 2 / The Mask Generation Function (MGF).

        :param hash_f: The hash function to use.
        :param hash_l: The length of the hash.
        :param mgf_seed: The seed for the MGF.
        :param mask_len: The length of the mask.
        :return: The mask.
        """
        t = b""
        for c in range((mask_len + hash_l - 1) // hash_l):
            t += hash_f(mgf_seed + c.to_bytes(4, byteorder="big"))
        return t[0:mask_len]

    def mgf_sha256(self, mgf_seed: bytes, mask_len: int) -> bytes:
        """MGF1-SHA1-256(mgfSeed, maskLen)."""
        return self.mgf(self.sha256, 32, mgf_seed, mask_len)

    def mgf_sha512(self, mgf_seed: bytes, mask_len: int):
        """MGF1-SHA1-512(mgfSeed, maskLen)."""
        return self.mgf(self.sha512, 64, mgf_seed, mask_len)

    def hmac(self, hash_f, hash_l, hash_b, k, text):
        """FIPS PUB 198-1 HMAC."""
        if len(k) > hash_b:
            k = hash_f(k)
        ipad = bytearray(hash_b)
        ipad[0 : len(k)] = k
        opad = bytearray(ipad)
        for i in range(hash_b):
            ipad[i] ^= 0x36
            opad[i] ^= 0x5C
        return hash_f(opad + hash_f(ipad + text))

    def hmac_sha256(self, k: bytes, text: bytes, n=32):
        """Trunc_n(HMAC-SHA-256(k, text)): Internal hook.

        :param k: The key for the HMAC-sha256.
        :param text: The text to hash.
        :param n: The number of bytes to return. Defaults to 32.
        """
        return self.hmac(self.sha256, 32, 64, k, text)[0:n]

    def hmac_sha512(self, k: bytes, text: bytes, n: int = 64) -> bytes:
        """Trunc_n(HMAC-SHA-256(k, text)): Internal hook.

        :param k: The key for the HMAC-sha512.
        :param text: The text to hash.
        :param n: The number of bytes to return. Defaults to 64.
        :return: The truncated hash.
        """
        return self.hmac(self.sha512, 64, 128, k, text)[0:n]

    #   10.2    SLH-DSA Using SHA2 for Security Category 1

    def sha256_h_msg(self, r: bytes, pk_seed: bytes, pk_root: bytes, m: bytes) -> bytes:
        return self.mgf_sha256(r + pk_seed + self.sha256(r + pk_seed + pk_root + m), self.m)

    def sha256_prf(self, pk_seed: bytes, sk_seed: bytes, adrs: ADRS) -> bytes:
        """Compute the SHA256 Pseudo-Random Function.

        :param pk_seed: The public seed.
        :param sk_seed: The secret seed.
        :param adrs: The address.
        :return: The truncated hash, based on `n`.
        """
        return self.sha256(pk_seed + bytes(64 - self.n) + adrs.adrsc() + sk_seed, self.n)

    def sha256_prf_msg(self, sk_prf: bytes, opt_rand: bytes, m: bytes) -> bytes:
        """Compute the HMAC for the message.

        :param sk_prf: The secret key for HMAC-sha256.
        :param opt_rand: The optional random value.
        :param m: The message.
        :return: The truncated hash, based on `n`.
        """
        return self.hmac_sha256(sk_prf, opt_rand + m, self.n)

    def sha256_f(self, pk_seed: bytes, adrs: ADRS, m1: bytes):
        """Compute the hash function.

        :param pk_seed: The public seed.
        :param adrs: The address.
        :param m1: The message.
        :return: The truncated hash, based on `n`.
        """
        return self.sha256(pk_seed + bytes(64 - self.n) + adrs.adrsc() + m1, self.n)

    #   10.3    SLH-DSA Using SHA2 for Security Categories 3 and 5

    def sha512_h_msg(self, r: bytes, pk_seed: bytes, pk_root: bytes, m: bytes) -> bytes:
        """Compute the hash of the message."""
        return self.mgf_sha512(r + pk_seed + self.sha512(r + pk_seed + pk_root + m), self.m)

    def sha512_prf_msg(self, sk_prf: bytes, opt_rand: bytes, m: bytes):
        """Compute the PRF for the message.

        :param sk_prf: The secret key for the PRF.
        :param opt_rand: The optional random value.
        :param m: The message.
        :return: The truncated hash.
        """
        return self.hmac_sha512(sk_prf, opt_rand + m, self.n)

    def sha512_h(self, pk_seed: bytes, adrs: ADRS, m2: bytes) -> bytes:
        """Compute the SHA512 hash function."""
        return self.sha512(pk_seed + bytes(128 - self.n) + adrs.adrsc() + m2, self.n)

    #   --- FIPS 205 Algorithms

    def to_int(self, s, n):
        """Algorithm 2: toInt(X, n). Convert a byte string to an integer."""
        t = 0
        for i in range(n):
            t = (t << 8) + int(s[i])
        return t

    def to_byte(self, x, n):
        """Algorithm 3: toByte(x, n). Convert an integer to a byte string."""
        t = x
        s = bytearray(n)
        for i in range(n):
            s[n - 1 - i] = t & 0xFF
            t >>= 8
        return s

    def base_2b(self, s, b, out_len):
        """Algorithm 4: base_2b (X, b, out_len).

        Compute the base 2**b representation of X.
        """
        i = 0  # in
        c = 0  # bits
        t = 0  # total
        v = []  # baseb
        m = (1 << b) - 1  # mask
        for j in range(out_len):
            while c < b:
                t = (t << 8) + int(s[i])
                i += 1
                c += 8
            c -= b
            v += [(t >> c) & m]
        return v

    def chain(self, x, i, s, pk_seed, adrs):
        """Algorithm 5: chain(X, i, s, PK.seed, ADRS).
        Chaining function used in WOTS+.
        """
        if i + s >= self.w:
            return None
        t = x
        for j in range(i, i + s):
            adrs.set_hash_address(j)
            t = self.h_f(pk_seed, adrs, t)
        return t

    def wots_pkgen(self, sk_seed: bytes, pk_seed: bytes, adrs: ADRS):
        """Algorithm 6: wots_PKgen(SK.seed, PK.seed, ADRS).

        Generate a WOTS+ public key.
        """
        sk_adrs = adrs.copy()
        sk_adrs.set_type_and_clear(ADRS.WOTS_PRF)
        sk_adrs.set_key_pair_address(adrs.get_key_pair_address())
        tmp = b""
        for i in range(self.len):
            sk_adrs.set_chain_address(i)
            sk = self.prf(pk_seed, sk_seed, sk_adrs)
            adrs.set_chain_address(i)
            tmp += self.chain(sk, 0, self.w - 1, pk_seed, adrs)
        wotspk_adrs = adrs.copy()
        wotspk_adrs.set_type_and_clear(ADRS.WOTS_PK)
        wotspk_adrs.set_key_pair_address(adrs.get_key_pair_address())
        pk = self.h_t(pk_seed, wotspk_adrs, tmp)
        return pk

    def wots_sign(self, m, sk_seed, pk_seed, adrs):
        """Algorithm 7: wots_sign(M, SK.seed, PK.seed, ADRS).

        Generate a WOTS+ signature on an n-byte message.
        """
        csum = 0
        msg = self.base_2b(m, self.lg_w, self.len1)
        for i in range(self.len1):
            csum += self.w - 1 - msg[i]
        csum <<= (8 - ((self.len2 * self.lg_w) % 8)) % 8
        msg += self.base_2b(self.to_byte(csum, (self.len2 * self.lg_w + 7) // 8), self.lg_w, self.len2)
        sk_adrs = adrs.copy()
        sk_adrs.set_type_and_clear(ADRS.WOTS_PRF)
        sk_adrs.set_key_pair_address(adrs.get_key_pair_address())
        sig = b""
        for i in range(self.len):
            sk_adrs.set_chain_address(i)
            sk = self.prf(pk_seed, sk_seed, sk_adrs)
            adrs.set_chain_address(i)
            sig += self.chain(sk, 0, msg[i], pk_seed, adrs)

        return sig

    def wots_pk_from_sig(self, sig, m, pk_seed, adrs):
        """Algorithm 8: wots_PKFromSig(sig, M, PK.seed, ADRS).

        Compute a WOTS+ public key from a message and its signature.
        """
        csum = 0
        msg = self.base_2b(m, self.lg_w, self.len1)
        for i in range(self.len1):
            csum += self.w - 1 - msg[i]
        csum <<= (8 - ((self.len2 * self.lg_w) % 8)) % 8
        msg += self.base_2b(self.to_byte(csum, (self.len2 * self.lg_w + 7) // 8), self.lg_w, self.len2)
        tmp = b""
        for i in range(self.len):
            adrs.set_chain_address(i)
            tmp += self.chain(sig[i * self.n : (i + 1) * self.n], msg[i], self.w - 1 - msg[i], pk_seed, adrs)
        wots_pk_adrs = adrs.copy()
        wots_pk_adrs.set_type_and_clear(ADRS.WOTS_PK)
        wots_pk_adrs.set_key_pair_address(adrs.get_key_pair_address())
        pk_sig = self.h_t(pk_seed, wots_pk_adrs, tmp)
        return pk_sig

    def xmss_node(self, sk_seed: bytes, i: int, z: int, pk_seed: bytes, adrs: ADRS):
        """Algorithm 9: xmss_node(SK.seed, i, z, PK.seed, ADRS).
        Compute the root of a Merkle subtree of WOTS+ public keys.
        """
        if z > self.hp or i >= 2 ** (self.hp - z):
            return None
        if z == 0:
            adrs.set_type_and_clear(ADRS.WOTS_HASH)
            adrs.set_key_pair_address(i)
            node = self.wots_pkgen(sk_seed, pk_seed, adrs)
        else:
            lnode = self.xmss_node(sk_seed, 2 * i, z - 1, pk_seed, adrs)
            rnode = self.xmss_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs)
            adrs.set_type_and_clear(ADRS.TREE)
            adrs.set_tree_height(z)
            adrs.set_tree_index(i)
            node = self.h_h(pk_seed, adrs, lnode + rnode)
        return node

    def xmss_sign(self, m: bytes, sk_seed: bytes, idx: int, pk_seed: bytes, adrs: ADRS) -> bytes:
        """Algorithm 10: xmss_sign(M, SK.seed, idx, PK.seed, ADRS).

        Generate an XMSS signature.
        """
        auth = b""
        for j in range(self.hp):
            k = (idx >> j) ^ 1
            auth += self.xmss_node(sk_seed, k, j, pk_seed, adrs)
        adrs.set_type_and_clear(ADRS.WOTS_HASH)
        adrs.set_key_pair_address(idx)
        sig = self.wots_sign(m, sk_seed, pk_seed, adrs)
        sig_xmss = sig + auth
        return sig_xmss

    def xmss_pk_from_sig(self, idx, sig_xmss, m, pk_seed, adrs):
        """Algorithm 11: xmss_PKFromSig(idx, SIG_XMSS, M, PK.seed, ADRS).

        Compute an XMSS public key from an XMSS signature.
        """
        adrs.set_type_and_clear(ADRS.WOTS_HASH)
        adrs.set_key_pair_address(idx)
        sig = sig_xmss[0 : self.len * self.n]
        auth = sig_xmss[self.len * self.n :]
        node_0 = self.wots_pk_from_sig(sig, m, pk_seed, adrs)

        adrs.set_type_and_clear(ADRS.TREE)
        adrs.set_tree_index(idx)
        for k in range(self.hp):
            adrs.set_tree_height(k + 1)
            auth_k = auth[k * self.n : (k + 1) * self.n]
            if (idx >> k) & 1 == 0:
                adrs.set_tree_index(adrs.get_tree_index() // 2)
                node_1 = self.h_h(pk_seed, adrs, node_0 + auth_k)
            else:
                adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                node_1 = self.h_h(pk_seed, adrs, auth_k + node_0)
            node_0 = node_1

        return node_0

    def ht_sign(self, m: bytes, sk_seed: bytes, pk_seed: bytes, i_tree: int, i_leaf: int):
        """Algorithm 12: ht_sign(M, SK.seed, PK.seed, idx_tree, idx_leaf).

        Generate a hypertree signature.

        :param m: The message to sign.
        :param sk_seed: The secret seed.
        :param pk_seed: The public seed.
        :param i_tree: The tree index.
        :param i_leaf: The leaf index.
        """
        adrs = ADRS()
        adrs.set_tree_address(i_tree)
        sig_tmp = self.xmss_sign(m, sk_seed, i_leaf, pk_seed, adrs)
        sig_ht = sig_tmp
        root = self.xmss_pk_from_sig(i_leaf, sig_tmp, m, pk_seed, adrs)
        hp_m = (1 << self.hp) - 1
        for j in range(1, self.d):
            i_leaf = i_tree & hp_m
            i_tree = i_tree >> self.hp
            adrs.set_layer_address(j)
            adrs.set_tree_address(i_tree)
            sig_tmp = self.xmss_sign(root, sk_seed, i_leaf, pk_seed, adrs)
            sig_ht += sig_tmp
            if j < self.d - 1:
                root = self.xmss_pk_from_sig(i_leaf, sig_tmp, root, pk_seed, adrs)
        return sig_ht

    def ht_verify(self, m, sig_ht, pk_seed, i_tree, i_leaf, pk_root) -> bool:
        """Algorithm 13: ht_verify(M, SIG_HT, PK.seed, idx_tree, idx_leaf,PK.root).

        Verify a hypertree signature.

        :param m: The message.
        :param sig_ht: The signature.
        :param pk_seed: The public seed.
        :param i_tree: The tree index.
        :param i_leaf: The leaf index.
        :param pk_root: The root public key.
        :return: True if the signature is valid, False otherwise.


        """
        adrs = ADRS()
        adrs.set_tree_address(i_tree)
        sig_tmp = sig_ht[0 : (self.hp + self.len) * self.n]
        node = self.xmss_pk_from_sig(i_leaf, sig_tmp, m, pk_seed, adrs)

        hp_m = (1 << self.hp) - 1
        for j in range(1, self.d):
            i_leaf = i_tree & hp_m
            i_tree = i_tree >> self.hp
            adrs.set_layer_address(j)
            adrs.set_tree_address(i_tree)
            sig_tmp = sig_ht[j * (self.hp + self.len) * self.n : (j + 1) * (self.hp + self.len) * self.n]
            node = self.xmss_pk_from_sig(i_leaf, sig_tmp, node, pk_seed, adrs)
        return node == pk_root

    def fors_sk_gen(self, sk_seed, pk_seed, adrs, idx):
        """Algorithm 14: fors_SKgen(SK.seed, PK.seed, ADRS, idx).
        Generate a FORS private-key value.
        """
        sk_adrs = adrs.copy()
        sk_adrs.set_type_and_clear(ADRS.FORS_PRF)
        sk_adrs.set_key_pair_address(adrs.get_key_pair_address())
        sk_adrs.set_tree_index(idx)
        return self.prf(pk_seed, sk_seed, sk_adrs)

    def fors_node(self, sk_seed, i, z, pk_seed, adrs):
        """Algorithm 15: fors_node(SK.seed, i, z, PK.seed, ADRS).

        Compute the root of a Merkle subtree of FORS public values.
        """
        if z > self.a or i >= (self.k << (self.a - z)):
            return None
        if z == 0:
            sk = self.fors_sk_gen(sk_seed, pk_seed, adrs, i)
            adrs.set_tree_height(0)
            adrs.set_tree_index(i)
            node = self.h_f(pk_seed, adrs, sk)
        else:
            lnode = self.fors_node(sk_seed, 2 * i, z - 1, pk_seed, adrs)
            rnode = self.fors_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs)
            adrs.set_tree_height(z)
            adrs.set_tree_index(i)
            node = self.h_h(pk_seed, adrs, lnode + rnode)
        return node

    def fors_sign(self, md: bytes, sk_seed: bytes, pk_seed: bytes, adrs: ADRS):
        """Algorithm 16: fors_sign(md, SK.seed, PK.seed, ADRS).

        Generate a FORS signature.

        :param md: The message digest.
        :param sk_seed: The secret seed.
        :param pk_seed: The public seed.
        :param adrs: The address.

        """
        sig_fors = b""
        indices = self.base_2b(md, self.a, self.k)
        for i in range(self.k):
            sig_fors += self.fors_sk_gen(sk_seed, pk_seed, adrs, (i << self.a) + indices[i])
            for j in range(self.a):
                s = (indices[i] >> j) ^ 1
                sig_fors += self.fors_node(sk_seed, (i << (self.a - j)) + s, j, pk_seed, adrs)
        return sig_fors

    def fors_pk_from_sig(self, sig_fors, md, pk_seed, adrs):
        """Algorithm 17: fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS).

        Compute a FORS public key from a FORS signature.
        """

        def get_sk(sig_fors, i):
            return sig_fors[i * (self.a + 1) * self.n : (i * (self.a + 1) + 1) * self.n]

        def get_auth(sig_fors, i):
            return sig_fors[(i * (self.a + 1) + 1) * self.n : (i + 1) * (self.a + 1) * self.n]

        indices = self.base_2b(md, self.a, self.k)

        root = b""
        for i in range(self.k):
            sk = get_sk(sig_fors, i)
            adrs.set_tree_height(0)
            adrs.set_tree_index((i << self.a) + indices[i])
            node_0 = self.h_f(pk_seed, adrs, sk)

            auth = get_auth(sig_fors, i)
            for j in range(self.a):
                auth_j = auth[j * self.n : (j + 1) * self.n]
                adrs.set_tree_height(j + 1)
                if (indices[i] >> j) & 1 == 0:
                    adrs.set_tree_index(adrs.get_tree_index() // 2)
                    node_1 = self.h_h(pk_seed, adrs, node_0 + auth_j)
                else:
                    adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                    node_1 = self.h_h(pk_seed, adrs, auth_j + node_0)
                node_0 = node_1
            root += node_0

        fors_pk_adrs = adrs.copy()
        fors_pk_adrs.set_type_and_clear(ADRS.FORS_ROOTS)
        fors_pk_adrs.set_key_pair_address(adrs.get_key_pair_address())
        pk = self.h_t(pk_seed, fors_pk_adrs, root)
        return pk

    def slh_keygen_internal(self, sk_seed: bytes, sk_prf: bytes, pk_seed: bytes) -> Tuple[bytes, bytes]:
        """Algorithm 18: slh_keygen_internal().

        :param sk_seed: The secret seed.
        :param sk_prf: The secret Pseudo-Random Function seed.
        :param pk_seed: The public seed.
        :returns: The public and secret key.
        """
        #   The behavior is different if one performs three distinct
        adrs = ADRS()
        adrs.set_layer_address(self.d - 1)
        pk_root = self.xmss_node(sk_seed, 0, self.hp, pk_seed, adrs)
        sk = sk_seed + sk_prf + pk_seed + pk_root
        pk = pk_seed + pk_root
        return (pk, sk)  #   Alg 17 has (sk, pk)

    def split_digest(self, digest: bytes) -> Tuple[bytes, int, int]:
        """Helper: Lines 11-16 of Alg 18 / Lines 10-15 of Alg 19."""
        ka1 = (self.k * self.a + 7) // 8
        md = digest[0:ka1]
        hd = self.h // self.d
        hhd = self.h - hd
        ka2 = ka1 + ((hhd + 7) // 8)
        i_tree = self.to_int(digest[ka1:ka2], (hhd + 7) // 8) % (2**hhd)
        ka3 = ka2 + ((hd + 7) // 8)
        i_leaf = self.to_int(digest[ka2:ka3], (hd + 7) // 8) % (2**hd)
        return md, i_tree, i_leaf

    def slh_sign_internal(self, m: bytes, sk: bytes, addrnd: Optional[bytes] = None) -> bytes:
        """Algorithm 19: slh_sign_internal(M, SK).

        :param m: The message to sign.
        :param sk: The secret key.
        :param addrnd: The optional random address, as bytes. Defaults to `pk_seed`.
        """
        adrs = ADRS()
        sk_seed = sk[0 : self.n]
        sk_prf = sk[self.n : 2 * self.n]
        pk_seed = sk[2 * self.n : 3 * self.n]
        pk_root = sk[3 * self.n :]

        if addrnd is None:
            addrnd = pk_seed

        r = self.prf_msg(sk_prf, addrnd, m)
        sig = r

        digest = self.h_msg(r, pk_seed, pk_root, m)
        (md, i_tree, i_leaf) = self.split_digest(digest)

        adrs.set_tree_address(i_tree)
        adrs.set_type_and_clear(ADRS.FORS_TREE)
        adrs.set_key_pair_address(i_leaf)

        sig_fors = self.fors_sign(md, sk_seed, pk_seed, adrs)
        sig += sig_fors

        pk_fors = self.fors_pk_from_sig(sig_fors, md, pk_seed, adrs)
        sig_ht = self.ht_sign(pk_fors, sk_seed, pk_seed, i_tree, i_leaf)
        sig += sig_ht

        return sig

    def slh_verify_internal(self, m, sig, pk):
        """Algorithm 20: slh_verify_internal(M, SIG, PK)."""
        if len(sig) != self.sig_sz or len(pk) != self.pk_sz:
            return False

        pk_seed = pk[: self.n]
        pk_root = pk[self.n :]

        adrs = ADRS()
        r = sig[0 : self.n]
        sig_fors = sig[self.n : (1 + self.k * (1 + self.a)) * self.n]
        sig_ht = sig[(1 + self.k * (1 + self.a)) * self.n :]

        digest = self.h_msg(r, pk_seed, pk_root, m)
        (md, i_tree, i_leaf) = self.split_digest(digest)

        adrs.set_tree_address(i_tree)
        adrs.set_type_and_clear(ADRS.FORS_TREE)
        adrs.set_key_pair_address(i_leaf)

        pk_fors = self.fors_pk_from_sig(sig_fors, md, pk_seed, adrs)
        return self.ht_verify(pk_fors, sig_ht, pk_seed, i_tree, i_leaf, pk_root)

    #   XXX Note 2024-11-09: Not covered by test vectors.
    def slh_keygen(self, param: Optional[str] = None):
        """Algorithm 21, Algorithm 21 slh_keygen().

        :param param: The parameter set to use, identified by the hash function.
        (e,g., "shake256").
        """
        if param is not None:
            self.__init__(param)
        sk_seed = self.rbg(self.n)
        sk_prf = self.rbg(self.n)
        pk_seed = self.rbg(self.n)
        return self.slh_keygen_internal(sk_seed, sk_prf, pk_seed)

    #   XXX Note 2024-11-09: Not covered by test vectors.
    def slh_sign(self, m: bytes, ctx: bytes, sk: bytes, addrnd=None, param: Optional[str] = None):
        """Algorithm 22, slh_sign(M, ctx, SK).

        :param m: The message to sign.
        :param ctx: The context.
        :param sk: The secret key.
        :param addrnd: The random address.
        :param param: The parameter set to use, identified by the hash function.
        """
        if param is not None:
            self.__init__(param)
        if len(ctx) > 255:
            return None

        mp = integer_to_bytes(0, 1) + integer_to_bytes(len(ctx), 1) + ctx + m
        sig = self.slh_sign_internal(mp, sk, addrnd)
        return sig

    #   XXX Note 2024-11-09: Not covered by test vectors.
    def hash_slh_sign(self, m, ctx, ph, sk, rnd=None, param=None):
        """Algorithm 23, hash_slh_sign(M, ctx, PH, SK)."""
        if param is not None:
            self.__init__(param)
        if len(ctx) > 255:
            raise ValueError(f"The provided context is too long: {len(ctx)}")

        if ph == "sha-256":
            oid = bytes([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])
            phm = SHA256.new(m).digest()
        elif ph == "sha-512":
            oid = bytes([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03])
            phm = SHA512.new(m).digest()
        elif ph == "shake128":
            oid = bytes([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B])
            phm = SHAKE128.new(m).read(256 // 8)
        elif ph == "shake256":
            oid = bytes([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C])
            phm = SHAKE256.new(m).read(512 // 8)
        else:
            return None

        mp = integer_to_bytes(1, 1) + integer_to_bytes(len(ctx), 1) + ctx + oid + phm
        sig = self.slh_sign_internal(sk, mp, rnd)
        return sig

    #   XXX Note 2024-11-09: Not covered by test vectors.
    def slh_verify(self, m: bytes, sig: bytes, ctx: bytes, pk: bytes, param: Optional[str] = None) -> bool:
        """Algorithm 24, slh_verify(M, SIG, ctx, PK).

        :param m: The message to verify.
        :param sig: The signature to verify.
        :param ctx: The context.
        :param pk: The public key.
        :param param: The parameter set to use, identified by the hash function.
        :return: True if the signature is valid, False otherwise.
        """
        if param is not None:
            self.__init__(param)
        if len(ctx) > 255:
            return False

        mp = integer_to_bytes(0, 1) + integer_to_bytes(len(ctx), 1) + ctx + m
        return self.slh_verify_internal(mp, sig, pk)

    #   XXX Note 2024-11-09: Not covered by test vectors.
    def hash_ml_dsa_verify(
        self, pk: bytes, m: bytes, sig: bytes, ctx: bytes, ph: str, param: Optional[str] = None
    ) -> bool:
        """Algorithm 25, hash_slh_verify(M, SIG, ctx, PH, PK).

        :param pk: The public key.
        :param m: The message to verify.
        :param sig: The signature to verify.
        :param ctx: The context.
        :param ph: The hash function to use.
        :param param: The parameter set to use.
        :return: True if the signature is valid, False otherwise
        """
        if param is not None:
            self.__init__(param)
        if len(ctx) > 255:
            raise ValueError(f"The provided context is too long: {len(ctx)}")

        if ph == "SHA-256":
            oid = bytes([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])
            phm = SHA256.new(m).digest()
        elif ph == "SHA-512":
            oid = bytes([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03])
            phm = SHA512.new(m).digest()
        elif ph == "SHAKE128":
            oid = bytes([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B])
            phm = SHAKE128.new(m).read(256 // 8)
        elif ph == "SHAKE256":
            oid = bytes([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C])
            phm = SHAKE256.new(m).read(512 // 8)
        else:
            raise ValueError(f"Unsupported hash function: {ph}")

        mp = integer_to_bytes(1, 1) + integer_to_bytes(len(ctx), 1) + ctx + oid + phm
        return self.slh_verify_internal(mp, sig, pk)


#   Section 11: Table 2. SLH-DSA parameter sets
SLH_DSA_PARAMS = {
    "slh-dsa-sha2-128s": SLH_DSA(hashname="SHA2", n=16, h=63, d=7, hp=9, a=12, k=14, lg_w=4, m=30),
    "slh-dsa-shake-128s": SLH_DSA(hashname="SHAKE", n=16, h=63, d=7, hp=9, a=12, k=14, lg_w=4, m=30),
    "slh-dsa-sha2-128f": SLH_DSA(hashname="SHA2", n=16, h=66, d=22, hp=3, a=6, k=33, lg_w=4, m=34),
    "slh-dsa-shake-128f": SLH_DSA(hashname="SHAKE", n=16, h=66, d=22, hp=3, a=6, k=33, lg_w=4, m=34),
    "slh-dsa-sha2-192s": SLH_DSA(hashname="SHA2", n=24, h=63, d=7, hp=9, a=14, k=17, lg_w=4, m=39),
    "slh-dsa-shake-192s": SLH_DSA(hashname="SHAKE", n=24, h=63, d=7, hp=9, a=14, k=17, lg_w=4, m=39),
    "slh-dsa-sha2-192f": SLH_DSA(hashname="SHA2", n=24, h=66, d=22, hp=3, a=8, k=33, lg_w=4, m=42),
    "slh-dsa-shake-192f": SLH_DSA(hashname="SHAKE", n=24, h=66, d=22, hp=3, a=8, k=33, lg_w=4, m=42),
    "slh-dsa-sha2-256s": SLH_DSA(hashname="SHA2", n=32, h=64, d=8, hp=8, a=14, k=22, lg_w=4, m=47),
    "slh-dsa-shake-256s": SLH_DSA(hashname="SHAKE", n=32, h=64, d=8, hp=8, a=14, k=22, lg_w=4, m=47),
    "slh-dsa-sha2-256f": SLH_DSA(hashname="SHA2", n=32, h=68, d=17, hp=4, a=9, k=35, lg_w=4, m=49),
    "slh-dsa-shake-256f": SLH_DSA(hashname="SHAKE", n=32, h=68, d=17, hp=4, a=9, k=35, lg_w=4, m=49),
}


def param_keygen(sk_seed: bytes, sk_prf, pk_seed: bytes, param: str):
    """Generate a SLH-DSA key pair."""
    slh = SLH_DSA_PARAMS[param]
    return slh.slh_keygen_internal(sk_seed, sk_prf, pk_seed)


def param_sign(msg: bytes, sk: bytes, addrnd: Optional[bytes], param: str) -> bytes:
    """Sign a message with SLH-DSA.

    :param msg: The message to sign.
    :param sk: The secret key.
    :param addrnd: The optional random address.
    :param param: The parameter set to use, identified by the hash function.
    :return: The signature.
    """
    slh = SLH_DSA_PARAMS[param]
    return slh.slh_sign_internal(msg, sk, addrnd)


def param_verify(msg, sig, pk, param):
    """Verify a SLH-DSA signature."""
    slh = SLH_DSA_PARAMS[param]
    return slh.slh_verify_internal(msg, sig, pk)
