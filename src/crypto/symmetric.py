"""Symmetric cryptography primitives: AES-256-GCM, ChaCha20-Poly1305, HKDF-SHA256."""

from __future__ import annotations

import hmac
import os
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand


def zeroize(buffer: bytearray | memoryview) -> None:
    """Overwrites sensitive memory buffer in place."""
    for i in range(len(buffer)):
        buffer[i] = 0


def constant_time_compare(val1: bytes, val2: bytes) -> bool:
    """Constant-time byte sequence equality check."""
    return hmac.compare_digest(val1, val2)


class AES256GCMCipher:
    """AES-256-GCM authenticated encryption with 256-bit keys and 96-bit nonces."""

    KEY_SIZE = 32  # 256 bits
    NONCE_SIZE = 12  # 96 bits
    TAG_SIZE = 16  # 128 bits

    @classmethod
    def generate_key(cls) -> bytes:
        return os.urandom(cls.KEY_SIZE)

    @classmethod
    def generate_nonce(cls) -> bytes:
        return os.urandom(cls.NONCE_SIZE)

    @classmethod
    def encrypt(
        cls,
        key: bytes,
        plaintext: bytes,
        associated_data: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        """Encrypts plaintext with AES-256-GCM.

        Returns:
            Tuple of (ciphertext_with_tag, nonce)
        """
        if len(key) != cls.KEY_SIZE:
            raise ValueError(f"AES-256 key must be {cls.KEY_SIZE} bytes, got {len(key)}")
        if nonce is None:
            nonce = cls.generate_nonce()
        elif len(nonce) != cls.NONCE_SIZE:
            raise ValueError(f"AES-GCM nonce must be {cls.NONCE_SIZE} bytes, got {len(nonce)}")

        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        return ciphertext, nonce

    @classmethod
    def decrypt(
        cls,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """Decrypts and verifies ciphertext with AES-256-GCM.

        Raises:
            cryptography.exceptions.InvalidTag on tamper or wrong key.
        """
        if len(key) != cls.KEY_SIZE:
            raise ValueError(f"AES-256 key must be {cls.KEY_SIZE} bytes, got {len(key)}")
        if len(nonce) != cls.NONCE_SIZE:
            raise ValueError(f"AES-GCM nonce must be {cls.NONCE_SIZE} bytes, got {len(nonce)}")

        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)


class ChaCha20Poly1305Cipher:
    """ChaCha20-Poly1305 authenticated encryption with 256-bit keys and 96-bit nonces."""

    KEY_SIZE = 32
    NONCE_SIZE = 12

    @classmethod
    def generate_key(cls) -> bytes:
        return os.urandom(cls.KEY_SIZE)

    @classmethod
    def encrypt(
        cls,
        key: bytes,
        plaintext: bytes,
        associated_data: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        if len(key) != cls.KEY_SIZE:
            raise ValueError(f"Key must be {cls.KEY_SIZE} bytes, got {len(key)}")
        if nonce is None:
            nonce = os.urandom(cls.NONCE_SIZE)
        chacha = ChaCha20Poly1305(key)
        ciphertext = chacha.encrypt(nonce, plaintext, associated_data)
        return ciphertext, nonce

    @classmethod
    def decrypt(
        cls,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        if len(key) != cls.KEY_SIZE:
            raise ValueError(f"Key must be {cls.KEY_SIZE} bytes, got {len(key)}")
        chacha = ChaCha20Poly1305(key)
        return chacha.decrypt(nonce, ciphertext, associated_data)


def hkdf_extract(salt: Optional[bytes], ikm: bytes) -> bytes:
    """HKDF-Extract using SHA-256 to extract a pseudorandom key (PRK)."""
    if salt is None or len(salt) == 0:
        salt = b"\x00" * 32
    return hmac.new(salt, ikm, hashes.SHA256().name).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-Expand using SHA-256 to expand PRK to desired key length."""
    hkdf_exp = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=length,
        info=info,
    )
    return hkdf_exp.derive(prk)


def hkdf_derive(
    salt: Optional[bytes],
    ikm: bytes,
    info: bytes,
    length: int = 32,
) -> bytes:
    """Full HKDF Extract-and-Expand using SHA-256."""
    hkdf_inst = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt if salt else None,
        info=info,
    )
    return hkdf_inst.derive(ikm)
