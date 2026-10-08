"""Quantum-resistant file chunk encryption, key encapsulation, and DEK wrapping."""

from __future__ import annotations

import base64
import hashlib
import struct
from typing import Dict, Tuple
from src.crypto.kem import MLKEM768
from src.crypto.symmetric import AES256GCMCipher, hkdf_derive, zeroize
from src.vault.chunker import FileChunk


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


class WrappedDEK:
    """Carries the ML-KEM-768 encapsulated Data Encryption Key (DEK)."""

    def __init__(self, mlkem_ct: bytes, encrypted_dek: bytes, nonce: bytes):
        self.mlkem_ct = mlkem_ct
        self.encrypted_dek = encrypted_dek
        self.nonce = nonce

    def to_dict(self) -> dict:
        return {
            "mlkem_ct": b64e(self.mlkem_ct),
            "encrypted_dek": b64e(self.encrypted_dek),
            "nonce": b64e(self.nonce),
        }

    @classmethod
    def from_dict(cls, d: dict) -> WrappedDEK:
        return cls(
            mlkem_ct=b64d(d["mlkem_ct"]),
            encrypted_dek=b64d(d["encrypted_dek"]),
            nonce=b64d(d["nonce"]),
        )


class VaultEncryptor:
    """Manages file encryption with ephemeral AES-256-GCM DEKs and ML-KEM-768 key encapsulation."""

    WRAP_INFO = b"HPQ-Vault-DEK-Wrap-v1"

    @classmethod
    def generate_dek(cls) -> bytes:
        return AES256GCMCipher.generate_key()

    @classmethod
    def wrap_dek(cls, dek: bytes, recipient_mlkem_pub: bytes) -> WrappedDEK:
        """Wraps (encrypts) the ephemeral DEK under the recipient's ML-KEM-768 public key."""
        shared_secret, mlkem_ct = MLKEM768.encapsulate(recipient_mlkem_pub)

        # Encrypt DEK under the ML-KEM shared secret
        encrypted_dek, nonce = AES256GCMCipher.encrypt(
            key=shared_secret,
            plaintext=dek,
            associated_data=cls.WRAP_INFO,
        )

        ss_ba = bytearray(shared_secret)
        zeroize(ss_ba)

        return WrappedDEK(mlkem_ct=mlkem_ct, encrypted_dek=encrypted_dek, nonce=nonce)

    @classmethod
    def unwrap_dek(cls, wrapped_dek: WrappedDEK, recipient_mlkem_priv: bytes) -> bytes:
        """Unwraps the DEK using the recipient's ML-KEM-768 secret key."""
        shared_secret = MLKEM768.decapsulate(recipient_mlkem_priv, wrapped_dek.mlkem_ct)

        dek = AES256GCMCipher.decrypt(
            key=shared_secret,
            nonce=wrapped_dek.nonce,
            ciphertext=wrapped_dek.encrypted_dek,
            associated_data=cls.WRAP_INFO,
        )

        ss_ba = bytearray(shared_secret)
        zeroize(ss_ba)

        return dek

    @classmethod
    def derive_chunk_nonce(cls, dek: bytes, chunk_index: int) -> bytes:
        """Deterministically derives a unique 96-bit (12-byte) nonce for each chunk."""
        return hkdf_derive(
            salt=b"HPQ-Vault-ChunkNonce-Salt",
            ikm=dek,
            info=b"HPQ-Vault-Chunk-" + struct.pack(">I", chunk_index),
            length=12,
        )

    @classmethod
    def encrypt_chunk(cls, dek: bytes, chunk: FileChunk) -> Tuple[bytes, str]:
        """Encrypts a single FileChunk.

        Returns:
            Tuple of (ciphertext_with_tag, ciphertext_sha256_hex)
        """
        nonce = cls.derive_chunk_nonce(dek, chunk.index)
        ad = b"HPQ-Chunk-" + struct.pack(">I", chunk.index) + chunk.sha256_hex.encode("ascii")

        ciphertext, _ = AES256GCMCipher.encrypt(
            key=dek,
            plaintext=chunk.data,
            associated_data=ad,
            nonce=nonce,
        )
        ct_sha256 = hashlib.sha256(ciphertext).hexdigest()
        return ciphertext, ct_sha256

    @classmethod
    def decrypt_chunk(
        cls,
        dek: bytes,
        chunk_index: int,
        expected_plaintext_sha256_hex: str,
        ciphertext: bytes,
    ) -> bytes:
        """Decrypts a chunk and asserts plaintext integrity against manifest hash."""
        nonce = cls.derive_chunk_nonce(dek, chunk_index)
        ad = b"HPQ-Chunk-" + struct.pack(">I", chunk_index) + expected_plaintext_sha256_hex.encode("ascii")

        plaintext = AES256GCMCipher.decrypt(
            key=dek,
            nonce=nonce,
            ciphertext=ciphertext,
            associated_data=ad,
        )

        # Integrity verification
        actual_hash = hashlib.sha256(plaintext).hexdigest()
        if actual_hash != expected_plaintext_sha256_hex:
            raise ValueError(
                f"Chunk {chunk_index} integrity check failed: expected {expected_plaintext_sha256_hex}, got {actual_hash}"
            )

        return plaintext
