"""Cryptographic Vault File Manifest signed with ML-DSA-65."""

from __future__ import annotations

import base64
import json
import uuid
from typing import List, Optional
from src.crypto.signatures import MLDSA65
from src.identity.keys import IdentityKeyPair
from src.vault.encryption import WrappedDEK


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


class VaultFileManifest:
    """End-to-end authenticated file manifest.

    Binds together:
    - Encrypted file metadata (filename, size, chunks)
    - Ordered chunk SHA-256 hashes (plaintext and ciphertext)
    - ML-KEM-768 wrapped Data Encryption Key (DEK)
    - Recipient prekey ID for deterministic key unwrap
    - ML-DSA-65 digital signature by the sender
    """

    def __init__(
        self,
        file_id: str,
        filename: str,
        total_size: int,
        chunk_size: int,
        chunk_count: int,
        file_hash: str,
        chunk_hashes: List[str],
        encrypted_chunk_hashes: List[str],
        wrapped_dek: WrappedDEK,
        sender_id: str,
        recipient_id: str,
        timestamp: float,
        recipient_prekey_id: Optional[int] = None,
        signature: bytes = b"",
    ):
        self.file_id = file_id
        self.filename = filename
        self.total_size = total_size
        self.chunk_size = chunk_size
        self.chunk_count = chunk_count
        self.file_hash = file_hash
        self.chunk_hashes = chunk_hashes
        self.encrypted_chunk_hashes = encrypted_chunk_hashes
        self.wrapped_dek = wrapped_dek
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.timestamp = timestamp
        self.recipient_prekey_id = recipient_prekey_id
        self.signature = signature

    def get_canonical_payload(self) -> bytes:
        """Constructs deterministic JSON payload for signing."""
        canonical_dict = {
            "file_id": self.file_id,
            "filename": self.filename,
            "total_size": self.total_size,
            "chunk_size": self.chunk_size,
            "chunk_count": self.chunk_count,
            "file_hash": self.file_hash,
            "chunk_hashes": self.chunk_hashes,
            "encrypted_chunk_hashes": self.encrypted_chunk_hashes,
            "wrapped_dek": self.wrapped_dek.to_dict(),
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "recipient_prekey_id": self.recipient_prekey_id,
            "timestamp": self.timestamp,
        }
        return b"HPQ-Vault-Manifest-v1:" + json.dumps(canonical_dict, sort_keys=True).encode("utf-8")

    def sign(self, sender_identity: IdentityKeyPair) -> None:
        """Signs the manifest using the sender's ML-DSA-65 identity key."""
        payload = self.get_canonical_payload()
        self.signature = sender_identity.sign(payload)

    def verify(self, sender_mldsa_pub: bytes) -> bool:
        """Verifies the ML-DSA-65 signature on the manifest."""
        payload = self.get_canonical_payload()
        return MLDSA65.verify(sender_mldsa_pub, payload, self.signature)

    def to_dict(self) -> dict:
        return {
            "file_id": self.file_id,
            "filename": self.filename,
            "total_size": self.total_size,
            "chunk_size": self.chunk_size,
            "chunk_count": self.chunk_count,
            "file_hash": self.file_hash,
            "chunk_hashes": self.chunk_hashes,
            "encrypted_chunk_hashes": self.encrypted_chunk_hashes,
            "wrapped_dek": self.wrapped_dek.to_dict(),
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "recipient_prekey_id": self.recipient_prekey_id,
            "timestamp": self.timestamp,
            "signature": b64e(self.signature),
        }

    @classmethod
    def from_dict(cls, d: dict) -> VaultFileManifest:
        return cls(
            file_id=d["file_id"],
            filename=d["filename"],
            total_size=d["total_size"],
            chunk_size=d["chunk_size"],
            chunk_count=d["chunk_count"],
            file_hash=d["file_hash"],
            chunk_hashes=d["chunk_hashes"],
            encrypted_chunk_hashes=d["encrypted_chunk_hashes"],
            wrapped_dek=WrappedDEK.from_dict(d["wrapped_dek"]),
            sender_id=d["sender_id"],
            recipient_id=d["recipient_id"],
            recipient_prekey_id=d.get("recipient_prekey_id"),
            timestamp=d["timestamp"],
            signature=b64d(d["signature"]),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_str: str) -> VaultFileManifest:
        return cls.from_dict(json.loads(json_str))
