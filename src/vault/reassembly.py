"""High-level packaging, encryption, validation, and reassembly of vault files."""

from __future__ import annotations

import hashlib
import time
import uuid
from typing import Dict, Tuple
from src.identity.keys import IdentityKeyPair
from src.vault.chunker import FileChunker
from src.vault.encryption import VaultEncryptor
from src.vault.manifest import VaultFileManifest


class FileVaultEngine:
    """End-to-end engine for packaging and unpackaging vault files."""

    @classmethod
    def package_file(
        cls,
        file_bytes: bytes,
        filename: str,
        sender_identity: IdentityKeyPair,
        recipient_id: str,
        recipient_mlkem_pub: bytes,
        recipient_prekey_id: int | None = None,
        chunk_size: int = FileChunker.DEFAULT_CHUNK_SIZE,
    ) -> Tuple[VaultFileManifest, Dict[str, bytes]]:
        """Splits file into chunks, encrypts each chunk under an ephemeral AES-256 DEK,
        wraps the DEK with recipient's ML-KEM-768 public key, and signs the manifest.

        Returns:
            Tuple of (signed_manifest, dict_of_encrypted_chunks_by_hash)
        """
        # 1. Chunk file
        chunks, total_size, file_hash = FileChunker.chunk_bytes(file_bytes, chunk_size)

        # 2. Ephemeral DEK and ML-KEM-768 wrapping
        dek = VaultEncryptor.generate_dek()
        wrapped_dek = VaultEncryptor.wrap_dek(dek, recipient_mlkem_pub)

        # 3. Encrypt each chunk
        encrypted_chunks: Dict[str, bytes] = {}
        chunk_hashes = []
        encrypted_chunk_hashes = []

        for chunk in chunks:
            chunk_hashes.append(chunk.sha256_hex)
            ct_bytes, ct_hash = VaultEncryptor.encrypt_chunk(dek, chunk)
            encrypted_chunks[ct_hash] = ct_bytes
            encrypted_chunk_hashes.append(ct_hash)

        # 4. Construct and sign manifest
        file_id = str(uuid.uuid4())
        manifest = VaultFileManifest(
            file_id=file_id,
            filename=filename,
            total_size=total_size,
            chunk_size=chunk_size,
            chunk_count=len(chunks),
            file_hash=file_hash,
            chunk_hashes=chunk_hashes,
            encrypted_chunk_hashes=encrypted_chunk_hashes,
            wrapped_dek=wrapped_dek,
            sender_id=sender_identity.user_id,
            recipient_id=recipient_id,
            recipient_prekey_id=recipient_prekey_id,
            timestamp=time.time(),
        )
        manifest.sign(sender_identity)

        return manifest, encrypted_chunks

    @classmethod
    def reassemble_file(
        cls,
        manifest: VaultFileManifest,
        encrypted_chunks: Dict[str, bytes],
        recipient_mlkem_priv: bytes,
        sender_mldsa_pub: bytes,
    ) -> bytes:
        """Verifies manifest signature, unwraps DEK with ML-KEM-768 secret key,
        authenticates and decrypts all chunks, and reassembles the original file.

        Returns:
            Reassembled original plaintext file bytes.
        Raises:
            ValueError on signature failure, missing chunk, or hash mismatch.
        """
        # 1. Cryptographically verify sender's ML-DSA-65 signature on manifest
        if not manifest.verify(sender_mldsa_pub):
            raise ValueError("Vault file rejected: Manifest ML-DSA-65 signature is invalid!")

        # 2. Unwrap DEK using recipient's ML-KEM-768 secret key
        dek = VaultEncryptor.unwrap_dek(manifest.wrapped_dek, recipient_mlkem_priv)

        # 3. Decrypt and verify each chunk in order
        reassembled_chunks = []
        full_hasher = hashlib.sha256()

        for idx, (expected_pt_hash, expected_ct_hash) in enumerate(
            zip(manifest.chunk_hashes, manifest.encrypted_chunk_hashes)
        ):
            if expected_ct_hash not in encrypted_chunks:
                raise ValueError(f"Missing encrypted chunk {idx} ({expected_ct_hash})")

            ct_data = encrypted_chunks[expected_ct_hash]

            # Verify ciphertext hash
            actual_ct_hash = hashlib.sha256(ct_data).hexdigest()
            if actual_ct_hash != expected_ct_hash:
                raise ValueError(f"Encrypted chunk {idx} hash mismatch!")

            # Decrypt and verify plaintext hash
            pt_chunk = VaultEncryptor.decrypt_chunk(
                dek=dek,
                chunk_index=idx,
                expected_plaintext_sha256_hex=expected_pt_hash,
                ciphertext=ct_data,
            )
            full_hasher.update(pt_chunk)
            reassembled_chunks.append(pt_chunk)

        # 4. Final verification of full reassembled file hash
        final_hash = full_hasher.hexdigest()
        if final_hash != manifest.file_hash:
            raise ValueError(
                f"Full file integrity check failed: expected {manifest.file_hash}, got {final_hash}"
            )

        return b"".join(reassembled_chunks)
