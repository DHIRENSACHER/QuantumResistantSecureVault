"""Unit tests for the Quantum-Resistant File Vault engine."""

import pytest
from src.identity import IdentityKeyPair
from src.crypto.kem import MLKEM768
from src.vault import FileChunker, VaultEncryptor, VaultFileManifest, FileVaultEngine


class TestFileVault:
    def test_chunker_exact_reassembly(self):
        data = b"Arbitrary chunker test stream bytes" * 500
        chunks, total_size, full_hash = FileChunker.chunk_bytes(data, chunk_size=256)

        assert total_size == len(data)
        assert len(chunks) == (len(data) + 255) // 256
        reassembled = b"".join(c.data for c in chunks)
        assert reassembled == data

    def test_dek_wrap_unwrap(self):
        pk, sk = MLKEM768.generate_keypair()
        dek = VaultEncryptor.generate_dek()

        wrapped_dek = VaultEncryptor.wrap_dek(dek, pk)
        unwrapped_dek = VaultEncryptor.unwrap_dek(wrapped_dek, sk)

        assert unwrapped_dek == dek

    def test_multi_chunk_packaging_and_reassembly(self):
        alice_id = IdentityKeyPair.generate("alice")
        bob_id = IdentityKeyPair.generate("bob")
        bob_pk, bob_sk = MLKEM768.generate_keypair()

        file_content = b"Quantum-Resistant Secure Vault Multi-Chunk Verification\n" * 1000  # ~56 KB
        manifest, encrypted_chunks = FileVaultEngine.package_file(
            file_bytes=file_content,
            filename="document.docx",
            sender_identity=alice_id,
            recipient_id="bob",
            recipient_mlkem_pub=bob_pk,
            chunk_size=4096,  # 4 KB chunks -> ~14 chunks
        )

        assert manifest.chunk_count > 10
        assert manifest.verify(alice_id.mldsa_pub) is True

        # Reassemble
        decrypted = FileVaultEngine.reassemble_file(
            manifest=manifest,
            encrypted_chunks=encrypted_chunks,
            recipient_mlkem_priv=bob_sk,
            sender_mldsa_pub=alice_id.mldsa_pub,
        )
        assert decrypted == file_content

    def test_tampered_chunk_detected(self):
        alice_id = IdentityKeyPair.generate("alice")
        bob_id = IdentityKeyPair.generate("bob")
        bob_pk, bob_sk = MLKEM768.generate_keypair()

        file_content = b"Data to be tampered in transit" * 200
        manifest, encrypted_chunks = FileVaultEngine.package_file(
            file_bytes=file_content,
            filename="tamper_test.txt",
            sender_identity=alice_id,
            recipient_id="bob",
            recipient_mlkem_pub=bob_pk,
            chunk_size=1024,
        )

        # Corrupt one chunk
        first_chunk_hash = manifest.encrypted_chunk_hashes[0]
        corrupted_bytes = bytearray(encrypted_chunks[first_chunk_hash])
        corrupted_bytes[10] ^= 0x55
        encrypted_chunks[first_chunk_hash] = bytes(corrupted_bytes)

        with pytest.raises(ValueError, match="hash mismatch"):
            FileVaultEngine.reassemble_file(
                manifest=manifest,
                encrypted_chunks=encrypted_chunks,
                recipient_mlkem_priv=bob_sk,
                sender_mldsa_pub=alice_id.mldsa_pub,
            )

    def test_tampered_manifest_signature_rejected(self):
        alice_id = IdentityKeyPair.generate("alice")
        bob_id = IdentityKeyPair.generate("bob")
        bob_pk, bob_sk = MLKEM768.generate_keypair()

        manifest, encrypted_chunks = FileVaultEngine.package_file(
            file_bytes=b"Manifest signature tamper test",
            filename="test.txt",
            sender_identity=alice_id,
            recipient_id="bob",
            recipient_mlkem_pub=bob_pk,
        )

        # Alter filename in manifest
        manifest.filename = "hacked_name.exe"

        with pytest.raises(ValueError, match="Manifest ML-DSA-65 signature is invalid"):
            FileVaultEngine.reassemble_file(
                manifest=manifest,
                encrypted_chunks=encrypted_chunks,
                recipient_mlkem_priv=bob_sk,
                sender_mldsa_pub=alice_id.mldsa_pub,
            )
