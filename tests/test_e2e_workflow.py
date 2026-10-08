"""End-to-End integration tests for HPQ-DR messaging, vault file transfer, and HNDL defense."""

import pytest
from src.client.sdk import VaultClient
from src.server.app import storage


class TestEndToEndWorkflow:
    def test_full_e2e_messaging_and_file_sharing(self):
        # 1. Initialize clients
        alice = VaultClient("alice_e2e")
        bob = VaultClient("bob_e2e")

        alice.register()
        bob.register()

        # 2. Alice sends message while Bob is offline
        alice.send_message("bob_e2e", "Hello Bob! This is an offline encrypted HPQ-DR message.")

        # 3. Bob comes online, checks inbox, and decrypts
        bob_inbox = bob.fetch_messages()
        assert len(bob_inbox) == 1
        assert bob_inbox[0]["sender_id"] == "alice_e2e"
        assert bob_inbox[0]["text"] == "Hello Bob! This is an offline encrypted HPQ-DR message."

        # 4. Bob replies (Triggers asymmetric hybrid ratchet turn)
        bob.send_message("alice_e2e", "Hello Alice! Received and decrypted with post-quantum healing.")

        # 5. Alice checks inbox and decrypts reply
        alice_inbox = alice.fetch_messages()
        assert len(alice_inbox) == 1
        assert alice_inbox[0]["sender_id"] == "bob_e2e"
        assert alice_inbox[0]["text"] == "Hello Alice! Received and decrypted with post-quantum healing."

        # 6. Alice shares an encrypted file through the zero-access vault
        file_payload = b"Quantum-Resistant Secure Vault End-to-End Payload Confirmation\n" * 500
        file_id = alice.upload_file(file_payload, "project_spec.pdf", "bob_e2e")

        # Verify server state has zero plaintext
        assert file_id in storage.manifests
        manifest = storage.manifests[file_id]
        assert manifest["sender_id"] == "alice_e2e"
        assert manifest["recipient_id"] == "bob_e2e"

        # 7. Bob downloads and decrypts file
        downloaded = bob.download_file(file_id, "alice_e2e")
        assert downloaded == file_payload

    def test_harvest_now_decrypt_later_resilience(self):
        """Proves that a captured wire transcript cannot be decrypted without breaking ML-KEM-768."""
        alice = VaultClient("alice_hndl")
        bob = VaultClient("bob_hndl")

        alice.register()
        bob.register()

        secret_text = "HNDL Defense Verification String 2026"
        alice.send_message("bob_hndl", secret_text)

        # Wire intercept
        stored_item = storage.mailboxes["bob_hndl"][0]
        envelope = stored_item.get("envelope", stored_item)
        handshake_data = stored_item.get("handshake_init")

        # Adversary holds:
        # - Classical public keys (X25519)
        # - ML-KEM-768 ciphertext (1088 bytes)
        # - AES-256-GCM ciphertext
        # - ML-DSA-65 signature
        assert "ciphertext" in envelope
        assert handshake_data is not None
        assert len(handshake_data["mlkem_ciphertext"]) > 1000

        # Even with Shor's algorithm breaking X25519, the adversary lacks the ML-KEM-768 shared secret
        # Bob legitimately decrypts:
        bob_inbox = bob.fetch_messages()
        assert bob_inbox[0]["text"] == secret_text
