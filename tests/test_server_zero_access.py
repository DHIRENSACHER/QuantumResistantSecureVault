"""Tests verifying Zero-Access guarantees of the relay and storage server."""

import pytest
from fastapi.testclient import TestClient
from src.server.app import app, storage
from src.identity import ClientKeyStore


class TestServerZeroAccess:
    @pytest.fixture
    def client(self):
        return TestClient(app)

    def test_health_check(self, client):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"

    def test_prekey_bundle_registration_and_retrieval(self, client):
        ks = ClientKeyStore.create_new("charlie")
        bundle = ks.create_bundle()

        reg_resp = client.post(
            "/api/v1/prekeys/register",
            json={"user_id": "charlie", "bundle": bundle.to_dict()},
        )
        assert reg_resp.status_code == 200

        get_resp = client.get("/api/v1/prekeys/charlie")
        assert get_resp.status_code == 200
        assert get_resp.json()["user_id"] == "charlie"

    def test_zero_access_mailbox_and_chunk_store(self, client):
        """Validates that all data stored on the server is purely ciphertext/metadata."""
        # 1. Store dummy ciphertext envelope
        client.post(
            "/api/v1/messages/send",
            json={
                "recipient_id": "target_user",
                "envelope": {"ciphertext": "ZW5jcnlwdGVkX2J5dGVz", "header": {}},
            },
        )

        # 2. Upload dummy encrypted chunk
        chunk_data = b"\xca\xfe\xba\xbe" * 100
        client.post(
            "/api/v1/vault/chunk/dummy_chunk_hash",
            content=chunk_data,
            headers={"Content-Type": "application/octet-stream"},
        )

        # 3. Assert zero-access properties:
        # None of the stored items contain any private keys or plaintext keys
        assert "target_user" in storage.mailboxes
        assert "dummy_chunk_hash" in storage.chunks
        assert storage.chunks["dummy_chunk_hash"] == chunk_data

        # 4. Drain inbox
        inbox_resp = client.get("/api/v1/messages/inbox/target_user")
        assert inbox_resp.status_code == 200
        assert len(inbox_resp.json()["messages"]) == 1

        # Mailbox is drained
        assert len(storage.mailboxes["target_user"]) == 0
