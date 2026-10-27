"""Unit and integration tests for Attacker Interceptor, 3-account keystore isolation, and adversarial attack vectors (Read, Modify, Delete)."""

import pytest
from fastapi.testclient import TestClient

from src.client.sdk import VaultClient
from src.attacker.interceptor import AttackerInterceptor
from src.attacker.server import app as attacker_app
from src.server.app import storage, demo_manager as demo_mgr
from src.crypto.signatures import MLDSA65


class TestAttackerAndThreeAccounts:
    """Verifies Alice, Bob, and Intruder separation and adversarial resilience."""

    def setup_method(self):
        # Reset interceptor state between tests
        self.interceptor = AttackerInterceptor.get_instance()
        self.interceptor.packets.clear()
        self.interceptor.mode = "hold"
        self.interceptor.stats = {
            "total_intercepted": 0,
            "read_attempts": 0,
            "tampered_count": 0,
            "dropped_count": 0,
            "forwarded_count": 0,
        }

    def test_three_accounts_unique_keypairs(self):
        """Validates that Alice, Bob, and Intruder have isolated, distinct cryptographic keypairs."""
        alice = demo_mgr.get_or_create_client("alice")
        bob = demo_mgr.get_or_create_client("bob")
        intruder = demo_mgr.get_or_create_client("intruder")

        # Public keys must all be distinct
        assert alice.keystore.identity.mldsa_pub != bob.keystore.identity.mldsa_pub
        assert alice.keystore.identity.mldsa_pub != intruder.keystore.identity.mldsa_pub
        assert bob.keystore.identity.mldsa_pub != intruder.keystore.identity.mldsa_pub

        assert alice.keystore.identity.x25519_pub != bob.keystore.identity.x25519_pub
        assert alice.keystore.identity.x25519_pub != intruder.keystore.identity.x25519_pub
        assert bob.keystore.identity.x25519_pub != intruder.keystore.identity.x25519_pub

        # User list contains Alice and Bob, and does NOT expose the intruder on the main server
        user_list = demo_mgr.list_users()
        user_ids = [u["user_id"] for u in user_list]
        assert "alice" in user_ids
        assert "bob" in user_ids
        assert "intruder" not in user_ids

    def test_interceptor_packet_capture_on_wire(self):
        """Verifies that sending an encrypted message captures wire traffic in the interceptor."""
        alice = demo_mgr.get_or_create_client("alice")
        bob = demo_mgr.get_or_create_client("bob")

        initial_count = self.interceptor.stats["total_intercepted"]
        res = demo_mgr.send_message("alice", "bob", "Classified communication: Operation PQC")

        assert res["status"] in ["success", "tamper_error"]
        assert self.interceptor.stats["total_intercepted"] == initial_count + 1

        packets = self.interceptor.list_packets()
        assert len(packets) >= 1
        latest_pkt = packets[0]
        assert latest_pkt["sender_id"] == "alice"
        assert latest_pkt["recipient_id"] == "bob"
        assert latest_pkt["ciphertext_b64"] != ""
        assert latest_pkt["signature_b64"] != ""

    def test_attacker_read_cryptanalysis_and_lattice_shield(self):
        """Proves simulated cryptanalysis: classical ECDH is solved, but ML-KEM-768 lattice shield leaks 0 bits."""
        alice = demo_mgr.get_or_create_client("alice")
        bob = demo_mgr.get_or_create_client("bob")

        demo_mgr.send_message("alice", "bob", "Intercept me if you can!")
        packets = self.interceptor.list_packets()
        packet_id = packets[0]["packet_id"]

        read_res = self.interceptor.attempt_read(packet_id)
        assert read_res["packet_id"] == packet_id
        assert read_res["phase_1_trial_decryption"]["status"] == "FAILED"
        assert read_res["phase_2_classical_crqc_attack"]["status"] == "CLASSICAL_COMPROMISED"
        assert read_res["phase_3_lattice_shield_defense"]["status"] == "UNBREAKABLE"
        assert read_res["final_outcome"]["plaintext_revealed"] is False
        assert read_res["final_outcome"]["bytes_leaked"] == 0

    def test_attacker_modify_ciphertext_detected_and_rejected(self):
        """Simulates MITM bit-flipping ciphertext; proves ML-DSA-65 and AEAD reject corrupted data."""
        self.interceptor.set_mode("tamper")

        res = demo_mgr.send_message("alice", "bob", "Integrity critical wire instruction.")
        assert res["status"] == "tamper_error"
        assert res["message"]["is_tampered"] is True
        assert res["message"]["status"] == "tamper_detected_and_dropped"
        assert "Tamper" in res["message"]["text"] or "MAC Invalid" in res["message"]["text"]
        assert res["message"]["signature_verified"] is False

    def test_attacker_modify_signature_corruption(self):
        """Verifies that directly corrupting NIST FIPS 204 ML-DSA-65 signature fails verification."""
        alice = demo_mgr.get_or_create_client("alice")
        bob = demo_mgr.get_or_create_client("bob")

        demo_mgr.send_message("alice", "bob", "Signature tampering test message.")
        packets = self.interceptor.list_packets()
        packet_id = packets[0]["packet_id"]

        tamper_res = self.interceptor.tamper_packet(packet_id, tamper_type="signature_corrupt")
        assert tamper_res["status"] == "tampered"
        tampered_env = tamper_res["tampered_envelope"]

        # Recipient attempts to verify corrupted signature
        from src.protocol.message import SecureEnvelope

        corrupted_env = SecureEnvelope.from_dict(tampered_env)
        assert corrupted_env.verify_signature(alice.keystore.identity.mldsa_pub) is False

    def test_attacker_delete_packet_dos(self):
        """Simulates packet deletion/drop: message never arrives at recipient."""
        self.interceptor.set_mode("drop")

        res = demo_mgr.send_message("alice", "bob", "Ghost packet intended for destruction.")
        assert res["status"] == "dropped_by_attacker"
        assert res["message"]["is_dropped"] is True
        assert "PACKET DROPPED BY INTRUDER" in res["message"]["text"]

    def test_intruder_power_toggle_chat_and_vault(self):
        """Tests ON/OFF switch on the intruder server:
        When ON: messages & vault docs are tampered, Alice & Bob get error.
        When OFF: messages & vault docs pass cleanly without errors.
        """
        # 1. Turn Intruder Server ON
        self.interceptor.set_power(True)
        assert self.interceptor.is_on() is True

        # Alice sends message to Bob -> Automatically tampered, Bob detects and rejects
        msg_res = demo_mgr.send_message("alice", "bob", "Secret wire message with intruder ON")
        assert msg_res["status"] == "tamper_error"
        assert msg_res["message"]["is_tampered"] is True

        # Alice uploads vault document for Bob -> Tampered on wire, Bob decryption rejected
        upload_res = demo_mgr.upload_file("alice", "bob", "top_secret.pdf", b"Confidential Payload")
        assert upload_res["is_tampered"] is True
        assert upload_res["status"] == "uploaded_tampered"

        download_res = demo_mgr.download_file("bob", upload_res["file_id"])
        assert download_res["status"] == "decryption_failed"
        assert "tampered" in download_res["error"].lower() or "signature" in download_res["error"].lower()

        # 2. Turn Intruder Server OFF
        self.interceptor.set_power(False)
        assert self.interceptor.is_on() is False

        # Alice sends message to Bob -> Clean pass-through, no error
        clean_msg = demo_mgr.send_message("alice", "bob", "Clean message with intruder OFF")
        assert clean_msg["status"] == "success"
        assert clean_msg["message"]["is_tampered"] is False

        # Alice uploads vault document for Bob -> Clean pass-through, Bob decrypts successfully
        clean_upload = demo_mgr.upload_file("alice", "bob", "clean_spec.txt", b"Clean Document Contents")
        assert clean_upload["is_tampered"] is False
        assert clean_upload["status"] == "uploaded"

        clean_download = demo_mgr.download_file("bob", clean_upload["file_id"])
        assert clean_download["status"] == "downloaded_and_verified"
        assert clean_download["text_content"] == "Clean Document Contents"

    def test_no_intruder_on_main_server_apis(self):
        """Validates that intruder is not exposed as a regular user on the main server."""
        users = demo_mgr.list_users()
        user_ids = [u["user_id"] for u in users]
        assert "intruder" not in user_ids

        state = demo_mgr.get_state(active_user="alice")
        assert "intruder" not in state["users"]
        assert state["peer_id"] != "intruder"

    def test_attacker_fastapi_server_endpoints(self):
        """Validates the independent port 8080 Attacker Server REST API."""
        client = TestClient(attacker_app)

        # 1. UI root check
        ui_res = client.get("/")
        assert ui_res.status_code == 200

        # 2. Status check
        status_res = client.get("/api/v1/attacker/status")
        assert status_res.status_code == 200
        assert "interceptor_mode" in status_res.json()
        assert "is_on" in status_res.json()

        # 3. Power toggle check
        power_res = client.post("/api/v1/attacker/power", json={"state": "off"})
        assert power_res.status_code == 200
        assert power_res.json()["is_on"] is False

        power_on_res = client.post("/api/v1/attacker/power", json={"state": "on"})
        assert power_on_res.status_code == 200
        assert power_on_res.json()["is_on"] is True

        # 4. Mode switch check
        mode_res = client.post("/api/v1/attacker/mode", json={"mode": "hold"})
        assert mode_res.status_code == 200
        assert mode_res.json()["mode"] == "hold"

        # 5. Packets endpoint
        demo_mgr.send_message("alice", "bob", "Wire probe for FastAPI attacker test.")
        pkts_res = client.get("/api/v1/attacker/packets")
        assert pkts_res.status_code == 200
        pkts_data = pkts_res.json()["packets"]
        assert len(pkts_data) > 0

        pkt_id = pkts_data[0]["packet_id"]

        # 6. Read attack endpoint
        read_res = client.post("/api/v1/attacker/action/read", json={"packet_id": pkt_id})
        assert read_res.status_code == 200
        assert read_res.json()["result"]["final_outcome"]["bytes_leaked"] == 0

        # 7. Modify attack endpoint
        modify_res = client.post(
            "/api/v1/attacker/action/modify",
            json={"packet_id": pkt_id, "tamper_type": "ciphertext_bitflip", "auto_forward": False}
        )
        assert modify_res.status_code == 200
        assert modify_res.json()["status"] == "tampered"

        # 8. Delete attack endpoint
        delete_res = client.post("/api/v1/attacker/action/delete", json={"packet_id": pkt_id})
        assert delete_res.status_code == 200
        assert delete_res.json()["status"] == "dropped"
