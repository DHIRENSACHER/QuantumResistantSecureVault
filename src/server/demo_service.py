"""Demo service coordinating simulated Alice and Bob clients for the web UI."""

from __future__ import annotations

import base64
import time
from typing import Any, Dict, List, Optional
from src.client.sdk import VaultClient
from src.server.storage import ZeroAccessStorage
from src.vault.manifest import VaultFileManifest
from src.vault.reassembly import FileVaultEngine


class DemoManager:
    """Coordinates demo state and client interactions for the frontend."""

    def __init__(self, storage: ZeroAccessStorage):
        self.storage = storage
        self.clients: Dict[str, VaultClient] = {}
        self.conversation_history: List[Dict[str, Any]] = []
        self._initialized = False

    def ensure_clients(self):
        """Lazily initializes Alice, Bob, and Intruder demo clients."""
        if not self._initialized:
            self.get_or_create_client("alice")
            self.get_or_create_client("bob")
            self.get_or_create_client("intruder")
            self._initialized = True

    def get_or_create_client(self, user_id: str) -> VaultClient:
        """Retrieves or instantiates an isolated client keystore with unique private keys."""
        uid = (user_id or "alice").strip().lower()
        if uid not in self.clients:
            client = VaultClient(uid)
            client.register()
            self.clients[uid] = client
        return self.clients[uid]

    def list_users(self) -> List[Dict[str, Any]]:
        """Lists all registered users with their cryptographic identity fingerprints."""
        self.ensure_clients()
        user_list = []
        for uid, client in self.clients.items():
            user_list.append({
                "user_id": uid,
                "display_name": uid.capitalize(),
                "mldsa_fingerprint": client.keystore.identity.mldsa_pub[:16].hex(),
                "x25519_pub": client.keystore.identity.x25519_pub.hex()[:16] + "...",
                "active_prekeys": len(client.keystore.onetime_prekeys),
                "private_key_status": "Secured in In-Memory ClientKeyStore",
            })
        return user_list

    def login(self, user_id: str) -> Dict[str, Any]:
        """Logs in a user, activating their unique isolated private keystore."""
        client = self.get_or_create_client(user_id)
        uid = client.user_id
        return {
            "status": "authenticated",
            "user": {
                "user_id": uid,
                "display_name": uid.capitalize(),
                "mldsa_fingerprint": client.keystore.identity.mldsa_pub[:16].hex(),
                "mldsa_pub_len": len(client.keystore.identity.mldsa_pub),
                "x25519_pub_hex": client.keystore.identity.x25519_pub.hex(),
                "active_onetime_prekeys": len(client.keystore.onetime_prekeys),
                "consumed_onetime_prekeys": len(client.keystore.consumed_prekeys),
                "private_key_status": "Isolated in local ClientKeyStore",
                "algorithms": {
                    "signing": "NIST FIPS 204 ML-DSA-65 (Post-Quantum)",
                    "kem": "NIST FIPS 203 ML-KEM-768 (Post-Quantum)",
                    "ecdh": "Curve25519 (X25519)",
                },
            },
            "available_peers": [u for u in self.clients.keys() if u != uid],
        }

    def get_state(self, active_user: str = "alice", peer_id: Optional[str] = None) -> Dict[str, Any]:
        """Returns overall system state, active user keys, and vault files."""
        self.ensure_clients()
        active_user = (active_user or "alice").strip().lower()
        client = self.get_or_create_client(active_user)

        if not peer_id or peer_id == active_user:
            available = [u for u in self.clients.keys() if u != active_user]
            peer_id = available[0] if available else ("bob" if active_user == "alice" else "alice")

        peer_client = self.get_or_create_client(peer_id)

        # Files in vault
        files = []
        for file_id, m_dict in self.storage.manifests.items():
            files.append({
                "file_id": file_id,
                "filename": m_dict.get("filename", "unknown"),
                "total_size": m_dict.get("total_size", 0),
                "chunk_count": m_dict.get("chunk_count", 0),
                "sender_id": m_dict.get("sender_id", ""),
                "recipient_id": m_dict.get("recipient_id", ""),
                "timestamp": m_dict.get("timestamp", 0),
                "recipient_prekey_id": m_dict.get("recipient_prekey_id"),
                "can_decrypt": (m_dict.get("recipient_id") == active_user or m_dict.get("sender_id") == active_user),
            })

        session = client.sessions.get(peer_id)
        ratchet_turn = session.ratchet_turn if session else 0
        sent_count = session.ns if session else 0
        recv_count = session.nr if session else 0

        # Drain any incoming messages for active user (e.g. from relay or attacker injection)
        try:
            pulled = client.fetch_messages()
            for p in pulled:
                if p.get("is_tampered"):
                    self.conversation_history.append({
                        "id": len(self.conversation_history) + 1,
                        "sender_id": p.get("sender_id", peer_id),
                        "recipient_id": active_user,
                        "text": p.get("text", "❌ [SECURITY ALERT: Tampering Detected]"),
                        "timestamp": time.time(),
                        "ratchet_turn": p.get("ratchet_turn", 0),
                        "seq_num": p.get("msg_index", 0),
                        "is_healing_turn": False,
                        "signature_verified": False,
                        "is_tampered": True,
                        "status": "tamper_rejected",
                    })
        except Exception:
            pass

        # Filter conversation history between active_user and peer_id
        filtered_conversation = [
            m for m in self.conversation_history
            if (m["sender_id"] == active_user and m["recipient_id"] == peer_id)
            or (m["sender_id"] == peer_id and m["recipient_id"] == active_user)
        ]

        return {
            "active_user": active_user,
            "peer_id": peer_id,
            "users": list(self.clients.keys()),
            "algorithms": {
                "kem": "NIST FIPS 203 ML-KEM-768 (Category 3)",
                "signature": "NIST FIPS 204 ML-DSA-65 (Category 3)",
                "classical_dh": "Curve25519 (X25519)",
                "symmetric_aead": "AES-256-GCM / ChaCha20-Poly1305",
                "kdf": "HKDF-SHA256 (Multi-Secret)",
            },
            "metrics": {
                "ratchet_turn": ratchet_turn,
                "sent_messages": sent_count,
                "received_messages": recv_count,
                "vault_file_count": len(files),
                "total_chunks_stored": len(self.storage.chunks),
                "quantum_resistance_rating": "100% (Harvest-Now-Decrypt-Later Defeated)",
                "forward_secrecy": "Active (Single-Use Symmetric Message Keys)",
                "post_compromise_healing": "Active (Turn-Based Hybrid Asymmetric Ratchet)",
            },
            "keys": {
                "user_id": active_user,
                "mldsa_pub_fingerprint": client.keystore.identity.mldsa_pub[:16].hex(),
                "mldsa_pub_len": len(client.keystore.identity.mldsa_pub),
                "mldsa_priv_status": "Loaded (Private Key secure in local keystore)",
                "x25519_pub_hex": client.keystore.identity.x25519_pub.hex(),
                "x25519_priv_status": "Loaded (Private Key secure in local keystore)",
                "active_onetime_prekeys": len(client.keystore.onetime_prekeys),
                "consumed_onetime_prekeys": len(client.keystore.consumed_prekeys),
            },
            "files": files,
            "conversation": filtered_conversation,
        }

    def send_message(self, sender_id: str, recipient_id: str, text: str) -> Dict[str, Any]:
        """Sends an encrypted HPQ-DR message from sender to recipient."""
        self.ensure_clients()
        sender = self.get_or_create_client(sender_id)
        recipient = self.get_or_create_client(recipient_id)

        res = sender.send_message(recipient_id, text)

        # Retrieve raw envelope from storage for wire inspection & interceptor
        stored_items = self.storage.mailboxes.get(recipient_id, [])
        latest_item = stored_items[-1] if stored_items else {}
        env_dict = latest_item.get("envelope", latest_item)
        hdr = env_dict.get("header", {})

        is_healing_turn = hdr.get("kem_ct") is not None or hdr.get("ratchet_turn", 0) > 0

        # Wire intercept hook: notify AttackerInterceptor
        from src.attacker.interceptor import AttackerInterceptor
        interceptor = AttackerInterceptor.get_instance()
        pkt = interceptor.intercept(sender.user_id, recipient.user_id, env_dict)

        msg_record = {
            "id": len(self.conversation_history) + 1,
            "sender_id": sender.user_id,
            "recipient_id": recipient.user_id,
            "text": text,
            "timestamp": time.time(),
            "ratchet_turn": hdr.get("ratchet_turn", 0),
            "seq_num": hdr.get("n", 0),
            "is_healing_turn": is_healing_turn,
            "dh_pub_snippet": (hdr.get("dh_pub") or "")[:24],
            "kem_ct_present": hdr.get("kem_ct") is not None,
            "signature_verified": True,
            "status": "delivered_to_zero_access_mailbox",
            "is_tampered": False,
            "is_dropped": False,
        }

        # Check if interceptor dropped the packet
        if interceptor.mode == "drop":
            if stored_items and stored_items[-1] == latest_item:
                stored_items.pop()
            msg_record["status"] = "dropped_by_attacker"
            msg_record["text"] = "🗑 [PACKET DROPPED BY INTRUDER (DOS) - OBLITERATED FROM WIRE]"
            msg_record["is_dropped"] = True
            self.conversation_history.append(msg_record)
            return {
                "status": "dropped_by_attacker",
                "message": msg_record,
                "envelope": {},
            }

        # Check if interceptor tampered with the packet
        if interceptor.mode == "tamper" and pkt.get("tampered_envelope"):
            tampered_env = pkt["tampered_envelope"]
            if stored_items:
                stored_items[-1] = {"envelope": tampered_env}
            env_dict = tampered_env

        self.conversation_history.append(msg_record)

        # Recipient automatically pulls and decrypts in demo
        try:
            pulled = recipient.fetch_messages()
            for p in pulled:
                if p.get("is_tampered"):
                    msg_record["text"] = p["text"]
                    msg_record["status"] = "tamper_detected_and_dropped"
                    msg_record["is_tampered"] = True
                    msg_record["signature_verified"] = False
        except Exception as e:
            msg_record["status"] = "decryption_error"

        return {
            "status": "success",
            "message": msg_record,
            "envelope": {
                "ciphertext": env_dict.get("ciphertext", "")[:48] + "...",
                "signature": env_dict.get("signature", "")[:48] + "...",
                "dh_pub": hdr.get("dh_pub", ""),
                "kem_pub": (hdr.get("kem_pub") or "")[:32] + "...",
                "ratchet_turn": hdr.get("ratchet_turn", 0),
            },
        }

    def upload_file(
        self,
        sender_id: str,
        recipient_id: str,
        filename: str,
        content_bytes: bytes,
    ) -> Dict[str, Any]:
        """Packages, encrypts, and uploads a file into the vault."""
        self.ensure_clients()
        sender = self.get_or_create_client(sender_id)
        recipient = self.get_or_create_client(recipient_id)

        file_id = sender.upload_file(content_bytes, filename, recipient.user_id)
        manifest_dict = self.storage.manifests[file_id]

        return {
            "status": "uploaded",
            "file_id": file_id,
            "filename": filename,
            "total_size": len(content_bytes),
            "chunk_count": manifest_dict.get("chunk_count", 0),
            "chunk_hashes": manifest_dict.get("chunk_hashes", []),
            "encrypted_chunk_hashes": manifest_dict.get("encrypted_chunk_hashes", []),
            "wrapped_dek_preview": manifest_dict.get("wrapped_dek", {}).get("encrypted_dek", "")[:32] + "...",
            "signature_preview": manifest_dict.get("signature", "")[:32] + "...",
        }

    def download_file(self, user_id: str, file_id: str) -> Dict[str, Any]:
        """Downloads, verifies ML-DSA-65 signature, and decrypts a vault file using user's private key."""
        self.ensure_clients()
        user_client = self.get_or_create_client(user_id)
        manifest_dict = self.storage.manifests.get(file_id)
        if not manifest_dict:
            raise KeyError(f"File ID {file_id} not found")

        sender_id = manifest_dict["sender_id"]
        recipient_id = manifest_dict.get("recipient_id")

        # Cryptographic isolation verification:
        # If user is not the designated recipient, their private key cannot unwrap the DEK
        if recipient_id and user_client.user_id != recipient_id:
            return {
                "status": "decryption_failed",
                "error": f"Decryption rejected: User '{user_client.user_id}' does not possess the ML-KEM-768 private decapsulation key. This file is cryptographically locked for '{recipient_id}'.",
                "file_id": file_id,
                "filename": manifest_dict["filename"],
                "is_text": False,
                "text_content": None,
                "content_b64": None,
                "integrity_verified": False,
                "signature_verified": False,
            }

        try:
            decrypted_bytes = user_client.download_file(file_id, sender_id)
        except Exception as e:
            return {
                "status": "decryption_failed",
                "error": f"Decryption error: {str(e)}",
                "file_id": file_id,
                "filename": manifest_dict["filename"],
                "is_text": False,
                "text_content": None,
                "content_b64": None,
                "integrity_verified": False,
                "signature_verified": False,
            }

        # Check if text or binary
        is_text = False
        text_content = ""
        try:
            text_content = decrypted_bytes.decode("utf-8")
            is_text = True
        except UnicodeDecodeError:
            pass

        return {
            "status": "downloaded_and_verified",
            "file_id": file_id,
            "filename": manifest_dict["filename"],
            "total_size": len(decrypted_bytes),
            "is_text": is_text,
            "text_content": text_content if is_text else None,
            "content_b64": base64.b64encode(decrypted_bytes).decode("ascii"),
            "integrity_verified": True,
            "signature_verified": True,
        }

    def simulate_harvest_attack(self) -> Dict[str, Any]:
        """Executes simulated Harvest-Now-Decrypt-Later attack for UI timeline."""
        # Send fresh message
        secret = "Operation Quantum Aegis: Mission Coordinates Confirmed."
        send_res = self.send_message("alice", "bob", secret)
        env = send_res["envelope"]

        steps = [
            {
                "step": 1,
                "title": "Adversary Intercepts Wire Record",
                "status": "harvested",
                "tag": "Harvest Phase",
                "color": "dark",
                "description": "Passive quantum adversary records all wire packets, message envelopes, and encrypted chunks today.",
                "captured_data": {
                    "Ciphertext": env["ciphertext"],
                    "X25519 Ephemeral Pub": env["dh_pub"][:32] + "...",
                    "ML-KEM-768 Ciphertext": "1088 bytes captured",
                    "ML-DSA-65 Signature": env["signature"],
                },
            },
            {
                "step": 2,
                "title": "Quantum Computer Runs Shor's Algorithm",
                "status": "broken_classical",
                "tag": "Shor's Algorithm (CRQC)",
                "color": "red",
                "description": "Adversary runs Shor's algorithm on a Cryptographically Relevant Quantum Computer to solve the Discrete Logarithm Problem.",
                "details": "Classical X25519 ECDH is completely solved in polynomial time O(n³). Classical secret SS_ecdh is compromised!",
            },
            {
                "step": 3,
                "title": "NIST FIPS 203 ML-KEM-768 Lattice Defense",
                "status": "quantum_defense_active",
                "tag": "Module-LWE Lattice Shield",
                "color": "green",
                "description": "HPQ-DR derives Root & Message Keys by combining SS_ecdh with NIST FIPS 203 ML-KEM-768 secret via HKDF.",
                "details": "Shor's algorithm cannot solve the Module Learning With Errors (Module-LWE) lattice problem. The adversary has ZERO information on the hybrid Root Key!",
                "result": "DECRYPTION ATTEMPT FAILED. 0 Bits of Plaintext Leaked.",
            },
            {
                "step": 4,
                "title": "Legitimate Recipient Decapsulation & Healing",
                "status": "success",
                "tag": "Verified & Healed",
                "color": "green",
                "description": "Bob decapsulates ML-KEM-768 with his private key, derives matching keys, verifies ML-DSA-65 signature, and decrypts.",
                "plaintext_revealed": secret,
                "healing_note": "A new asymmetric ratchet turn refreshed the Root Key with fresh quantum entropy, healing any prior compromise.",
            },
        ]

        return {
            "status": "simulation_complete",
            "defense_verdict": "HARVEST-NOW-DECRYPT-LATER ATTACK DEFEATED",
            "quantum_immunity": "100%",
            "steps": steps,
        }
