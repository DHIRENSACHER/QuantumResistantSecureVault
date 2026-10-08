"""High-level Client SDK for HPQ-DR Messaging and Zero-Access File Vault."""

from __future__ import annotations

from typing import Dict, List, Optional
from fastapi.testclient import TestClient
from src.identity import ClientKeyStore, PreKeyBundle
from src.protocol import PQXDHHandshake, HPQDoubleRatchet, SecureEnvelope, HandshakeInitMessage
from src.vault import FileVaultEngine, VaultFileManifest
class VaultClient:
    """End-user client SDK managing keys, ratchets, messaging, and encrypted vault operations."""

    def __init__(self, user_id: str, transport: Optional[TestClient] = None):
        self.user_id = user_id
        if transport is not None:
            self.transport = transport
        else:
            from src.server.app import app
            self.transport = TestClient(app)
        self.keystore = ClientKeyStore.create_new(user_id, opk_count=20)

        # Active ratchet sessions: peer_id -> HPQDoubleRatchet
        self.sessions: Dict[str, HPQDoubleRatchet] = {}
        # Known peer identity keys: peer_id -> ML-DSA-65 public key
        self.peer_identities: Dict[str, bytes] = {}
        # Pending handshake init messages to send with first message: peer_id -> HandshakeInitMessage
        self._pending_handshake: Dict[str, HandshakeInitMessage] = {}

    def register(self) -> dict:
        """Publishes public PreKeyBundle to relay server."""
        bundle = self.keystore.create_bundle()
        resp = self.transport.post(
            "/api/v1/prekeys/register",
            json={"user_id": self.user_id, "bundle": bundle.to_dict()},
        )
        resp.raise_for_status()
        return resp.json()

    def get_peer_bundle(self, peer_id: str) -> PreKeyBundle:
        """Fetches peer's public prekey bundle from server."""
        resp = self.transport.get(f"/api/v1/prekeys/{peer_id}")
        resp.raise_for_status()
        bundle = PreKeyBundle.from_dict(resp.json())
        self.peer_identities[peer_id] = bundle.identity_key_pqc
        return bundle

    def ensure_session(self, peer_id: str) -> HPQDoubleRatchet:
        """Initializes HPQ-DR session if not already active."""
        if peer_id in self.sessions:
            return self.sessions[peer_id]

        peer_bundle = self.get_peer_bundle(peer_id)
        init_msg, rk, ck, eph_priv = PQXDHHandshake.initiate(
            initiator_identity=self.keystore.identity,
            peer_bundle=peer_bundle,
        )

        self._pending_handshake[peer_id] = init_msg

        ratchet = HPQDoubleRatchet(
            local_identity=self.keystore.identity,
            peer_id=peer_id,
            peer_mldsa_pub=peer_bundle.identity_key_pqc,
            root_key=rk,
            is_initiator=True,
            initial_chain_key=ck,
            initial_dh_priv=eph_priv,
            peer_dh_pub=peer_bundle.signed_prekey_classic,
            peer_kem_pub=peer_bundle.onetime_prekey_pqc,
        )
        self.sessions[peer_id] = ratchet
        return ratchet

    def send_message(self, recipient_id: str, message_text: str) -> dict:
        """Encrypts message with HPQ-DR and delivers envelope to recipient mailbox."""
        ratchet = self.ensure_session(recipient_id)
        envelope = ratchet.encrypt(message_text.encode("utf-8"))

        envelope_dict = envelope.to_dict()
        message_payload = {"envelope": envelope_dict}

        # If this is the initial message in session, attach the HandshakeInitMessage
        if recipient_id in self._pending_handshake:
            message_payload["handshake_init"] = self._pending_handshake.pop(recipient_id).to_dict()

        resp = self.transport.post(
            "/api/v1/messages/send",
            json={"recipient_id": recipient_id, "envelope": message_payload},
        )
        resp.raise_for_status()
        return {"status": "sent", "recipient_id": recipient_id, "ratchet_turn": envelope.header.ratchet_turn}

    def fetch_messages(self) -> List[dict]:
        """Pulls pending encrypted envelopes from server inbox and decrypts them."""
        resp = self.transport.get(f"/api/v1/messages/inbox/{self.user_id}")
        resp.raise_for_status()
        raw_items = resp.json().get("messages", [])

        decrypted_messages = []
        for raw_item in raw_items:
            # Handle payload wrapper or raw envelope
            if "envelope" in raw_item and "header" not in raw_item:
                envelope_dict = raw_item["envelope"]
                handshake_dict = raw_item.get("handshake_init")
            else:
                envelope_dict = raw_item
                handshake_dict = None

            envelope = SecureEnvelope.from_dict(envelope_dict)
            sender_id = envelope.header.sender_id

            if sender_id not in self.sessions:
                if handshake_dict is not None:
                    init_msg = HandshakeInitMessage.from_dict(handshake_dict)
                    b_rk, b_ck = PQXDHHandshake.receive(self.keystore, init_msg)
                    ratchet = HPQDoubleRatchet(
                        local_identity=self.keystore.identity,
                        peer_id=sender_id,
                        peer_mldsa_pub=init_msg.initiator_mldsa_pub,
                        root_key=b_rk,
                        is_initiator=False,
                        initial_chain_key=b_ck,
                        initial_dh_priv=self.keystore.signed_prekey.x25519_priv,
                        peer_dh_pub=init_msg.ephemeral_x25519_pub,
                    )
                    self.sessions[sender_id] = ratchet
                    self.peer_identities[sender_id] = init_msg.initiator_mldsa_pub
                else:
                    raise ValueError(f"No active session or handshake for sender {sender_id}")

            ratchet = self.sessions[sender_id]
            try:
                plaintext = ratchet.decrypt(envelope)
                decrypted_messages.append({
                    "sender_id": sender_id,
                    "text": plaintext.decode("utf-8"),
                    "ratchet_turn": envelope.header.ratchet_turn,
                    "msg_index": envelope.header.n,
                    "is_tampered": False,
                })
            except Exception as e:
                decrypted_messages.append({
                    "sender_id": sender_id,
                    "text": f"❌ [SECURITY ALERT: ML-DSA-65 Signature Tampered / MAC Invalid. Packet Dropped by {self.user_id.capitalize()}.]",
                    "ratchet_turn": envelope.header.ratchet_turn,
                    "msg_index": envelope.header.n,
                    "is_tampered": True,
                    "error": str(e),
                })

        return decrypted_messages

    def upload_file(self, file_bytes: bytes, filename: str, recipient_id: str) -> str:
        """Packages, encrypts, and uploads a file into the zero-access vault."""
        recipient_bundle = self.get_peer_bundle(recipient_id)

        manifest, encrypted_chunks = FileVaultEngine.package_file(
            file_bytes=file_bytes,
            filename=filename,
            sender_identity=self.keystore.identity,
            recipient_id=recipient_id,
            recipient_mlkem_pub=recipient_bundle.onetime_prekey_pqc,
            recipient_prekey_id=recipient_bundle.onetime_prekey_id,
        )

        # Upload encrypted chunks
        for chunk_hash, chunk_data in encrypted_chunks.items():
            resp = self.transport.post(
                f"/api/v1/vault/chunk/{chunk_hash}",
                content=chunk_data,
                headers={"Content-Type": "application/octet-stream"},
            )
            resp.raise_for_status()

        # Upload signed manifest
        resp_m = self.transport.post(
            "/api/v1/vault/manifest",
            json={"file_id": manifest.file_id, "manifest": manifest.to_dict()},
        )
        resp_m.raise_for_status()

        return manifest.file_id

    def download_file(self, file_id: str, sender_id: str) -> bytes:
        """Downloads, verifies ML-DSA-65 signature, and decrypts a vault file."""
        # 1. Fetch manifest
        resp = self.transport.get(f"/api/v1/vault/manifest/{file_id}")
        resp.raise_for_status()
        manifest = VaultFileManifest.from_dict(resp.json())

        # 2. Ensure sender's identity key is known
        if sender_id not in self.peer_identities:
            self.get_peer_bundle(sender_id)
        sender_mldsa_pub = self.peer_identities[sender_id]

        # 3. Download encrypted chunks
        encrypted_chunks = {}
        for chunk_hash in manifest.encrypted_chunk_hashes:
            resp_c = self.transport.get(f"/api/v1/vault/chunk/{chunk_hash}")
            resp_c.raise_for_status()
            encrypted_chunks[chunk_hash] = resp_c.content

        # 4. Find recipient's ML-KEM private key
        opk = self.keystore.get_prekey_for_decrypt(manifest.recipient_prekey_id)
        if opk is not None:
            recipient_priv = opk.mlkem_priv
        elif self.keystore.onetime_prekeys:
            recipient_priv = next(iter(self.keystore.onetime_prekeys.values())).mlkem_priv
        elif self.keystore.consumed_prekeys:
            recipient_priv = next(iter(self.keystore.consumed_prekeys.values())).mlkem_priv
        else:
            raise ValueError("Recipient has no one-time ML-KEM prekeys available to unwrap DEK")

        # Reassemble
        return FileVaultEngine.reassemble_file(
            manifest=manifest,
            encrypted_chunks=encrypted_chunks,
            recipient_mlkem_priv=recipient_priv,
            sender_mldsa_pub=sender_mldsa_pub,
        )
