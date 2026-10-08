"""Attacker Interceptor Engine simulating wiretapping, cryptanalysis, and active MITM attacks."""

from __future__ import annotations

import base64
import copy
import time
import uuid
from typing import Any, Dict, List, Optional


class AttackerInterceptor:
    """Core interception engine for eavesdropping, tampering, and packet dropping."""

    _instance: Optional[AttackerInterceptor] = None

    @classmethod
    def get_instance(cls) -> AttackerInterceptor:
        if cls._instance is None:
            cls._instance = AttackerInterceptor()
        return cls._instance

    def __init__(self):
        # packet_id -> packet_dict
        self.packets: Dict[str, Dict[str, Any]] = {}
        # Interceptor mode: "hold" (manual action), "pass" (auto-forward), "tamper" (auto-tamper), "drop" (auto-drop)
        self.mode: str = "hold"
        self.stats = {
            "total_intercepted": 0,
            "read_attempts": 0,
            "tampered_count": 0,
            "dropped_count": 0,
            "forwarded_count": 0,
        }

    def intercept(self, sender_id: str, recipient_id: str, envelope_dict: dict) -> Dict[str, Any]:
        """Captures a message envelope from the wire in real time."""
        packet_id = f"pkt_{int(time.time() * 1000)}_{uuid.uuid4().hex[:6]}"
        header = envelope_dict.get("header", {})
        ct_b64 = envelope_dict.get("ciphertext", "")
        sig_b64 = envelope_dict.get("signature", "")

        ct_bytes_len = len(base64.b64decode(ct_b64)) if ct_b64 else 0
        kem_ct = header.get("kem_ct")
        kem_ct_len = len(base64.b64decode(kem_ct)) if kem_ct else 0

        packet = {
            "packet_id": packet_id,
            "timestamp": time.time(),
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "status": "intercepted",
            "raw_envelope": copy.deepcopy(envelope_dict),
            "tampered_envelope": None,
            "ciphertext_b64": ct_b64,
            "ciphertext_len": ct_bytes_len,
            "dh_pub_b64": header.get("dh_pub", ""),
            "kem_ct_b64": kem_ct,
            "kem_ct_len": kem_ct_len,
            "signature_b64": sig_b64,
            "ratchet_turn": header.get("ratchet_turn", 0),
            "seq_num": header.get("n", 0),
            "cryptanalysis_result": None,
            "delivery_result": None,
        }

        self.stats["total_intercepted"] += 1
        self.packets[packet_id] = packet

        # If in auto-tamper mode, automatically apply bit-flip
        if self.mode == "tamper":
            self.tamper_packet(packet_id, "ciphertext_bitflip")
        elif self.mode == "drop":
            self.drop_packet(packet_id)
        elif self.mode == "pass":
            packet["status"] = "forwarded"
            self.stats["forwarded_count"] += 1

        return packet

    def attempt_read(self, packet_id: str) -> Dict[str, Any]:
        """Simulates an attacker attempting to read/decrypt the intercepted wire packet."""
        packet = self.packets.get(packet_id)
        if not packet:
            raise KeyError(f"Packet {packet_id} not found")

        self.stats["read_attempts"] += 1

        ct_b64 = packet["ciphertext_b64"]
        ct_bytes = base64.b64decode(ct_b64) if ct_b64 else b""
        raw_hex_preview = ct_bytes[:32].hex()

        result = {
            "packet_id": packet_id,
            "timestamp": time.time(),
            "target_ciphertext_hex": raw_hex_preview + ("..." if len(ct_bytes) > 32 else ""),
            "ciphertext_size_bytes": len(ct_bytes),
            "phase_1_trial_decryption": {
                "method": "Attacker Keystore Decapsulation",
                "status": "FAILED",
                "details": "Attacker does not possess Bob's ML-KEM-768 or X25519 private keys. AEAD tag validation failed.",
            },
            "phase_2_classical_crqc_attack": {
                "method": "Shor's Algorithm on Curve25519 (Discrete Log)",
                "status": "CLASSICAL_COMPROMISED",
                "details": "Shor's algorithm solves discrete log in polynomial time O(n³). Classical secret SS_ecdh extracted!",
                "compromised_ecdh_secret": "9a3f81e2b407... (Leaked)",
            },
            "phase_3_lattice_shield_defense": {
                "method": "NIST FIPS 203 ML-KEM-768 (Module-LWE)",
                "status": "UNBREAKABLE",
                "details": "HPQ-DR derives Root & Message Keys by hashing SS_ecdh with ML-KEM-768 secret: KDF(SS_ecdh || SS_kem). Shor's algorithm CANNOT solve Module-LWE lattices. The attacker has ZERO information on the combined key!",
                "lattice_secret": "SECURE (256-bit quantum security level)",
            },
            "final_outcome": {
                "plaintext_revealed": False,
                "bytes_leaked": 0,
                "attacker_view": "ENCRYPTED_PSEUDORANDOM_NOISE",
                "defense_summary": "Zero bits leaked. Message completely protected by Hybrid Post-Quantum Double Ratchet.",
            },
        }

        packet["cryptanalysis_result"] = result
        packet["status"] = "read_attempted"
        return result

    def tamper_packet(
        self,
        packet_id: str,
        tamper_type: str = "ciphertext_bitflip",
        custom_payload: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Modifies the intercepted envelope to simulate an active MITM tamper attack."""
        packet = self.packets.get(packet_id)
        if not packet:
            raise KeyError(f"Packet {packet_id} not found")

        self.stats["tampered_count"] += 1
        tampered_env = copy.deepcopy(packet["raw_envelope"])

        tamper_details = {}

        if custom_payload:
            # Inject arbitrary forged base64 ciphertext
            forged_bytes = custom_payload.encode("utf-8")
            tampered_env["ciphertext"] = base64.b64encode(forged_bytes).decode("ascii")
            tamper_details = {
                "type": "custom_injection",
                "description": f"Injected custom attacker payload ({len(forged_bytes)} bytes)",
            }
        elif tamper_type == "ciphertext_bitflip":
            # Flip the last byte of the ciphertext
            raw_ct = base64.b64decode(tampered_env["ciphertext"])
            if raw_ct:
                barr = bytearray(raw_ct)
                barr[-1] ^= 0xFF  # Invert all bits in the last byte
                tampered_env["ciphertext"] = base64.b64encode(bytes(barr)).decode("ascii")
            tamper_details = {
                "type": "ciphertext_bitflip",
                "description": "Flipped 8 bits in the AES-256-GCM ciphertext payload.",
            }
        elif tamper_type == "signature_corrupt":
            # Corrupt the ML-DSA-65 signature bytes
            sig = tampered_env.get("signature", "")
            if len(sig) > 20:
                tampered_env["signature"] = "AAAA" + sig[4:]
            tamper_details = {
                "type": "signature_corrupt",
                "description": "Corrupted 32 bits of the NIST FIPS 204 ML-DSA-65 digital signature.",
            }
        elif tamper_type == "header_seq_alter":
            # Tamper with ratchet sequence counter
            if "header" in tampered_env:
                tampered_env["header"]["n"] = tampered_env["header"].get("n", 0) + 999
            tamper_details = {
                "type": "header_seq_alter",
                "description": "Altered message sequence number to trigger replay/out-of-order desync.",
            }

        packet["tampered_envelope"] = tampered_env
        packet["status"] = "tampered"
        packet["tamper_details"] = tamper_details

        return {
            "packet_id": packet_id,
            "status": "tampered",
            "tamper_details": tamper_details,
            "tampered_envelope": tampered_env,
        }

    def drop_packet(self, packet_id: str) -> Dict[str, Any]:
        """Drops / deletes an intercepted packet so it never reaches the recipient."""
        packet = self.packets.get(packet_id)
        if not packet:
            raise KeyError(f"Packet {packet_id} not found")

        self.stats["dropped_count"] += 1
        packet["status"] = "dropped"
        packet["delivery_result"] = {
            "status": "dropped_by_attacker",
            "message": "Packet destroyed. Recipient will not receive this message.",
            "delivered": False,
        }

        return {
            "packet_id": packet_id,
            "status": "dropped",
            "message": "Packet permanently dropped from delivery queue.",
        }

    def forward_packet(self, packet_id: str, use_tampered: bool = False) -> Dict[str, Any]:
        """Marks a packet as forwarded to the recipient (clean or tampered)."""
        packet = self.packets.get(packet_id)
        if not packet:
            raise KeyError(f"Packet {packet_id} not found")

        self.stats["forwarded_count"] += 1
        env_to_deliver = packet["tampered_envelope"] if (use_tampered and packet.get("tampered_envelope")) else packet["raw_envelope"]
        is_tampered = use_tampered and (packet.get("tampered_envelope") is not None)

        packet["status"] = "forwarded_tampered" if is_tampered else "forwarded_clean"
        packet["delivery_result"] = {
            "status": "forwarded",
            "is_tampered": is_tampered,
            "delivered": True,
            "envelope": env_to_deliver,
        }

        return {
            "packet_id": packet_id,
            "status": packet["status"],
            "is_tampered": is_tampered,
            "envelope": env_to_deliver,
        }

    def list_packets(self) -> List[Dict[str, Any]]:
        """Returns all intercepted packets in reverse chronological order."""
        return sorted(self.packets.values(), key=lambda p: p["timestamp"], reverse=True)

    def get_status(self) -> Dict[str, Any]:
        """Returns interceptor mode and live telemetry."""
        return {
            "interceptor_mode": self.mode,
            "active_target": "alice ⇄ bob",
            "stats": self.stats,
            "total_captured": len(self.packets),
            "pending_in_queue": len([p for p in self.packets.values() if p["status"] == "intercepted"]),
        }

    def set_mode(self, new_mode: str) -> str:
        """Sets interceptor mode: 'hold', 'pass', 'tamper', 'drop'."""
        if new_mode in ["hold", "pass", "tamper", "drop"]:
            self.mode = new_mode
        return self.mode
