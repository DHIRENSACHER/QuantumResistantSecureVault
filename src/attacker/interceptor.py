"""Attacker Interceptor Engine simulating wiretapping, cryptanalysis, and active MITM attacks."""

from __future__ import annotations

import base64
import copy
import json
import os
import tempfile
import time
import uuid
from typing import Any, Dict, List, Optional

STATE_FILE = os.path.join(tempfile.gettempdir(), "quantum_vault_interceptor_state.json")


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
        # Interceptor mode: "tamper" (ON), "off" / "pass" (OFF), "hold" (manual action), "drop" (auto-drop)
        # Defaults to ON ("tamper")
        self.mode: str = "tamper"
        self._last_file_mtime: float = 0.0
        self.stats = {
            "total_intercepted": 0,
            "read_attempts": 0,
            "tampered_count": 0,
            "dropped_count": 0,
            "forwarded_count": 0,
        }
        self._sync_state_from_disk()

    def _sync_state_from_disk(self):
        """Syncs interceptor power/mode state from shared disk file across server processes."""
        try:
            if os.path.exists(STATE_FILE):
                mtime = os.path.getmtime(STATE_FILE)
                if mtime > self._last_file_mtime:
                    with open(STATE_FILE, "r") as f:
                        data = json.load(f)
                        saved_mode = data.get("mode")
                        if saved_mode:
                            self.mode = saved_mode
                    self._last_file_mtime = mtime
        except Exception:
            pass

    def _persist_state_to_disk(self):
        """Persists interceptor state to disk for multi-process coordination."""
        try:
            with open(STATE_FILE, "w") as f:
                json.dump({
                    "mode": self.mode,
                    "is_on": self.is_on(),
                    "timestamp": time.time(),
                }, f)
            self._last_file_mtime = os.path.getmtime(STATE_FILE)
        except Exception:
            pass

    def is_on(self) -> bool:
        """Returns True if the intruder interception & tampering server is ON."""
        self._sync_state_from_disk()
        return self.mode in ("tamper", "on")

    def set_power(self, is_on: bool) -> bool:
        """Turns the intruder server ON (auto-tampering) or OFF (clean pass-through)."""
        if is_on:
            self.mode = "tamper"
        else:
            self.mode = "off"
        self._persist_state_to_disk()
        return self.is_on()

    def intercept(self, sender_id: str, recipient_id: str, envelope_dict: dict) -> Dict[str, Any]:
        packet_id = f"pkt_{int(time.time() * 1000)}_{uuid.uuid4().hex[:6]}"
        if isinstance(envelope_dict, dict) and "envelope" in envelope_dict and isinstance(envelope_dict["envelope"], dict):
            inner_env = envelope_dict["envelope"]
        else:
            inner_env = envelope_dict if isinstance(envelope_dict, dict) else {}
        header = inner_env.get("header", {}) if isinstance(inner_env, dict) else {}
        ct_b64 = inner_env.get("ciphertext", "") if isinstance(inner_env, dict) else ""
        sig_b64 = inner_env.get("signature", "") if isinstance(inner_env, dict) else ""

        ct_bytes_len = len(base64.b64decode(ct_b64)) if ct_b64 else 0
        kem_ct = header.get("kem_ct") if isinstance(header, dict) else None
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
            "dh_pub_b64": header.get("dh_pub", "") if isinstance(header, dict) else "",
            "kem_ct_b64": kem_ct,
            "kem_ct_len": kem_ct_len,
            "signature_b64": sig_b64,
            "ratchet_turn": header.get("ratchet_turn", 0) if isinstance(header, dict) else 0,
            "seq_num": header.get("n", 0) if isinstance(header, dict) else 0,
            "cryptanalysis_result": None,
            "delivery_result": None,
        }

        self.stats["total_intercepted"] += 1
        self.packets[packet_id] = packet

        # If in auto-tamper mode, automatically apply bit-flip
        if self.is_on():
            self.tamper_packet(packet_id, "ciphertext_bitflip")
        elif self.mode == "drop":
            self.drop_packet(packet_id)
        elif self.mode in ("pass", "off"):
            packet["status"] = "forwarded"
            self.stats["forwarded_count"] += 1

        return packet

    def intercept_vault_file(
        self,
        sender_id: str,
        recipient_id: str,
        filename: str,
        manifest_dict: dict,
    ) -> Dict[str, Any]:
        """Captures a zero-access file vault deposit on the wire and tampers if ON."""
        self._sync_state_from_disk()
        packet_id = f"pkt_vault_{int(time.time() * 1000)}_{uuid.uuid4().hex[:6]}"
        manifest_copy = copy.deepcopy(manifest_dict)
        sig = manifest_copy.get("signature", "")
        wrapped = manifest_copy.get("wrapped_dek", {})

        kem_ct = wrapped.get("kem_ciphertext", "")
        kem_len = len(base64.b64decode(kem_ct)) if kem_ct else 0

        packet = {
            "packet_id": packet_id,
            "timestamp": time.time(),
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "payload_type": "vault_file",
            "filename": filename,
            "status": "intercepted",
            "raw_envelope": manifest_copy,
            "tampered_envelope": None,
            "ciphertext_b64": wrapped.get("encrypted_dek", ""),
            "ciphertext_len": manifest_copy.get("total_size", 0),
            "dh_pub_b64": "",
            "kem_ct_b64": kem_ct,
            "kem_ct_len": kem_len,
            "signature_b64": sig,
            "ratchet_turn": 0,
            "seq_num": manifest_copy.get("chunk_count", 1),
            "cryptanalysis_result": None,
            "delivery_result": None,
        }

        self.stats["total_intercepted"] += 1
        self.packets[packet_id] = packet

        if self.is_on():
            # Automatically corrupt ML-DSA-65 signature on the manifest
            tampered_manifest = copy.deepcopy(manifest_dict)
            if sig and len(sig) > 20:
                tampered_manifest["signature"] = "AAAA" + sig[4:]
            else:
                tampered_manifest["signature"] = "corrupted_signature_by_intruder"

            packet["tampered_envelope"] = tampered_manifest
            packet["status"] = "tampered"
            packet["tamper_details"] = {
                "type": "manifest_signature_corrupt",
                "description": f"Corrupted NIST FIPS 204 ML-DSA-65 signature on vault manifest for '{filename}'.",
            }
            self.stats["tampered_count"] += 1
            return {
                "packet_id": packet_id,
                "is_tampered": True,
                "tampered_manifest": tampered_manifest,
                "packet": packet,
            }
        else:
            packet["status"] = "forwarded_clean"
            self.stats["forwarded_count"] += 1
            return {
                "packet_id": packet_id,
                "is_tampered": False,
                "tampered_manifest": manifest_dict,
                "packet": packet,
            }

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

        if isinstance(tampered_env, dict) and "envelope" in tampered_env and isinstance(tampered_env["envelope"], dict):
            env_target = tampered_env["envelope"]
        else:
            env_target = tampered_env if isinstance(tampered_env, dict) else {}

        tamper_details = {}

        if custom_payload:
            # Inject arbitrary forged base64 ciphertext
            forged_bytes = custom_payload.encode("utf-8")
            env_target["ciphertext"] = base64.b64encode(forged_bytes).decode("ascii")
            tamper_details = {
                "type": "custom_injection",
                "description": f"Injected custom attacker payload ({len(forged_bytes)} bytes)",
            }
        elif tamper_type == "ciphertext_bitflip":
            raw_ct = None
            if "ciphertext" in env_target and env_target["ciphertext"]:
                try:
                    raw_ct = base64.b64decode(env_target["ciphertext"])
                except Exception:
                    raw_ct = None
            if raw_ct:
                barr = bytearray(raw_ct)
                barr[-1] ^= 0xFF  # Invert all bits in the last byte
                env_target["ciphertext"] = base64.b64encode(bytes(barr)).decode("ascii")
            elif "signature" in env_target and env_target["signature"]:
                sig = env_target["signature"]
                env_target["signature"] = "AAAA" + sig[4:] if len(sig) > 4 else "corrupt"
            tamper_details = {
                "type": "ciphertext_bitflip",
                "description": "Flipped 8 bits in the AES-256-GCM ciphertext payload.",
            }
        elif tamper_type == "signature_corrupt":
            sig = env_target.get("signature", "") if isinstance(env_target, dict) else ""
            if sig and len(sig) > 20:
                env_target["signature"] = "AAAA" + sig[4:]
            else:
                env_target["signature"] = "corrupted_signature_by_intruder"
            tamper_details = {
                "type": "signature_corrupt",
                "description": "Corrupted 32 bits of the NIST FIPS 204 ML-DSA-65 digital signature.",
            }
        elif tamper_type == "header_seq_alter":
            if isinstance(env_target, dict) and "header" in env_target and isinstance(env_target["header"], dict):
                env_target["header"]["n"] = env_target["header"].get("n", 0) + 999
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
        """Returns interceptor mode, power state, and live telemetry."""
        self._sync_state_from_disk()
        return {
            "is_on": self.is_on(),
            "interceptor_mode": self.mode,
            "active_target": "alice ⇄ bob",
            "stats": self.stats,
            "total_captured": len(self.packets),
            "pending_in_queue": len([p for p in self.packets.values() if p["status"] == "intercepted"]),
        }

    def set_mode(self, new_mode: str) -> str:
        """Sets interceptor mode: 'on', 'off', 'hold', 'pass', 'tamper', 'drop'."""
        normalized = new_mode.lower().strip()
        if normalized in ["on", "tamper"]:
            self.mode = "tamper"
        elif normalized in ["off", "pass"]:
            self.mode = "off"
        elif normalized in ["hold", "drop"]:
            self.mode = normalized
        self._persist_state_to_disk()
        return self.mode
