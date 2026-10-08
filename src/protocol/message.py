"""Message envelope, headers, and cryptographic formatting for HPQ-DR."""

from __future__ import annotations

import base64
import json
import struct
from typing import Optional
from src.crypto.signatures import MLDSA65


def b64e(data: Optional[bytes]) -> Optional[str]:
    return base64.b64encode(data).decode("ascii") if data is not None else None


def b64d(data: Optional[str]) -> Optional[bytes]:
    return base64.b64decode(data.encode("ascii")) if data is not None else None


class RatchetHeader:
    """Header attached to every HPQ-DR message.

    Carries asymmetric ratchet parameters, message sequence numbers, and
    PQC encapsulation material when an asymmetric ratchet turn occurs.
    """

    def __init__(
        self,
        sender_id: str,
        recipient_id: str,
        dh_pub: bytes,  # Sender's ephemeral X25519 public key (32 bytes)
        pn: int,  # Number of messages in previous sending chain
        n: int,  # Message index in current sending chain
        ratchet_turn: int,  # Number of asymmetric ratchet turns
        kem_ct: Optional[bytes] = None,  # ML-KEM ciphertext (1088 bytes) on new ratchet turn
        kem_pub: Optional[bytes] = None,  # Sender's fresh ML-KEM public key (1184 bytes)
    ):
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.dh_pub = dh_pub
        self.pn = pn
        self.n = n
        self.ratchet_turn = ratchet_turn
        self.kem_ct = kem_ct
        self.kem_pub = kem_pub

    def to_bytes(self) -> bytes:
        """Serializes header deterministically for signing and authentication."""
        kem_ct_bytes = self.kem_ct if self.kem_ct is not None else b""
        kem_pub_bytes = self.kem_pub if self.kem_pub is not None else b""

        meta = struct.pack(
            ">IIIIII",
            len(self.sender_id.encode("utf-8")),
            len(self.recipient_id.encode("utf-8")),
            self.pn,
            self.n,
            self.ratchet_turn,
            len(kem_ct_bytes),
        )
        return (
            b"HPQ-DR-HDR-v1"
            + meta
            + self.sender_id.encode("utf-8")
            + self.recipient_id.encode("utf-8")
            + self.dh_pub
            + struct.pack(">I", len(kem_pub_bytes))
            + kem_ct_bytes
            + kem_pub_bytes
        )

    def to_dict(self) -> dict:
        return {
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "dh_pub": b64e(self.dh_pub),
            "pn": self.pn,
            "n": self.n,
            "ratchet_turn": self.ratchet_turn,
            "kem_ct": b64e(self.kem_ct),
            "kem_pub": b64e(self.kem_pub),
        }

    @classmethod
    def from_dict(cls, d: dict) -> RatchetHeader:
        return cls(
            sender_id=d["sender_id"],
            recipient_id=d["recipient_id"],
            dh_pub=b64d(d["dh_pub"]),
            pn=d["pn"],
            n=d["n"],
            ratchet_turn=d["ratchet_turn"],
            kem_ct=b64d(d.get("kem_ct")),
            kem_pub=b64d(d.get("kem_pub")),
        )


class SecureEnvelope:
    """Outer transport envelope containing header, AES-256-GCM ciphertext, and ML-DSA-65 signature."""

    def __init__(
        self,
        header: RatchetHeader,
        nonce: bytes,
        ciphertext: bytes,
        signature: bytes,
    ):
        self.header = header
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.signature = signature

    @classmethod
    def construct_signed_payload(
        cls, header: RatchetHeader, nonce: bytes, ciphertext: bytes
    ) -> bytes:
        return header.to_bytes() + nonce + ciphertext

    def verify_signature(self, sender_mldsa_pub: bytes) -> bool:
        """Verifies that the envelope was signed by the sender's ML-DSA-65 identity key."""
        payload = self.construct_signed_payload(self.header, self.nonce, self.ciphertext)
        return MLDSA65.verify(sender_mldsa_pub, payload, self.signature)

    def to_dict(self) -> dict:
        return {
            "header": self.header.to_dict(),
            "nonce": b64e(self.nonce),
            "ciphertext": b64e(self.ciphertext),
            "signature": b64e(self.signature),
        }

    @classmethod
    def from_dict(cls, d: dict) -> SecureEnvelope:
        return cls(
            header=RatchetHeader.from_dict(d["header"]),
            nonce=b64d(d["nonce"]),
            ciphertext=b64d(d["ciphertext"]),
            signature=b64d(d["signature"]),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_str: str) -> SecureEnvelope:
        return cls.from_dict(json.loads(json_str))
