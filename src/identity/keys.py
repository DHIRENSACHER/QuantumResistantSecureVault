"""Identity keys, Signed PreKeys, and One-Time PreKeys for HPQ-DR."""

from __future__ import annotations

import struct
import time
from typing import Optional, Tuple
from src.crypto.signatures import MLDSA65
from src.crypto.kem import X25519DH, MLKEM768


class IdentityKeyPair:
    """Long-term cryptographic identity.

    Consists of:
    - ML-DSA-65 keypair (FIPS 204 digital signature for quantum-resistant authentication)
    - X25519 keypair (classical long-term key agreement identity)
    """

    def __init__(
        self,
        user_id: str,
        mldsa_pub: bytes,
        mldsa_priv: bytes,
        x25519_pub: bytes,
        x25519_priv: bytes,
    ):
        self.user_id = user_id
        self.mldsa_pub = mldsa_pub
        self.mldsa_priv = mldsa_priv
        self.x25519_pub = x25519_pub
        self.x25519_priv = x25519_priv

    @classmethod
    def generate(cls, user_id: str) -> IdentityKeyPair:
        """Generates fresh long-term identity keys."""
        mldsa_pub, mldsa_priv = MLDSA65.generate_keypair()
        x25519_pub, x25519_priv = X25519DH.generate_keypair()
        return cls(
            user_id=user_id,
            mldsa_pub=mldsa_pub,
            mldsa_priv=mldsa_priv,
            x25519_pub=x25519_pub,
            x25519_priv=x25519_priv,
        )

    def sign(self, message: bytes) -> bytes:
        """Signs message using ML-DSA-65 identity key."""
        return MLDSA65.sign(self.mldsa_priv, message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verifies signature against this identity's ML-DSA-65 public key."""
        return MLDSA65.verify(self.mldsa_pub, message, signature)


class SignedPreKeyPair:
    """Medium-term classical X25519 prekey signed with the ML-DSA-65 identity key."""

    def __init__(
        self,
        key_id: int,
        x25519_pub: bytes,
        x25519_priv: bytes,
        timestamp: float,
        signature: bytes,
    ):
        self.key_id = key_id
        self.x25519_pub = x25519_pub
        self.x25519_priv = x25519_priv
        self.timestamp = timestamp
        self.signature = signature

    @staticmethod
    def construct_signed_payload(key_id: int, x25519_pub: bytes, timestamp: float) -> bytes:
        """Constructs deterministic payload for ML-DSA-65 signing."""
        return b"HPQ-DR-SignedPreKey-v1" + struct.pack(">Id", key_id, timestamp) + x25519_pub

    @classmethod
    def generate(cls, key_id: int, identity_key: IdentityKeyPair) -> SignedPreKeyPair:
        """Generates and signs an X25519 signed prekey."""
        x25519_pub, x25519_priv = X25519DH.generate_keypair()
        ts = time.time()
        payload = cls.construct_signed_payload(key_id, x25519_pub, ts)
        sig = identity_key.sign(payload)
        return cls(
            key_id=key_id,
            x25519_pub=x25519_pub,
            x25519_priv=x25519_priv,
            timestamp=ts,
            signature=sig,
        )

    def verify(self, identity_mldsa_pub: bytes) -> bool:
        """Verifies signature using the issuer's ML-DSA-65 public key."""
        payload = self.construct_signed_payload(self.key_id, self.x25519_pub, self.timestamp)
        return MLDSA65.verify(identity_mldsa_pub, payload, self.signature)


class OneTimePreKeyPair:
    """Ephemeral post-quantum ML-KEM-768 prekey for single-use initial handshakes."""

    def __init__(
        self,
        key_id: int,
        mlkem_pub: bytes,
        mlkem_priv: bytes,
    ):
        self.key_id = key_id
        self.mlkem_pub = mlkem_pub
        self.mlkem_priv = mlkem_priv

    @classmethod
    def generate(cls, key_id: int) -> OneTimePreKeyPair:
        """Generates a fresh ML-KEM-768 one-time prekey."""
        pub, priv = MLKEM768.generate_keypair()
        return cls(key_id=key_id, mlkem_pub=pub, mlkem_priv=priv)
