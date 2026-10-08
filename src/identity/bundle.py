"""PreKey bundle data structures, validation, and local key store."""

from __future__ import annotations

import base64
import json
from typing import Dict, Optional
from src.crypto.signatures import MLDSA65
from src.identity.keys import IdentityKeyPair, SignedPreKeyPair, OneTimePreKeyPair


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


class PreKeyBundle:
    """Public prekey bundle fetched by initiator to establish a secure session."""

    def __init__(
        self,
        user_id: str,
        identity_key_pqc: bytes,
        identity_key_classic: bytes,
        signed_prekey_classic: bytes,
        signed_prekey_id: int,
        signed_prekey_sig: bytes,
        signed_prekey_ts: float,
        onetime_prekey_pqc: bytes,
        onetime_prekey_id: int,
    ):
        self.user_id = user_id
        self.identity_key_pqc = identity_key_pqc
        self.identity_key_classic = identity_key_classic
        self.signed_prekey_classic = signed_prekey_classic
        self.signed_prekey_id = signed_prekey_id
        self.signed_prekey_sig = signed_prekey_sig
        self.signed_prekey_ts = signed_prekey_ts
        self.onetime_prekey_pqc = onetime_prekey_pqc
        self.onetime_prekey_id = onetime_prekey_id

    def verify(self) -> bool:
        """Cryptographically verifies the bundle's signed prekey signature.

        Returns:
            True if the ML-DSA-65 signature on the classical prekey is valid.
        """
        payload = SignedPreKeyPair.construct_signed_payload(
            self.signed_prekey_id, self.signed_prekey_classic, self.signed_prekey_ts
        )
        return MLDSA65.verify(self.identity_key_pqc, payload, self.signed_prekey_sig)

    def to_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "identity_key_pqc": b64e(self.identity_key_pqc),
            "identity_key_classic": b64e(self.identity_key_classic),
            "signed_prekey_classic": b64e(self.signed_prekey_classic),
            "signed_prekey_id": self.signed_prekey_id,
            "signed_prekey_sig": b64e(self.signed_prekey_sig),
            "signed_prekey_ts": self.signed_prekey_ts,
            "onetime_prekey_pqc": b64e(self.onetime_prekey_pqc),
            "onetime_prekey_id": self.onetime_prekey_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> PreKeyBundle:
        return cls(
            user_id=data["user_id"],
            identity_key_pqc=b64d(data["identity_key_pqc"]),
            identity_key_classic=b64d(data["identity_key_classic"]),
            signed_prekey_classic=b64d(data["signed_prekey_classic"]),
            signed_prekey_id=data["signed_prekey_id"],
            signed_prekey_sig=b64d(data["signed_prekey_sig"]),
            signed_prekey_ts=data["signed_prekey_ts"],
            onetime_prekey_pqc=b64d(data["onetime_prekey_pqc"]),
            onetime_prekey_id=data["onetime_prekey_id"],
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_str: str) -> PreKeyBundle:
        return cls.from_dict(json.loads(json_str))


class ClientKeyStore:
    """Maintains a client's private identity, active signed prekey, and one-time prekeys."""

    def __init__(self, identity: IdentityKeyPair):
        self.identity = identity
        self.signed_prekey: Optional[SignedPreKeyPair] = None
        self.onetime_prekeys: Dict[int, OneTimePreKeyPair] = {}
        self.consumed_prekeys: Dict[int, OneTimePreKeyPair] = {}
        self._next_spk_id = 1
        self._next_opk_id = 1

    @classmethod
    def create_new(cls, user_id: str, opk_count: int = 10) -> ClientKeyStore:
        """Initializes a fresh identity with signed prekey and a batch of one-time prekeys."""
        identity = IdentityKeyPair.generate(user_id)
        store = cls(identity)
        store.rotate_signed_prekey()
        store.generate_onetime_prekeys(opk_count)
        return store

    def rotate_signed_prekey(self) -> SignedPreKeyPair:
        """Generates and activates a new signed prekey."""
        spk = SignedPreKeyPair.generate(self._next_spk_id, self.identity)
        self.signed_prekey = spk
        self._next_spk_id += 1
        return spk

    def generate_onetime_prekeys(self, count: int = 10) -> list[OneTimePreKeyPair]:
        """Generates a batch of ML-KEM-768 one-time prekeys."""
        created = []
        for _ in range(count):
            opk = OneTimePreKeyPair.generate(self._next_opk_id)
            self.onetime_prekeys[self._next_opk_id] = opk
            created.append(opk)
            self._next_opk_id += 1
        return created

    def create_bundle(self, onetime_prekey_id: Optional[int] = None) -> PreKeyBundle:
        """Exports a public bundle for publishing or peer retrieval."""
        if self.signed_prekey is None:
            self.rotate_signed_prekey()

        if onetime_prekey_id is None:
            if not self.onetime_prekeys:
                self.generate_onetime_prekeys(5)
            onetime_prekey_id = next(iter(self.onetime_prekeys))

        opk = self.onetime_prekeys[onetime_prekey_id]
        return PreKeyBundle(
            user_id=self.identity.user_id,
            identity_key_pqc=self.identity.mldsa_pub,
            identity_key_classic=self.identity.x25519_pub,
            signed_prekey_classic=self.signed_prekey.x25519_pub,
            signed_prekey_id=self.signed_prekey.key_id,
            signed_prekey_sig=self.signed_prekey.signature,
            signed_prekey_ts=self.signed_prekey.timestamp,
            onetime_prekey_pqc=opk.mlkem_pub,
            onetime_prekey_id=opk.key_id,
        )

    def consume_onetime_prekey(self, key_id: int) -> OneTimePreKeyPair:
        """Retrieves and immediately marks consumed to prevent reuse in new handshakes."""
        if key_id not in self.onetime_prekeys:
            raise KeyError(f"One-time prekey {key_id} not found or already consumed")
        opk = self.onetime_prekeys.pop(key_id)
        self.consumed_prekeys[key_id] = opk
        return opk

    def get_prekey_for_decrypt(self, key_id: Optional[int]) -> Optional[OneTimePreKeyPair]:
        """Retrieves prekey by ID from active or recently consumed prekeys."""
        if key_id is not None:
            if key_id in self.onetime_prekeys:
                return self.onetime_prekeys[key_id]
            if key_id in self.consumed_prekeys:
                return self.consumed_prekeys[key_id]
        return None
