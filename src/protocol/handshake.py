"""PQXDH-style Hybrid Initial Handshake for HPQ-DR."""

from __future__ import annotations

import base64
import json
import struct
from typing import Tuple
from src.crypto.kem import X25519DH, MLKEM768
from src.crypto.signatures import MLDSA65
from src.crypto.symmetric import hkdf_derive
from src.identity.keys import IdentityKeyPair
from src.identity.bundle import PreKeyBundle, ClientKeyStore, b64e, b64d


class HandshakeInitMessage:
    """Initial handshake message sent from initiator to recipient."""

    def __init__(
        self,
        initiator_id: str,
        recipient_id: str,
        initiator_mldsa_pub: bytes,
        initiator_x25519_pub: bytes,
        ephemeral_x25519_pub: bytes,
        signed_prekey_id: int,
        onetime_prekey_id: int,
        mlkem_ciphertext: bytes,
        signature: bytes,
    ):
        self.initiator_id = initiator_id
        self.recipient_id = recipient_id
        self.initiator_mldsa_pub = initiator_mldsa_pub
        self.initiator_x25519_pub = initiator_x25519_pub
        self.ephemeral_x25519_pub = ephemeral_x25519_pub
        self.signed_prekey_id = signed_prekey_id
        self.onetime_prekey_id = onetime_prekey_id
        self.mlkem_ciphertext = mlkem_ciphertext
        self.signature = signature

    def get_signed_payload(self) -> bytes:
        meta = struct.pack(
            ">IIII",
            len(self.initiator_id.encode("utf-8")),
            len(self.recipient_id.encode("utf-8")),
            self.signed_prekey_id,
            self.onetime_prekey_id,
        )
        return (
            b"HPQ-DR-HandshakeInit-v1"
            + meta
            + self.initiator_id.encode("utf-8")
            + self.recipient_id.encode("utf-8")
            + self.initiator_mldsa_pub
            + self.initiator_x25519_pub
            + self.ephemeral_x25519_pub
            + self.mlkem_ciphertext
        )

    def verify_signature(self) -> bool:
        payload = self.get_signed_payload()
        return MLDSA65.verify(self.initiator_mldsa_pub, payload, self.signature)

    def to_dict(self) -> dict:
        return {
            "initiator_id": self.initiator_id,
            "recipient_id": self.recipient_id,
            "initiator_mldsa_pub": b64e(self.initiator_mldsa_pub),
            "initiator_x25519_pub": b64e(self.initiator_x25519_pub),
            "ephemeral_x25519_pub": b64e(self.ephemeral_x25519_pub),
            "signed_prekey_id": self.signed_prekey_id,
            "onetime_prekey_id": self.onetime_prekey_id,
            "mlkem_ciphertext": b64e(self.mlkem_ciphertext),
            "signature": b64e(self.signature),
        }

    @classmethod
    def from_dict(cls, d: dict) -> HandshakeInitMessage:
        return cls(
            initiator_id=d["initiator_id"],
            recipient_id=d["recipient_id"],
            initiator_mldsa_pub=b64d(d["initiator_mldsa_pub"]),
            initiator_x25519_pub=b64d(d["initiator_x25519_pub"]),
            ephemeral_x25519_pub=b64d(d["ephemeral_x25519_pub"]),
            signed_prekey_id=d["signed_prekey_id"],
            onetime_prekey_id=d["onetime_prekey_id"],
            mlkem_ciphertext=b64d(d["mlkem_ciphertext"]),
            signature=b64d(d["signature"]),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_str: str) -> HandshakeInitMessage:
        return cls.from_dict(json.loads(json_str))


class PQXDHHandshake:
    """PQXDH-style hybrid initial handshake combining X25519 and ML-KEM-768."""

    SALT = b"HPQ-DR-Handshake-Salt-v1"
    INFO = b"HPQ-DR-Handshake-InitialKeys-v1"

    @classmethod
    def initiate(
        cls,
        initiator_identity: IdentityKeyPair,
        peer_bundle: PreKeyBundle,
    ) -> Tuple[HandshakeInitMessage, bytes, bytes, bytes]:
        """Initiator (Alice) starts session with recipient (Bob).

        Returns:
            Tuple of (HandshakeInitMessage, root_key, sending_chain_key, eph_x25519_priv)
        Raises:
            ValueError if peer bundle signature is invalid.
        """
        # 1. Cryptographically verify Bob's ML-DSA-65 signed prekey
        if not peer_bundle.verify():
            raise ValueError("Handshake aborted: Peer's ML-DSA-65 prekey bundle signature is invalid!")

        # 2. Ephemeral classical keypair
        eph_x25519_pub, eph_x25519_priv = X25519DH.generate_keypair()

        # 3. ML-KEM-768 encapsulation against Bob's one-time prekey
        ss_kem, mlkem_ct = MLKEM768.encapsulate(peer_bundle.onetime_prekey_pqc)

        # 4. Triple Diffie-Hellman (X3DH classical component)
        dh1 = X25519DH.diffie_hellman(initiator_identity.x25519_priv, peer_bundle.signed_prekey_classic)
        dh2 = X25519DH.diffie_hellman(eph_x25519_priv, peer_bundle.identity_key_classic)
        dh3 = X25519DH.diffie_hellman(eph_x25519_priv, peer_bundle.signed_prekey_classic)

        # 5. Hybrid KDF combination: DH1 || DH2 || DH3 || SS_KEM
        ikm = dh1 + dh2 + dh3 + ss_kem
        derived_keys = hkdf_derive(
            salt=cls.SALT,
            ikm=ikm,
            info=cls.INFO,
            length=64,
        )
        root_key = derived_keys[0:32]
        chain_key = derived_keys[32:64]

        # 6. Construct signed HandshakeInitMessage
        msg = HandshakeInitMessage(
            initiator_id=initiator_identity.user_id,
            recipient_id=peer_bundle.user_id,
            initiator_mldsa_pub=initiator_identity.mldsa_pub,
            initiator_x25519_pub=initiator_identity.x25519_pub,
            ephemeral_x25519_pub=eph_x25519_pub,
            signed_prekey_id=peer_bundle.signed_prekey_id,
            onetime_prekey_id=peer_bundle.onetime_prekey_id,
            mlkem_ciphertext=mlkem_ct,
            signature=b"",
        )
        msg.signature = initiator_identity.sign(msg.get_signed_payload())

        return msg, root_key, chain_key, eph_x25519_priv

    @classmethod
    def receive(
        cls,
        recipient_keystore: ClientKeyStore,
        msg: HandshakeInitMessage,
    ) -> Tuple[bytes, bytes]:
        """Recipient (Bob) processes HandshakeInitMessage from Alice.

        Returns:
            Tuple of (root_key, receiving_chain_key)
        Raises:
            ValueError if message signature is invalid.
        """
        # 1. Verify initiator's ML-DSA-65 signature on handshake message
        if not msg.verify_signature():
            raise ValueError("Handshake aborted: Initiator's ML-DSA-65 signature is invalid!")

        # 2. Retrieve recipient's private prekeys
        if (
            recipient_keystore.signed_prekey is None
            or recipient_keystore.signed_prekey.key_id != msg.signed_prekey_id
        ):
            raise ValueError(f"Signed prekey ID {msg.signed_prekey_id} not available")

        spk_priv = recipient_keystore.signed_prekey.x25519_priv
        opk = recipient_keystore.consume_onetime_prekey(msg.onetime_prekey_id)

        # 3. Decapsulate ML-KEM-768 ciphertext
        ss_kem = MLKEM768.decapsulate(opk.mlkem_priv, msg.mlkem_ciphertext)

        # 4. Compute matching classical Diffie-Hellman shared secrets
        dh1 = X25519DH.diffie_hellman(spk_priv, msg.initiator_x25519_pub)
        dh2 = X25519DH.diffie_hellman(recipient_keystore.identity.x25519_priv, msg.ephemeral_x25519_pub)
        dh3 = X25519DH.diffie_hellman(spk_priv, msg.ephemeral_x25519_pub)

        # 5. Hybrid KDF combination
        ikm = dh1 + dh2 + dh3 + ss_kem
        derived_keys = hkdf_derive(
            salt=cls.SALT,
            ikm=ikm,
            info=cls.INFO,
            length=64,
        )
        root_key = derived_keys[0:32]
        chain_key = derived_keys[32:64]

        return root_key, chain_key
