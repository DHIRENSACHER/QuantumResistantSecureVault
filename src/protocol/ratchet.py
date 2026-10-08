"""Hybrid Post-Quantum Double Ratchet (HPQ-DR) Protocol Engine."""

from __future__ import annotations

from typing import Dict, Optional, Tuple
from src.crypto.kem import X25519DH, MLKEM768
from src.crypto.symmetric import (
    AES256GCMCipher,
    hkdf_derive,
    zeroize,
)
from src.identity.keys import IdentityKeyPair
from src.protocol.message import RatchetHeader, SecureEnvelope


class HPQDoubleRatchet:
    """Hybrid Post-Quantum Double Ratchet Engine.

    Guarantees:
    - Forward Secrecy via symmetric KDF message chains.
    - Post-Compromise Security ("healing") via turn-based hybrid asymmetric ratchets
      combining classical X25519 ECDH and NIST FIPS 203 ML-KEM-768.
    - Non-repudiation & Authenticity via NIST FIPS 204 ML-DSA-65 envelope signatures.
    """

    KDF_RK_SALT = b"HPQ-DR-KDF-RootKey-Salt-v1"
    KDF_RK_INFO = b"HPQ-DR-KDF-RootKey-Info-v1"
    KDF_CK_INFO = b"HPQ-DR-KDF-ChainKey-v1"
    KDF_MK_INFO = b"HPQ-DR-KDF-MessageKey-v1"
    HYBRID_KEM_SALT = b"HPQ-DR-Ratchet-Hybrid-Salt-v1"
    HYBRID_KEM_INFO = b"HPQ-DR-Ratchet-Hybrid-Info-v1"
    MAX_SKIPPED_KEYS = 2000

    def __init__(
        self,
        local_identity: IdentityKeyPair,
        peer_id: str,
        peer_mldsa_pub: bytes,
        root_key: bytes,
        is_initiator: bool,
        initial_chain_key: Optional[bytes] = None,
        initial_dh_priv: Optional[bytes] = None,
        peer_dh_pub: Optional[bytes] = None,
        peer_kem_pub: Optional[bytes] = None,
    ):
        self.local_identity = local_identity
        self.peer_id = peer_id
        self.peer_mldsa_pub = peer_mldsa_pub

        # Root key
        self.root_key = root_key

        # Ephemeral Asymmetric Ratchet State (X25519)
        if initial_dh_priv is not None:
            self.dhs_priv = initial_dh_priv
            from cryptography.hazmat.primitives.asymmetric import x25519
            from cryptography.hazmat.primitives import serialization
            priv = x25519.X25519PrivateKey.from_private_bytes(initial_dh_priv)
            self.dhs_pub = priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        else:
            self.dhs_pub, self.dhs_priv = X25519DH.generate_keypair()

        self.dhr_pub: Optional[bytes] = peer_dh_pub

        # Ephemeral PQC Ratchet State (ML-KEM-768)
        self.local_kem_pub, self.local_kem_priv = MLKEM768.generate_keypair()
        self.peer_kem_pub: Optional[bytes] = peer_kem_pub

        # One-time pending KEM ciphertext to transmit in next outbound header
        self._pending_kem_ct: Optional[bytes] = None

        # Chains
        if is_initiator:
            self.cks: Optional[bytes] = initial_chain_key  # Sending chain key
            self.ckr: Optional[bytes] = None               # Receiving chain key
        else:
            self.cks: Optional[bytes] = None
            self.ckr: Optional[bytes] = initial_chain_key  # Receiving chain key

        # Message & Turn Counters
        self.ns: int = 0
        self.nr: int = 0
        self.pn: int = 0
        self.ratchet_turn: int = 0

        # Skipped keys cache: (header_dh_pub, message_index) -> message_key
        self.skipped_message_keys: Dict[Tuple[bytes, int], bytes] = {}

    # -------------------------------------------------------------------------
    # KDF Helpers
    # -------------------------------------------------------------------------

    def _kdf_rk(self, rk: bytes, hybrid_secret: bytes) -> Tuple[bytes, bytes]:
        """Root KDF deriving new root key and chain key from hybrid secret."""
        derived = hkdf_derive(
            salt=self.KDF_RK_SALT,
            ikm=rk + hybrid_secret,
            info=self.KDF_RK_INFO,
            length=64,
        )
        return derived[0:32], derived[32:64]

    def _symmetric_step(self, chain_key: bytes) -> Tuple[bytes, bytes]:
        """Advances symmetric chain key and derives a fresh 256-bit message key."""
        next_ck = hkdf_derive(salt=None, ikm=chain_key, info=self.KDF_CK_INFO, length=32)
        mk = hkdf_derive(salt=None, ikm=chain_key, info=self.KDF_MK_INFO, length=32)
        return next_ck, mk

    def _combine_hybrid_secret(self, ss_ecdh: bytes, ss_kem: bytes) -> bytes:
        """Domain-separated HKDF combination of classical ECDH and post-quantum KEM secrets."""
        return hkdf_derive(
            salt=self.HYBRID_KEM_SALT,
            ikm=ss_ecdh + ss_kem,
            info=self.HYBRID_KEM_INFO,
            length=32,
        )

    # -------------------------------------------------------------------------
    # Asymmetric Ratchet Steps
    # -------------------------------------------------------------------------

    def _dh_ratchet(self, header: RatchetHeader) -> None:
        """Processes peer's new ratchet turn and prepares next sending ratchet."""
        self.pn = self.ns
        self.ns = 0
        self.nr = 0
        self.dhr_pub = header.dh_pub
        self.ratchet_turn += 1

        # 1. Compute receiving hybrid shared secret
        ss_ecdh = X25519DH.diffie_hellman(self.dhs_priv, self.dhr_pub)
        if header.kem_ct is not None:
            ss_kem = MLKEM768.decapsulate(self.local_kem_priv, header.kem_ct)
        else:
            ss_kem = b"\x00" * 32

        hybrid_recv = self._combine_hybrid_secret(ss_ecdh, ss_kem)
        self.root_key, self.ckr = self._kdf_rk(self.root_key, hybrid_recv)

        # Update peer's advertised ML-KEM public key
        if header.kem_pub is not None:
            self.peer_kem_pub = header.kem_pub

        # 2. Generate new ephemeral keypair for sending
        self.dhs_pub, self.dhs_priv = X25519DH.generate_keypair()
        self.local_kem_pub, self.local_kem_priv = MLKEM768.generate_keypair()

        # Compute sending hybrid shared secret
        ss_ecdh_send = X25519DH.diffie_hellman(self.dhs_priv, self.dhr_pub)
        if self.peer_kem_pub is not None:
            ss_kem_send, self._pending_kem_ct = MLKEM768.encapsulate(self.peer_kem_pub)
        else:
            ss_kem_send = b"\x00" * 32
            self._pending_kem_ct = None

        hybrid_send = self._combine_hybrid_secret(ss_ecdh_send, ss_kem_send)
        self.root_key, self.cks = self._kdf_rk(self.root_key, hybrid_send)

    # -------------------------------------------------------------------------
    # Sending / Encryption
    # -------------------------------------------------------------------------

    def encrypt(self, plaintext: bytes) -> SecureEnvelope:
        """Encrypts plaintext with next symmetric Message Key and signs envelope."""
        if self.cks is None:
            # First send for recipient who hasn't sent yet: initialize sending ratchet
            self.dhs_pub, self.dhs_priv = X25519DH.generate_keypair()
            self.local_kem_pub, self.local_kem_priv = MLKEM768.generate_keypair()

            ss_ecdh = X25519DH.diffie_hellman(self.dhs_priv, self.dhr_pub)
            if self.peer_kem_pub is not None:
                ss_kem, self._pending_kem_ct = MLKEM768.encapsulate(self.peer_kem_pub)
            else:
                ss_kem = b"\x00" * 32
                self._pending_kem_ct = None

            hybrid_send = self._combine_hybrid_secret(ss_ecdh, ss_kem)
            self.root_key, self.cks = self._kdf_rk(self.root_key, hybrid_send)

        # Advance symmetric chain
        self.cks, mk = self._symmetric_step(self.cks)

        # Build message header
        header = RatchetHeader(
            sender_id=self.local_identity.user_id,
            recipient_id=self.peer_id,
            dh_pub=self.dhs_pub,
            pn=self.pn,
            n=self.ns,
            ratchet_turn=self.ratchet_turn,
            kem_ct=self._pending_kem_ct,
            kem_pub=self.local_kem_pub,
        )
        self._pending_kem_ct = None  # Transmitted
        self.ns += 1

        # Encrypt plaintext with AES-256-GCM using MK
        ciphertext, nonce = AES256GCMCipher.encrypt(
            key=mk,
            plaintext=plaintext,
            associated_data=header.to_bytes(),
        )

        # Secure zeroize Message Key
        mk_ba = bytearray(mk)
        zeroize(mk_ba)

        # Sign envelope with sender's ML-DSA-65 identity key
        signed_payload = SecureEnvelope.construct_signed_payload(header, nonce, ciphertext)
        signature = self.local_identity.sign(signed_payload)

        return SecureEnvelope(
            header=header,
            nonce=nonce,
            ciphertext=ciphertext,
            signature=signature,
        )

    # -------------------------------------------------------------------------
    # Receiving / Decryption
    # -------------------------------------------------------------------------

    def _skip_message_keys(self, until: int) -> None:
        """Derives and caches skipped message keys for out-of-order delivery."""
        if self.ckr is not None:
            while self.nr < until:
                self.ckr, mk = self._symmetric_step(self.ckr)
                if len(self.skipped_message_keys) < self.MAX_SKIPPED_KEYS:
                    self.skipped_message_keys[(self.dhr_pub, self.nr)] = mk
                self.nr += 1

    def decrypt(self, envelope: SecureEnvelope) -> bytes:
        """Verifies envelope, handles ratcheting, and decrypts message."""
        # 1. Verify ML-DSA-65 signature on envelope
        if not envelope.verify_signature(self.peer_mldsa_pub):
            raise ValueError("Decryption aborted: Envelope ML-DSA-65 signature is invalid!")

        header = envelope.header

        # Check if key was skipped previously
        skipped_key = self.skipped_message_keys.pop((header.dh_pub, header.n), None)
        if skipped_key is not None:
            plaintext = AES256GCMCipher.decrypt(
                key=skipped_key,
                nonce=envelope.nonce,
                ciphertext=envelope.ciphertext,
                associated_data=header.to_bytes(),
            )
            mk_ba = bytearray(skipped_key)
            zeroize(mk_ba)
            return plaintext

        # Always update peer's advertised ML-KEM public key
        if header.kem_pub is not None:
            self.peer_kem_pub = header.kem_pub

        # 2. Check if peer initiated a new asymmetric ratchet turn
        if self.dhr_pub != header.dh_pub:
            self._skip_message_keys(header.pn)
            self._dh_ratchet(header)

        # 3. Skip any missed messages in current chain up to header.n
        self._skip_message_keys(header.n)

        # 4. Advance receiving chain key
        self.ckr, mk = self._symmetric_step(self.ckr)
        self.nr += 1

        # 5. Decrypt and verify ciphertext
        plaintext = AES256GCMCipher.decrypt(
            key=mk,
            nonce=envelope.nonce,
            ciphertext=envelope.ciphertext,
            associated_data=header.to_bytes(),
        )

        mk_ba = bytearray(mk)
        zeroize(mk_ba)

        return plaintext
