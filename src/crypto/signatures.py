"""Digital signatures: NIST FIPS 204 ML-DSA-65 (CRYSTALS-Dilithium3) and Classical Ed25519."""

from __future__ import annotations

from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from dilithium_py.dilithium import Dilithium3


class MLDSA65:
    """NIST FIPS 204 ML-DSA-65 (CRYSTALS-Dilithium3) Signature Scheme."""

    PUBLIC_KEY_SIZE = 1952
    SECRET_KEY_SIZE = 4000

    @classmethod
    def generate_keypair(cls) -> Tuple[bytes, bytes]:
        """Generates (public_key, secret_key) tuple."""
        pk, sk = Dilithium3.keygen()
        return pk, sk

    @classmethod
    def sign(cls, secret_key: bytes, message: bytes) -> bytes:
        """Signs a message using the ML-DSA-65 secret key.

        Returns:
            signature bytes
        """
        if len(secret_key) != cls.SECRET_KEY_SIZE:
            raise ValueError(
                f"Invalid ML-DSA-65 secret key length: expected {cls.SECRET_KEY_SIZE}, got {len(secret_key)}"
            )
        return Dilithium3.sign(secret_key, message)

    @classmethod
    def verify(cls, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verifies an ML-DSA-65 signature against the public key and message.

        Returns:
            True if valid, False otherwise.
        """
        if len(public_key) != cls.PUBLIC_KEY_SIZE:
            return False
        try:
            return Dilithium3.verify(public_key, message, signature)
        except Exception:
            return False


class Ed25519Signer:
    """Classical Ed25519 digital signature scheme."""

    KEY_SIZE = 32

    @classmethod
    def generate_keypair(cls) -> Tuple[bytes, bytes]:
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key()
        priv_bytes = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return pub_bytes, priv_bytes

    @classmethod
    def sign(cls, secret_key_bytes: bytes, message: bytes) -> bytes:
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(secret_key_bytes)
        return priv.sign(message)

    @classmethod
    def verify(cls, public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
        try:
            pub = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            pub.verify(signature, message)
            return True
        except (InvalidSignature, ValueError):
            return False
