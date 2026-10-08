"""Key Encapsulation Mechanisms (KEM): NIST FIPS 203 ML-KEM-768, X25519 ECDH, and Hybrid KEM."""

from __future__ import annotations

from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from kyber_py.kyber import Kyber768
from .symmetric import hkdf_derive


class MLKEM768:
    """NIST FIPS 203 ML-KEM-768 (Crystals-Kyber) Implementation."""

    PUBLIC_KEY_SIZE = 1184
    SECRET_KEY_SIZE = 2400
    CIPHERTEXT_SIZE = 1088
    SHARED_SECRET_SIZE = 32

    @classmethod
    def generate_keypair(cls) -> Tuple[bytes, bytes]:
        """Generates (public_key, secret_key) tuple."""
        pk, sk = Kyber768.keygen()
        return pk, sk

    @classmethod
    def encapsulate(cls, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulates a fresh shared secret against recipient's public key.

        Returns:
            Tuple of (shared_secret [32 bytes], ciphertext [1088 bytes])
        """
        if len(public_key) != cls.PUBLIC_KEY_SIZE:
            raise ValueError(
                f"Invalid ML-KEM-768 public key length: expected {cls.PUBLIC_KEY_SIZE}, got {len(public_key)}"
            )
        shared_secret, ciphertext = Kyber768.encaps(public_key)
        return shared_secret, ciphertext

    @classmethod
    def decapsulate(cls, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulates the shared secret from ciphertext using secret key.

        Returns:
            shared_secret [32 bytes]
        """
        if len(secret_key) != cls.SECRET_KEY_SIZE:
            raise ValueError(
                f"Invalid ML-KEM-768 secret key length: expected {cls.SECRET_KEY_SIZE}, got {len(secret_key)}"
            )
        if len(ciphertext) != cls.CIPHERTEXT_SIZE:
            raise ValueError(
                f"Invalid ML-KEM-768 ciphertext length: expected {cls.CIPHERTEXT_SIZE}, got {len(ciphertext)}"
            )
        return Kyber768.decaps(secret_key, ciphertext)


class X25519DH:
    """Classical Curve25519 Elliptic Curve Diffie-Hellman."""

    KEY_SIZE = 32

    @classmethod
    def generate_keypair(cls) -> Tuple[bytes, bytes]:
        """Generates (public_key_bytes, private_key_bytes)."""
        priv = x25519.X25519PrivateKey.generate()
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
    def diffie_hellman(cls, private_key_bytes: bytes, peer_public_key_bytes: bytes) -> bytes:
        """Computes ECDH shared secret between private key and peer public key."""
        if len(private_key_bytes) != cls.KEY_SIZE or len(peer_public_key_bytes) != cls.KEY_SIZE:
            raise ValueError(f"X25519 keys must be {cls.KEY_SIZE} bytes")
        priv = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)
        pub = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        return priv.exchange(pub)


class HybridKEMExchange:
    """Hybrid Post-Quantum Key Encapsulation combining X25519 and ML-KEM-768.

    Domain-separated HKDF mixes classical ECDH shared secret and PQC lattice shared secret:
    CombinedSecret = HKDF-Extract(salt='HPQ-DR-v1-HybridKEM', IKM = SS_ECDH || SS_PQC)
    """

    SALT = b"HPQ-DR-v1-HybridKEM-Combination"
    INFO = b"HPQ-DR-v1-HybridKEM-Derivation"

    @classmethod
    def combine_secrets(cls, ss_ecdh: bytes, ss_pqc: bytes) -> bytes:
        """Derives a single 256-bit hybrid shared secret from both primitives."""
        combined_ikm = ss_ecdh + ss_pqc
        return hkdf_derive(
            salt=cls.SALT,
            ikm=combined_ikm,
            info=cls.INFO,
            length=32,
        )

    @classmethod
    def encapsulate(
        cls,
        peer_x25519_pub: bytes,
        peer_mlkem_pub: bytes,
    ) -> Tuple[bytes, bytes, bytes]:
        """Executes hybrid encapsulation.

        Returns:
            Tuple of (hybrid_shared_secret, ephemeral_x25519_pub, mlkem_ciphertext)
        """
        # 1. Ephemeral X25519 exchange
        eph_x25519_pub, eph_x25519_priv = X25519DH.generate_keypair()
        ss_ecdh = X25519DH.diffie_hellman(eph_x25519_priv, peer_x25519_pub)

        # 2. ML-KEM-768 encapsulation
        ss_pqc, mlkem_ct = MLKEM768.encapsulate(peer_mlkem_pub)

        # 3. Hybrid combination
        hybrid_ss = cls.combine_secrets(ss_ecdh, ss_pqc)
        return hybrid_ss, eph_x25519_pub, mlkem_ct

    @classmethod
    def decapsulate(
        cls,
        my_x25519_priv: bytes,
        my_mlkem_priv: bytes,
        ephemeral_x25519_pub: bytes,
        mlkem_ciphertext: bytes,
    ) -> bytes:
        """Executes hybrid decapsulation.

        Returns:
            hybrid_shared_secret (32 bytes)
        """
        # 1. Classical ECDH decapsulation
        ss_ecdh = X25519DH.diffie_hellman(my_x25519_priv, ephemeral_x25519_pub)

        # 2. ML-KEM-768 decapsulation
        ss_pqc = MLKEM768.decapsulate(my_mlkem_priv, mlkem_ciphertext)

        # 3. Hybrid combination
        return cls.combine_secrets(ss_ecdh, ss_pqc)
