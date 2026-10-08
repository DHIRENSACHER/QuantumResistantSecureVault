"""Unit tests for cryptographic primitives: ML-KEM-768, ML-DSA-65, X25519, AES-256-GCM, ChaCha20-Poly1305, HKDF."""

import pytest
from src.crypto.kem import MLKEM768, X25519DH, HybridKEMExchange
from src.crypto.signatures import MLDSA65, Ed25519Signer
from src.crypto.symmetric import (
    AES256GCMCipher,
    ChaCha20Poly1305Cipher,
    hkdf_derive,
    hkdf_extract,
    hkdf_expand,
    constant_time_compare,
    zeroize,
)


class TestSymmetricPrimitives:
    def test_aes_256_gcm_roundtrip(self):
        key = AES256GCMCipher.generate_key()
        assert len(key) == 32
        plaintext = b"Top secret post-quantum payload"
        ad = b"associated-metadata"

        ct, nonce = AES256GCMCipher.encrypt(key, plaintext, associated_data=ad)
        assert len(nonce) == 12
        assert ct != plaintext

        decrypted = AES256GCMCipher.decrypt(key, nonce, ct, associated_data=ad)
        assert decrypted == plaintext

    def test_aes_256_gcm_tamper_detection(self):
        key = AES256GCMCipher.generate_key()
        plaintext = b"Sensitive message"
        ct, nonce = AES256GCMCipher.encrypt(key, plaintext)

        # Tamper with ciphertext
        tampered_ct = bytearray(ct)
        tampered_ct[0] ^= 0x01

        with pytest.raises(Exception):
            AES256GCMCipher.decrypt(key, nonce, bytes(tampered_ct))

    def test_chacha20_poly1305_roundtrip(self):
        key = ChaCha20Poly1305Cipher.generate_key()
        plaintext = b"ChaCha20 streaming AEAD payload"
        ct, nonce = ChaCha20Poly1305Cipher.encrypt(key, plaintext)
        decrypted = ChaCha20Poly1305Cipher.decrypt(key, nonce, ct)
        assert decrypted == plaintext

    def test_hkdf_consistency(self):
        salt = b"test-salt-123456"
        ikm = b"input-key-material-32-bytes-long"
        info = b"info-label"
        k1 = hkdf_derive(salt, ikm, info, length=32)
        k2 = hkdf_derive(salt, ikm, info, length=32)
        assert k1 == k2
        assert len(k1) == 32

    def test_zeroize(self):
        buf = bytearray(b"sensitive_password")
        zeroize(buf)
        assert buf == bytearray(len(b"sensitive_password"))


class TestPostQuantumKEM:
    def test_ml_kem_768_keypair_and_encap(self):
        pk, sk = MLKEM768.generate_keypair()
        assert len(pk) == MLKEM768.PUBLIC_KEY_SIZE
        assert len(sk) == MLKEM768.SECRET_KEY_SIZE

        shared_secret, ct = MLKEM768.encapsulate(pk)
        assert len(shared_secret) == 32
        assert len(ct) == MLKEM768.CIPHERTEXT_SIZE

        decapped_secret = MLKEM768.decapsulate(sk, ct)
        assert constant_time_compare(shared_secret, decapped_secret)

    def test_ml_kem_invalid_ciphertext_produces_wrong_secret(self):
        pk, sk = MLKEM768.generate_keypair()
        shared_secret, ct = MLKEM768.encapsulate(pk)

        # In implicit rejection KEMs (ML-KEM/Kyber), tampered ciphertext decapsulates to a pseudorandom secret
        tampered_ct = bytearray(ct)
        tampered_ct[50] ^= 0xFF

        decapped_secret = MLKEM768.decapsulate(sk, bytes(tampered_ct))
        assert decapped_secret != shared_secret

    def test_hybrid_kem_roundtrip(self):
        # Alice has X25519 and ML-KEM
        x_pub, x_priv = X25519DH.generate_keypair()
        m_pub, m_priv = MLKEM768.generate_keypair()

        # Bob encapsulates against Alice's public keys
        ss_bob, eph_x_pub, m_ct = HybridKEMExchange.encapsulate(x_pub, m_pub)

        # Alice decapsulates using her private keys
        ss_alice = HybridKEMExchange.decapsulate(x_priv, m_priv, eph_x_pub, m_ct)

        assert constant_time_compare(ss_bob, ss_alice)
        assert len(ss_bob) == 32


class TestPostQuantumSignatures:
    def test_ml_dsa_65_roundtrip(self):
        pk, sk = MLDSA65.generate_keypair()
        assert len(pk) == MLDSA65.PUBLIC_KEY_SIZE
        assert len(sk) == MLDSA65.SECRET_KEY_SIZE

        msg = b"Verify this statement under FIPS 204"
        sig = MLDSA65.sign(sk, msg)
        assert MLDSA65.verify(pk, msg, sig) is True

    def test_ml_dsa_65_tamper_rejection(self):
        pk, sk = MLDSA65.generate_keypair()
        msg = b"Authentic message"
        sig = MLDSA65.sign(sk, msg)

        # Tampered message
        assert MLDSA65.verify(pk, b"Tampered message", sig) is False

        # Tampered signature
        tampered_sig = bytearray(sig)
        tampered_sig[100] ^= 0x01
        assert MLDSA65.verify(pk, msg, bytes(tampered_sig)) is False

    def test_ed25519_classical_roundtrip(self):
        pub, priv = Ed25519Signer.generate_keypair()
        msg = b"Classical signature"
        sig = Ed25519Signer.sign(priv, msg)
        assert Ed25519Signer.verify(pub, msg, sig) is True
        assert Ed25519Signer.verify(pub, b"Altered", sig) is False
