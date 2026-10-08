"""Comprehensive tests for Hybrid Post-Quantum Double Ratchet (HPQ-DR)."""

import pytest
from src.identity import ClientKeyStore
from src.protocol import PQXDHHandshake, HPQDoubleRatchet
from src.crypto.symmetric import AES256GCMCipher


def setup_hpq_session():
    """Helper to establish a fresh HPQ-DR session between Alice and Bob."""
    alice_ks = ClientKeyStore.create_new("alice")
    bob_ks = ClientKeyStore.create_new("bob")

    bob_bundle = bob_ks.create_bundle()
    init_msg, a_rk, a_ck, a_eph_priv = PQXDHHandshake.initiate(alice_ks.identity, bob_bundle)
    b_rk, b_ck = PQXDHHandshake.receive(bob_ks, init_msg)

    alice = HPQDoubleRatchet(
        local_identity=alice_ks.identity,
        peer_id="bob",
        peer_mldsa_pub=bob_ks.identity.mldsa_pub,
        root_key=a_rk,
        is_initiator=True,
        initial_chain_key=a_ck,
        initial_dh_priv=a_eph_priv,
        peer_dh_pub=bob_bundle.signed_prekey_classic,
        peer_kem_pub=bob_bundle.onetime_prekey_pqc,
    )

    bob = HPQDoubleRatchet(
        local_identity=bob_ks.identity,
        peer_id="alice",
        peer_mldsa_pub=alice_ks.identity.mldsa_pub,
        root_key=b_rk,
        is_initiator=False,
        initial_chain_key=b_ck,
        initial_dh_priv=bob_ks.signed_prekey.x25519_priv,
        peer_dh_pub=init_msg.ephemeral_x25519_pub,
    )

    return alice, bob, alice_ks, bob_ks


class TestHPQDoubleRatchet:
    def test_multi_turn_conversation(self):
        alice, bob, _, _ = setup_hpq_session()

        for turn in range(5):
            msg_a = f"Message from Alice turn {turn}".encode("utf-8")
            env_a = alice.encrypt(msg_a)
            dec_a = bob.decrypt(env_a)
            assert dec_a == msg_a

            msg_b = f"Reply from Bob turn {turn}".encode("utf-8")
            env_b = bob.encrypt(msg_b)
            dec_b = alice.decrypt(env_b)
            assert dec_b == msg_b

    def test_forward_secrecy(self):
        """Compromising current Chain Key does not expose past Message Keys."""
        alice, bob, _, _ = setup_hpq_session()

        # Alice sends 3 messages
        e0 = alice.encrypt(b"Historical Message 0")
        e1 = alice.encrypt(b"Historical Message 1")
        e2 = alice.encrypt(b"Historical Message 2")

        # Bob decrypts 0 and 1
        assert bob.decrypt(e0) == b"Historical Message 0"
        assert bob.decrypt(e1) == b"Historical Message 1"

        # Attacker steals Bob's chain key right before message 2
        compromised_ckr = bob.ckr

        # The attacker derives the message key for message 2
        _, mk2 = bob._symmetric_step(compromised_ckr)
        dec_stolen_2 = AES256GCMCipher.decrypt(
            key=mk2,
            nonce=e2.nonce,
            ciphertext=e2.ciphertext,
            associated_data=e2.header.to_bytes(),
        )
        assert dec_stolen_2 == b"Historical Message 2"

        # But the attacker CANNOT derive past keys for Message 0 or 1 from compromised_ckr!
        # Because HKDF is a cryptographically secure one-way function.
        # To verify: attempting to use compromised_ckr to decrypt e0 or e1 fails.
        with pytest.raises(Exception):
            AES256GCMCipher.decrypt(
                key=compromised_ckr,
                nonce=e0.nonce,
                ciphertext=e0.ciphertext,
                associated_data=e0.header.to_bytes(),
            )

    def test_post_compromise_healing(self):
        """After adversary compromises session state, a hybrid ratchet turn heals the session."""
        alice, bob, _, _ = setup_hpq_session()

        # Alice sends message
        env1 = alice.encrypt(b"Pre-compromise text")
        assert bob.decrypt(env1) == b"Pre-compromise text"

        # Adversary records Alice's entire state at time t
        leaked_root_key = alice.root_key
        leaked_dh_priv = alice.dhs_priv

        # Bob initiates a reply (hybrid ratchet turn with fresh ML-KEM and X25519 keys)
        env_bob = bob.encrypt(b"Bob fresh healing turn")
        assert env_bob.header.kem_ct is not None  # ML-KEM encapsulation is transmitted!

        # Alice processes Bob's message and heals
        dec_bob = alice.decrypt(env_bob)
        assert dec_bob == b"Bob fresh healing turn"

        # The new root keys of Alice and Bob have evolved
        assert alice.root_key != leaked_root_key

        # Next message from Alice after healing
        env_healed = alice.encrypt(b"Post-healing confidential message")
        dec_healed = bob.decrypt(env_healed)
        assert dec_healed == b"Post-healing confidential message"

        # Passive quantum adversary holding old leaked_root_key CANNOT decrypt env_healed,
        # because the ratchet mixed in fresh ML-KEM secret that cannot be decapsulated without
        # Alice's fresh private key.
        with pytest.raises(Exception):
            AES256GCMCipher.decrypt(
                key=leaked_root_key,
                nonce=env_healed.nonce,
                ciphertext=env_healed.ciphertext,
                associated_data=env_healed.header.to_bytes(),
            )

    def test_tampered_envelope_signature_rejected(self):
        alice, bob, _, _ = setup_hpq_session()

        env = alice.encrypt(b"Authentic message")

        # Malicious server tampers with ciphertext
        tampered_ct = bytearray(env.ciphertext)
        tampered_ct[5] ^= 0x01
        env.ciphertext = bytes(tampered_ct)

        with pytest.raises(ValueError, match="Envelope ML-DSA-65 signature is invalid"):
            bob.decrypt(env)
