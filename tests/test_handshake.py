"""Unit and integration tests for PQXDH-style hybrid initial handshake."""

import pytest
from src.identity import ClientKeyStore, PreKeyBundle
from src.protocol.handshake import PQXDHHandshake


class TestPQXDHHandshake:
    def test_successful_handshake_session_establishment(self):
        alice_keystore = ClientKeyStore.create_new("alice")
        bob_keystore = ClientKeyStore.create_new("bob")

        bob_bundle = bob_keystore.create_bundle()
        assert bob_bundle.verify() is True

        # Alice initiates handshake
        init_msg, a_rk, a_ck, a_eph = PQXDHHandshake.initiate(
            alice_keystore.identity, bob_bundle
        )
        assert len(a_rk) == 32
        assert len(a_ck) == 32
        assert init_msg.verify_signature() is True

        # Bob receives handshake
        b_rk, b_ck = PQXDHHandshake.receive(bob_keystore, init_msg)

        assert a_rk == b_rk
        assert a_ck == b_ck

    def test_handshake_aborts_on_invalid_prekey_signature(self):
        alice_keystore = ClientKeyStore.create_new("alice")
        bob_keystore = ClientKeyStore.create_new("bob")

        bob_bundle = bob_keystore.create_bundle()
        # Tamper with Bob's signed prekey signature
        tampered_sig = bytearray(bob_bundle.signed_prekey_sig)
        tampered_sig[20] ^= 0xFF
        bob_bundle.signed_prekey_sig = bytes(tampered_sig)

        assert bob_bundle.verify() is False

        with pytest.raises(ValueError, match="ML-DSA-65 prekey bundle signature is invalid"):
            PQXDHHandshake.initiate(alice_keystore.identity, bob_bundle)

    def test_handshake_aborts_on_tampered_init_message(self):
        alice_keystore = ClientKeyStore.create_new("alice")
        bob_keystore = ClientKeyStore.create_new("bob")

        bob_bundle = bob_keystore.create_bundle()
        init_msg, a_rk, a_ck, _ = PQXDHHandshake.initiate(
            alice_keystore.identity, bob_bundle
        )

        # Attacker tampers with ephemeral key
        tampered_eph = bytearray(init_msg.ephemeral_x25519_pub)
        tampered_eph[0] ^= 0x01
        init_msg.ephemeral_x25519_pub = bytes(tampered_eph)

        with pytest.raises(ValueError, match="Initiator's ML-DSA-65 signature is invalid"):
            PQXDHHandshake.receive(bob_keystore, init_msg)

    def test_one_time_prekey_cannot_be_reused(self):
        alice_keystore = ClientKeyStore.create_new("alice")
        bob_keystore = ClientKeyStore.create_new("bob")

        bob_bundle = bob_keystore.create_bundle()
        init_msg, _, _, _ = PQXDHHandshake.initiate(
            alice_keystore.identity, bob_bundle
        )

        # Bob processes once -> consumes OPK
        PQXDHHandshake.receive(bob_keystore, init_msg)

        # Second attempt with same OPK must fail (replay protection)
        with pytest.raises(KeyError, match="already consumed"):
            PQXDHHandshake.receive(bob_keystore, init_msg)
