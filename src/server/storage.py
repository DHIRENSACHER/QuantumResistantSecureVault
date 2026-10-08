"""Zero-access server storage backend for bundles, encrypted mailboxes, and chunks."""

from __future__ import annotations

from typing import Dict, List, Optional


class ZeroAccessStorage:
    """In-memory or persistent store enforcing zero-knowledge server architecture.

    The server stores only:
    - Public PreKey bundles
    - Encrypted message envelopes
    - Encrypted file chunks
    - Signed manifests

    The server NEVER has access to:
    - Plaintext messages or file contents
    - Ephemeral message keys (MK)
    - Data encryption keys (DEK)
    - Any client private keys
    """

    def __init__(self):
        # user_id -> list of PreKeyBundle dicts
        self.prekey_bundles: Dict[str, List[dict]] = {}
        # user_id -> list of encrypted message envelopes
        self.mailboxes: Dict[str, List[dict]] = {}
        # file_id -> manifest dict
        self.manifests: Dict[str, dict] = {}
        # chunk_sha256 -> encrypted bytes
        self.chunks: Dict[str, bytes] = {}

    def register_bundle(self, user_id: str, bundle_dict: dict) -> None:
        """Stores a public prekey bundle for a user."""
        if user_id not in self.prekey_bundles:
            self.prekey_bundles[user_id] = []
        self.prekey_bundles[user_id].append(bundle_dict)

    def fetch_bundle(self, user_id: str) -> Optional[dict]:
        """Pops a one-time prekey bundle for session initialization."""
        bundles = self.prekey_bundles.get(user_id, [])
        if not bundles:
            return None
        # Pop one-time bundle to avoid reuse
        if len(bundles) > 1:
            return bundles.pop(0)
        return bundles[0]  # If only 1 left, return it

    def store_message(self, recipient_id: str, envelope_dict: dict) -> None:
        """Appends an encrypted message envelope to the recipient's mailbox."""
        if recipient_id not in self.mailboxes:
            self.mailboxes[recipient_id] = []
        self.mailboxes[recipient_id].append(envelope_dict)

    def fetch_and_drain_messages(self, user_id: str) -> List[dict]:
        """Retrieves and clears all pending encrypted messages for a user."""
        messages = self.mailboxes.get(user_id, [])
        self.mailboxes[user_id] = []
        return messages

    def store_manifest(self, file_id: str, manifest_dict: dict) -> None:
        """Stores a signed vault file manifest."""
        self.manifests[file_id] = manifest_dict

    def fetch_manifest(self, file_id: str) -> Optional[dict]:
        """Fetches a signed vault file manifest."""
        return self.manifests.get(file_id)

    def store_chunk(self, chunk_hash: str, chunk_data: bytes) -> None:
        """Stores an encrypted chunk indexed by its ciphertext SHA-256 hash."""
        self.chunks[chunk_hash] = chunk_data

    def fetch_chunk(self, chunk_hash: str) -> Optional[bytes]:
        """Fetches an encrypted chunk."""
        return self.chunks.get(chunk_hash)
