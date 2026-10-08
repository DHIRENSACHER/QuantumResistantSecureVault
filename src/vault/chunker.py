"""Streaming file chunker and Merkle/SHA-256 integrity calculator."""

from __future__ import annotations

import hashlib
import io
from typing import BinaryIO, Generator, List, Tuple


class FileChunk:
    """Represents a single chunk of file data with integrity metadata."""

    def __init__(self, index: int, data: bytes, sha256_hex: str):
        self.index = index
        self.data = data
        self.sha256_hex = sha256_hex


class FileChunker:
    """Chunks binary streams or files and calculates SHA-256 hashes."""

    DEFAULT_CHUNK_SIZE = 1024 * 512  # 512 KB

    @classmethod
    def chunk_stream(
        cls,
        stream: BinaryIO,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> Generator[FileChunk, None, Tuple[int, str]]:
        """Yields FileChunk instances from a readable binary stream.

        Returns:
            Tuple of (total_bytes, full_file_sha256_hex) upon completion.
        """
        full_hasher = hashlib.sha256()
        chunk_index = 0
        total_bytes = 0

        while True:
            chunk_data = stream.read(chunk_size)
            if not chunk_data:
                break
            total_bytes += len(chunk_data)
            full_hasher.update(chunk_data)

            chunk_hash = hashlib.sha256(chunk_data).hexdigest()
            yield FileChunk(index=chunk_index, data=chunk_data, sha256_hex=chunk_hash)
            chunk_index += 1

        return total_bytes, full_hasher.hexdigest()

    @classmethod
    def chunk_bytes(
        cls,
        data: bytes,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> Tuple[List[FileChunk], int, str]:
        """Convenience method to chunk an in-memory byte buffer."""
        stream = io.BytesIO(data)
        chunks = []
        gen = cls.chunk_stream(stream, chunk_size)
        try:
            while True:
                chunks.append(next(gen))
        except StopIteration as e:
            total_bytes, full_hash = e.value
            return chunks, total_bytes, full_hash
