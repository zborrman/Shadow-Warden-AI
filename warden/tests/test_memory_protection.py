"""Tests for runtime memory protection (SEC-07)."""
from __future__ import annotations

import pytest


class TestSecureWipe:
    def test_secure_wipe_zeros_memory(self):
        from warden.crypto.memory_protection import secure_wipe
        buf = bytearray(b"super-secret-key-material-32byte")
        assert any(b != 0 for b in buf), "buf should not already be zeroed"
        secure_wipe(buf)
        assert all(b == 0 for b in buf), "all bytes must be zeroed after secure_wipe"

    def test_secure_wipe_empty_buffer_no_error(self):
        from warden.crypto.memory_protection import secure_wipe
        secure_wipe(bytearray())

    def test_secure_wipe_rejects_immutable_bytes(self):
        from warden.crypto.memory_protection import secure_wipe
        with pytest.raises(TypeError):
            secure_wipe(b"immutable")  # type: ignore[arg-type]


class TestSecureMemoryDecorator:
    def test_decorator_does_not_break_execution(self):
        from warden.crypto.memory_protection import secure_memory

        @secure_memory
        def add(a: int, b: int) -> int:
            return a + b

        assert add(2, 3) == 5

    def test_decorator_wipes_bytearray_args(self):
        from warden.crypto.memory_protection import secure_memory

        wiped: list[bytearray] = []

        @secure_memory
        def consume(buf: bytearray) -> int:
            wiped.append(buf)
            return len(buf)

        key = bytearray(b"secret")
        result = consume(key)
        assert result == 6
        # After the call, key should be zeroed
        assert all(b == 0 for b in key)

    def test_decorator_propagates_return_value(self):
        from warden.crypto.memory_protection import secure_memory

        @secure_memory
        def get_hash(data: bytes) -> str:
            import hashlib
            return hashlib.sha256(data).hexdigest()

        h = get_hash(b"test")
        assert len(h) == 64
