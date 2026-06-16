"""
warden/crypto/memory_protection.py  (Phase 3-7)
──────────────────────────────────────────────────
Runtime memory protection utilities.

secure_wipe(buf)
  Zero every byte of a mutable bytearray/memoryview and verify all bytes
  are zero.  Call when you're done with key material.

@secure_memory decorator
  Wraps a function so that:
    - on POSIX: mlock() is called on the process memory pages before the
      function executes (prevents swapping key material to disk).
    - on return (or exception): any bytearray arguments are zeroed via
      secure_wipe().
  Skips gracefully on Windows and platforms without mlock capability — the
  decorated function always executes normally regardless of platform support.

Usage
─────
    from warden.crypto.memory_protection import secure_memory, secure_wipe

    @secure_memory
    def generate_key() -> bytes:
        priv = bytearray(32)
        os.urandom(32)  # fill
        ...
        return bytes(priv)

    buf = bytearray(secret_bytes)
    use_key(buf)
    secure_wipe(buf)   # zeroes all 32 bytes
"""
from __future__ import annotations

import contextlib
import ctypes
import ctypes.util
import functools
import logging
import sys
from collections.abc import Callable

log = logging.getLogger("warden.crypto.memory_protection")

_IS_POSIX   = sys.platform != "win32"
_IS_WINDOWS = sys.platform == "win32"
_libc: ctypes.CDLL | None = None


def _get_libc() -> ctypes.CDLL | None:
    global _libc
    if _libc is None and _IS_POSIX:
        try:
            name = ctypes.util.find_library("c") or "libc.so.6"
            _libc = ctypes.CDLL(name, use_errno=True)
        except Exception:
            _libc = None
    return _libc


def _try_mlock(buf: memoryview | bytearray) -> bool:
    """Lock memory pages into RAM (prevent swap). Fail-open on unsupported platforms."""
    if _IS_WINDOWS:
        try:
            k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            addr = ctypes.addressof((ctypes.c_char * len(buf)).from_buffer(buf))  # type: ignore[arg-type]
            return bool(k32.VirtualLock(ctypes.c_void_p(addr), ctypes.c_size_t(len(buf))))
        except Exception:
            return False

    libc = _get_libc()
    if libc is None:
        return False
    try:
        mutable = bytearray(buf) if not isinstance(buf, bytearray) else buf
        addr = ctypes.addressof((ctypes.c_char * len(mutable)).from_buffer(mutable))
        rc = libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(len(mutable)))
        return rc == 0
    except Exception:
        return False


def secure_wipe(buf: bytearray | memoryview) -> None:
    """
    Overwrite every byte of *buf* with zeros and verify.

    Works in-place on bytearray; memoryview must be writable.
    Raises TypeError if buf is immutable bytes.
    """
    if isinstance(buf, (bytes, str)):
        raise TypeError("secure_wipe requires a mutable bytearray or writable memoryview")
    n = len(buf)
    if n == 0:
        return
    # Write zeros
    for i in range(n):
        buf[i] = 0
    # Verify (prevents compiler from eliding the wipe)
    if any(buf[i] != 0 for i in range(n)):
        log.error("secure_wipe: verification failed — some bytes not zeroed")


def secure_memory(fn: Callable) -> Callable:
    """
    Decorator that applies memory protection around a function.

    - Attempts mlock before execution (fail-open).
    - After execution (or on exception), secure_wipes any bytearray arguments
      that were passed by the caller.

    Skips silently on platforms without mlock support.
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        # Collect mutable byte buffers from args
        byte_args = [a for a in args if isinstance(a, bytearray)]
        byte_kwargs = [v for v in kwargs.values() if isinstance(v, bytearray)]
        all_bufs = byte_args + byte_kwargs

        # Try to lock pages
        for buf in all_bufs:
            _try_mlock(buf)

        try:
            return fn(*args, **kwargs)
        finally:
            for buf in all_bufs:
                with contextlib.suppress(Exception):
                    secure_wipe(buf)

    return wrapper
