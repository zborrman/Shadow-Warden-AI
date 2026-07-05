"""
warden/redaction/ — Data protection and redaction facade package.

Canonical import path for all PII/secret/content redaction modules.
"""
from __future__ import annotations

from warden.obfuscation import decode as decode_obfuscation
from warden.output_sanitizer import get_sanitizer as get_output_sanitizer
from warden.secret_redactor import SecretRedactor

__all__ = [
    "SecretRedactor",
    "decode_obfuscation",
    "get_output_sanitizer",
]
