"""Fake adapters for all Shadow Warden external dependencies."""
from warden.testing.fakes.anthropic_fake import FakeAnthropicClient
from warden.testing.fakes.evolution_fake import FakeEvolutionEngine
from warden.testing.fakes.nvidia_fake import FakeNvidiaClient
from warden.testing.fakes.s3_fake import FakeS3Storage

__all__ = [
    "FakeAnthropicClient",
    "FakeNvidiaClient",
    "FakeS3Storage",
    "FakeEvolutionEngine",
]
