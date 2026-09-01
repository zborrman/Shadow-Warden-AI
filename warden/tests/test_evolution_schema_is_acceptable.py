"""
warden/tests/test_evolution_schema_is_acceptable.py

The Evolution Engine has never produced a rule. Not because it was never
invoked — production logs `evolution_queued` every fifteen minutes — and not,
as was recorded for a while, because of an account spend cap. Every call reached
the Anthropic API and came back::

    400 invalid_request_error — output_config.format.schema:
    For 'object' type, 'additionalProperties' must be explicitly set to false

`EvolutionResponse.model_json_schema()` was passed straight to
`output_config.format.schema`, and Pydantic does not emit `additionalProperties`
unless a model declares `extra="forbid"`. So the schema was rejected at the top
level and again inside `$defs`, on every attempt, for as long as the Claude
backend has been selected.

Nothing caught it because the failure is entirely on the far side of an HTTP
call: the pipeline is unaffected, the request that triggered evolution succeeds,
and the only symptom is `warden_evolution_failed_total` climbing — a counter
nobody reads until they go looking for why no rules exist.

This file asserts the property the API enforces, against the schema actually
sent. A test that checked the two objects we happen to have today would pass the
moment someone adds a third.
"""
from __future__ import annotations

import pytest

from warden.brain.evolve import EvolutionResponse, _strict_json_schema


def _objects(schema: dict, path: str = "$"):
    """Yield (path, node) for every object-typed node in a JSON schema."""
    if not isinstance(schema, dict):
        return
    if schema.get("type") == "object":
        yield path, schema
    for key in ("properties", "$defs", "definitions", "patternProperties"):
        for name, sub in (schema.get(key) or {}).items():
            yield from _objects(sub, f"{path}.{key}.{name}")
    for key in ("items", "additionalItems", "not"):
        if isinstance(schema.get(key), dict):
            yield from _objects(schema[key], f"{path}.{key}")
    for key in ("anyOf", "oneOf", "allOf", "prefixItems"):
        for i, sub in enumerate(schema.get(key) or []):
            yield from _objects(sub, f"{path}.{key}[{i}]")


@pytest.fixture(scope="module")
def sent() -> dict:
    """Exactly what goes into `output_config.format.schema`."""
    return _strict_json_schema(EvolutionResponse.model_json_schema())


class TestTheSchemaTheApiActuallyReceives:
    def test_every_object_forbids_additional_properties(self, sent):
        """The rule the 400 was enforcing, applied to every node rather than
        the two that exist today."""
        offenders = [
            path for path, node in _objects(sent)
            if node.get("additionalProperties") is not False
        ]
        assert not offenders, (
            "Anthropic rejects an object schema without additionalProperties: "
            f"false — missing at {offenders}"
        )

    def test_there_is_more_than_one_object_to_check(self, sent):
        """Guards the guard: if the walker stopped finding nodes, the assertion
        above would pass by finding nothing."""
        assert len(list(_objects(sent))) >= 2

    def test_the_raw_pydantic_schema_would_still_be_rejected(self):
        """The reason the hardening step exists rather than a model config.

        If Pydantic ever starts emitting the key on its own this fails, and the
        wrapper can go — but it must be a deliberate removal, not a silent
        assumption.
        """
        raw = EvolutionResponse.model_json_schema()
        missing = [p for p, n in _objects(raw) if n.get("additionalProperties") is not False]
        assert missing, (
            "Pydantic now emits additionalProperties itself; _strict_json_schema "
            "may be removable, but check every $defs entry before doing it"
        )

    def test_hardening_preserves_the_contract(self, sent):
        """Adding the key must not disturb what the model actually requires."""
        raw = EvolutionResponse.model_json_schema()
        assert sent["required"] == raw["required"]
        assert set(sent["properties"]) == set(raw["properties"])

    def test_it_is_idempotent(self, sent):
        assert _strict_json_schema(sent) == sent


class TestTheHardeningHandlesShapesWeDoNotUseYet:
    """A nested model added later must be covered without anyone remembering."""

    def test_nested_arrays_of_objects(self):
        raw = {
            "type": "object",
            "properties": {
                "items": {"type": "array", "items": {"type": "object", "properties": {}}},
            },
        }
        out = _strict_json_schema(raw)
        assert out["additionalProperties"] is False
        assert out["properties"]["items"]["items"]["additionalProperties"] is False

    def test_union_branches(self):
        raw = {"anyOf": [{"type": "object", "properties": {}}, {"type": "string"}]}
        out = _strict_json_schema(raw)
        assert out["anyOf"][0]["additionalProperties"] is False
        assert "additionalProperties" not in out["anyOf"][1]

    def test_a_non_object_is_left_alone(self):
        assert _strict_json_schema({"type": "string"}) == {"type": "string"}

    def test_the_input_is_not_mutated(self):
        raw = {"type": "object", "properties": {}}
        _strict_json_schema(raw)
        assert "additionalProperties" not in raw
