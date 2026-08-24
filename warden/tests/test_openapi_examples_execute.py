"""
warden/tests/test_openapi_examples_execute.py — the documented examples must work.

An OpenAPI example is the first code anyone runs against this API. Nothing
checked that the examples were valid against their own request model, and they
were not: every `/filter` and `/filter/batch` example used the key ``text``,
while ``FilterRequest`` declares ``content``. Verified against production
2026-08-24, the published payload returned::

    HTTP 422  {"type":"missing","loc":["body","content"],"msg":"Field required"}

So the documented request never reached the filter at all.

The ``clean`` example was wrong a second, more interesting way. "Summarise the
quarterly revenue report in three bullet points." was labelled *Legitimate
request (allowed)* and returned ``403 RED — Confidential data detected
(Financial records)``: data classification runs ahead of the jailbreak pipeline
and rejects it outright. The one example advertised as the happy path was the
single payload guaranteed to fail.

Schema conformance alone would not have caught that second bug — the payload was
well-formed. So this suite checks both properties: examples validate against
their schema, *and* they behave the way their own summary claims.
"""
from __future__ import annotations

import pytest

_PATHS = ("/filter", "/filter/batch")


def _request_examples(spec: dict, path: str) -> dict:
    body = spec["paths"][path]["post"].get("requestBody", {})
    return body.get("content", {}).get("application/json", {}).get("examples", {}) or {}


@pytest.fixture(scope="module")
def spec() -> dict:
    from warden.main import app

    return app.openapi()


def test_the_paths_under_test_exist(spec) -> None:
    """Guard the guard: a renamed route would make every check below vacuous."""
    missing = [p for p in _PATHS if p not in spec["paths"]]
    assert not missing, f"{missing} not in the spec — this suite would check nothing"


def test_examples_exist_to_check(spec) -> None:
    for path in _PATHS:
        assert _request_examples(spec, path), (
            f"{path} documents no request examples, so nothing here is verified"
        )


def _body_model(path: str):
    """The Pydantic model FastAPI will actually validate this route's body with."""
    from warden.main import app

    for route in app.routes:
        if getattr(route, "path", None) == path and "POST" in getattr(route, "methods", ()):
            field = getattr(route, "body_field", None)
            if field is None:
                continue
            # FastAPI's ModelField exposes the model on field_info.annotation.
            # `type_` existed in older versions and raises AttributeError now, so
            # read both rather than pinning to one FastAPI generation.
            model = getattr(getattr(field, "field_info", None), "annotation", None)
            return model if model is not None else getattr(field, "type_", None)
    return None


@pytest.mark.parametrize("path", _PATHS)
def test_request_examples_validate_against_the_real_model(spec, path) -> None:
    """The bug that shipped: examples keyed `text` against a model wanting `content`.

    Validated against the route's own Pydantic model rather than the derived JSON
    schema — that is what FastAPI will apply to a real request, so agreement here
    means the documented payload cannot 422.
    """
    import pydantic

    model = _body_model(path)
    assert model is not None, (
        f"could not find the body model for POST {path} — without it this test "
        "would silently check nothing"
    )

    for name, example in _request_examples(spec, path).items():
        try:
            model.model_validate(example["value"])
        except pydantic.ValidationError as exc:
            pytest.fail(
                f"{path} example {name!r} is not valid for {model.__name__}: "
                f"{exc.errors()}\n"
                f"value: {example['value']}\n\n"
                "Anyone copying this from the docs gets an HTTP 422 on their first call."
            )


@pytest.mark.slow
@pytest.mark.parametrize("path", _PATHS)
def test_request_examples_are_accepted_by_the_api(client, spec, path) -> None:
    """Executable, not merely well-formed. 422 here means the docs are wrong."""
    for name, example in _request_examples(spec, path).items():
        r = client.post(path, json=example["value"])
        assert r.status_code != 422, (
            f"{path} example {name!r} was rejected as malformed: {r.text[:300]}"
        )


@pytest.mark.slow
def test_the_example_labelled_allowed_is_actually_allowed(client, spec) -> None:
    """A "Legitimate request (allowed)" example must not be rejected.

    This is the check that would have caught the 403 RED. The payload was
    schema-valid, so only running it reveals that the documented happy path is
    refused by a guard sitting in front of the pipeline.
    """
    examples = _request_examples(spec, "/filter")
    allowed = {
        name: ex for name, ex in examples.items()
        if "allow" in (ex.get("summary", "") + name).lower()
    }
    assert allowed, (
        "no /filter example is labelled as allowed — one should be, and this "
        "assertion exists so the test cannot pass by finding nothing to check"
    )

    for name, ex in allowed.items():
        r = client.post("/filter", json=ex["value"])
        assert r.status_code == 200, (
            f"example {name!r} is documented as legitimate and allowed, but the "
            f"API answered {r.status_code}: {r.text[:300]}\n\n"
            "Pick a payload that exercises the jailbreak pipeline without "
            "tripping the data classifier in front of it — financial, health and "
            "credential terms are all rejected before the filter runs."
        )
        assert r.json().get("allowed") is True, (
            f"example {name!r} is documented as allowed but the pipeline blocked it: "
            f"{r.json()}"
        )
