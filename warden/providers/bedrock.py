"""
warden/providers/bedrock.py
━━━━━━━━━━━━━━━━━━━━━━━━━━
Amazon Bedrock Converse / ConverseStream API adapter.

Converts OpenAI /v1/chat/completions payloads to the Bedrock Converse format,
signs requests with AWS Signature Version 4, and converts the response back to
the OpenAI wire format so the rest of the proxy pipeline is provider-agnostic.

Model name convention (used in openai_proxy):
    "bedrock/<model-id>"
    e.g. "bedrock/amazon.nova-lite-v1:0"
         "bedrock/anthropic.claude-3-haiku-20240307-v1:0"
         "bedrock/meta.llama3-8b-instruct-v1:0"
         "bedrock/mistral.mistral-7b-instruct-v0:2"

Environment variables (set in docker-compose / .env):
    AWS_ACCESS_KEY_ID       — IAM access key ID
    AWS_SECRET_ACCESS_KEY   — IAM secret access key
    AWS_REGION              — Bedrock region (default: us-east-1)

IAM permissions required:
    bedrock:InvokeModel on arn:aws:bedrock:<region>::foundation-model/*
    bedrock:InvokeModelWithResponseStream on same resource (streaming)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import struct
import time
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx

# ── AWS Signature Version 4 ───────────────────────────────────────────────────

def _hmac_sha256(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _sigv4_headers(
    method: str,
    url: str,
    body: bytes,
    region: str,
    service: str,
    access_key: str,
    secret_key: str,
) -> dict[str, str]:
    """
    Build the Authorization + date headers required for AWS SigV4.

    Only the minimum headers are signed (content-type, host, x-amz-*) to keep
    the implementation self-contained and dependency-free (no boto3 required).
    """
    parsed   = urlparse(url)
    host     = parsed.netloc
    path     = parsed.path or "/"

    now        = datetime.now(UTC)
    date_stamp = now.strftime("%Y%m%d")
    amz_date   = now.strftime("%Y%m%dT%H%M%SZ")

    payload_hash = hashlib.sha256(body).hexdigest()

    # Headers that will be signed — must be sorted lexicographically
    signed: dict[str, str] = {
        "content-type":         "application/json",
        "host":                 host,
        "x-amz-content-sha256": payload_hash,
        "x-amz-date":           amz_date,
    }
    canonical_headers = "".join(f"{k}:{v}\n" for k, v in sorted(signed.items()))
    signed_headers    = ";".join(sorted(signed.keys()))

    # Canonical request
    canonical_request = "\n".join([
        method,
        path,
        "",                  # query string (none)
        canonical_headers,
        signed_headers,
        payload_hash,
    ])

    # String to sign
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign   = "\n".join([
        "AWS4-HMAC-SHA256",
        amz_date,
        credential_scope,
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    ])

    # Derived signing key
    signing_key = _hmac_sha256(
        _hmac_sha256(
            _hmac_sha256(
                _hmac_sha256(f"AWS4{secret_key}".encode(), date_stamp),
                region,
            ),
            service,
        ),
        "aws4_request",
    )

    signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()

    auth = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope},"
        f" SignedHeaders={signed_headers}, Signature={signature}"
    )

    return {
        "Authorization":        auth,
        "Content-Type":         "application/json",
        "X-Amz-Date":           amz_date,
        "X-Amz-Content-SHA256": payload_hash,
    }


# ── Payload conversion: OpenAI → Bedrock Converse ─────────────────────────────

def oai_to_converse(oai_payload: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """
    Convert an OpenAI /chat/completions payload to the Bedrock Converse format.

    Returns ``(bedrock_payload, model_id)`` where ``model_id`` is the raw
    Bedrock model ID (the part after "bedrock/" in the ``model`` field).
    """
    raw_model = oai_payload.get("model", "")
    model_id  = raw_model[8:] if raw_model.lower().startswith("bedrock/") else raw_model

    system_blocks: list[dict[str, str]]  = []
    converse_msgs: list[dict[str, Any]]  = []

    for msg in oai_payload.get("messages", []):
        role    = msg.get("role", "user")
        content = msg.get("content", "")

        # Normalise content to a list of Bedrock content blocks
        if isinstance(content, str):
            blocks: list[dict[str, Any]] = [{"text": content}]
        elif isinstance(content, list):
            blocks = []
            for item in content:
                if isinstance(item, dict):
                    if item.get("type") == "text":
                        blocks.append({"text": item.get("text", "")})
                    elif item.get("type") == "image_url":
                        # Minimal fallback — real image support needs base64 data
                        blocks.append({"text": "[image]"})
                else:
                    blocks.append({"text": str(item)})
        else:
            blocks = [{"text": str(content)}]

        if role == "system":
            system_blocks.extend(blocks)
        else:
            # Bedrock only accepts "user" / "assistant"
            safe_role = role if role in ("user", "assistant") else "user"
            converse_msgs.append({"role": safe_role, "content": blocks})

    bedrock_payload: dict[str, Any] = {"messages": converse_msgs}

    if system_blocks:
        bedrock_payload["system"] = system_blocks

    inference: dict[str, Any] = {}
    if "max_tokens" in oai_payload:
        inference["maxTokens"] = int(oai_payload["max_tokens"])
    if "temperature" in oai_payload:
        inference["temperature"] = float(oai_payload["temperature"])
    if "top_p" in oai_payload:
        inference["topP"] = float(oai_payload["top_p"])
    stops = oai_payload.get("stop")
    if stops:
        inference["stopSequences"] = [stops] if isinstance(stops, str) else list(stops)
    if inference:
        bedrock_payload["inferenceConfig"] = inference

    return bedrock_payload, model_id


# ── Response conversion: Bedrock Converse → OpenAI ────────────────────────────

def converse_to_oai(bedrock_resp: dict[str, Any], original_model: str) -> dict[str, Any]:
    """
    Convert a Bedrock Converse response to the OpenAI chat.completion format.
    """
    output_msg     = bedrock_resp.get("output", {}).get("message", {})
    content_blocks = output_msg.get("content", [])
    text           = "".join(b.get("text", "") for b in content_blocks if "text" in b)

    stop_reason   = bedrock_resp.get("stopReason", "end_turn")
    finish_reason = "stop" if stop_reason in ("end_turn", "stop_sequence") else stop_reason

    usage      = bedrock_resp.get("usage", {})
    prompt_tok = usage.get("inputTokens",  0)
    comp_tok   = usage.get("outputTokens", 0)
    total_tok  = usage.get("totalTokens",  prompt_tok + comp_tok)

    ts = int(time.time())

    return {
        "id":      f"chatcmpl-bedrock-{ts}",
        "object":  "chat.completion",
        "created": ts,
        "model":   original_model,
        "choices": [{
            "index":         0,
            "message":       {"role": "assistant", "content": text},
            "finish_reason": finish_reason,
        }],
        "usage": {
            "prompt_tokens":     prompt_tok,
            "completion_tokens": comp_tok,
            "total_tokens":      total_tok,
        },
    }


# ── Public async entrypoint ───────────────────────────────────────────────────

async def call_bedrock(
    oai_payload: dict[str, Any],
    *,
    region:     str = "us-east-1",
    access_key: str = "",
    secret_key: str = "",
    timeout:    float = 60.0,
) -> dict[str, Any]:
    """
    Send an OpenAI-format payload to Amazon Bedrock Converse API and return an
    OpenAI-format response dict.

    Raises ``httpx.HTTPStatusError`` on 4xx/5xx responses from Bedrock.
    """
    bedrock_payload, model_id = oai_to_converse(oai_payload)
    original_model = oai_payload.get("model", f"bedrock/{model_id}")

    url  = f"https://bedrock-runtime.{region}.amazonaws.com/model/{model_id}/converse"
    body = json.dumps(bedrock_payload).encode()

    headers = _sigv4_headers(
        method     = "POST",
        url        = url,
        body       = body,
        region     = region,
        service    = "bedrock",
        access_key = access_key,
        secret_key = secret_key,
    )

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(url, content=body, headers=headers)
        resp.raise_for_status()
        bedrock_resp = resp.json()

    return converse_to_oai(bedrock_resp, original_model)


# ── AWS EventStream parser ────────────────────────────────────────────────────
# Used by stream_bedrock() to decode the binary ConverseStream response.
#
# Frame layout (big-endian):
#   Prelude (12 bytes): total_length(4) | headers_length(4) | prelude_crc(4)
#   Headers (variable): name_len(1) | name(N) | type(1) | value_len(2) | value(M)
#   Payload (variable): UTF-8 JSON
#   Message CRC (4 bytes)

def _parse_event_frame(buf: bytes) -> tuple[dict[str, Any], int] | None:
    """
    Parse one AWS EventStream frame from *buf*.

    Returns ``(event, bytes_consumed)`` when a complete frame is available,
    or ``None`` when *buf* does not yet contain a complete frame.

    ``event`` is a dict with keys ``"type"`` (str) and ``"data"`` (dict).
    CRC validation is intentionally omitted — transport-layer TLS provides
    equivalent integrity.
    """
    if len(buf) < 12:
        return None

    total_len, headers_len = struct.unpack_from(">II", buf, 0)  # skip prelude CRC at +8
    if len(buf) < total_len:
        return None                      # incomplete frame — wait for more bytes

    # ── Parse headers ─────────────────────────────────────────────────────────
    headers: dict[str, str] = {}
    pos     = 12                         # start of headers section
    end     = 12 + headers_len
    while pos < end:
        if pos >= end:
            break
        name_len = buf[pos];  pos += 1
        if pos + name_len > end:
            break
        name = buf[pos: pos + name_len].decode("utf-8");  pos += name_len
        if pos >= end:
            break
        val_type = buf[pos];  pos += 1
        if val_type == 7:                # string header
            if pos + 2 > end:
                break
            val_len = struct.unpack_from(">H", buf, pos)[0];  pos += 2
            if pos + val_len > end:
                break
            val = buf[pos: pos + val_len].decode("utf-8");    pos += val_len
        else:
            break                        # unsupported header type — stop parsing
        headers[name] = val

    # ── Extract payload ───────────────────────────────────────────────────────
    payload_start = 12 + headers_len
    payload_end   = total_len - 4       # exclude 4-byte message CRC
    payload_bytes = buf[payload_start:payload_end]

    event_type = headers.get(":event-type", "")
    try:
        payload: dict[str, Any] = json.loads(payload_bytes) if payload_bytes else {}
    except (json.JSONDecodeError, ValueError):
        payload = {}

    return {"type": event_type, "data": payload}, total_len


# ── Streaming entrypoint ──────────────────────────────────────────────────────

async def stream_bedrock(
    oai_payload: dict[str, Any],
    *,
    region:     str = "us-east-1",
    access_key: str = "",
    secret_key: str = "",
    timeout:    float = 120.0,
) -> AsyncGenerator[dict[str, Any], None]:
    """
    Stream from the Amazon Bedrock ConverseStream API, yielding OpenAI-compatible
    ``chat.completion.chunk`` dicts.

    The caller collects these chunks exactly as it would collect chunks from the
    OpenAI SSE streaming path — all OutputGuard / masking logic in the proxy
    applies identically.

    Event type mapping:
        contentBlockDelta → chunk with delta.content text
        messageStop       → chunk with finish_reason set
        metadata          → ignored (token counts not available mid-stream)
    """
    bedrock_payload, model_id = oai_to_converse(oai_payload)
    original_model = oai_payload.get("model", f"bedrock/{model_id}")

    url  = (
        f"https://bedrock-runtime.{region}.amazonaws.com"
        f"/model/{model_id}/converse-stream"
    )
    body = json.dumps(bedrock_payload).encode()

    headers = _sigv4_headers(
        method     = "POST",
        url        = url,
        body       = body,
        region     = region,
        service    = "bedrock",
        access_key = access_key,
        secret_key = secret_key,
    )

    ts     = int(time.time())
    msg_id = f"chatcmpl-bedrock-{ts}"

    async with httpx.AsyncClient(timeout=timeout) as client:
        async with client.stream("POST", url, content=body, headers=headers) as resp:
            resp.raise_for_status()

            buf = b""
            async for raw_chunk in resp.aiter_bytes():
                buf += raw_chunk
                # Drain all complete frames from the buffer
                while True:
                    result = _parse_event_frame(buf)
                    if result is None:
                        break
                    event, consumed = result
                    buf = buf[consumed:]

                    etype = event.get("type", "")
                    edata = event.get("data", {})

                    if etype == "contentBlockDelta":
                        text = edata.get("delta", {}).get("text", "")
                        if text:
                            yield {
                                "id":      msg_id,
                                "object":  "chat.completion.chunk",
                                "created": ts,
                                "model":   original_model,
                                "choices": [{
                                    "index":         0,
                                    "delta":         {"content": text},
                                    "finish_reason": None,
                                }],
                            }

                    elif etype == "messageStop":
                        stop = edata.get("stopReason", "end_turn")
                        finish = "stop" if stop in ("end_turn", "stop_sequence") else stop
                        yield {
                            "id":      msg_id,
                            "object":  "chat.completion.chunk",
                            "created": ts,
                            "model":   original_model,
                            "choices": [{
                                "index":         0,
                                "delta":         {},
                                "finish_reason": finish,
                            }],
                        }
