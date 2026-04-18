"""
warden/shadow_ai/signatures.py
────────────────────────────────
Known AI provider fingerprint database.

Each entry describes how to recognise a provider by:
  - DNS domains it uses
  - URL path patterns present in requests
  - Response headers it emits
  - Local-network ports it typically listens on (for self-hosted models)

Used by ShadowAIDetector for both network probing and DNS telemetry.
"""
from __future__ import annotations

from typing import TypedDict


class ProviderSignature(TypedDict):
    domains:          list[str]
    url_patterns:     list[str]
    response_headers: list[str]
    local_ports:      list[int]
    risk_level:       str          # HIGH | MEDIUM | LOW
    category:         str          # GENERATIVE_AI | EMBEDDING_API | INFERENCE_API | LOCAL_AI
    display_name:     str


# ── Known AI provider signatures ──────────────────────────────────────────────

AI_PROVIDERS: dict[str, ProviderSignature] = {

    "openai": {
        "display_name":      "OpenAI",
        "domains":           ["api.openai.com", "openai.com", "oai.azure.com",
                              "oaidalleapiprodscus.blob.core.windows.net"],
        "url_patterns":      ["/v1/chat/completions", "/v1/completions",
                              "/v1/embeddings", "/v1/images/generations",
                              "/v1/audio/transcriptions"],
        "response_headers":  ["x-openai-organization", "openai-processing-ms",
                              "openai-version", "x-ratelimit-limit-tokens"],
        "local_ports":       [],
        "risk_level":        "HIGH",
        "category":          "GENERATIVE_AI",
    },

    "anthropic": {
        "display_name":      "Anthropic / Claude",
        "domains":           ["api.anthropic.com"],
        "url_patterns":      ["/v1/messages", "/v1/complete"],
        "response_headers":  ["anthropic-version", "x-cloud-trace-context"],
        "local_ports":       [],
        "risk_level":        "HIGH",
        "category":          "GENERATIVE_AI",
    },

    "google_gemini": {
        "display_name":      "Google Gemini / Vertex AI",
        "domains":           ["generativelanguage.googleapis.com",
                              "aiplatform.googleapis.com",
                              "us-central1-aiplatform.googleapis.com"],
        "url_patterns":      ["/v1/models/gemini", "/v1beta/models/gemini",
                              "/v1/projects/", "/predict"],
        "response_headers":  ["x-goog-request-id"],
        "local_ports":       [],
        "risk_level":        "HIGH",
        "category":          "GENERATIVE_AI",
    },

    "cohere": {
        "display_name":      "Cohere",
        "domains":           ["api.cohere.ai", "api.cohere.com"],
        "url_patterns":      ["/v1/generate", "/v1/chat", "/v1/embed"],
        "response_headers":  ["x-cohere-request-id"],
        "local_ports":       [],
        "risk_level":        "HIGH",
        "category":          "GENERATIVE_AI",
    },

    "mistral": {
        "display_name":      "Mistral AI",
        "domains":           ["api.mistral.ai"],
        "url_patterns":      ["/v1/chat/completions", "/v1/embeddings"],
        "response_headers":  ["x-mistral-version"],
        "local_ports":       [],
        "risk_level":        "HIGH",
        "category":          "GENERATIVE_AI",
    },

    "together_ai": {
        "display_name":      "Together AI",
        "domains":           ["api.together.xyz", "api.together.ai"],
        "url_patterns":      ["/v1/chat/completions", "/v1/completions",
                              "/inference"],
        "response_headers":  ["x-together-request-id"],
        "local_ports":       [],
        "risk_level":        "HIGH",
        "category":          "INFERENCE_API",
    },

    "replicate": {
        "display_name":      "Replicate",
        "domains":           ["api.replicate.com", "replicate.delivery"],
        "url_patterns":      ["/v1/predictions", "/v1/models/"],
        "response_headers":  ["x-replit-user-id"],   # often Replit-hosted
        "local_ports":       [],
        "risk_level":        "MEDIUM",
        "category":          "INFERENCE_API",
    },

    "huggingface": {
        "display_name":      "Hugging Face Inference",
        "domains":           ["api-inference.huggingface.co",
                              "huggingface.co", "router.huggingface.co"],
        "url_patterns":      ["/models/", "/pipeline/"],
        "response_headers":  ["x-compute-type", "x-cache"],
        "local_ports":       [],
        "risk_level":        "MEDIUM",
        "category":          "INFERENCE_API",
    },

    "azure_openai": {
        "display_name":      "Azure OpenAI Service",
        "domains":           ["openai.azure.com", "cognitiveservices.azure.com"],
        "url_patterns":      ["/openai/deployments/", "/openai/models/"],
        "response_headers":  ["apim-request-id", "x-ms-request-id"],
        "local_ports":       [],
        "risk_level":        "HIGH",
        "category":          "GENERATIVE_AI",
    },

    "aws_bedrock": {
        "display_name":      "AWS Bedrock",
        "domains":           ["bedrock.us-east-1.amazonaws.com",
                              "bedrock-runtime.us-east-1.amazonaws.com",
                              "bedrock.amazonaws.com"],
        "url_patterns":      ["/model/", "/invoke", "/converse"],
        "response_headers":  ["x-amzn-requestid", "x-amz-bedrock"],
        "local_ports":       [],
        "risk_level":        "HIGH",
        "category":          "GENERATIVE_AI",
    },

    # ── Local / self-hosted models ─────────────────────────────────────────────

    "ollama": {
        "display_name":      "Ollama (Local LLM)",
        "domains":           [],   # local only
        "url_patterns":      ["/api/generate", "/api/chat", "/api/tags",
                              "/api/show"],
        "response_headers":  [],
        "local_ports":       [11434],
        "risk_level":        "MEDIUM",
        "category":          "LOCAL_AI",
    },

    "localai": {
        "display_name":      "LocalAI",
        "domains":           [],
        "url_patterns":      ["/v1/chat/completions", "/v1/completions",
                              "/v1/models"],
        "response_headers":  ["x-local-ai"],
        "local_ports":       [8080, 8081],
        "risk_level":        "MEDIUM",
        "category":          "LOCAL_AI",
    },

    "lm_studio": {
        "display_name":      "LM Studio",
        "domains":           [],
        "url_patterns":      ["/v1/chat/completions", "/v1/models"],
        "response_headers":  ["x-lm-studio"],
        "local_ports":       [1234],
        "risk_level":        "MEDIUM",
        "category":          "LOCAL_AI",
    },

    "gradio": {
        "display_name":      "Gradio AI App",
        "domains":           ["gradio.live", "huggingface.co"],
        "url_patterns":      ["/api/predict", "/run/predict", "/queue/join"],
        "response_headers":  ["x-gradio-version"],
        "local_ports":       [7860, 7861, 7862],
        "risk_level":        "LOW",
        "category":          "LOCAL_AI",
    },

    "text_generation_webui": {
        "display_name":      "oobabooga text-generation-webui",
        "domains":           [],
        "url_patterns":      ["/api/v1/generate", "/api/v1/chat",
                              "/v1/chat/completions"],
        "response_headers":  [],
        "local_ports":       [5000, 5001],
        "risk_level":        "MEDIUM",
        "category":          "LOCAL_AI",
    },

    "perplexity": {
        "display_name":      "Perplexity AI",
        "domains":           ["api.perplexity.ai"],
        "url_patterns":      ["/chat/completions"],
        "response_headers":  [],
        "local_ports":       [],
        "risk_level":        "HIGH",
        "category":          "GENERATIVE_AI",
    },

    "groq": {
        "display_name":      "Groq",
        "domains":           ["api.groq.com"],
        "url_patterns":      ["/openai/v1/chat/completions"],
        "response_headers":  ["x-groq-request-id"],
        "local_ports":       [],
        "risk_level":        "HIGH",
        "category":          "GENERATIVE_AI",
    },
}

# ── Flat domain → provider key lookup (built once at import) ──────────────────

DOMAIN_TO_PROVIDER: dict[str, str] = {}
for _key, _sig in AI_PROVIDERS.items():
    for _domain in _sig["domains"]:
        DOMAIN_TO_PROVIDER[_domain.lower()] = _key

# ── Local ports across all providers ─────────────────────────────────────────

LOCAL_AI_PORTS: list[int] = sorted({
    p for sig in AI_PROVIDERS.values() for p in sig["local_ports"]
})

# Standard HTTP/HTTPS ports to probe on any host
PROBE_PORTS: list[int] = [80, 443, 8080, 8443] + LOCAL_AI_PORTS

RISK_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
