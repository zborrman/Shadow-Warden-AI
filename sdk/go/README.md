# shadow-warden-go

Go SDK for the [Shadow Warden AI](https://shadowwarden.ai) security gateway.

## Install

```bash
go get github.com/shadowwarden/warden-go
```

## Quick start

```go
import "github.com/shadowwarden/warden-go/warden"

client, err := warden.New("http://localhost:8001", "sk_your_api_key")
if err != nil {
    log.Fatal(err)
}
defer client.Close()

result, err := client.Filter(ctx, userInput, nil)
if err != nil {
    var blocked *warden.BlockedError
    if errors.As(err, &blocked) {
        http.Error(w, "Request blocked by security policy", 400)
        return
    }
    log.Fatal(err)
}

// result.FilteredContent has secrets redacted — safe to forward to your AI model
response, err := openaiClient.Chat.Completions.Create(ctx, openai.ChatCompletionNewParams{
    Messages: []openai.ChatCompletionMessageParamUnion{
        openai.UserMessage(result.FilteredContent),
    },
    Model: openai.ChatModelGPT4o,
})
```

## Scan AI output

```go
scanResult, err := client.FilterOutput(ctx, aiResponse, "tenant-id")
if err != nil {
    log.Fatal(err)
}
if !scanResult.Safe {
    // Use scanResult.SanitizedOutput instead
    log.Printf("Output sanitized (risk=%s)", scanResult.RiskLevel)
    aiResponse = scanResult.SanitizedOutput
}
```

## Batch filtering

```go
results, err := client.FilterBatch(ctx, []warden.BatchItem{
    {Content: messages[0], TenantID: "acme"},
    {Content: messages[1], TenantID: "acme"},
    {Content: messages[2], TenantID: "beta"},
})
```

## Client options

```go
client, err := warden.New(
    "https://warden.company.internal",
    "sk_...",
    warden.WithTimeout(10 * time.Second),
    warden.WithTenantID("acme-corp"),       // default tenant_id for all calls
    warden.WithHTTPClient(customHTTPClient), // bring your own transport
)
```

## Error types

| Type | When |
|------|------|
| `*BlockedError` | Gateway returned `allowed: false` |
| `*GatewayError` | Gateway returned HTTP 4xx / 5xx |
| `*TimeoutError` | HTTP request timed out or context cancelled |
| `*WardenError`  | SDK-level error (e.g. invalid config) |

## Run tests

```bash
cd sdk/go
go test ./warden/...
```

## Requirements

- Go 1.21+
- Shadow Warden gateway v1.0+
