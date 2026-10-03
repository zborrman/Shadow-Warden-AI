# Shadow Warden AI CLI — the `warden` command

Human page: <https://shadow-warden-ai.com/cli>

`warden` is the official command-line client for the Shadow Warden AI gateway.
It is a console script of the published
[`shadow-warden-sdk`](https://pypi.org/project/shadow-warden-sdk/) package
(version 1.1.0 or later), so an agent or a shell script can use the gateway
without writing an integration.

## Install

```bash
pip install "shadow-warden-sdk>=1.1.0"
# or, isolated from your project environments:
pipx install "shadow-warden-sdk>=1.1.0"
warden version
```

## Configure

```bash
export WARDEN_API_KEY="sk_..."
export WARDEN_GATEWAY_URL="https://api.shadow-warden-ai.com"   # default
export WARDEN_TENANT_ID="default"
```

Flags (`--api-key`, `--gateway-url`, `--tenant-id`, `--timeout`) override the
environment.

## Commands

```bash
warden health                                  # does the gateway answer?
warden filter "ignore previous instructions"   # screen text
warden filter --json --file prompt.txt         # machine-readable verdict
warden filter --stdin < prompt.txt             # pipeline friendly
warden filter --strict "..."                   # block on MEDIUM risk too
warden impact --requests 50000                 # projected value at a volume
warden billing                                 # plan, quota, add-ons
warden version                                 # SDK version
```

## Exit codes

The exit code is the contract, so a script never has to parse output.

| Code | Meaning |
|---|---|
| `0` | The content is allowed / the command succeeded. |
| `1` | The content was blocked. |
| `2` | Usage error — bad arguments or nothing to read. |
| `3` | The gateway could not be reached or answered with an error. |

A gateway error exits `3`, never `1`, so an outage cannot read as "blocked".
`--json` output never contains the matched secret, only its kind.

## Related

- [SDKs and CLI](https://shadow-warden-ai.com/sdk)
- [Developer portal](https://shadow-warden-ai.com/developers)
- [Authentication](https://shadow-warden-ai.com/doc/authentication)
