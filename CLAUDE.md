# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Identity

This is **Hephaestus** — an OT/ICS-focused fork of [beelzebub](https://github.com/mariocandela/beelzebub). The Go module name remains `github.com/mariocandela/beelzebub/v3`. It adds Modbus TCP, Siemens S7Comm, and IEC 60870-5-104 protocol honeypots on top of the original SSH/HTTP/TCP/Telnet stack, plus an Anthropic Claude LLM provider and a full monitoring stack (Prometheus + Grafana + Loki + InfluxDB).

## Build & Test Commands

No local Go is assumed — build and single-package tests via Docker:

```bash
# Build (requires Docker; no local Go needed)
docker run --rm -v $(pwd):/workspace -w /workspace golang:1.24 go build ./...

# Run a single package's tests (Docker)
docker run --rm -v $(pwd):/workspace -w /workspace golang:1.24 \
  go test ./protocols/strategies/MODBUS/...

# Unit tests — make targets call go directly (requires local Go)
make test.unit                        # go test ./...
make test.unit.verbose                # go test ./... -v

# Integration tests (requires RabbitMQ via docker compose)
make test.dependencies.start
make test.integration                 # INTEGRATION=1 go test ./...
make test.dependencies.down

# Start/stop full stack
make beelzebub.start                  # docker compose build && up -d
make beelzebub.stop                   # docker compose down
```

## Architecture

### Startup Flow

`main.go` → `parser.Init()` reads YAML configs → `builder.NewDirector().BuildBeelzebub()` wires tracing + strategies → `builder.Run()` starts each service in a goroutine → process blocks on a `quit` channel.

### Strategy Pattern

Every protocol is a **separate package** under `protocols/strategies/<PROTO>/` and implements the single interface:

```go
// protocols/protocol_manager.go
type ServiceStrategy interface {
    Init(beelzebubServiceConfiguration parser.BeelzebubServiceConfiguration, tracer tracer.Tracer) error
}
```

`builder/builder.go:Run()` switches on the `protocol` string from YAML and calls `protocolManager.InitService()`. Each `Init` spawns a goroutine and returns immediately.

### Adding a New Protocol

1. Create `protocols/strategies/<PROTO>/<proto>.go` implementing `ServiceStrategy`.
2. Add a new iota constant to the `Protocol` type in `tracer/tracer.go` and extend the `String()` array.
3. Register a Prometheus counter in `tracer.GetInstance()` and wire it in `updatePrometheusCounters()`.
4. Add a `case "<proto>":` branch in `builder/builder.go:Run()`.
5. Add a service config file to `configurations/services/<proto>-<port>.yaml`.

### Configuration System

Two-tier YAML:

| File | Purpose |
|---|---|
| `configurations/beelzebub.yaml` | Core: logging, RabbitMQ, Prometheus, beelzebub-cloud |
| `configurations/services/*.yaml` | One file per honeypot service |

`parser.BeelzebubServiceConfiguration` is the canonical struct for service configs (`parser/configurations_parser.go`). Do not add new top-level YAML fields without updating this struct.

YAML field reuse for OT protocols (avoid adding new fields for OT data):

| YAML Field | Modbus | S7Comm | IEC 104 |
|---|---|---|---|
| `banner` | Slave ID | Serial number | ASDU common address |
| `serverName` | Vendor string | PLC module name | Station name |
| `serverVersion` | Firmware version | Firmware version | RTU firmware version |
| `commands` | Register overrides (`FC03:0-4` → hex values) | unused | unused |

### Tracer

`tracer.GetInstance()` is a singleton. It runs 5 worker goroutines consuming from an `eventsChan`. All protocol strategies receive a `tracer.Tracer` interface and call `TraceEvent(tracer.Event{...})`. The `tracer.Strategy` function (set at build time) forwards events to stdout JSON, RabbitMQ, or beelzebub-cloud.

### LLM Plugin

`plugins/llm-integration.go` supports three providers:

| Provider | Config key | Notes |
|---|---|---|
| OpenAI | `llmProvider: openai` | `openAISecretKey` in YAML |
| Ollama | `llmProvider: ollama` | `host` points to local Ollama |
| Anthropic Claude | `llmProvider: anthropic` | `openAISecretKey` in YAML (misnamed) |

The `LLM_API_KEY` environment variable overrides `openAISecretKey` for all providers at runtime.

LLM is triggered when a `Command.Plugin` field equals `"LLMHoneypot"`. The `plugins.BuildHoneypot()` function selects the system prompt automatically by protocol (SSH/Telnet → Linux terminal, HTTP → vulnerable server, Modbus → PLC register values, S7Comm → module order number). Input and output validation guardrails can be enabled per-service via `inputValidationEnabled`/`outputValidationEnabled` in the plugin YAML block.

### Malware Capture (SSH)

The SSH strategy (`protocols/strategies/SSH/ssh.go`) captures:
- **SCP uploads**: saves files to `/samples/<timestamp>_<ip>_<filename>`
- **wget/curl commands**: fetches URLs in background goroutines, saves to `/samples/`; capped at 10 MB per file, 30-second timeout, TLS verification disabled
- **SCP downloads** (`scp -f`): generates synthetic file contents via LLM and saves a copy to `/samples/` for defender review

### HTTP Strategy

HTTP supports HTTPS when `TLSCertPath` and `TLSKeyPath` are set in the service config. The `FallbackCommand` field acts as a catch-all for unmatched routes (regex ignored). Prometheus metrics are exposed on `:2112/metrics`.

### beelzebub-cloud

When `BeelzebubCloud.Enabled` is true in `beelzebub.yaml`, `Builder.Run()` calls the cloud API to override local service configs (`GetHoneypotsConfigurations()`), polled every 15 seconds. This allows dynamic honeypot management without restarting the process.

### Monitoring Stack

`monitoring/` contains Grafana dashboards and Loki/Prometheus configs. `docker-compose.yml` wires everything together. The monitoring stack is separate from the honeypot binary. Integration tests use a separate compose file at `integration_test/docker-compose.yml`.

### SSH Service Config

`passwordRegex` in the service YAML controls which passwords are accepted (e.g. `".*"` accepts all). The SSH strategy validates each login attempt against this regex.

### Shared Strategy Instances

`builder.go:Run()` creates **one instance per protocol type** (e.g. one `SSHStrategy`). All SSH service configs share that instance — `SSHStrategy.Sessions` is therefore shared across all SSH ports.

## Deployment

Server: `ssh -i ~/.ssh/id_rsa azureuser@20.240.47.97 -p 2022`
Repo on server: `~/hephaestus/`

```bash
# Build on server (no local Go)
ssh -i ~/.ssh/id_rsa azureuser@20.240.47.97 -p 2022 \
  "docker run --rm -v ~/hephaestus:/workspace -w /workspace golang:1.24 go build -buildvcs=false ./..."

# Restart honeypot
ssh -i ~/.ssh/id_rsa azureuser@20.240.47.97 -p 2022 \
  "cd ~/hephaestus && docker compose restart beelzebub"

# Restart full monitoring stack
ssh -i ~/.ssh/id_rsa azureuser@20.240.47.97 -p 2022 \
  "cd ~/hephaestus && docker compose restart promtail grafana"
```

**Note:** Several subdirs on the server lack execute-bits (owned by root or `drw-r--r--`).
Use `sudo chmod u+X <dir>` before writing, or `sudo mv` via `/tmp` for root-owned files.

## Recent Changes (2026-03-13)

### Modbus — MEI Device Identification (FC=0x2B)
`protocols/strategies/MODBUS/modbus.go` — improved MEI response:
- Splits `serverName` into vendor + product (e.g. `"ABB RTU500"` → `ABB` / `RTU500`)
- Returns 5 objects: VendorName, ProductCode, MajorMinorRevision, VendorUrl, ProductName
- Conformity level `0x82` (regular, individual access)
- Much more realistic fingerprint against Shodan/Censys scanners

### IEC-104 — Session End Bug Fix
`protocols/strategies/IEC104/iec104.go` — session-end TraceEvent now includes
`RemoteAddr`, `SourceIp`, `SourcePort`, `Description` (previously all empty).

### SSH — Canned Responses (GPU savings)
`configurations/services/ssh-22.yaml` — static responses added before the LLM catch-all
for ~20 common recon commands: `nvidia-smi`, `lspci`, `uname`, `hostname`,
`cat /etc/os-release`, `free`, `df -h`, `w`, `who`, `uptime`, `last`, `nproc`, `lscpu`.
**YAML gotcha:** multiline handlers with table-formatted output (headers with many spaces)
must use quoted strings with `\n` instead of `|` block scalars — otherwise the first
heavily-indented line sets the block's indentation level and the next line breaks parsing.

### Grafana — World Map GeoIP
`monitoring/promtail-config.yaml` — added `geoip` pipeline stage using GeoLite2-Country.mmdb.
`docker-compose.yml` — `geoip-init` now downloads `GeoLite2-Country.mmdb` from
`P3TERX/GeoLite.mmdb` (MaxMind-compatible; DB-IP's format caused "unknown database type").
`monitoring/grafana/grafana.ini` — db_path updated.
Dashboard panel `location.lookup` changed from `sourceIp` → `geoip_country_code`.

### Grafana — BoberTech Logo Panel
`monitoring/grafana/img/bobertech.jpg` — logo mounted into Grafana at
`/usr/share/grafana/public/img/bobertech.jpg`.
Dashboard: transparent Text-panel (id=99) in top-right corner with image + text
"AI Compute / Powered by BoberTech".
`grafana.ini`: `disable_sanitize_html = true` required for HTML in Text panels.

## Testing Conventions

- Use `testify/assert` and `testify/require`.
- Protocol tests use a local `mockTracer` struct implementing `tracer.Tracer`.
- Use `net.Listen("tcp", "127.0.0.1:0")` + `l.Close()` to find a free port, then pass the address to `Init()`.
- Integration tests are gated by `os.Getenv("INTEGRATION") == "1"` and use `integration_test/docker-compose.yml`.
- The `plugins` package tests mock HTTP with `github.com/jarcoal/httpmock`.
