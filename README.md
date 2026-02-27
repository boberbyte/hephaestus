# Hephaestus

> ⚠️ **Work in Progress** — This is an OT/ICS-focused fork of [beelzebub](https://github.com/mariocandela/beelzebub) and is under active development. Expect breaking changes.

**Hephaestus** is an OT/ICS honeypot framework built on top of [beelzebub](https://github.com/mariocandela/beelzebub). It extends the original IT honeypot capabilities with industrial protocol support, AI-generated process values, and a full monitoring stack tailored for operational technology environments.

## What's different from beelzebub?

| Feature | beelzebub | Hephaestus |
|---------|-----------|------------|
| SSH / HTTP / TCP / Telnet | ✅ | ✅ |
| Modbus TCP (port 502) | ❌ | ✅ |
| Siemens S7Comm (port 102) | ❌ | ✅ |
| IEC 60870-5-104 (port 2404) | ❌ | ✅ |
| AI-generated register values | ❌ | ✅ |
| OT Historian (InfluxDB) | ❌ | ✅ |
| Grafana + Loki + Prometheus | ❌ | ✅ |
| GeoIP world map | ❌ | ✅ |
| LLM provider: Anthropic Claude | ❌ | ✅ |

## Overview

Hephaestus simulates an OT/ICS environment — PLCs, RTUs, and historians — to attract and analyze attacks against industrial infrastructure. OT protocol honeypots use Claude (Anthropic) to generate realistic process values (temperature, pressure, flow) so that sophisticated scanners cannot easily distinguish the honeypot from a real installation.

## Table of Contents

- [Global Threat Intelligence Community](#global-threat-intelligence-community)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
  - [Core Configuration](#core-configuration)
  - [Service Configuration](#service-configuration)
- [Protocol Examples](#protocol-examples)
  - [MCP Honeypot](#mcp-honeypot)
  - [HTTP Honeypot](#http-honeypot)
  - [SSH Honeypot](#ssh-honeypot)
  - [TELNET Honeypot](#telnet-honeypot)
  - [TCP Honeypot](#tcp-honeypot)
  - [OT/ICS Honeypots](#otics-honeypots)
    - [Modbus TCP](#modbus-tcp)
    - [Siemens S7Comm](#siemens-s7comm)
    - [IEC 60870-5-104](#iec-60870-5-104)
- [Observability](#observability)
  - [Prometheus Metrics](#prometheus-metrics)
  - [RabbitMQ Integration](#rabbitmq-integration)
  - [Beelzebub Cloud](#beelzebub-cloud)
- [Testing](#testing)
- [Code Quality](#code-quality)
- [Contributing](#contributing)
- [License](#license)

## Global Threat Intelligence Community

Our mission is to establish a collaborative ecosystem of security researchers and white hat professionals worldwide, dedicated to creating a distributed honeypot network that identifies emerging malware, discovers zero-day vulnerabilities, and neutralizes active botnets.

[![White Paper](https://img.shields.io/badge/White_Paper-v1.0-blue?style=for-the-badge)](https://github.com/beelzebub-labs/white-paper/)

The white paper includes information on how to join our Discord community and contribute to the global threat intelligence network. 

## Key Features

Beelzebub offers a wide range of features to enhance your honeypot environment:

- **Low-code configuration**: YAML-based, modular service definition
- **LLM integration**: The LLM convincingly simulates a real system, creating high-interaction honeypot experiences, while actually maintaining low-interaction architecture for enhanced security and easy management
- **Multi-protocol support**: SSH, HTTP, TCP, TELNET, MCP (detect prompt injection against LLM agents), and OT/ICS protocols: Modbus TCP, Siemens S7Comm, IEC 60870-5-104
- **Prometheus metrics & observability**: Built-in metrics endpoint for monitoring
- **Event tracing**: Multiple output strategies (stdout, RabbitMQ, Beelzebub Cloud)
- **Docker & Kubernetes ready**: Deploy anywhere with provided configurations
- **ELK stack ready**: Official integration available at [Elastic docs](https://www.elastic.co/docs/reference/integrations/beelzebub)

## LLM Honeypot Demo

![demo-beelzebub](https://github.com/user-attachments/assets/4dbb9a67-6c12-49c5-82ac-9b3e340406ca)

## Quick Start

You can run Beelzebub via Docker, Go compiler(cross device), or Helm (Kubernetes).

### Using Docker Compose

1. Build the Docker images:

   ```bash
   $ docker compose build
   ```

2. Start Beelzebub in detached mode:

   ```bash
   $ docker compose up -d
   ```


### Using Go Compiler

1. Download the necessary Go modules:

   ```bash
   $ go mod download
   ```

2. Build the Beelzebub executable:

   ```bash
   $ go build
   ```

3. Run Beelzebub:

   ```bash
   $ ./beelzebub
   ```

### Deploy on kubernetes cluster using helm

1. Install helm

2. Deploy beelzebub:

   ```bash
   $ helm install beelzebub ./beelzebub-chart
   ```

3. Next release

   ```bash
   $ helm upgrade beelzebub ./beelzebub-chart
   ```

## Configuration

Beelzebub uses a two-tier configuration system:

1. **Core configuration** (`beelzebub.yaml`) - Global settings for logging, tracing, and Prometheus
2. **Service configurations** (`services/*.yaml`) - Individual honeypot service definitions

### Core Configuration

The core configuration file controls global behavior:

```yaml
core:
  logging:
    debug: false
    debugReportCaller: false
    logDisableTimestamp: true
    logsPath: ./logs
  tracings:
    rabbit-mq:
      enabled: false
      uri: "amqp://guest:guest@localhost:5672/"
  prometheus:
    path: "/metrics"
    port: ":2112"
  beelzebub-cloud:
    enabled: false
    uri: ""
    auth-token: ""
```

### Service Configuration

Each honeypot service is defined in a separate YAML file in the `services/` directory. To run Beelzebub with custom paths:

```bash
./beelzebub --confCore ./configurations/beelzebub.yaml --confServices ./configurations/services/
```

Additional flags:
- `--memLimitMiB <value>` - Set memory limit in MiB (default: 100, use -1 to disable)

## Protocol Examples

Below are example configurations for each supported protocol.

### MCP Honeypot

MCP (Model Context Protocol) honeypots are decoy tools designed to detect prompt injection attacks against LLM agents.

#### Why Use an MCP Honeypot?

An MCP honeypot is a **decoy tool** that the agent should never invoke under normal circumstances. Integrating this strategy into your agent pipeline offers three key benefits:

- **Real-time detection of guardrail bypass attempts** - Instantly identify when a prompt injection attack successfully convinces the agent to invoke a restricted tool
- **Automatic collection of real attack prompts** - Every activation logs genuine malicious prompts, enabling continuous improvement of your filtering mechanisms
- **Continuous monitoring of attack trends** - Track exploit frequency and system resilience using objective, actionable measurements (HAR, TPR, MTP)

![video-mcp-diagram](https://github.com/user-attachments/assets/e04fd19e-9537-427e-9131-9bee31d8ebad)

**mcp-8000.yaml**:

```yaml
apiVersion: "v1"
protocol: "mcp"
address: ":8000"
description: "MCP Honeypot"
tools:
  - name: "tool:user-account-manager"
    description: "Tool for querying and modifying user account details. Requires administrator privileges."
    params:
      - name: "user_id"
        description: "The ID of the user account to manage."
      - name: "action"
        description: "The action to perform on the user account, possible values are: get_details, reset_password, deactivate_account"
    handler: |
      {
        "tool_id": "tool:user-account-manager",
        "status": "completed",
        "output": {
          "message": "Tool 'tool:user-account-manager' executed successfully. Results are pending internal processing and will be logged.",
          "result": {
            "operation_status": "success",
            "details": "email: kirsten@gmail.com, role: admin, last-login: 02/07/2025"
          }
        }
      }
  - name: "tool:system-log"
    description: "Tool for querying system logs. Requires administrator privileges."
    params:
      - name: "filter"
        description: "The input used to filter the logs."
    handler: |
      {
        "tool_id": "tool:system-log",
        "status": "completed",
        "output": {
          "message": "Tool 'tool:system-log' executed successfully. Results are pending internal processing and will be logged.",
          "result": {
            "operation_status": "success",
            "details": "Info: email: kirsten@gmail.com, last-login: 02/07/2025"
          }
        }
      }
```

Invoke remotely via `http://beelzebub:port/mcp` (Streamable HTTP Server).

### HTTP Honeypot

HTTP honeypots respond to web requests with configurable responses based on URL pattern matching.

**http-80.yaml** (WordPress simulation):

```yaml
apiVersion: "v1"
protocol: "http"
address: ":80"
description: "Wordpress 6.0"
commands:
  - regex: "^(/index.php|/index.html|/)$"
    handler:
      <html>
        <header>
          <title>Wordpress 6 test page</title>
        </header>
        <body>
          <h1>Hello from Wordpress</h1>
        </body>
      </html>
    headers:
      - "Content-Type: text/html"
      - "Server: Apache/2.4.53 (Debian)"
      - "X-Powered-By: PHP/7.4.29"
    statusCode: 200
  - regex: "^(/wp-login.php|/wp-admin)$"
    handler:
      <html>
        <header>
          <title>Wordpress 6 test page</title>
        </header>
        <body>
          <form action="" method="post">
            <label for="uname"><b>Username</b></label>
            <input type="text" placeholder="Enter Username" name="uname" required>

            <label for="psw"><b>Password</b></label>
            <input type="password" placeholder="Enter Password" name="psw" required>

            <button type="submit">Login</button>
          </form>
        </body>
      </html>
    headers:
      - "Content-Type: text/html"
      - "Server: Apache/2.4.53 (Debian)"
      - "X-Powered-By: PHP/7.4.29"
    statusCode: 200
  - regex: "^.*$"
    handler:
      <html>
        <header>
          <title>404</title>
        </header>
        <body>
          <h1>Not found!</h1>
        </body>
      </html>
    headers:
      - "Content-Type: text/html"
      - "Server: Apache/2.4.53 (Debian)"
      - "X-Powered-By: PHP/7.4.29"
    statusCode: 404
```

**http-8080.yaml** (Apache 401 simulation):

```yaml
apiVersion: "v1"
protocol: "http"
address: ":8080"
description: "Apache 401"
commands:
  - regex: ".*"
    handler: "Unauthorized"
    headers:
      - "www-Authenticate: Basic"
      - "server: Apache"
    statusCode: 401
```

### SSH Honeypot

SSH honeypots support both static command responses and LLM-powered dynamic interactions.

#### LLM-Powered SSH Honeypot

Using OpenAI as the LLM provider:

```yaml
apiVersion: "v1"
protocol: "ssh"
address: ":2222"
description: "SSH interactive OpenAI  GPT-4"
commands:
  - regex: "^(.+)$"
    plugin: "LLMHoneypot"
serverVersion: "OpenSSH"
serverName: "ubuntu"
passwordRegex: "^(root|qwerty|Smoker666|123456|jenkins|minecraft|sinus|alex|postgres|Ly123456)$"
deadlineTimeoutSeconds: 60
plugin:
   llmProvider: "openai"
   llmModel: "gpt-4o" #Models https://platform.openai.com/docs/models
   openAISecretKey: "sk-proj-123456"
```

Using local Ollama instance:

```yaml
apiVersion: "v1"
protocol: "ssh"
address: ":2222"
description: "SSH Ollama Llama3"
commands:
  - regex: "^(.+)$"
    plugin: "LLMHoneypot"
serverVersion: "OpenSSH"
serverName: "ubuntu"
passwordRegex: "^(root|qwerty|Smoker666|123456|jenkins|minecraft|sinus|alex|postgres|Ly123456)$"
deadlineTimeoutSeconds: 60
plugin:
   llmProvider: "ollama"
   llmModel: "codellama:7b"
   host: "http://localhost:11434/api/chat"
```

Using a custom prompt:

```yaml
apiVersion: "v1"
protocol: "ssh"
address: ":2222"
description: "SSH interactive OpenAI  GPT-4"
commands:
  - regex: "^(.+)$"
    plugin: "LLMHoneypot"
serverVersion: "OpenSSH"
serverName: "ubuntu"
passwordRegex: "^(root|qwerty|Smoker666|123456|jenkins|minecraft|sinus|alex|postgres|Ly123456)$"
deadlineTimeoutSeconds: 60
plugin:
   llmProvider: "openai"
   llmModel: "gpt-4o"
   openAISecretKey: "sk-proj-123456"
   prompt: "You will act as an Ubuntu Linux terminal. The user will type commands, and you are to reply with what the terminal should show. Your responses must be contained within a single code block."
```

#### Static SSH Honeypot

```yaml
apiVersion: "v1"
protocol: "ssh"
address: ":22"
description: "SSH interactive"
commands:
  - regex: "^ls$"
    handler: "Documents Images Desktop Downloads .m2 .kube .ssh .docker"
  - regex: "^pwd$"
    handler: "/home/"
  - regex: "^uname -m$"
    handler: "x86_64"
  - regex: "^docker ps$"
    handler: "CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES"
  - regex: "^docker .*$"
    handler: "Error response from daemon: dial unix docker.raw.sock: connect: connection refused"
  - regex: "^uname$"
    handler: "Linux"
  - regex: "^ps$"
    handler: "PID TTY TIME CMD\n21642 ttys000 0:00.07 /bin/dockerd"
  - regex: "^(.+)$"
    handler: "command not found"
serverVersion: "OpenSSH"
serverName: "ubuntu"
passwordRegex: "^(root|qwerty|Smoker666)$"
deadlineTimeoutSeconds: 60
```

### TELNET Honeypot

TELNET honeypots provide terminal-based interaction similar to SSH, with support for both static responses and LLM integration.

#### LLM-Powered TELNET Honeypot

```yaml
apiVersion: "v1"
protocol: "telnet"
address: ":23"
description: "TELNET LLM Honeypot"
commands:
  - regex: "^(.+)$"
    plugin: "LLMHoneypot"
serverName: "router"
passwordRegex: "^(admin|root|password|123456)$"
deadlineTimeoutSeconds: 120
plugin:
   llmProvider: "openai"
   llmModel: "gpt-4o"
   openAISecretKey: "sk-proj-..."
```

#### Static TELNET Honeypot

```yaml
apiVersion: "v1"
protocol: "telnet"
address: ":23"
description: "TELNET Router Simulation"
commands:
  - regex: "^show version$"
    handler: "Cisco IOS Software, Version 15.1(4)M4"
  - regex: "^show ip interface brief$"
    handler: "Method Status Protocol\nFastEthernet0/0 192.168.1.1 YES NVRAM up up"
  - regex: "^(.+)$"
    handler: "% Unknown command"
serverName: "router"
passwordRegex: "^(admin|cisco|password)$"
deadlineTimeoutSeconds: 60
```

### TCP Honeypot

TCP honeypots respond with a configurable banner to any TCP connection. Useful for simulating database servers or other TCP services.

```yaml
apiVersion: "v1"
protocol: "tcp"
address: ":3306"
description: "MySQL 8.0.29"
banner: "8.0.29"
deadlineTimeoutSeconds: 10
```

### OT/ICS Honeypots

Beelzebub supports three industrial control system protocols, giving protocol-accurate responses to scanners such as Shodan, nmap ICS scripts, plcscan, and ICS-specific attack tools. All implementations use only Go standard library — no extra dependencies required.

| Protocol | Default port | Standard |
|---|---|---|
| Modbus TCP | 502 | IEC 61158 |
| Siemens S7Comm | 102 | Siemens proprietary (TPKT/COTP/S7) |
| IEC 60870-5-104 | 2404 | IEC 60870-5-104 |

#### Modbus TCP

Implements the full MBAP header and routes the most common function codes:

| Function code | Name | Behaviour |
|---|---|---|
| `0x01` / `0x02` | Read Coils / Discrete Inputs | Returns `⌈qty/8⌉` zero bytes |
| `0x03` / `0x04` | Read Holding / Input Registers | Returns `qty×2` zero bytes (overridable) |
| `0x05` / `0x06` / `0x0F` / `0x10` | Write | Echoes acknowledgment |
| `0x11` | Report Slave ID | Returns `serverName` + run indicator |
| `0x2B` | MEI Device Identification | Returns vendor/product from `serverName`/`serverVersion` |
| Unknown | — | Exception response (FC\|0x80, code 0x01) |

Use `commands` to override register values for specific address ranges:

```yaml
apiVersion: "v1"
protocol: "modbus"
address: ":502"
description: "Siemens S7-1200 Modbus Server"
serverName: "Siemens"
serverVersion: "V4.4"
banner: "1"                    # Slave ID
deadlineTimeoutSeconds: 30
commands:
  - regex: "FC03:0-4"          # Override holding registers 0-4
    handler: "0064 00C8 012C 01F4 0258"   # Values in hex (100, 200, 300, 400, 600)
```

Verify with nmap or mbpoll:

```bash
nmap -p 502 --script modbus-discover localhost
echo -ne "\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0A" | nc localhost 502 | xxd
```

#### Siemens S7Comm

Implements the full TPKT → COTP → S7 protocol stack used by Siemens S7-300/400/1200/1500 PLCs:

1. **COTP handshake** — responds to Connection Request (CR `0xE0`) with Connection Confirm (CC `0xD0`)
2. **S7 negotiate** — acknowledges Setup Communication with max PDU size 960 bytes
3. **SZL reads** — serves module identification, CPU component, and module info from YAML config fields:

| SZL ID | Content | Config field |
|---|---|---|
| `0x001C` | Module identification | `serverName` |
| `0x0011` | CPU component / firmware | `serverVersion` |
| `0x0111` | Module info / serial | `banner` |

```yaml
apiVersion: "v1"
protocol: "s7comm"
address: ":102"
description: "Siemens S7-300 PLC"
serverName: "6ES7 315-2EH14-0AB0"   # Shown as module identification
serverVersion: "V3.3.13"             # Shown as firmware version
banner: "S7300-01"                   # Shown as serial number
deadlineTimeoutSeconds: 60
```

Verify with nmap:

```bash
nmap -p 102 --script s7-info localhost
```

#### IEC 60870-5-104

Implements the IEC 104 application layer with a full frame state machine:

- **U-frames**: handles STARTDT, STOPDT, and TESTFR with correct confirmations
- **I-frames**: parses ASDU (TypeID, Cause of Transmission, Common Address, IOA) and sends S-frame acknowledgments; command TypeIDs (45–64) receive activation confirmation (COT=7) followed by activation termination (COT=10)
- **S-frames**: acknowledgment-only frames are handled silently
- **Keepalive**: sends TESTFR_act every 30 seconds while the data transfer is active

```yaml
apiVersion: "v1"
protocol: "iec104"
address: ":2404"
description: "IEC 60870-5-104 RTU"
serverName: "PowerLogic RTU"
serverVersion: "1.2.0"
banner: "1"                    # ASDU common address
deadlineTimeoutSeconds: 120
```

Verify with netcat:

```bash
# Send STARTDT_act — expect STARTDT_con (0x0B) in response
echo -ne "\x68\x04\x07\x00\x00\x00" | nc localhost 2404 | xxd
```

## Observability

### Prometheus Metrics

Beelzebub exposes Prometheus metrics at the configured endpoint (default: `:2112/metrics`). Available metrics include:

- `beelzebub_events_total` - Total number of honeypot events
- `beelzebub_events_ssh_total` - SSH-specific events
- `beelzebub_events_http_total` - HTTP-specific events
- `beelzebub_events_tcp_total` - TCP-specific events
- `beelzebub_events_telnet_total` - TELNET-specific events
- `beelzebub_events_mcp_total` - MCP-specific events
- `beelzebub_modbus_events_total` - Modbus TCP events
- `beelzebub_s7comm_events_total` - Siemens S7Comm events
- `beelzebub_iec104_events_total` - IEC 60870-5-104 events

### RabbitMQ Integration

Enable RabbitMQ tracing to publish honeypot events to a message queue:

```yaml
core:
  tracings:
    rabbit-mq:
      enabled: true
      uri: "amqp://guest:guest@localhost:5672/"
```

Events are published as JSON messages for downstream processing.

## Testing

### Unit Tests

```bash
make test.unit
```

### Integration Tests

Integration tests require external dependencies (RabbitMQ, etc.):

```bash
make test.dependencies.start
make test.integration
make test.dependencies.down
```

## Code Quality

We maintain high code quality through:

- **Automated Testing**: Unit and integration tests run on every pull request
- **Static Analysis**: Go Report Card and CodeQL for code quality and security checks
- **Code Coverage**: Monitored via [Codecov](https://codecov.io/gh/mariocandela/beelzebub)
- **Continuous Integration**: GitHub Actions pipelines on every commit
- **Code Reviews**: All contributions undergo peer review

## Contributing

The Beelzebub team welcomes contributions and project participation. Whether you want to report bugs, contribute new features, or have any questions, please refer to our [Contributor Guide](CONTRIBUTING.md) for detailed information. We encourage all participants and maintainers to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md) and foster a supportive and respectful community.

Happy hacking!

## License

Beelzebub is licensed under the [GNU GPL v3 License](LICENSE).

## Supported By

[![JetBrains logo.](https://resources.jetbrains.com/storage/products/company/brand/logos/jetbrains.svg)](https://jb.gg/OpenSourceSupport)

![gitbook logo](https://i.postimg.cc/VNQh5hnk/gitbook.png)
