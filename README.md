# cloudnan-agent

A lightweight agent that runs on managed servers and connects to the Cloudnan control plane. The agent establishes an outbound gRPC connection, so no inbound ports need to be opened on the managed server.

## How It Works

The agent dials out to the control plane on port 9443 (gRPC) and maintains a persistent bidirectional stream. The control plane pushes commands through this stream; the agent executes them and streams back the results. Authentication uses dual layers: an mTLS client certificate at the transport level and a Bearer token in every gRPC call's metadata.

On first run with `--panel`, the agent performs automatic PKI enrollment:
1. Fetches the gRPC address and CA certificate from the panel HTTP API
2. Generates an ECDSA P-256 keypair locally
3. Submits a CSR to the panel and receives a signed client certificate
4. Saves the CA cert, client cert, and private key to `/etc/cloudnan/pki/`
5. Persists the full configuration to `/etc/cloudnan/agent.yaml`

Subsequent restarts only need `--config` and `--panel` (for the gRPC address refresh). The token never appears on the command line — it is stored in the config file with mode 600.

## Requirements

- Linux (amd64 or arm64)
- Root access (required for system-level operations)
- Outbound TCP access to the control plane on port 9443 (or 443 via Cloudflare Tunnel)

## Installation

Use the install script. It downloads the binary, writes the agent config with mode 600, creates a systemd service, and starts the agent.

```bash
curl -sSL https://github.com/cloudnan-tech/cloudnan-agent/releases/latest/download/install.sh \
  | sudo bash -s -- --token TOKEN --id AGENT_ID --panel https://panel.example.com
```

**Options**

| Flag | Description |
|---|---|
| `--token` | Authentication token issued by the panel when adding a server |
| `--id` | Agent ID assigned by the panel |
| `--panel` | Panel base URL (e.g. `https://panel.example.com`) |
| `--download-url` | Override binary download base URL (default: GitHub Releases) |
| `--upgrade` | Upgrade an existing installation in place |
| `--uninstall` | Remove the agent and all its files |

**Useful commands after installation**

```bash
systemctl status cloudnan-agent
journalctl -u cloudnan-agent -f
systemctl restart cloudnan-agent
```

## Cloudflare Tunnel Mode

If the control plane is behind a Cloudflare Tunnel (port 443), the agent automatically detects `tls_mode=system` from the panel config response and switches to system CA verification instead of mTLS. No manual configuration is needed.

## Configuration

The config file lives at `/etc/cloudnan/agent.yaml` (mode 600, root only). The install script creates it automatically. For manual setup, copy `config.example.yaml`:

```bash
cp config.example.yaml /etc/cloudnan/agent.yaml
chmod 600 /etc/cloudnan/agent.yaml
```

**Key fields**

| Field | Default | Description |
|---|---|---|
| `agent.id` | auto-generated | Unique agent identifier |
| `agent.token` | | Bearer token for gRPC authentication |
| `control_plane.address` | `localhost:9443` | gRPC endpoint of the control plane |
| `tls.enabled` | `false` | Enable TLS (set to `true` in production) |
| `tls.use_system_certs` | `false` | Use system CAs instead of custom CA (Cloudflare Tunnel mode) |
| `tls.insecure_skip_verify` | `false` | Skip TLS verification — do not use in production |
| `metrics.interval` | `10s` | How often to collect and stream system metrics |
| `executor.default_timeout` | `300s` | Default command execution timeout |
| `executor.blocked_commands` | see example | Command prefixes that are always rejected |

## Building from Source

**Requirements:** Go 1.21+, `protoc` with `protoc-gen-go` and `protoc-gen-go-grpc` (only needed if modifying `.proto` files)

```bash
# Build for current platform
make build

# Build for Linux (amd64 + arm64)
make build-linux

# Run tests
make test

# Regenerate protobuf code (after modifying proto/agent/agent.proto)
make proto
```

Binaries are placed in `bin/`.

## Capabilities

The agent handles the following command types dispatched by the control plane:

| Type | Description |
|---|---|
| `EXEC` | Run arbitrary shell commands |
| `INSTALL` | Install packages via apt-get, yum, dnf, or apk |
| `SERVICE` | Manage systemd services (start, stop, restart, status) |
| `DOCKER` | Execute Docker CLI commands |
| `FILE` | Read, write, delete, list, copy files on the server filesystem |
| `SSH` | Sync authorized keys, update sshd_config, restart sshd |
| `CHECK_MODULE` | Detect installed software by binary path or Docker container |
| `RECONNECT` | Trigger a graceful reconnect for zero-downtime control plane deploys |

**Metrics streamed every 10 seconds (configurable):**
CPU usage (overall and per-core, steal, iowait), memory (used, cached, buffers, swap), disk (per partition with inodes), disk I/O deltas, network (bytes, errors, drops), load averages, uptime, top 30 processes, systemd service states, Docker container states, UFW firewall rules.

## Security Model

- The agent runs as root. This is required for filesystem access, SSH config management, package installation, and service control.
- Authentication is dual-layer: mTLS client certificate at the transport level plus a Bearer token in every gRPC call.
- The Bearer token is stored in `/etc/cloudnan/agent.yaml` (mode 600) and never passed as a command-line argument.
- Client certificates are stored in `/etc/cloudnan/pki/` (mode 700 directory, 600 files).
- Certificates are renewed automatically before expiry via a background daily check.
- A blocklist of destructive command prefixes (`rm -rf /`, `mkfs`, fork bombs, disk wipes) is enforced in the executor.
- File operations are sandboxed: paths are resolved and verified to remain within the configured root directory.

## License

Apache 2.0
