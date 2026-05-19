# gretl-ebpf

Standalone eBPF observability agent for Gretl Enterprise. Runs on Linux servers (non-K8s) alongside the main `gretl-agent`. Requires kernel ≥ 5.8 with BTF.

## What it does

- **Process attribution** — attaches `execve` tracepoint to observe every process spawn; classifies AI agent frameworks (LangGraph, vLLM, Ollama, Ray, CrewAI) automatically
- **TCP visibility** — kprobes on `tcp_v4_connect` + `inet_csk_accept` to map outbound/inbound connections without a service mesh
- **Security auditing** — flags shells inside processes, network scanning tools, sudo executions, package managers at runtime
- **Idle detection** — monitors `/proc/net/dev` + CPU perf samples; sends sleep hint to the Gretl backend after configurable idle timeout

## Installation

Installed automatically by `gretl.dev/install-agent.sh` when the host kernel supports it. Manual install:

```bash
# Requires root
curl -fsSL https://gretl.dev/releases/gretl-ebpf-linux-$(uname -m | sed s/x86_64/amd64/ | sed s/aarch64/arm64/) \
  -o /opt/gretl/gretl-ebpf
chmod +x /opt/gretl/gretl-ebpf
setcap cap_bpf,cap_perfmon,cap_net_admin,cap_sys_ptrace+ep /opt/gretl/gretl-ebpf

GR_TOKEN=<token> GR_SERVER_ID=<id> /opt/gretl/gretl-ebpf
```

## Requirements

| Requirement | Minimum |
|---|---|
| Linux kernel | 5.8 |
| BTF | `/sys/kernel/btf/vmlinux` must exist |
| Capabilities | `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN`, `CAP_SYS_PTRACE` |
| Architecture | `x86_64` or `aarch64` |

## Building

```bash
# Install Rust nightly + bpf-linker
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker --no-default-features

# Build (requires nightly for the eBPF programs crate)
cargo +nightly build --release --package gretl-ebpf-agent
```

## Architecture

```
Kernel space                         Userspace
───────────────────────────────────  ────────────────────────────────────
tracepoint/sys_enter_execve          EventProcessor
  └─ ExecveEvent ──────────────────► classify_agent() → tag server
                                     is_security_relevant() → audit log
kprobe/tcp_v4_connect
kretprobe/inet_csk_accept            Reporter
  └─ TcpEvent ─────────────────────► POST /otlp/v1/events
                                     POST /otlp/v1/metrics
          ↑ RingBuf (512KB)
          shared memory, zero-copy   IdleTracker
                                     /proc/net/dev + CPU samples
                                     → POST /servers/:id/idle
```
