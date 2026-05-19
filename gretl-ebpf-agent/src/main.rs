mod classifier;
mod events;
mod idle;
mod reporter;

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::RingBuf,
    programs::{KProbe, TracePoint},
    Bpf,
};
use aya_log::BpfLogger;
use clap::Parser;
use events::EventProcessor;
use idle::IdleTracker;
use reporter::Reporter;
use std::time::Duration;
use tokio::{
    io::unix::AsyncFd,
    signal,
    time::{interval, MissedTickBehavior},
};

/// Gretl eBPF observability agent.
/// Attaches kernel probes to observe process activity, TCP connections,
/// and CPU usage — then reports to the Gretl backend without code changes.
#[derive(Parser, Debug)]
#[command(name = "gretl-ebpf", version, about)]
struct Args {
    /// Gretl API endpoint
    #[arg(long, env = "GR_API", default_value = "https://api.gretl.dev")]
    api: String,

    /// Gretl token (GR_TOKEN)
    #[arg(long, env = "GR_TOKEN")]
    token: String,

    /// Server ID registered with Gretl
    #[arg(long, env = "GR_SERVER_ID", default_value = "")]
    server_id: String,

    /// Flush interval in seconds
    #[arg(long, default_value = "15")]
    flush_interval: u64,

    /// Idle timeout in seconds before sending sleep hint (0 = disabled)
    #[arg(long, env = "GR_IDLE_TIMEOUT", default_value = "1800")]
    idle_timeout: u64,
}

// Embed the eBPF bytecode compiled by build.rs at compile time.
// include_bytes_aligned! ensures the BPF ELF is 8-byte aligned as required by libbpf.
static EBPF_BYTES: &[u8] = include_bytes_aligned!(
    concat!(env!("OUT_DIR"), "/gretl-ebpf-ebpf")
);

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).init();

    // ── Load eBPF programs ────────────────────────────────────────────────────
    let mut bpf = Bpf::load(EBPF_BYTES)
        .context("failed to load eBPF bytecode — is kernel >= 5.8 with BTF?")?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        log::warn!("eBPF logging unavailable: {e}");
    }

    // execve tracepoint
    let prog: &mut TracePoint = bpf
        .program_mut("gretl_execve")
        .context("execve program not found")?
        .try_into()?;
    prog.load()?;
    prog.attach("syscalls", "sys_enter_execve")
        .context("failed to attach execve tracepoint")?;
    log::info!("attached tracepoint syscalls/sys_enter_execve");

    // tcp_v4_connect kprobe + kretprobe
    let prog: &mut KProbe = bpf
        .program_mut("gretl_tcp_connect")
        .context("tcp_connect kprobe not found")?
        .try_into()?;
    prog.load()?;
    prog.attach("tcp_v4_connect", 0)
        .context("failed to attach tcp_v4_connect kprobe")?;

    let prog: &mut KProbe = bpf
        .program_mut("gretl_tcp_connect_ret")
        .context("tcp_connect_ret kretprobe not found")?
        .try_into()?;
    prog.load()?;
    prog.attach("tcp_v4_connect", 0)
        .context("failed to attach tcp_v4_connect kretprobe")?;

    // inet_csk_accept kretprobe (inbound)
    let prog: &mut KProbe = bpf
        .program_mut("gretl_tcp_accept")
        .context("tcp_accept kretprobe not found")?
        .try_into()?;
    prog.load()?;
    prog.attach("inet_csk_accept", 0)
        .context("failed to attach inet_csk_accept kretprobe")?;

    log::info!("attached TCP kprobes");

    // ── Set up ring buffer consumer ───────────────────────────────────────────
    let ring_buf = RingBuf::try_from(
        bpf.map_mut("EVENTS").context("EVENTS map not found")?
    )?;
    let mut async_fd = AsyncFd::new(ring_buf)?;

    // ── Set up reporter + processor ───────────────────────────────────────────
    let reporter  = Reporter::new(args.api.clone(), args.token.clone());
    let node      = hostname();
    let mut proc  = EventProcessor::new(reporter, args.server_id.clone(), node);
    let mut idle  = IdleTracker::new();
    let idle_timeout = Duration::from_secs(args.idle_timeout);

    let mut flush_tick = interval(Duration::from_secs(args.flush_interval));
    flush_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

    log::info!("gretl-ebpf running — server_id={}", args.server_id);

    loop {
        tokio::select! {
            // New ring-buffer events available
            guard = async_fd.readable_mut() => {
                let mut guard = guard?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    proc.process_raw(&item);
                }
                guard.clear_ready();
            }

            // Periodic flush
            _ = flush_tick.tick() => {
                if let Err(e) = proc.reporter.flush_events().await {
                    log::warn!("flush failed: {e}");
                }

                // Idle detection
                if args.idle_timeout > 0 {
                    if let Some(idle_dur) = idle.tick(0) {
                        if idle_dur >= idle_timeout {
                            log::info!("server idle for {idle_dur:?} — reporting to backend");
                            report_idle(&args).await;
                        }
                    }
                }
            }

            // Graceful shutdown on SIGTERM / Ctrl-C
            _ = signal::ctrl_c() => {
                log::info!("shutting down");
                let _ = proc.reporter.flush_events().await;
                break;
            }
        }
    }

    Ok(())
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .unwrap_or_default()
        .trim()
        .to_string()
}

async fn report_idle(args: &Args) {
    // PATCH /servers/:id to signal idle — reuses the existing agent heartbeat mechanism
    let client = reqwest::Client::new();
    let url    = format!("{}/servers/{}/idle", args.api, args.server_id);
    if let Err(e) = client
        .post(&url)
        .bearer_auth(&args.token)
        .json(&serde_json::json!({ "source": "ebpf" }))
        .send()
        .await
    {
        log::warn!("idle report failed: {e}");
    }
}
