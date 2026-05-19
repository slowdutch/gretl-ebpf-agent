/// Idle detection for non-K8s servers.
/// Reads /proc/net/dev to track network TX/RX bytes, supplementing CPU-based detection.
/// If both CPU (from perf samples) AND net bytes are below threshold for idle_timeout,
/// the server is considered idle and the agent sends a sleep hint to the backend.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use anyhow::Result;

const IDLE_NET_BYTES_THRESHOLD: u64 = 10 * 1024; // 10KB/interval = effectively idle
const IDLE_CPU_SAMPLE_THRESHOLD: u32 = 5;        // < 5 perf samples/interval ≈ < 5mc
const IDLE_CHECK_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Default)]
pub struct IdleTracker {
    prev_rx:      u64,
    prev_tx:      u64,
    idle_since:   Option<Instant>,
    cpu_samples:  u32,
    last_check:   Option<Instant>,
}

impl IdleTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Called every IDLE_CHECK_INTERVAL. Returns Some(idle_duration) if idle.
    pub fn tick(&mut self, cpu_samples_this_interval: u32) -> Option<Duration> {
        let now = Instant::now();
        if let Some(last) = self.last_check {
            if now.duration_since(last) < IDLE_CHECK_INTERVAL {
                self.cpu_samples += cpu_samples_this_interval;
                return None;
            }
        }
        self.last_check = Some(now);

        let (rx, tx) = read_proc_net_dev().unwrap_or((0, 0));
        let delta_rx = rx.saturating_sub(self.prev_rx);
        let delta_tx = tx.saturating_sub(self.prev_tx);
        self.prev_rx = rx;
        self.prev_tx = tx;

        let net_idle = delta_rx + delta_tx < IDLE_NET_BYTES_THRESHOLD;
        let cpu_idle = self.cpu_samples < IDLE_CPU_SAMPLE_THRESHOLD;
        self.cpu_samples = 0;

        if net_idle && cpu_idle {
            if self.idle_since.is_none() {
                self.idle_since = Some(now);
            }
            Some(now.duration_since(self.idle_since.unwrap()))
        } else {
            self.idle_since = None;
            None
        }
    }
}

fn read_proc_net_dev() -> Result<(u64, u64)> {
    let content = std::fs::read_to_string("/proc/net/dev")?;
    let mut total_rx = 0u64;
    let mut total_tx = 0u64;

    for line in content.lines().skip(2) {
        let line = line.trim();
        if line.starts_with("lo:") { continue; } // skip loopback
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 { continue; }
        // Interface: rx_bytes(1) ... tx_bytes(9)
        total_rx += parts[1].parse::<u64>().unwrap_or(0);
        total_tx += parts[9].parse::<u64>().unwrap_or(0);
    }

    Ok((total_rx, total_tx))
}
