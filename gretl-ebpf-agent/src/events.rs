/// Event processor — reads raw bytes from the aya RingBuf, deserialises events,
/// classifies agent types, detects security-relevant activity, and routes to reporter.

use crate::{
    classifier::{classify_agent, is_security_relevant, SecurityHint},
    reporter::{Reporter, SecurityEventPayload},
};
use gretl_ebpf_common::{EventKind, ExecveEvent, TcpEvent};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn bytes_to_str(b: &[u8]) -> String {
    let end = b.iter().position(|&x| x == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).to_string()
}

fn u32_to_ipv4(addr: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (addr >> 24) & 0xff,
        (addr >> 16) & 0xff,
        (addr >> 8)  & 0xff,
        addr         & 0xff,
    )
}

pub struct EventProcessor {
    pub reporter:  Reporter,
    pub server_id: String,
    pub node:      String,
    /// Callback for agent detection: (pid, agent_type)
    pub on_agent_detected: Option<Box<dyn Fn(u32, &str) + Send>>,
}

impl EventProcessor {
    pub fn new(reporter: Reporter, server_id: String, node: String) -> Self {
        Self { reporter, server_id, node, on_agent_detected: None }
    }

    /// Process a raw ring-buffer entry. The first byte is the EventKind tag.
    pub fn process_raw(&mut self, data: &[u8]) {
        if data.is_empty() { return; }
        let kind = data[0];
        let payload = &data[1..];

        match kind {
            k if k == EventKind::Execve as u8 => {
                if payload.len() >= core::mem::size_of::<ExecveEvent>() {
                    let ev = unsafe { &*(payload.as_ptr() as *const ExecveEvent) };
                    self.handle_execve(ev);
                }
            }
            k if k == EventKind::Tcp as u8 => {
                if payload.len() >= core::mem::size_of::<TcpEvent>() {
                    let ev = unsafe { &*(payload.as_ptr() as *const TcpEvent) };
                    self.handle_tcp(ev);
                }
            }
            _ => {}
        }
    }

    fn handle_execve(&mut self, ev: &ExecveEvent) {
        let comm     = bytes_to_str(&ev.comm);
        let filename = bytes_to_str(&ev.filename);
        let argv1    = bytes_to_str(&ev.argv1);

        // Agent type detection
        if let Some(agent_type) = classify_agent(&comm, &filename, &argv1) {
            log::info!("agent detected pid={} comm={} type={}", ev.pid, comm, agent_type);
            if let Some(cb) = &self.on_agent_detected {
                cb(ev.pid, agent_type);
            }
        }

        // Security audit
        if let Some(hint) = is_security_relevant(&comm, &filename, ev.uid) {
            self.emit_security_event_execve(ev, &comm, &filename, &argv1, &hint);
        }
    }

    fn handle_tcp(&mut self, ev: &TcpEvent) {
        let comm      = bytes_to_str(&ev.comm);
        let direction = if ev.direction == 0 { "outbound" } else { "inbound" };

        log::debug!(
            "tcp {} pid={} comm={} {}:{} → {}:{}",
            direction, ev.pid, comm,
            u32_to_ipv4(ev.src_addr), ev.src_port,
            u32_to_ipv4(ev.dst_addr), ev.dst_port,
        );

        // Flag connections to unusual high ports from processes that shouldn't be networking
        if ev.direction == 0 && ev.dst_port > 1024 && ev.dst_port != 443 && ev.dst_port != 80 {
            if matches!(comm.as_str(), "bash" | "sh" | "python" | "python3") {
                self.reporter.push_event(SecurityEventPayload {
                    cluster_id:    String::new(),
                    ts:            now_ms(),
                    namespace:     String::new(),
                    workload:      String::new(),
                    pod:           String::new(),
                    node:          self.node.clone(),
                    event_type:    "outbound_conn".to_string(),
                    severity:      "warn".to_string(),
                    pid:           ev.pid,
                    process_name:  comm.clone(),
                    cmdline:       String::new(),
                    parent_process: String::new(),
                    remote_ip:     u32_to_ipv4(ev.dst_addr),
                    remote_port:   ev.dst_port,
                    local_port:    ev.src_port,
                    protocol:      "TCP".to_string(),
                    rule_id:       "SHELL_OUTBOUND_CONN".to_string(),
                    description:   format!("Shell/interpreter made outbound connection to {}:{}", u32_to_ipv4(ev.dst_addr), ev.dst_port),
                });
            }
        }
    }

    fn emit_security_event_execve(
        &mut self,
        ev:       &ExecveEvent,
        comm:     &str,
        filename: &str,
        argv1:    &str,
        hint:     &SecurityHint,
    ) {
        self.reporter.push_event(SecurityEventPayload {
            cluster_id:     String::new(),
            ts:             now_ms(),
            namespace:      String::new(),
            workload:       String::new(),
            pod:            String::new(),
            node:           self.node.clone(),
            event_type:     hint.event_type.to_string(),
            severity:       hint.severity.to_string(),
            pid:            ev.pid,
            process_name:   comm.to_string(),
            cmdline:        format!("{} {}", filename, argv1),
            parent_process: String::new(),
            remote_ip:      String::new(),
            remote_port:    0,
            local_port:     0,
            protocol:       String::new(),
            rule_id:        hint.rule_id.to_string(),
            description:    hint.description.to_string(),
        });
    }
}
