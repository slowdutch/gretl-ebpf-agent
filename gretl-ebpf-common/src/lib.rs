#![no_std]

/// Process spawn event — emitted on every execve syscall.
/// Used for agent auto-detection and security auditing.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecveEvent {
    pub pid:      u32,
    pub ppid:     u32,
    pub uid:      u32,
    pub _pad:     u32,
    /// comm — kernel's 16-byte process name (basename of argv[0])
    pub comm:     [u8; 16],
    /// argv[0] — full path, truncated to 64 bytes
    pub filename: [u8; 64],
    /// argv[1] — first argument, useful for interpreters (python script.py, node agent.js)
    pub argv1:    [u8; 64],
}

/// TCP connection event — emitted on outbound connect or inbound accept.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TcpEvent {
    pub pid:       u32,
    pub _pad:      u32,
    pub comm:      [u8; 16],
    /// IPv4 addresses in host byte order
    pub src_addr:  u32,
    pub dst_addr:  u32,
    pub src_port:  u16,
    pub dst_port:  u16,
    /// 0 = outbound (connect), 1 = inbound (accept)
    pub direction: u8,
    pub _pad2:     [u8; 3],
}

/// CPU perf-event sample — emitted at ~100Hz per CPU by the profiler.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CpuSampleEvent {
    pub pid:           u32,
    pub tgid:          u32,
    pub comm:          [u8; 16],
    pub user_stack_id: i32,
    pub kern_stack_id: i32,
    pub cpu:           u32,
    pub _pad:          u32,
    pub period_ns:     u64,
}

/// Unified event tag — written as the first byte of every ring-buffer entry
/// so userspace can dispatch without unsafe casts.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Execve    = 1,
    Tcp       = 2,
    CpuSample = 3,
}

// Safety: all event types are plain C structs with no pointers — safe to send across
// the ring buffer boundary (kernel writes, userspace reads as bytes then casts).
unsafe impl Send for ExecveEvent {}
unsafe impl Send for TcpEvent {}
unsafe impl Send for CpuSampleEvent {}
