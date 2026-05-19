#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user_str_bytes,
    },
    macros::{kprobe, kretprobe, map, tracepoint},
    maps::RingBuf,
    programs::{ProbeContext, RetProbeContext, TracePointContext},
};
use aya_log_ebpf::info;
use gretl_ebpf_common::{CpuSampleEvent, EventKind, ExecveEvent, TcpEvent};

// ── Shared ring buffer ────────────────────────────────────────────────────────
// Single 512KB ring buffer for all event types.
// Userspace reads and dispatches by EventKind tag.

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(512 * 1024, 0);

// ── execve tracepoint ─────────────────────────────────────────────────────────
// Fires on every process spawn. Used for:
//   - Agent auto-detection (langgraph, vllm, ollama, ray, crewai)
//   - Security auditing (unusual spawns inside containers)
//   - Per-process attribution (maps pid → process name)

#[tracepoint]
pub fn gretl_execve(ctx: TracePointContext) -> u32 {
    match try_execve(ctx) {
        Ok(_) => 0,
        Err(_) => 0, // never fail — drop event silently
    }
}

fn try_execve(ctx: TracePointContext) -> Result<(), i64> {
    // tracepoint/syscalls/sys_enter_execve layout:
    //   +16  filename ptr  (*const u8)
    //   +24  argv ptr      (**const u8)
    let filename_ptr = unsafe { ctx.read_at::<u64>(16)? } as *const u8;
    let argv_ptr     = unsafe { ctx.read_at::<u64>(24)? } as *const *const u8;

    let pidtgid = bpf_get_current_pid_tgid();
    let pid     = (pidtgid >> 32) as u32;
    let ppid    = (pidtgid & 0xffffffff) as u32;
    let uid     = (bpf_get_current_uid_gid() >> 32) as u32;

    let mut event = ExecveEvent {
        pid,
        ppid,
        uid,
        _pad:     0,
        comm:     [0u8; 16],
        filename: [0u8; 64],
        argv1:    [0u8; 64],
    };

    // comm — kernel's own process name for this task
    let _ = bpf_get_current_comm(&mut event.comm);

    // filename — argv[0], the path being executed
    if !filename_ptr.is_null() {
        let _ = unsafe {
            bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename)
        };
    }

    // argv[1] — first argument (e.g. "agent.py" when exec is "python")
    if !argv_ptr.is_null() {
        let argv1_ptr = unsafe {
            let ptr_to_argv1 = argv_ptr.add(1) as *const u64;
            bpf_probe_read_user_str_bytes(ptr_to_argv1 as *const u8, &mut [])
                .ok()
                .and_then(|_| Some(*(argv_ptr.add(1) as *const u64) as *const u8))
                .unwrap_or(core::ptr::null())
        };
        if !argv1_ptr.is_null() {
            let _ = unsafe {
                bpf_probe_read_user_str_bytes(argv1_ptr, &mut event.argv1)
            };
        }
    }

    emit_execve(&event)
}

fn emit_execve(event: &ExecveEvent) -> Result<(), i64> {
    // Reserve: 1 byte kind tag + sizeof(ExecveEvent)
    const SZ: u32 = 1 + core::mem::size_of::<ExecveEvent>() as u32;
    if let Some(mut entry) = EVENTS.reserve::<[u8; SZ as usize]>(0) {
        let buf = unsafe { entry.as_mut_ptr() };
        unsafe {
            *buf = EventKind::Execve as u8;
            core::ptr::copy_nonoverlapping(
                event as *const ExecveEvent as *const u8,
                buf.add(1),
                core::mem::size_of::<ExecveEvent>(),
            );
        }
        entry.submit(0);
    }
    Ok(())
}

// ── tcp_v4_connect kretprobe (outbound) ───────────────────────────────────────
// Fires when an outbound TCP connection completes (connect(2) returns 0).
// Captures source/destination IP+port for the traffic map.

#[map]
static CONNECT_PID: aya_ebpf::maps::HashMap<u64, TcpEvent> =
    aya_ebpf::maps::HashMap::with_max_entries(4096, 0);

#[kprobe]
pub fn gretl_tcp_connect(ctx: ProbeContext) -> u32 {
    match try_tcp_connect_entry(ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

fn try_tcp_connect_entry(ctx: ProbeContext) -> Result<(), i64> {
    // sk = first arg (struct sock*)
    let sk: *const u8 = ctx.arg(0).ok_or(1i64)?;
    if sk.is_null() { return Ok(()); }

    let pidtgid = bpf_get_current_pid_tgid();
    let pid     = (pidtgid >> 32) as u32;

    let mut event = TcpEvent {
        pid,
        _pad:      0,
        comm:      [0u8; 16],
        src_addr:  0,
        dst_addr:  0,
        src_port:  0,
        dst_port:  0,
        direction: 0, // outbound
        _pad2:     [0u8; 3],
    };
    let _ = bpf_get_current_comm(&mut event.comm);

    // Read daddr and dport from sock_common (offsets for IPv4):
    //   __be32 skc_daddr        @ +0
    //   __be16 skc_dport        @ +12
    //   __u16  skc_num (sport)  @ +14
    unsafe {
        event.dst_addr = u32::from_be(
            *(sk.add(0) as *const u32)
        );
        event.dst_port = u16::from_be(
            *(sk.add(12) as *const u16)
        );
        event.src_port = *(sk.add(14) as *const u16);
    }

    let _ = CONNECT_PID.insert(&pidtgid, &event, 0);
    Ok(())
}

#[kretprobe]
pub fn gretl_tcp_connect_ret(ctx: RetProbeContext) -> u32 {
    match try_tcp_connect_ret(ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

fn try_tcp_connect_ret(ctx: RetProbeContext) -> Result<(), i64> {
    let ret: i64 = ctx.ret().ok_or(1i64)?;
    if ret != 0 { return Ok(()); } // connect failed — skip

    let pidtgid = bpf_get_current_pid_tgid();
    if let Some(event) = CONNECT_PID.get(&pidtgid) {
        emit_tcp(event)?;
    }
    let _ = CONNECT_PID.remove(&pidtgid);
    Ok(())
}

// ── inet_csk_accept kretprobe (inbound) ──────────────────────────────────────
// Fires when accept(2) returns a new socket — i.e. an inbound connection arrived.

#[kretprobe]
pub fn gretl_tcp_accept(ctx: RetProbeContext) -> u32 {
    match try_tcp_accept(ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

fn try_tcp_accept(ctx: RetProbeContext) -> Result<(), i64> {
    let sk: *const u8 = ctx.ret().ok_or(1i64)?;
    if sk.is_null() { return Ok(()); }

    let pidtgid = bpf_get_current_pid_tgid();
    let pid     = (pidtgid >> 32) as u32;

    let mut event = TcpEvent {
        pid,
        _pad:      0,
        comm:      [0u8; 16],
        src_addr:  0,
        dst_addr:  0,
        src_port:  0,
        dst_port:  0,
        direction: 1, // inbound
        _pad2:     [0u8; 3],
    };
    let _ = bpf_get_current_comm(&mut event.comm);

    unsafe {
        event.src_addr = u32::from_be(*(sk.add(4) as *const u32)); // skc_rcv_saddr
        event.src_port = u16::from_be(*(sk.add(12) as *const u16));
        event.dst_port = *(sk.add(14) as *const u16);
    }

    emit_tcp(&event)
}

fn emit_tcp(event: &TcpEvent) -> Result<(), i64> {
    const SZ: u32 = 1 + core::mem::size_of::<TcpEvent>() as u32;
    if let Some(mut entry) = EVENTS.reserve::<[u8; SZ as usize]>(0) {
        let buf = unsafe { entry.as_mut_ptr() };
        unsafe {
            *buf = EventKind::Tcp as u8;
            core::ptr::copy_nonoverlapping(
                event as *const TcpEvent as *const u8,
                buf.add(1),
                core::mem::size_of::<TcpEvent>(),
            );
        }
        entry.submit(0);
    }
    Ok(())
}

// ── Panic handler (required for no_std) ──────────────────────────────────────

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
