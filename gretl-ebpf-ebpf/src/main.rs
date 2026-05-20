#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user_str_bytes,
    },
    macros::{kprobe, kretprobe, map, tracepoint},
    maps::RingBuf,
    programs::{ProbeContext, RetProbeContext, TracePointContext},
};
use aya_log_ebpf::info;
use gretl_ebpf_common::{EventKind, ExecveEvent, TcpEvent};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(512 * 1024, 0);

// ── execve tracepoint ─────────────────────────────────────────────────────────

#[tracepoint]
pub fn gretl_execve(ctx: TracePointContext) -> u32 {
    match try_execve(ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

fn try_execve(ctx: TracePointContext) -> Result<(), i64> {
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

    // bpf_get_current_comm() returns [u8; 16] in aya-ebpf 0.1
    event.comm = bpf_get_current_comm();

    if !filename_ptr.is_null() {
        let _ = unsafe {
            bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename)
        };
    }

    if !argv_ptr.is_null() {
        let argv1_ptr = unsafe {
            let ptr_to_argv1 = argv_ptr.add(1) as *const u64;
            *(ptr_to_argv1) as *const u8
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
    const SZ: usize = 1 + core::mem::size_of::<ExecveEvent>();
    if let Some(mut entry) = EVENTS.reserve::<[u8; SZ]>(0) {
        unsafe {
            let buf = entry.as_mut_ptr() as *mut u8;
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

// ── tcp_v4_connect kprobe (outbound) ─────────────────────────────────────────

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
        direction: 0,
        _pad2:     [0u8; 3],
    };
    event.comm = bpf_get_current_comm();

    unsafe {
        event.dst_addr = u32::from_be(*(sk.add(0) as *const u32));
        event.dst_port = u16::from_be(*(sk.add(12) as *const u16));
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
    if ret != 0 { return Ok(()); }

    let pidtgid = bpf_get_current_pid_tgid();
    // HashMap::get is unsafe in aya-ebpf 0.1
    if let Some(event) = unsafe { CONNECT_PID.get(&pidtgid) } {
        emit_tcp(event)?;
    }
    let _ = CONNECT_PID.remove(&pidtgid);
    Ok(())
}

// ── inet_csk_accept kretprobe (inbound) ──────────────────────────────────────

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
        direction: 1,
        _pad2:     [0u8; 3],
    };
    event.comm = bpf_get_current_comm();

    unsafe {
        event.src_addr = u32::from_be(*(sk.add(4) as *const u32));
        event.src_port = u16::from_be(*(sk.add(12) as *const u16));
        event.dst_port = *(sk.add(14) as *const u16);
    }

    emit_tcp(&event)
}

fn emit_tcp(event: &TcpEvent) -> Result<(), i64> {
    const SZ: usize = 1 + core::mem::size_of::<TcpEvent>();
    if let Some(mut entry) = EVENTS.reserve::<[u8; SZ]>(0) {
        unsafe {
            let buf = entry.as_mut_ptr() as *mut u8;
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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
