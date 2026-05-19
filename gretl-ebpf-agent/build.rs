// build.rs — compiles the eBPF programs crate and embeds the bytecode.
// aya-build handles the cross-compilation to bpfel-unknown-none automatically.
use aya_build::cargo_metadata;

fn main() {
    let metadata = cargo_metadata().unwrap();
    aya_build::build_ebpf_programs(&metadata, &["gretl-ebpf-ebpf"]).unwrap();
}
