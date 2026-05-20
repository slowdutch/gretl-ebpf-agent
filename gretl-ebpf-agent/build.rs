fn main() {
    aya_build::build_ebpf_programs(["gretl-ebpf-ebpf"]).unwrap();
}
