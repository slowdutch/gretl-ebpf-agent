fn main() {
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "gretl-ebpf-ebpf",
            root_dir: "../gretl-ebpf-ebpf",
            ..Default::default()
        }],
        aya_build::Toolchain::Nightly,
    )
    .unwrap();
}
