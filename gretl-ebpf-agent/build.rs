use std::{
    env, fs,
    path::PathBuf,
    process::Command,
};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.parent().unwrap();
    let ebpf_manifest = workspace_root.join("gretl-ebpf-ebpf/Cargo.toml");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    println!("cargo:rerun-if-changed={}", workspace_root.join("gretl-ebpf-ebpf/src").display());
    println!("cargo:rerun-if-changed={}", workspace_root.join("gretl-ebpf-common/src").display());

    let target = match env::var("CARGO_CFG_TARGET_ENDIAN").unwrap().as_str() {
        "big" => "bpfeb-unknown-none",
        _     => "bpfel-unknown-none",
    };

    // Compile the eBPF programs to BPF bytecode.
    // Uses a separate manifest so aya-ebpf (kernel-only) never enters the host workspace.
    let status = Command::new("rustup")
        .args([
            "run", "nightly",
            "cargo", "build",
            "--manifest-path", ebpf_manifest.to_str().unwrap(),
            "--target", target,
            "-Z", "build-std=core",
            "--release",
        ])
        .env("CARGO_TARGET_DIR", workspace_root.join("target-ebpf"))
        .status()
        .expect("failed to invoke cargo for eBPF build");

    assert!(status.success(), "eBPF program build failed");

    // Copy the compiled ELF to OUT_DIR where include_bytes_aligned! expects it.
    let binary_name = "gretl-ebpf-ebpf";
    let compiled = workspace_root
        .join("target-ebpf")
        .join(target)
        .join("release")
        .join(binary_name);

    fs::copy(&compiled, out_dir.join("gretl-ebpf-ebpf"))
        .unwrap_or_else(|e| panic!("failed to copy eBPF ELF from {}: {e}", compiled.display()));
}
