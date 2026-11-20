use std::env;

use anyhow::Result;

const DEFAULT_BPF_TOOLCHAIN: &str = "nightly-2026-02-17";

fn main() -> Result<()> {
    println!("cargo:rerun-if-env-changed=BPF_TOOLCHAIN");
    println!("cargo:rerun-if-env-changed=AYA_BUILD_SKIP");

    let out_dir = env::var("OUT_DIR").unwrap();
    let ebpf_out = std::path::Path::new(&out_dir).join("panopticon-ebpf");

    if env::var("AYA_BUILD_SKIP").as_deref() == Ok("1") {
        std::fs::write(&ebpf_out, b"DUMMY_EBPF_SKIPPED").ok();
        println!("cargo:warning=AYA_BUILD_SKIP=1; skipping eBPF build");
        return Ok(());
    }

    // Only build eBPF on Linux — macOS doesn't support BPF targets.
    // This allows `cargo build` on macOS for development/testing of
    // non-eBPF code while requiring Linux for the full build.
    if cfg!(target_os = "linux") {
        // Default to the same pinned nightly used by xtask, CI and the Dockerfile
        // so a plain `cargo build` is reproducible without extra env vars.
        let bpf_toolchain =
            env::var("BPF_TOOLCHAIN").unwrap_or_else(|_| DEFAULT_BPF_TOOLCHAIN.to_string());
        let toolchain = aya_build::Toolchain::Custom(&bpf_toolchain);
        aya_build::build_ebpf(
            [aya_build::Package {
                name: "panopticon-ebpf",
                root_dir: "../panopticon-ebpf",
                ..Default::default()
            }],
            toolchain,
        )?;
    } else {
        // On non-Linux, write a dummy stub so include_bytes_aligned!() compiles.
        // The loader code is cfg(target_os = "linux") gated and never executes on macOS.
        std::fs::write(&ebpf_out, b"DUMMY_EBPF_NOT_FOR_EXECUTION").ok();
        println!(
            "cargo:warning=eBPF build skipped (not on Linux). Agent will compile without eBPF programs."
        );
    }
    Ok(())
}
