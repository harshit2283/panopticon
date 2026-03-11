use which::which;

/// Verifies that `bpf-linker` is installed before attempting to build.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(bpf_target_arch, values(\"x86_64\", \"aarch64\"))");

    if which("bpf-linker").is_err() {
        panic!(
            "bpf-linker not found. Install it with: cargo install bpf-linker\n\
             See https://aya-rs.dev/book/start/development/"
        );
    }
}
