use std::collections::HashSet;
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use object::{Object, ObjectSection, read::File as ObjectFile};

#[derive(Debug, Parser)]
#[command(version, about = "Panopticon build orchestration")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Build eBPF programs (alternative to aya-build for standalone invocation)
    BuildEbpf {
        /// Build in release mode
        #[arg(long)]
        release: bool,
    },
    /// Test eBPF programs on a Linux system
    TestEbpf {
        /// Run with a specific interface (default: lo)
        #[arg(long, default_value = "lo")]
        interface: String,

        /// Duration in seconds to run the smoke test (default: 10)
        #[arg(long, default_value_t = 10)]
        duration: u32,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::BuildEbpf { release } => build_ebpf(release)?,
        Commands::TestEbpf {
            interface,
            duration,
        } => test_ebpf(&interface, duration)?,
    }

    Ok(())
}

/// Builds the panopticon-ebpf crate for the BPF target.
///
/// This is an alternative to the `aya-build` integration in the agent's
/// `build.rs`. Useful for standalone eBPF compilation during development.
fn build_ebpf(release: bool) -> Result<()> {
    let workspace_root = workspace_root()?;
    let ebpf_dir = workspace_root.join("panopticon-ebpf");
    let bpf_toolchain =
        env::var("BPF_TOOLCHAIN").unwrap_or_else(|_| "nightly-2026-02-17".to_string());

    if !ebpf_dir.exists() {
        bail!(
            "panopticon-ebpf directory not found at {}",
            ebpf_dir.display()
        );
    }

    let mut cmd = Command::new("cargo");
    cmd.arg(format!("+{bpf_toolchain}"));
    cmd.args([
        "build",
        "-p",
        "panopticon-ebpf",
        "--target",
        "bpfel-unknown-none",
        "-Z",
        "build-std=core",
    ]);

    if release {
        cmd.arg("--release");
    } else {
        // Some recent nightly+LLVM combinations fail BPF linking at opt-level 0
        // (stack arguments emitted in core formatting paths). Raise dev opt-level.
        cmd.env("CARGO_PROFILE_DEV_OPT_LEVEL", "2");
    }

    cmd.current_dir(&workspace_root);

    println!("Building eBPF programs...");
    println!("  Using BPF toolchain: +{bpf_toolchain} (override with BPF_TOOLCHAIN)");
    println!("  Command: {cmd:?}");

    let status = cmd.status().context("Failed to execute cargo build")?;
    if !status.success() {
        bail!("eBPF build failed with status: {status}");
    }

    validate_ebpf_object(&workspace_root, release)?;

    println!("eBPF build completed successfully.");
    Ok(())
}

fn validate_ebpf_object(workspace_root: &Path, release: bool) -> Result<()> {
    let profile = if release { "release" } else { "debug" };
    let path = workspace_root
        .join("target")
        .join("bpfel-unknown-none")
        .join(profile)
        .join("panopticon-ebpf");

    let bytes = std::fs::read(&path)
        .with_context(|| format!("Failed to read compiled eBPF object at {}", path.display()))?;
    if bytes.is_empty() {
        bail!("eBPF object is empty: {}", path.display());
    }

    let file = ObjectFile::parse(&*bytes)
        .with_context(|| format!("Failed to parse eBPF ELF object at {}", path.display()))?;

    let sections: HashSet<String> = file
        .sections()
        .filter_map(|s| s.name().ok().map(ToOwned::to_owned))
        .collect();

    validate_required_sections(&sections).with_context(|| {
        format!(
            "eBPF object validation failed for {}. Sections found: {:?}",
            path.display(),
            sections
        )
    })?;

    println!(
        "eBPF object validation passed: {} ({} bytes)",
        path.display(),
        bytes.len()
    );
    Ok(())
}

fn validate_required_sections(sections: &HashSet<String>) -> Result<()> {
    for required in ["license", "maps"] {
        if !sections.contains(required) {
            bail!("Missing required ELF section: {required}");
        }
    }

    let has_program_section = sections.iter().any(|section| {
        section == "classifier"
            || section.starts_with("classifier/")
            || section == "kprobe"
            || section.starts_with("kprobe/")
            || section == "kretprobe"
            || section.starts_with("kretprobe/")
            || section == "tracepoint"
            || section.starts_with("tracepoint/")
            || section == "uprobe"
            || section.starts_with("uprobe/")
            || section == "uretprobe"
            || section.starts_with("uretprobe/")
    });

    if !has_program_section {
        bail!("No expected eBPF program sections found");
    }

    Ok(())
}

/// Prints instructions and optionally runs eBPF tests on a Linux system.
///
/// eBPF programs require a Linux kernel (4.15+ minimum, 5.8+ recommended).
/// This command helps developers test on Linux VMs or bare-metal machines.
fn test_ebpf(interface: &str, duration: u32) -> Result<()> {
    let workspace_root = workspace_root()?;
    let bpf_toolchain =
        env::var("BPF_TOOLCHAIN").unwrap_or_else(|_| "nightly-2026-02-17".to_string());

    // Detect current platform
    let is_linux = cfg!(target_os = "linux");

    if !is_linux {
        println!("=== eBPF Testing Instructions ===");
        println!();
        println!(
            "eBPF programs can only be loaded on Linux. You are running on a non-Linux platform."
        );
        println!();
        println!("Option 1: Run on a Linux machine or VM");
        println!("  1. Copy or clone the repository to a Linux machine (kernel 5.8+)");
        println!("  2. Install prerequisites:");
        println!(
            "     sudo apt-get install clang-18 llvm-18 libelf-dev linux-headers-$(uname -r) pkg-config libssl-dev"
        );
        println!("     rustup toolchain install {bpf_toolchain} --component rust-src");
        println!("     cargo +{bpf_toolchain} install bpf-linker --locked");
        println!("  3. Build and test:");
        println!("     cargo xtask build-ebpf");
        println!("     cargo build -p panopticon-agent --release");
        println!(
            "     sudo ./target/release/panopticon-agent --interface {interface} --log-events --smoke-test"
        );
        println!();
        println!("Option 2: Use QEMU with virtme-ng (recommended for CI)");
        println!("  pip install virtme-ng");
        println!("  virtme-ng --run -- bash -c '\\");
        println!("    cd {} && \\", workspace_root.display());
        println!("    cargo xtask build-ebpf && \\");
        println!("    cargo build -p panopticon-agent --release && \\");
        println!("    ./target/release/panopticon-agent --interface lo --log-events --smoke-test'");
        println!();
        println!("Option 3: Docker with privileged mode");
        println!("  docker run --privileged -v /sys/kernel/debug:/sys/kernel/debug:ro \\");
        println!("    -v /sys/fs/bpf:/sys/fs/bpf \\");
        println!("    -v {}:/workspace \\", workspace_root.display());
        println!("    ubuntu:24.04 bash -c '\\");
        println!(
            "    apt-get update && apt-get install -y curl clang llvm libelf-dev linux-headers-$(uname -r) && \\"
        );
        println!("    cd /workspace && cargo xtask build-ebpf && \\");
        println!("    cargo build -p panopticon-agent --release && \\");
        println!("    ./target/release/panopticon-agent --interface lo --log-events --smoke-test'");
        println!();
        println!("Note: The --smoke-test flag makes the agent attach probes, verify events");
        println!("flow through the pipeline, and exit automatically.");
        return Ok(());
    }

    // On Linux: actually build and run the smoke test
    println!("=== eBPF Smoke Test ===");
    println!("Interface: {interface}");
    println!("Duration: {duration}s");
    println!();

    // Step 1: Build eBPF programs
    println!("Step 1: Building eBPF programs...");
    build_ebpf(false)?;

    // Step 2: Build agent
    println!("\nStep 2: Building agent...");
    let mut cmd = Command::new("cargo");
    cmd.args(["build", "-p", "panopticon-agent"]);
    cmd.current_dir(&workspace_root);
    let status = cmd.status().context("Failed to build agent")?;
    if !status.success() {
        bail!("Agent build failed with status: {status}");
    }

    // Step 3: Run agent with smoke-test flag
    println!("\nStep 3: Running agent smoke test (requires sudo)...");
    let agent_path = workspace_root.join("target/debug/panopticon-agent");
    if !agent_path.exists() {
        bail!("Agent binary not found at {}", agent_path.display());
    }

    let mut cmd = Command::new("sudo");
    cmd.args([
        "-E",
        agent_path.to_str().unwrap(),
        "--interface",
        interface,
        "--log-events",
        "--smoke-test",
    ]);
    cmd.current_dir(&workspace_root);

    println!("  Command: {cmd:?}");
    let status = cmd.status().context("Failed to run agent smoke test")?;
    if !status.success() {
        bail!("Agent smoke test failed with status: {status}");
    }

    println!("\neBPF smoke test completed successfully.");
    Ok(())
}

/// Finds the workspace root by looking for the directory containing `Cargo.toml`
/// with `[workspace]` section, walking up from the manifest directory.
fn workspace_root() -> Result<PathBuf> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| env::current_dir().expect("Failed to get current directory"));

    // xtask is at <workspace>/xtask, so workspace root is one level up
    let root = manifest_dir
        .parent()
        .context("Cannot find workspace root")?
        .to_path_buf();

    // Sanity check
    if !root.join("Cargo.toml").exists() {
        bail!(
            "Expected workspace Cargo.toml at {}, but not found",
            root.join("Cargo.toml").display()
        );
    }

    Ok(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_workspace_root_detection() {
        let root = workspace_root().expect("Should find workspace root");
        assert!(
            root.join("Cargo.toml").exists(),
            "Workspace root should contain Cargo.toml"
        );
    }

    #[test]
    fn test_ebpf_dir_exists() {
        let root = workspace_root().expect("Should find workspace root");
        assert!(
            root.join("panopticon-ebpf").exists(),
            "panopticon-ebpf directory should exist"
        );
    }

    #[test]
    fn test_validate_required_sections_ok() {
        let sections: HashSet<String> = ["license", "maps", "classifier"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(validate_required_sections(&sections).is_ok());
    }

    #[test]
    fn test_validate_required_sections_missing_maps() {
        let sections: HashSet<String> = ["license", "classifier"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(validate_required_sections(&sections).is_err());
    }
}
