#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

mod maps;
mod process_monitor;
mod sock_capture;
mod tls_probes;

// SAFETY: Required by #![no_std] + #![no_main]. The BPF verifier prevents
// actual panics at runtime, but rustc still requires a panic handler.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

// GPL license section — required for BPF programs that use GPL-only helpers
// (e.g., bpf_probe_read_kernel, bpf_get_current_task).
#[cfg(not(test))]
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
pub static LICENSE: [u8; 4] = *b"GPL\0";
