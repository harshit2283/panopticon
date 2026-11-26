/// Format an IPv4 address from a `u32` (network byte order already decoded).
pub fn format_ipv4(addr: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (addr >> 24) & 0xFF,
        (addr >> 16) & 0xFF,
        (addr >> 8) & 0xFF,
        addr & 0xFF,
    )
}

/// Current CLOCK_MONOTONIC time in nanoseconds — the same clock as the
/// kernel's `bpf_ktime_get_ns()`, so it can be compared with event timestamps.
/// (Wall-clock `SystemTime` is ~1.7e18 ns ahead and must never be mixed in.)
pub fn monotonic_now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime only writes to the provided timespec.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_ipv4() {
        assert_eq!(format_ipv4(0x7F000001), "127.0.0.1");
        assert_eq!(format_ipv4(0xC0A80001), "192.168.0.1");
        assert_eq!(format_ipv4(0), "0.0.0.0");
        assert_eq!(format_ipv4(0xFFFFFFFF), "255.255.255.255");
    }
}
