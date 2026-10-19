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

/// Interfaces carrying an IPv4 default route, parsed from `/proc/net/route`
/// content. Used when no interface is configured so the agent attaches to the
/// node's real uplink (`ens5`, `enp0s3`, `bond0`, ...) instead of assuming
/// `eth0`. Order is preserved and duplicates removed.
pub fn default_route_interfaces(proc_net_route: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in proc_net_route.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // Iface Destination Gateway Flags RefCnt Use Metric Mask ...
        if cols.len() < 8 {
            continue;
        }
        if cols[1] == "00000000" && cols[7] == "00000000" && !out.iter().any(|i| i == cols[0]) {
            out.push(cols[0].to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_route_interfaces() {
        let route =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
\
                     ens5\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
\
                     ens5\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
\
                     bond0\t00000000\t0101A8C0\t0003\t0\t0\t200\t00000000\t0\t0\t0
\
                     ens5\t00000000\t0100A8C0\t0003\t0\t0\t300\t00000000\t0\t0\t0
";
        assert_eq!(default_route_interfaces(route), vec!["ens5", "bond0"]);
        assert!(default_route_interfaces("").is_empty());
        assert!(
            default_route_interfaces(
                "Iface\tDestination
"
            )
            .is_empty()
        );
    }

    #[test]
    fn test_format_ipv4() {
        assert_eq!(format_ipv4(0x7F000001), "127.0.0.1");
        assert_eq!(format_ipv4(0xC0A80001), "192.168.0.1");
        assert_eq!(format_ipv4(0), "0.0.0.0");
        assert_eq!(format_ipv4(0xFFFFFFFF), "255.255.255.255");
    }
}
