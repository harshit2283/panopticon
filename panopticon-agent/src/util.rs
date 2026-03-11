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
