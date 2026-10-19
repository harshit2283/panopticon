//! Protocol detection runs on the first payload of every new connection.
#![no_main]

use libfuzzer_sys::fuzz_target;

#[allow(dead_code, unused_imports)]
#[path = "../../panopticon-agent/src/protocol/mod.rs"]
mod protocol;

use protocol::Direction;
use protocol::detect::detect_protocol;

fuzz_target!(|data: &[u8]| {
    if data.len() < 5 {
        return;
    }
    let sport = u16::from_le_bytes([data[0], data[1]]);
    let dport = u16::from_le_bytes([data[2], data[3]]);
    let dir = if data[4] & 1 == 0 {
        Direction::Egress
    } else {
        Direction::Ingress
    };
    let _ = detect_protocol(&data[5..], sport, dport, dir);
});
