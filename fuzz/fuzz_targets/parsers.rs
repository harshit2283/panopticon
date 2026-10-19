//! Feeds attacker-controlled byte streams into every L7 parser through the
//! same `ProtocolFsmAdapter` the agent uses. Any panic here is a remote
//! crash of an agent worker (packet payloads come from arbitrary peers).
//!
//! Input layout: byte 0 selects the protocol; the rest is a sequence of
//! segments `[hdr][len][bytes...]` where bit 0 of `hdr` is the direction,
//! so the fuzzer explores multi-packet reassembly and request/response
//! interleaving, not just single buffers.
#![no_main]

use libfuzzer_sys::fuzz_target;

#[allow(dead_code, unused_imports)]
#[path = "../../panopticon-agent/src/protocol/mod.rs"]
mod protocol;

use protocol::fsm::{ProtocolFsm, ProtocolFsmAdapter};
use protocol::{Direction, Protocol};

const PROTOCOLS: [Protocol; 9] = [
    Protocol::Http1,
    Protocol::Http2,
    Protocol::Grpc,
    Protocol::Mysql,
    Protocol::Postgres,
    Protocol::Redis,
    Protocol::Dns,
    Protocol::Kafka,
    Protocol::Amqp,
];

fuzz_target!(|data: &[u8]| {
    let Some((&sel, mut rest)) = data.split_first() else {
        return;
    };
    let mut fsm = ProtocolFsmAdapter::new(PROTOCOLS[sel as usize % PROTOCOLS.len()]);
    let mut ts = 1_000u64;
    while rest.len() >= 2 {
        let dir = if rest[0] & 1 == 0 {
            Direction::Egress
        } else {
            Direction::Ingress
        };
        let len = (rest[1] as usize).min(rest.len() - 2);
        let (seg, tail) = rest[2..].split_at(len);
        let _ = fsm.process_packet(dir, seg, ts);
        ts += 1_000;
        rest = tail;
    }
});
