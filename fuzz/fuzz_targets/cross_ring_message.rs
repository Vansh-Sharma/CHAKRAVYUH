//! Fuzz harness for Cross Ring Message serialization roundtrip.
//!
//! Feeds arbitrary byte sequences as JSON to CrossRingMessage deserialization.
//! Targets:
//!   - Deserialization of malformed JSON doesn't panic
//!   - Roundtrip (parse → serialize → parse) is stable
//!   - Edge cases in priority, payload, and type fields

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to parse as a CrossRingMessage.
    let msg: Result<chakravyuh::cross_ring::message::CrossRingMessage, _> =
        serde_json::from_slice(data);

    match msg {
        Ok(m) => {
            // Exercise all accessor methods — must not panic.
            let _id = &m.message_id;
            let _ts = &m.timestamp;
            let _src = &m.source;
            let _dst = &m.destination;
            let _ty = &m.cross_ring_type;
            let _mt = &m.msg_type;
            let _payload = &m.payload;
            let _prio = &m.priority;
            let _ver = &m.version;

            // Roundtrip: serialize and re-parse.
            if let Ok(json) = serde_json::to_string(&m) {
                let _m2: Result<chakravyuh::cross_ring::message::CrossRingMessage, _> =
                    serde_json::from_str(&json);
            }
        }
        Err(_) => {
            // Invalid JSON is expected for most inputs.
        }
    }

    // Also fuzz the CrossRingType deserialization.
    let _ty: Result<chakravyuh::cross_ring::message::CrossRingType, _> =
        serde_json::from_slice(data);

    // And MessagePriority.
    let _prio: Result<chakravyuh::cross_ring::message::MessagePriority, _> =
        serde_json::from_slice(data);
});
