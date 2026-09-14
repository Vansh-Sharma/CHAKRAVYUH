//! Fuzz harness for the Threat Ring Obfuscation Decoder.
//!
//! The decoder handles hex, URL-encoding, Base64, Base32, leetspeak,
//! Unicode escape, and reversed text. This is the most complex
//! pre-processing step and a prime target for:
//!   - Panics on malformed Base64/Base32/hex sequences
//!   - Buffer overflows when decoding produces large output
//!   - ReDoS in the regex extractors that identify encoded segments
//!   - Edge cases in leet→English mapping

#![no_main]

use chakravyuh::threat::ObfuscationDecoder;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let prompt = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Cap at 32 KiB — the decoder has its own 8 KiB cap on decoded output,
    // but we limit input too for fuzzing throughput.
    if prompt.len() > 32_000 {
        return;
    }

    let decoder = ObfuscationDecoder::new();
    let mut prompt_lower = prompt.to_lowercase();

    // This mutates prompt_lower by appending decoded segments.
    // Must not panic or write out of bounds.
    let _result = decoder.decode_into(prompt, &mut prompt_lower);
});
