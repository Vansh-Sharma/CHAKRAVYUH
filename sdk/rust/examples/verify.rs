/// Example: Verify audit evidence integrity using CHAKRAVYUH OS SDK.
///
/// Run with: cargo run --example verify

use chakravyuh::{Chakravyuh, HashAlgorithm, HashSpec, VerifyRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the client.
    let ck = Chakravyuh::builder()
        .api_key("ck_live_xxxxxxxxx")?
        .base_url("https://api.vinomoid.com")
        .build()?;

    // ─── Simple verification by evidence ID ─────────────────────
    println!("=== Simple Verification ===");

    let result = ck.verify("ev_8f14e45f").await?;

    println!("Verified:  {}", result.verified);
    println!("Integrity: {}", result.integrity);
    println!("Chain:     position {}", result.chain_position);
    println!("Timestamp: {}", result.timestamp);

    // ─── Verification with explicit hash ────────────────────────
    println!("\n=== Verification with Hash ===");

    let request = VerifyRequest::new("ev_a3f2b91c").with_hash(HashSpec {
        algorithm: HashAlgorithm::Sha256,
        value: "a3f2b91c8d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0".into(),
    });

    let result = ck.verify_with(request).await?;

    println!("Verified:  {}", result.verified);
    println!("Integrity: {}", result.integrity);
    println!("Chain:     position {}", result.chain_position);

    if let Some(hash) = &result.hash {
        println!("Hash Algo: {}", hash.algorithm);
    }

    if let Some(details) = &result.details {
        println!("Expected Hash: {}", details.expected_hash);
        println!("Actual Hash:   {}", details.actual_hash);
        println!("Divergence:    {}", details.divergence_at);
    }

    Ok(())
}