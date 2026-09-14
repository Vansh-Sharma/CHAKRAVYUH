/// Example: Check CHAKRAVYUH OS system health.
///
/// Run with: cargo run --example health

use chakravyuh::Chakravyuh;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ck = Chakravyuh::builder()
        .api_key("ck_live_xxxxxxxxx")?
        .base_url("https://api.vinomoid.com")
        .build()?;

    let health = ck.health().await?;

    println!("Status:      {}", health.status);
    println!("Version:     {}", health.version);
    println!("Uptime:      {}s", health.uptime_seconds);
    println!("Active Rings: {}", health.active_rings);

    if let Some(latency) = &health.latency {
        println!("P50 Latency: {:.1} ms", latency.p50_ms);
        println!("P95 Latency: {:.1} ms", latency.p95_ms);
        println!("P99 Latency: {:.1} ms", latency.p99_ms);
    }

    println!();
    println!("Build Info:");
    println!("  Commit: {}", health.build.commit);
    println!("  Target: {}", health.build.target);
    println!("  Profile: {}", health.build.profile);
    println!("  Rustc:  {}", health.build.rustc);

    println!();
    println!("Components:");
    println!("  Keshav Orchestrator: {}", health.components.keshav_orchestrator);
    println!("  Ananta Engine:       {}", health.components.ananta_engine);
    println!("  Sentinel:            {}", health.components.sentinel);
    println!("  Phoenix:             {}", health.components.phoenix);
    println!("  Trust Engine:        {}", health.components.trust_engine);
    println!("  Identity:            {}", health.components.identity);
    println!("  Policy Compiler:     {}", health.components.policy_compiler);
    println!("  Audit Engine:        {}", health.components.audit_engine);
    println!("  OVAPH:               {}", health.components.ovaph);

    if !health.degraded_reasons.is_empty() {
        println!();
        println!("Degraded Reasons:");
        for reason in &health.degraded_reasons {
            println!("  [{}] {}", reason.component, reason.issue);
        }
    }

    Ok(())
}
