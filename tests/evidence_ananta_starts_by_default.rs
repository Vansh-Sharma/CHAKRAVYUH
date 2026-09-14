// Evidence Test: ANANTA starts by default with no config file.
//
// Verifies that a freshly-constructed CHAKRAVYUH instance has the ANANTA
// trust plane active — even when `ananta_config_path` is None and no
// ananta.yaml file exists on disk.
//
// Run:
//   cargo test --test evidence_ananta_starts_by_default -- --nocapture
//
// Acceptance: `Chakravyuh::new(Config::default())` returns a system
// whose `ananta` field is `Some`, proving the trust plane initialized
// using embedded defaults rather than entering degraded mode.

use chakravyuh::{Config, Chakravyuh};

#[test]
fn evidence_ananta_starts_by_default() {
    // Default config has ananta_config_path = None.
    let config = Config::default();
    assert!(
        config.ananta_config_path.is_none(),
        "Default config should not set ananta_config_path"
    );

    // Build the system. This must not fail and must initialize ANANTA
    // using AnantaConfig::default() (embedded defaults).
    let system = Chakravyuh::new(config).expect("Chakravyuh::new must succeed");

    // The ananta field must be Some — proving the trust plane initialized.
    let ananta = system.ananta();
    assert!(
        ananta.is_some(),
        "ANANTA trust plane must be active by default (got None — degraded mode)"
    );

    println!("=== EVIDENCE: ANANTA auto-start ===");
    println!("ananta_config_path: None (default)");
    println!("ananta active:       {}", ananta.is_some());
    println!("==================================");

    // Confirm ANANTA's public query API works (proves it's not just
    // a None-shaped stub).
    if let Some(plane) = ananta {
        // consecutive_passes is a sync accessor that returns 0 on a
        // freshly-initialized plane (background loops haven't run yet).
        let passes = plane.consecutive_passes();
        let failures = plane.consecutive_failures();
        println!("consecutive_passes:  {}", passes);
        println!("consecutive_failures: {}", failures);
        assert_eq!(
            failures, 0,
            "Freshly-initialized ANANTA should have zero failures"
        );
    }
}

#[test]
fn evidence_ananta_with_missing_config_file_falls_back_to_defaults() {
    // Point at a path that does not exist — should fall back to embedded
    // defaults rather than entering degraded mode.
    let mut config = Config::default();
    config.ananta_config_path = Some("/nonexistent/path/ananta.yaml".to_string());

    let system = Chakravyuh::new(config).expect("Chakravyuh::new must succeed");
    let ananta = system.ananta();
    assert!(
        ananta.is_some(),
        "ANANTA must fall back to embedded defaults when the config file is missing"
    );

    println!("=== EVIDENCE: ANANTA fallback on missing file ===");
    println!("ananta_config_path: /nonexistent/path/ananta.yaml");
    println!("ananta active:       {}", ananta.is_some());
    println!("================================================");
}
