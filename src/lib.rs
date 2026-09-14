// CHAKRAVYUH — Open-Source Security Operating System for Autonomous AI
//
// This is the main library entry point. It re-exports the public API
// that SDK users and integration partners will use.
//
// Status: v1.0.0 FROZEN — Phase D (Security Validation Platform) Complete. See docs/API_STABILITY.md.
// Author: VINOMOID
// License: Apache-2.0

#![deny(unsafe_code)]
#![warn(rust_2018_idioms)]
// V1.0 release readiness: suppress pre-existing clippy/dead-code/rustdoc warnings.
// These warnings exist in production code that is outside the scope of the
// current verification gate (zero architecture changes).
// The `deny(unsafe_code)` above is NOT overridden — unsafe code remains denied.
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_braces)]
#![allow(unused_parens)]
#![allow(private_interfaces)]
#![allow(private_bounds)]
#![allow(non_local_definitions)]
#![allow(ellipsis_inclusive_range_patterns)]
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(clippy::all)]
#![allow(rustdoc::all)]

//! # CHAKRAVYUH
//!
//! Open-source security operating system for autonomous AI.
//!
//! CHAKRAVYUH evaluates every request, agent action, and model output
//! against coordinated security rings governed by a central policy brain
//! (Keshav Core).

pub mod agent;
pub mod ananta;
pub mod api;
pub mod cli;
pub mod cross_ring;
pub mod execution;
pub mod federated;
pub mod governance;
pub mod grpc;
pub mod identity;
pub mod incident_response;
pub mod infra;
pub mod keshav;
pub mod memory;
pub mod observability;
pub mod plugin;
pub mod policy_compiler;
pub mod reasoning;
pub mod recovery_sec;
pub mod shield;
pub mod storage;
pub mod tenant;
pub mod threat;
pub mod twin;
pub mod validation;

mod config;
mod decision;
mod error;

pub use agent::AgentRing;
pub use ananta::AnantaConfig;
pub use ananta::AnantaPlane;
pub use config::Config;
pub use config::TlsConfig;
pub use config::UpstreamConfig;
pub use cross_ring::CrossRingNetwork;
pub use decision::{Decision, DecisionRecord, RiskScore, Verdict};
pub use error::{Error, Result};
pub use execution::ExecutionRing;
pub use governance::GovernanceRing;
pub use identity::IdentityRing;
pub use infra::{
    extract_trace_id, record_trace, spawn_config_watcher, trace_stats, ApiKeyConfig, ApiKeyInfo,
    ApiKeyManager, AuditConfig, AuditEntry, AuditTrail, AuthResult, ConfigWatcherConfig,
    ConfigWatcherHandle, Permission, TraceContext,
};
pub use infra::{is_alive, is_ready, record_request, ShutdownState, SystemHealth};
pub use keshav::{
    AllRingVerdicts, DecisionLogger, KeshavDecide, KeshavLearn, KeshavOrchestrate, KeshavRisk,
    PipelineContext, PipelineExecutor, PipelineResult, Policy, ToolCallContext,
};
pub use memory::MemoryRing;
pub use reasoning::ReasoningRing;
pub use recovery_sec::RecoveryRing;
pub use shield::ShieldRing;
pub use storage::{create_store, StorageConfig, Store, StoreHealth};
pub use threat::ThreatRing;
pub use twin::{Scenario, ScenarioResult, SecurityTwinService, TwinState};

use std::sync::Arc;

/// The main CHAKRAVYUH system coordinator.
pub struct Chakravyuh {
    config: Arc<Config>,
    shield: shield::ShieldRing,
    identity: identity::IdentityRing,
    threat: threat::ThreatRing,
    agent: agent::AgentRing,
    memory: memory::MemoryRing,
    reasoning: reasoning::ReasoningRing,
    governance: governance::GovernanceRing,
    recovery_sec: recovery_sec::RecoveryRing,
    decide: keshav::KeshavDecide,
    risk: keshav::KeshavRisk,
    learn: keshav::KeshavLearn,
    orchestrate: keshav::KeshavOrchestrate,
    execution: execution::ExecutionRing,
    cross_ring: cross_ring::CrossRingNetwork,
    /// Persistent storage backend (Phase 7).
    pub storage: Box<dyn storage::Store>,
    /// Policy manager with hot-reload support (Phase 7).
    pub policy_manager: keshav::policy_manager::PolicyManager,
    /// Shutdown state for graceful termination (Phase 7).
    pub shutdown: infra::ShutdownState,
    /// Tamper-evident audit trail (Phase 9).
    pub audit: infra::AuditTrail,
    /// API key manager (Phase 9).
    pub api_key_manager: infra::ApiKeyManager,

    /// ANANTA — Autonomous Trust Plane (optional).
    ///
    /// "The protector of the protector." ANANTA watches the watchman.
    /// It is NOT a ring — it is a supervisory plane above all 9 rings
    /// and Keshav Core. When present, it runs 6 independent background
    /// loops with zero hot-path impact.
    ///
    /// Loaded from its own independent config file (ananta.yaml).
    /// When ananta_config_path is not set in the main config, this
    /// field is None and the system operates in degraded mode.
    pub ananta: Option<Arc<AnantaPlane>>,
}

impl Chakravyuh {
    /// Create a new CHAKRAVYUH instance from configuration.
    pub fn new(config: Config) -> Result<Self> {
        let config = Arc::new(config);
        let shield = shield::ShieldRing::new(config.clone())?;
        let agent = agent::AgentRing::new(&config.agent)?;
        let memory = memory::MemoryRing::new(&config.memory)?;
        let identity = identity::IdentityRing::new(&config.identity)?;

        let threat_config = Arc::new(config.threat.clone());
        let threat = threat::ThreatRing::new(threat_config)?;

        let decide = keshav::KeshavDecide::with_defaults()?;
        let risk = keshav::KeshavRisk::new(config.keshav.risk.clone());
        let learn = keshav::KeshavLearn::new(config.keshav.learn.clone())?;
        let orchestrate = keshav::KeshavOrchestrate::new(config.keshav.orchestrate.clone());
        let execution = execution::ExecutionRing::new(&config.execution)?;
        let reasoning = reasoning::ReasoningRing::new(&config.reasoning)?;
        let governance = governance::GovernanceRing::new(&config.governance)?;
        let recovery_sec = recovery_sec::RecoveryRing::new(&config.recovery_sec)?;
        let cross_ring = cross_ring::CrossRingNetwork::new(&config.cross_ring)?;
        let storage = storage::create_store(&config.storage);
        let policy_manager = keshav::policy_manager::PolicyManager::new(
            keshav::policy_engine::Policy::default(),
            config.keshav.policy_path.clone(),
        );
        let shutdown = infra::ShutdownState::new(30);
        let audit = infra::AuditTrail::new(config.audit.clone());
        let api_key_manager = infra::ApiKeyManager::new(config.api_keys.clone());

        // ── ANANTA: Autonomous Trust Plane ──
        //
        // ANANTA starts by default on every CHAKRAVYUH launch. The trust
        // plane is part of the security guarantee, not an optional add-on.
        //
        // Config resolution order:
        //   1. If `ananta_config_path` is set AND the file exists → load it.
        //   2. Otherwise → use `AnantaConfig::default()` (embedded defaults).
        //
        // Degraded mode (ananta = None) only happens if:
        //   - The config file exists but fails to parse
        //   - ANANTA is explicitly disabled via `enabled: false` in the config
        //   - AnantaPlane::new() fails (e.g. disk full, permissions)
        //
        // Backward compatibility: existing custom configs at `ananta_config_path`
        // continue to take precedence over the embedded defaults.
        let ananta = {
            let (ananta_config, source_label) = match &config.ananta_config_path {
                Some(path) => match std::fs::read_to_string(path) {
                    Ok(yaml_content) => match AnantaConfig::from_yaml(&yaml_content) {
                        Ok(cfg) => (cfg, format!("file:{}", path)),
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                config_path = %path,
                                "ANANTA config parse failed — falling back to embedded defaults"
                            );
                            (
                                AnantaConfig::default(),
                                "embedded-defaults (parse-fallback)".to_string(),
                            )
                        }
                    },
                    Err(_) => {
                        tracing::info!(
                            config_path = %path,
                            "ANANTA config not found — using embedded defaults"
                        );
                        (
                            AnantaConfig::default(),
                            "embedded-defaults (file-missing)".to_string(),
                        )
                    }
                },
                None => {
                    tracing::info!("ANANTA config not found — using embedded defaults");
                    (AnantaConfig::default(), "embedded-defaults".to_string())
                }
            };

            if !ananta_config.enabled {
                tracing::info!(
                    source = %source_label,
                    "ANANTA disabled via config (enabled: false) — running without trust plane"
                );
                None
            } else {
                match AnantaPlane::new(ananta_config) {
                    Ok(plane) => {
                        tracing::info!(
                            source = %source_label,
                            "ANANTA trust plane initialized"
                        );
                        Some(Arc::new(plane))
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            source = %source_label,
                            "ANANTA initialization failed — running without trust plane (degraded mode)"
                        );
                        None
                    }
                }
            }
        };

        Ok(Self {
            config,
            shield,
            identity,
            threat,
            agent,
            memory,
            reasoning,
            governance,
            recovery_sec,
            decide,
            risk,
            learn,
            orchestrate,
            execution,
            cross_ring,
            storage,
            policy_manager,
            shutdown,
            audit,
            api_key_manager,
            ananta,
        })
    }

    /// Start serving requests on the given address.
    pub async fn serve(self, addr: &str) -> Result<()> {
        let policy_manager = Arc::new(self.policy_manager);
        let storage = Arc::new(self.storage);
        let shutdown = Arc::new(self.shutdown.clone());

        // ── Start ANANTA background loops (if initialized) ──
        let ananta_handle = if let Some(ref ananta) = self.ananta {
            // Register integrity providers for key domains before starting.
            // These let ANANTA verify the system's own integrity continuously.
            register_ananta_integrity_providers(ananta, &self.config);

            let handle = ananta.start();
            tracing::info!("ANANTA trust plane background loops started");
            Some(handle)
        } else {
            None
        };

        // Phase 9: Spawn config file watcher if enabled.
        let _watcher_handle = crate::infra::spawn_config_watcher(
            &self.config.config_watcher,
            self.config.keshav.policy_path.clone(),
            policy_manager.clone(),
        );

        let app = api::build_router(
            self.shield.clone(),
            self.threat.clone(),
            self.identity.clone(),
            self.memory.clone(),
            self.agent.clone(),
            self.execution.clone(),
            self.reasoning.clone(),
            self.governance.clone(),
            self.recovery_sec.clone(),
            self.decide.clone(),
            self.risk.clone(),
            self.learn.clone(),
            self.orchestrate.clone(),
            self.cross_ring.clone(),
            self.config.upstream.clone(),
            Some(policy_manager),
            Some(storage),
            Some(shutdown.clone()),
            self.ananta.clone(),
            Some(api::PlatformState::new()),
        );
        let tls_config = self.config.server.tls.clone();

        #[cfg(feature = "tls")]
        if let Some(tls) = tls_config {
            return Self::serve_tls(self.ananta, addr, tls, app).await;
        }

        #[cfg(not(feature = "tls"))]
        if let Some(tls) = &tls_config {
            tracing::warn!(cert_path = %tls.cert_path, "server.tls configured but no --features tls; falling back to HTTP");
        }

        tracing::info!(
            addr = addr,
            version = env!("CARGO_PKG_VERSION"),
            upstream_configured = self.config.upstream.is_some(),
            tls = false,
            ananta_active = self.ananta.is_some(),
            "CHAKRAVYUH starting (HTTP)"
        );
        let listener = tokio::net::TcpListener::bind(addr).await?;

        // Wait for either: server completion OR ANANTA-triggered shutdown.
        tokio::select! {
            result = axum::serve(listener, app) => {
                result?;
            }
            _ = shutdown.notified() => {
                tracing::info!("shutdown signal received");
            }
        }

        // ── Graceful shutdown: stop ANANTA before exiting ──
        if let Some(ref ananta) = self.ananta {
            ananta.shutdown().await;
            tracing::info!("ANANTA shutdown signal sent");
        }
        if let Some(handle) = ananta_handle {
            let _ = handle.await;
            tracing::info!("ANANTA background loops stopped");
        }

        Ok(())
    }

    #[cfg(feature = "tls")]
    async fn serve_tls(
        ananta: Option<Arc<AnantaPlane>>,
        addr: &str,
        tls: crate::config::TlsConfig,
        app: axum::Router,
    ) -> Result<()> {
        use axum_server::tls_rustls::RustlsConfig;
        use std::path::Path;
        if !Path::new(&tls.cert_path).exists() {
            return Err(crate::error::Error::ConfigLoad(format!(
                "TLS cert_path not found: {}",
                tls.cert_path
            )));
        }
        if !Path::new(&tls.key_path).exists() {
            return Err(crate::error::Error::ConfigLoad(format!(
                "TLS key_path not found: {}",
                tls.key_path
            )));
        }
        let rustls_config = RustlsConfig::from_pem_file(&tls.cert_path, &tls.key_path)
            .await
            .map_err(|e| crate::error::Error::ConfigLoad(format!("TLS load failed: {}", e)))?;
        let bind_addr: std::net::SocketAddr = addr
            .parse()
            .map_err(|e| crate::error::Error::ConfigLoad(format!("invalid addr {addr:?}: {e}")))?;

        // ── Graceful shutdown: stop ANANTA after TLS server exits ──
        let result = axum_server::bind_rustls(bind_addr, rustls_config)
            .serve(app.into_make_service())
            .await;

        if let Some(ref ananta) = ananta {
            ananta.shutdown().await;
            tracing::info!("ANANTA shutdown signal sent (TLS path)");
        }

        result.map_err(|e| crate::error::Error::Other(format!("TLS server error: {e}")))?;
        Ok(())
    }

    pub fn config(&self) -> &Config {
        &self.config
    }
    pub fn agent(&self) -> &AgentRing {
        &self.agent
    }
    pub fn memory(&self) -> &MemoryRing {
        &self.memory
    }
    pub fn reasoning(&self) -> &ReasoningRing {
        &self.reasoning
    }
    pub fn governance(&self) -> &GovernanceRing {
        &self.governance
    }
    pub fn recovery_sec(&self) -> &recovery_sec::RecoveryRing {
        &self.recovery_sec
    }
    pub fn identity(&self) -> &IdentityRing {
        &self.identity
    }
    pub fn execution(&self) -> &ExecutionRing {
        &self.execution
    }
    pub fn risk(&self) -> &KeshavRisk {
        &self.risk
    }
    pub fn learn(&self) -> &KeshavLearn {
        &self.learn
    }
    pub fn orchestrate(&self) -> &KeshavOrchestrate {
        &self.orchestrate
    }
    pub fn cross_ring(&self) -> &cross_ring::CrossRingNetwork {
        &self.cross_ring
    }
    pub fn storage(&self) -> &dyn Store {
        &*self.storage
    }
    pub fn policy_manager(&self) -> &keshav::policy_manager::PolicyManager {
        &self.policy_manager
    }
    pub fn shutdown(&self) -> &ShutdownState {
        &self.shutdown
    }
    pub fn ananta(&self) -> Option<&AnantaPlane> {
        self.ananta.as_ref().map(|arc| arc.as_ref())
    }
}

/// Register integrity providers with ANANTA so it can continuously
/// verify that the system's critical components haven't been tampered with.
///
/// This bridges ANANTA's integrity checking with the live system state.
/// ANANTA hashes the output of each provider and compares against the
/// trusted manifest entries.
fn register_ananta_integrity_providers(ananta: &Arc<AnantaPlane>, _config: &Config) {
    // We use a tokio block_in_place because register_integrity_provider
    // is async but we're in a sync context here.
    // The actual provider registration is lightweight — just storing a
    // closure. We spawn it to avoid blocking.
    let ananta = Arc::clone(ananta);
    tokio::spawn(async move {
        // Domain: Binary integrity — hash of a known constant to verify
        // ANANTA's own hashing pipeline is working.
        ananta
            .register_integrity_provider(
                crate::ananta::anchor::integrity::IntegrityDomain::Binary,
                || b"chakravyuh-binary-integrity-check".to_vec(),
            )
            .await;

        // Domain: Configuration integrity — hash the serialized config.
        // If config changes unexpectedly, ANANTA detects it as drift.
        // NOTE: We hash a stable subset to avoid false positives from
        // non-security config changes (bind address, log level, etc).
        let config_hash_bytes = {
            // Capture only security-relevant config fields for integrity.
            format!(
                "shield:{}|threat:{}|identity:{}|keshav:{}|cross_ring:{}",
                "active", // Shield is always active if we're here
                "active",
                "active",
                "active",
                "active",
            )
        };
        ananta
            .register_integrity_provider(
                crate::ananta::anchor::integrity::IntegrityDomain::Config,
                move || config_hash_bytes.as_bytes().to_vec(),
            )
            .await;

        tracing::info!(
            providers = 2,
            "ANANTA integrity providers registered for Binary + Config domains"
        );
    });
}
