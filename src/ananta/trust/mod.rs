// ANANTA Trust Engine
//
// The trust engine maintains the platform's trust state.
// It answers: "Is the Security OS trustworthy?"
//
// Components:
//   1. TrustState      — the current trust snapshot (score, per-domain levels)
//   2. TrustGraph      — entity-to-entity trust relationships
//   3. TrustProof      — cryptographic proof of platform integrity
//   4. TrustEngine     — Bayesian trust engine (Beta posterior, decay, propagation, fusion, prediction)
//   5. TrustDecay      — temporal trust decay engine (multi-model, scheduled, audited)
//   6. TrustPropagationBridge — bridges Bayesian engine into AnantaPlane trust state updates

pub mod trust_state;
pub mod trust_graph;
pub mod trust_proof;
pub mod trust_engine;
pub mod trust_decay;
pub mod trust_propagation_bridge;

pub use trust_state::TrustState;
pub use trust_graph::TrustGraph;
pub use trust_proof::TrustProof;
pub use trust_engine::*;
pub use trust_decay::*;