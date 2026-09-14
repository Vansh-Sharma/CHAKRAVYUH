// Handler module — all endpoint implementations.

pub mod protect;
pub mod verify;
pub mod policy;
pub mod health;
pub mod audit;
pub mod v1_public;

pub use protect::protect_handler;
pub use verify::verify_handler;
pub use policy::policy_evaluate_handler;
pub use health::health_handler;
pub use audit::audit_list_handler;
pub use v1_public::{protect_simple_handler, version_handler};
