//! Domain layer for the Account Management storage floor.
//!
//! Houses the error taxonomy, metric catalog, `IdP` provisioner contract,
//! tenant domain model + repository trait, the `TenantService`
//! domain-service layer, and the [`tenant_type`] compatibility-barrier
//! abstraction (with the production `GtsTenantTypeChecker` wired through
//! `infra::types_registry`). Bootstrap saga and the audit-pipeline
//! event-bus consumer arrive in later PRs. State-changing transitions
//! log placeholder lines on `target="am.events"`; those sites become
//! event-bus emit points when the platform audit transport lands.

pub mod error;
pub mod idp;
pub mod metrics;
pub mod tenant;
pub mod tenant_type;
