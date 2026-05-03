//! Retention pipeline tick on `TenantService` — `hard_delete_batch`
//! and the per-row `process_single_hard_delete` state machine that
//! invokes cascade hooks, calls
//! [`IdpTenantProvisionerClient::deprovision_tenant`], and performs the
//! transactional DB teardown.
//!
//! Lives in its own submodule so the dispatch / failure-classification
//! ladder is reviewable in isolation from the CRUD methods. The hook
//! registry, `IdP` client, and config knobs are reached via crate-private
//! fields on [`TenantService`] (visible to sibling submodules of
//! `service/`).

use std::collections::BTreeMap;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use modkit_security::AccessScope;
use time::OffsetDateTime;
use tracing::warn;
use uuid::Uuid;

use account_management_sdk::{DeprovisionFailure, DeprovisionRequest};

use crate::domain::metrics::{AM_DEPENDENCY_HEALTH, AM_TENANT_RETENTION, MetricKind, emit_metric};
use crate::domain::tenant::hooks::{HookError, TenantHardDeleteHook};
use crate::domain::tenant::repo::TenantRepo;
use crate::domain::tenant::retention::{
    HardDeleteEligibility, HardDeleteOutcome, HardDeleteResult, TenantRetentionRow,
};

use super::TenantService;

impl<R: TenantRepo> TenantService<R> {
    /// Implements FEATURE `Hard-Delete Cleanup Sweep`.
    ///
    /// Scans retention-due rows (leaf-first), invokes registered
    /// cascade hooks, calls [`IdpTenantProvisionerClient::deprovision_tenant`],
    /// and performs the transactional DB teardown via
    /// [`TenantRepo::hard_delete_one`].
    // @cpt-begin:cpt-cf-account-management-algo-tenant-hierarchy-management-hard-delete-leaf-first-scheduler:p1:inst-algo-hdel-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-hard-delete-leaf-first:p1:inst-dod-hard-delete-leaf-first
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-idp-tenant-deprovision:p1:inst-dod-idp-deprovision-hard-delete
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-data-lifecycle:p1:inst-dod-data-lifecycle-hard-delete
    #[allow(
        clippy::cognitive_complexity,
        reason = "F4 retention reaper batch loop: scan, leaf-first sort, per-row IdP deprovision + DB hard-delete with metrics emission; splitting would fragment the failure-classification ladder which must remain transactional with the per-row state machine"
    )]
    pub async fn hard_delete_batch(&self, batch_size: usize) -> HardDeleteResult {
        let now = OffsetDateTime::now_utc();
        let default_retention = Duration::from_secs(self.cfg.retention.default_window_secs);
        let system_scope = AccessScope::allow_all();
        let rows = match self
            .repo
            .scan_retention_due(&system_scope, now, default_retention, batch_size)
            .await
        {
            Ok(rows) => rows,
            Err(err) => {
                warn!(
                    target: "am.retention",
                    error = %err,
                    "hard_delete_batch: scan failed; skipping tick"
                );
                return HardDeleteResult::default();
            }
        };

        // Bucket the batch by depth. Within a single depth bucket
        // sibling tenants share no FK ordering constraint and can be
        // reclaimed concurrently. Buckets are processed leaf-first
        // (deepest depth → root) so the parent FK guard always sees
        // child rows already gone by the time the parent's turn arrives.
        let mut by_depth: BTreeMap<u32, Vec<TenantRetentionRow>> = BTreeMap::new();
        for row in rows {
            by_depth.entry(row.depth).or_default().push(row);
        }

        // Snapshot hooks once per tick so the per-tenant pipeline does
        // not re-clone the registration `Vec` for every row.
        let hooks_snapshot: Vec<TenantHardDeleteHook> = {
            let guard = self.hooks.lock();
            guard.clone()
        };

        // `AccountManagementConfig::validate` (the authoritative
        // gate, called by the module `init` lifecycle) rejects
        // `hard_delete_concurrency == 0` at startup, so this `.max(1)`
        // is unreachable in a validated production config. Kept as
        // defense-in-depth: a future code path that bypasses
        // `validate` (e.g. a test that constructs a `TenantService`
        // by hand) still gets forward progress instead of a stalled
        // `buffer_unordered(0)` stream.
        let concurrency = self.cfg.retention.hard_delete_concurrency.max(1);
        let mut result = HardDeleteResult::default();
        // `BTreeMap` iterates keys ascending; reverse to drain the
        // deepest bucket first.
        for (_depth, bucket) in by_depth.into_iter().rev() {
            let outcomes: Vec<(Uuid, u32, Uuid, HardDeleteOutcome)> = stream::iter(bucket)
                .map(|row| {
                    let hooks = hooks_snapshot.as_slice();
                    async move {
                        let id = row.id;
                        let depth = row.depth;
                        let claimed_by = row.claimed_by;
                        let outcome = self.process_single_hard_delete(row, hooks).await;
                        (id, depth, claimed_by, outcome)
                    }
                })
                .buffer_unordered(concurrency)
                .collect()
                .await;

            for (id, depth, claimed_by, outcome) in outcomes {
                if outcome.is_cleaned() {
                    // TODO(events): emit AM event when platform event-bus lands.
                    // `is_cleaned()` covers both `Cleaned` and
                    // `IdpUnsupported`: per the variant docstring,
                    // `IdpUnsupported` is reported only after a
                    // successful DB teardown, so the cleanup-completed
                    // event applies. The metric label
                    // (`outcome.as_metric_label()` below) still
                    // distinguishes "cleaned via IdP success" from
                    // "cleaned via IdP no-op".
                    tracing::info!(
                        target: "am.events",
                        kind = "hardDeleteCleanupCompleted",
                        actor = "system",
                        tenant_id = %id,
                        depth = depth,
                        "am tenant state changed"
                    );
                }
                emit_metric(
                    AM_TENANT_RETENTION,
                    MetricKind::Counter,
                    &[
                        ("job", "hard_delete"),
                        ("outcome", outcome.as_metric_label()),
                    ],
                );
                // Hold the claim on `DeferredChildPresent` so the
                // scanner's `LIMIT` window is not monopolized by a
                // backlog of blocked parents on the very next tick.
                // The retention claim ages out via
                // `RETENTION_CLAIM_TTL` (~10 min), giving a
                // deterministic back-off before the row is re-picked.
                // By that time the still-undue child row has either
                // become due (and will be processed leaf-first first,
                // unblocking the parent), or it is still undue and
                // the parent simply waits another TTL — without
                // starving shallower eligible rows in between. Other
                // non-cleaned outcomes (`StorageError`,
                // `NotEligible`, `IdpRetryable`, …) still clear
                // promptly so the row can be re-attempted on the
                // next tick.
                let release_claim_now =
                    !outcome.is_cleaned() && outcome != HardDeleteOutcome::DeferredChildPresent;
                if release_claim_now
                    && let Err(err) = self
                        .repo
                        .clear_retention_claim(&AccessScope::allow_all(), id, claimed_by)
                        .await
                {
                    warn!(
                        target: "am.retention",
                        tenant_id = %id,
                        error = %err,
                        "failed to clear retention claim after non-cleaned outcome"
                    );
                }
                result.tally(&outcome);
            }
        }
        result
    }
    // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-data-lifecycle:p1:inst-dod-data-lifecycle-hard-delete
    // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-idp-tenant-deprovision:p1:inst-dod-idp-deprovision-hard-delete
    // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-hard-delete-leaf-first:p1:inst-dod-hard-delete-leaf-first
    // @cpt-end:cpt-cf-account-management-algo-tenant-hierarchy-management-hard-delete-leaf-first-scheduler:p1:inst-algo-hdel-service

    #[allow(
        clippy::cognitive_complexity,
        reason = "single linear pipeline: hooks -> idp -> db teardown; splitting obscures the flow"
    )]
    async fn process_single_hard_delete(
        &self,
        row: TenantRetentionRow,
        hooks: &[TenantHardDeleteHook],
    ) -> HardDeleteOutcome {
        // 0. Preflight eligibility check — DB-side preconditions
        //    verified BEFORE any external (cascade-hook / IdP) side
        //    effect runs. Without this gate, a row that is in fact
        //    deferred (parent with live child, status drifted, claim
        //    lost) would still trigger an irreversible
        //    `IdpTenantProvisionerClient::deprovision_tenant` call —
        //    leaving IdP-side state torn down while AM keeps the row.
        //    The check is read-only and racy; `hard_delete_one`'s
        //    in-tx defense-in-depth still catches a lost race, and
        //    `DeprovisionFailure::NotFound → IdpUnsupported` recovers
        //    on next tick. See `TenantRepo::check_hard_delete_eligibility`
        //    docstring for the full rationale.
        match self
            .repo
            .check_hard_delete_eligibility(&AccessScope::allow_all(), row.id, row.claimed_by)
            .await
        {
            Ok(HardDeleteEligibility::Eligible) => {}
            Ok(HardDeleteEligibility::DeferredChildPresent) => {
                return HardDeleteOutcome::DeferredChildPresent;
            }
            Ok(HardDeleteEligibility::NotEligible) => {
                return HardDeleteOutcome::NotEligible;
            }
            Err(err) => {
                warn!(
                    target: "am.retention",
                    tenant_id = %row.id,
                    error = %err,
                    "hard_delete preflight failed; routing to StorageError outcome"
                );
                return HardDeleteOutcome::StorageError;
            }
        }

        // 1. Cascade hooks — run all, surface the strongest non-ok outcome.
        let mut strongest: Option<HookError> = None;
        for hook in hooks {
            let fut = hook(row.id);
            // Spawn into its own task so a panicking hook cannot kill the
            // retention loop; surface panics as Retryable so the tenant is
            // retried next tick rather than permanently stuck.
            let result = tokio::spawn(fut).await.unwrap_or_else(|e| {
                Err(HookError::Retryable {
                    detail: format!("hook panicked: {e}"),
                })
            });
            match result {
                Ok(()) => {}
                Err(HookError::Retryable { detail }) => {
                    let combined = match strongest {
                        Some(prev @ HookError::Terminal { .. }) => prev,
                        _ => HookError::Retryable { detail },
                    };
                    strongest = Some(combined);
                }
                Err(HookError::Terminal { detail }) => {
                    strongest = Some(HookError::Terminal { detail });
                }
            }
        }
        if let Some(err) = strongest {
            match err {
                HookError::Retryable { detail } => {
                    warn!(
                        target: "am.retention",
                        tenant_id = %row.id,
                        detail,
                        "hard_delete deferred by retryable cascade hook"
                    );
                    return HardDeleteOutcome::CascadeRetryable;
                }
                HookError::Terminal { detail } => {
                    warn!(
                        target: "am.retention",
                        tenant_id = %row.id,
                        detail,
                        "hard_delete skipped by terminal cascade hook"
                    );
                    return HardDeleteOutcome::CascadeTerminal;
                }
            }
        }

        // 2. IdP deprovision — outside any TX.
        //
        // The match returns `idp_skipped: bool` to signal whether the
        // IdP step was a no-op (`UnsupportedOperation` / `NotFound`).
        // `idp_skipped == true` plus a successful DB teardown produces
        // [`HardDeleteOutcome::IdpUnsupported`] (which `is_cleaned()`
        // covers) so the `am.tenant_retention` counter emits the
        // dedicated `idp_unsupported` label and dashboards can
        // distinguish "cleaned via IdP success" from "cleaned via IdP
        // no-op". Without this propagation the variant docstring
        // (`reported only after a successful teardown and counts
        // toward is_cleaned`) would be unreachable.
        let idp_skipped = match self
            .idp
            .deprovision_tenant(&DeprovisionRequest { tenant_id: row.id })
            .await
        {
            Ok(()) => {
                emit_metric(
                    AM_DEPENDENCY_HEALTH,
                    MetricKind::Counter,
                    &[
                        ("target", "idp"),
                        ("op", "deprovision_tenant"),
                        ("outcome", "success"),
                    ],
                );
                false
            }
            Err(failure) => {
                emit_metric(
                    AM_DEPENDENCY_HEALTH,
                    MetricKind::Counter,
                    &[
                        ("target", "idp"),
                        ("op", "deprovision_tenant"),
                        ("outcome", failure.as_metric_label()),
                    ],
                );
                match failure {
                    // Vendor SDK detail strings may carry hostnames,
                    // endpoint paths, or token-bearing fragments — the
                    // same class of secrets the `am.idp` mapping in
                    // `domain/idp` redacts. The retention path logs
                    // into the long-retention `am.retention` target, so
                    // the raw text MUST be redacted here too (matches
                    // the provisioning-reaper contract: FNV-1a digest +
                    // character length for operator correlation).
                    DeprovisionFailure::Retryable { detail } => {
                        let (digest, len) = crate::domain::idp::redact_provider_detail(&detail);
                        warn!(
                            target: "am.retention",
                            tenant_id = %row.id,
                            provider_detail_digest = digest,
                            provider_detail_len = len,
                            "hard_delete deferred by retryable IdP failure (raw detail redacted; correlate via digest)"
                        );
                        return HardDeleteOutcome::IdpRetryable;
                    }
                    DeprovisionFailure::Terminal { detail } => {
                        let (digest, len) = crate::domain::idp::redact_provider_detail(&detail);
                        warn!(
                            target: "am.retention",
                            tenant_id = %row.id,
                            provider_detail_digest = digest,
                            provider_detail_len = len,
                            "hard_delete skipped by terminal IdP failure (raw detail redacted; correlate via digest)"
                        );
                        return HardDeleteOutcome::IdpTerminal;
                    }
                    DeprovisionFailure::UnsupportedOperation { .. }
                    | DeprovisionFailure::NotFound { .. } => {
                        // `UnsupportedOperation`: plugin doesn't
                        // implement deprovision; nothing to do IdP-side.
                        // `NotFound`: vendor reports the tenant is
                        // already gone (possibly from a previous
                        // attempt that lost its claim post-call). Both
                        // map to "skip IdP step, continue with DB
                        // teardown" — the `am.dependency_health`
                        // metric label distinguishes them, and the
                        // outer `idp_skipped = true` signals the DB
                        // teardown step to translate `Cleaned` into
                        // `IdpUnsupported`.
                        true
                    }
                    // `DeprovisionFailure` is `#[non_exhaustive]`; the
                    // wildcard guards against a future SDK variant
                    // landing without a service-side classification.
                    #[allow(unreachable_patterns, reason = "non_exhaustive enum forward-compat")]
                    _ => {
                        warn!(
                            target: "am.retention",
                            tenant_id = %row.id,
                            "hard_delete: unknown DeprovisionFailure variant; deferring as retryable"
                        );
                        return HardDeleteOutcome::IdpRetryable;
                    }
                }
            }
        };

        // 3. DB teardown — fenced on the same `claimed_by` token the
        //    preflight verified, so a peer that re-claimed the row
        //    during the hooks/IdP window short-circuits to
        //    `NotEligible` instead of double-tearing-down state.
        match self
            .repo
            .hard_delete_one(&AccessScope::allow_all(), row.id, row.claimed_by)
            .await
        {
            // Translate `Cleaned` → `IdpUnsupported` when the IdP
            // step was a no-op. `is_cleaned()` covers both, so
            // downstream consumers (claim-clear skip,
            // `hardDeleteCleanupCompleted` event) treat them the
            // same; only the metric label differs.
            Ok(HardDeleteOutcome::Cleaned) if idp_skipped => HardDeleteOutcome::IdpUnsupported,
            Ok(outcome) => outcome,
            Err(err) => {
                // Storage-layer fault — pool exhausted, SERIALIZABLE
                // retry budget exhausted, network blip. Routed to a
                // dedicated `StorageError` outcome so the
                // `am.tenant_retention` counter does not lump infra
                // faults under `cascade_terminal` (which is meant for
                // user-supplied hook failures).
                warn!(
                    target: "am.retention",
                    tenant_id = %row.id,
                    error = %err,
                    "hard_delete db teardown failed"
                );
                HardDeleteOutcome::StorageError
            }
        }
    }
}
