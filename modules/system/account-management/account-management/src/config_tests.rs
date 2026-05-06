use super::*;

#[test]
fn default_validates_clean() {
    AccountManagementConfig::default()
        .validate()
        .expect("default config must always validate; it is the production fallback");
}

#[test]
fn idp_required_defaults_to_false() {
    // Pinned: deployments inheriting the default keep the existing
    // NoopProvisioner-fallback behaviour. Production deployments
    // that want fail-closed init must opt in explicitly.
    let cfg = AccountManagementConfig::default();
    assert!(
        !cfg.idp.required,
        "idp.required must default to false; production deployments opt in explicitly"
    );
}

#[test]
fn rejects_zero_retention_tick() {
    let cfg = AccountManagementConfig {
        retention: RetentionConfig {
            tick_secs: 0,
            ..RetentionConfig::default()
        },
        ..AccountManagementConfig::default()
    };
    let err = cfg.validate().expect_err("zero tick must reject");
    assert!(err.contains("retention.tick_secs"), "{err}");
}

#[test]
fn rejects_zero_reaper_tick() {
    let cfg = AccountManagementConfig {
        reaper: ReaperConfig {
            tick_secs: 0,
            ..ReaperConfig::default()
        },
        ..AccountManagementConfig::default()
    };
    let err = cfg.validate().expect_err("zero tick must reject");
    assert!(err.contains("reaper.tick_secs"), "{err}");
}

#[test]
fn rejects_zero_provisioning_timeout() {
    // Zero staleness threshold would make every fresh `Provisioning`
    // row instantly reaper-eligible — the reaper would compensate
    // creates that haven't even reached the IdP step yet.
    let cfg = AccountManagementConfig {
        reaper: ReaperConfig {
            provisioning_timeout_secs: 0,
            ..ReaperConfig::default()
        },
        ..AccountManagementConfig::default()
    };
    let err = cfg
        .validate()
        .expect_err("zero provisioning timeout must reject");
    assert!(err.contains("reaper.provisioning_timeout_secs"), "{err}");
}

#[test]
fn rejects_zero_hard_delete_batch_size() {
    let cfg = AccountManagementConfig {
        retention: RetentionConfig {
            hard_delete_batch_size: 0,
            ..RetentionConfig::default()
        },
        ..AccountManagementConfig::default()
    };
    let err = cfg.validate().expect_err("zero batch must reject");
    assert!(err.contains("retention.hard_delete_batch_size"), "{err}");
}

#[test]
fn rejects_zero_reaper_batch_size() {
    let cfg = AccountManagementConfig {
        reaper: ReaperConfig {
            batch_size: 0,
            ..ReaperConfig::default()
        },
        ..AccountManagementConfig::default()
    };
    let err = cfg.validate().expect_err("zero batch must reject");
    assert!(err.contains("reaper.batch_size"), "{err}");
}

#[test]
fn rejects_zero_hard_delete_concurrency() {
    let cfg = AccountManagementConfig {
        retention: RetentionConfig {
            hard_delete_concurrency: 0,
            ..RetentionConfig::default()
        },
        ..AccountManagementConfig::default()
    };
    let err = cfg.validate().expect_err("zero concurrency must reject");
    assert!(err.contains("retention.hard_delete_concurrency"), "{err}");
}

#[test]
fn rejects_zero_deprovision_concurrency() {
    let cfg = AccountManagementConfig {
        reaper: ReaperConfig {
            deprovision_concurrency: 0,
            ..ReaperConfig::default()
        },
        ..AccountManagementConfig::default()
    };
    let err = cfg.validate().expect_err("zero concurrency must reject");
    assert!(err.contains("reaper.deprovision_concurrency"), "{err}");
}

#[test]
fn rejects_zero_max_top() {
    let cfg = AccountManagementConfig {
        listing: ListingConfig { max_top: 0 },
        ..AccountManagementConfig::default()
    };
    let err = cfg.validate().expect_err("zero top must reject");
    assert!(err.contains("listing.max_top"), "{err}");
}

#[test]
fn rejects_excessive_depth_threshold() {
    let cfg = AccountManagementConfig {
        hierarchy: HierarchyConfig {
            depth_threshold: AccountManagementConfig::MAX_DEPTH_THRESHOLD + 1,
            ..HierarchyConfig::default()
        },
        ..AccountManagementConfig::default()
    };
    let err = cfg
        .validate()
        .expect_err("depth_threshold > MAX must reject");
    assert!(err.contains("hierarchy.depth_threshold"), "{err}");
}

#[test]
fn aggregates_multiple_failures_in_one_message() {
    let cfg = AccountManagementConfig {
        retention: RetentionConfig {
            tick_secs: 0,
            hard_delete_batch_size: 0,
            ..RetentionConfig::default()
        },
        reaper: ReaperConfig {
            tick_secs: 0,
            ..ReaperConfig::default()
        },
        ..AccountManagementConfig::default()
    };
    let err = cfg.validate().expect_err("triple-bad must reject");
    assert!(err.contains("retention.tick_secs"), "{err}");
    assert!(err.contains("reaper.tick_secs"), "{err}");
    assert!(err.contains("retention.hard_delete_batch_size"), "{err}");
}
