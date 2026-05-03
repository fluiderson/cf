//! Tests for the SDK tenant input/output contract.

use super::*;

#[test]
fn list_children_query_rejects_zero_top() {
    let err =
        ListChildrenQuery::new(uuid::Uuid::nil(), None, 0, 0).expect_err("top=0 must be rejected");
    assert_eq!(err, ListChildrenQueryError::TopMustBePositive);
}

#[test]
fn list_children_query_deserialize_rejects_zero_top() {
    // Pinned: serde routes through `RawListChildrenQuery` +
    // `TryFrom`, which calls `ListChildrenQuery::new` and surfaces
    // the same `TopMustBePositive` rejection. Without the
    // `#[serde(try_from = ...)]` wrapper, `top: 0` would silently
    // bypass the constructor invariant.
    let json = r#"{"parent_id":"00000000-0000-0000-0000-000000000000","top":0}"#;
    let err = serde_json::from_str::<ListChildrenQuery>(json)
        .expect_err("top=0 must be rejected on deserialization");
    let msg = err.to_string();
    assert!(
        msg.contains("top must be at least 1"),
        "expected TopMustBePositive surface in deserialize error, got: {msg}"
    );
}

#[test]
fn list_children_query_deserialize_accepts_valid_top() {
    let json = r#"{"parent_id":"00000000-0000-0000-0000-000000000000","top":10,"skip":5}"#;
    let q: ListChildrenQuery = serde_json::from_str(json).expect("valid query must deserialize");
    assert_eq!(q.top(), 10);
    assert_eq!(q.skip, 5);
    assert!(q.status_filter().is_none());
}

#[test]
fn list_children_query_accepts_sdk_visible_filters() {
    let q = ListChildrenQuery::new(
        uuid::Uuid::nil(),
        Some(vec![
            TenantStatus::Active,
            TenantStatus::Suspended,
            TenantStatus::Deleted,
        ]),
        10,
        0,
    )
    .expect("sdk-visible filter accepted");
    let statuses = q.status_filter().expect("filter");
    assert_eq!(statuses.len(), 3);
    assert!(statuses.contains(&TenantStatus::Active));
    assert!(statuses.contains(&TenantStatus::Suspended));
    assert!(statuses.contains(&TenantStatus::Deleted));
}

#[test]
fn list_children_query_normalizes_empty_filter_to_none() {
    // Pinned at the constructor: `Some(vec![])` must collapse to
    // `None` so the documented `status_filter()` equivalence holds at
    // every consumer without each one needing to remember it.
    let q = ListChildrenQuery::new(uuid::Uuid::nil(), Some(vec![]), 10, 0)
        .expect("empty filter normalized");
    assert!(
        q.status_filter().is_none(),
        "empty Vec<TenantStatus> must normalize to None per the contract"
    );
}

#[test]
fn list_children_query_accepts_none_filter() {
    let q = ListChildrenQuery::new(uuid::Uuid::nil(), None, 10, 0).expect("none accepted");
    assert!(q.status_filter().is_none());
    assert_eq!(q.parent_id, uuid::Uuid::nil());
    assert_eq!(q.top(), 10);
    assert_eq!(q.skip, 0);
}

#[test]
fn tenant_update_default_is_empty() {
    let u = TenantUpdate::default();
    assert!(u.is_empty());
}

#[test]
fn tenant_update_with_name_is_not_empty() {
    let u = TenantUpdate {
        name: Some("x".into()),
        ..Default::default()
    };
    assert!(!u.is_empty());
}

#[test]
fn tenant_update_with_status_is_not_empty() {
    let u = TenantUpdate {
        status: Some(TenantStatus::Active),
        ..Default::default()
    };
    assert!(!u.is_empty());
}
