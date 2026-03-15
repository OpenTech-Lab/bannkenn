mod support;

use chrono::{Duration as ChronoDuration, Utc};
use support::test_db;

#[tokio::test]
async fn insert_and_list_decisions() {
    let db = test_db().await;

    let id1 = db
        .insert_decision_with_timestamp(
            "192.168.1.1",
            "Test reason 1",
            "block",
            "agent",
            Some("2026-03-11T09:05:00+00:00"),
        )
        .await
        .expect("Failed to insert decision 1")
        .expect("decision should be inserted");
    let id2 = db
        .insert_decision_with_timestamp(
            "192.168.1.2",
            "Test reason 2",
            "block",
            "agent",
            Some("2026-03-11T09:00:00+00:00"),
        )
        .await
        .expect("Failed to insert decision 2")
        .expect("decision should be inserted");

    assert!(id2 > id1);

    let decisions = db
        .list_decisions(100)
        .await
        .expect("Failed to list decisions");
    assert_eq!(decisions.len(), 2);
    assert_eq!(decisions[0].ip, "192.168.1.1");
    assert_eq!(decisions[1].ip, "192.168.1.2");
    assert_eq!(decisions[0].reason, "Test reason 1");
    assert_eq!(decisions[1].reason, "Test reason 2");
    assert_eq!(decisions[0].created_at, "2026-03-11T09:05:00+00:00");
    assert_eq!(decisions[1].created_at, "2026-03-11T09:00:00+00:00");
}

#[tokio::test]
async fn list_local_decisions_excludes_community_feeds() {
    let db = test_db().await;

    db.insert_agent("agent-alpha", "token-a", None)
        .await
        .unwrap();
    db.insert_decision_with_timestamp(
        "203.0.113.44",
        "Manual block",
        "block",
        "agent-alpha",
        Some("2026-03-11T09:05:00+00:00"),
    )
    .await
    .unwrap()
    .expect("agent decision should be inserted");
    db.insert_decision_with_timestamp(
        "203.0.113.45",
        "Campaign auto-block: SSH brute force",
        "block",
        "campaign",
        Some("2026-03-11T09:04:00+00:00"),
    )
    .await
    .unwrap()
    .expect("campaign decision should be inserted");
    db.insert_decision_with_timestamp(
        "203.0.113.46",
        "ipsum_feed",
        "block",
        "ipsum_feed",
        Some("2026-03-11T09:06:00+00:00"),
    )
    .await
    .unwrap()
    .expect("community decision should be inserted");

    let decisions = db.list_local_decisions(10).await.unwrap();
    assert_eq!(decisions.len(), 2);
    assert_eq!(decisions[0].source, "agent-alpha");
    assert_eq!(decisions[1].source, "campaign");

    let incremental = db.list_local_decisions_since(0, 10).await.unwrap();
    assert_eq!(incremental.len(), 2);
    assert!(incremental.iter().all(|row| row.source != "ipsum_feed"));
}

#[tokio::test]
async fn list_community_feeds_includes_agent_and_campaign_sources() {
    let db = test_db().await;

    let agent_id = db
        .insert_agent("agent-alpha", "token-a", None)
        .await
        .unwrap();
    db.update_agent_nickname(agent_id, "Tokyo edge")
        .await
        .unwrap();

    db.insert_decision_with_timestamp(
        "203.0.113.10",
        "feed",
        "block",
        "ipsum_feed",
        Some("2026-03-11T09:00:00+00:00"),
    )
    .await
    .unwrap()
    .expect("feed decision should be inserted");
    db.insert_decision_with_timestamp(
        "203.0.113.11",
        "agent",
        "block",
        "agent-alpha",
        Some("2026-03-11T09:01:00+00:00"),
    )
    .await
    .unwrap()
    .expect("agent decision should be inserted");
    db.insert_decision_with_timestamp(
        "203.0.113.12",
        "campaign",
        "block",
        "campaign",
        Some("2026-03-11T09:02:00+00:00"),
    )
    .await
    .unwrap()
    .expect("campaign decision should be inserted");

    let sources = db.list_community_feeds().await.unwrap();
    assert_eq!(sources.len(), 3);
    assert_eq!(sources[0].source, "campaign");
    assert_eq!(sources[0].kind, "campaign");
    assert_eq!(sources[0].source_label, "Campaign auto-block");
    assert_eq!(sources[1].source, "agent-alpha");
    assert_eq!(sources[1].kind, "agent");
    assert_eq!(sources[1].source_label, "Tokyo edge");
    assert_eq!(sources[2].source, "ipsum_feed");
    assert_eq!(sources[2].kind, "community");
}

#[tokio::test]
async fn list_telemetry_orders_by_preserved_event_timestamp() {
    let db = test_db().await;

    db.insert_telemetry_event_with_timestamp(
        "10.0.0.1",
        "Invalid SSH user",
        "alert",
        "agent-a",
        None,
        Some("2026-03-11T09:10:00+00:00"),
    )
    .await
    .unwrap();
    db.insert_telemetry_event_with_timestamp(
        "10.0.0.2",
        "Invalid SSH user",
        "alert",
        "agent-a",
        None,
        Some("2026-03-11T09:00:00+00:00"),
    )
    .await
    .unwrap();

    let telemetry = db.list_telemetry_by_source("agent-a", 10).await.unwrap();
    assert_eq!(telemetry.len(), 2);
    assert_eq!(telemetry[0].ip, "10.0.0.1");
    assert_eq!(telemetry[0].created_at, "2026-03-11T09:10:00+00:00");
    assert_eq!(telemetry[1].ip, "10.0.0.2");
    assert_eq!(telemetry[1].created_at, "2026-03-11T09:00:00+00:00");
}

#[tokio::test]
async fn list_ssh_logins_orders_by_preserved_event_timestamp() {
    let db = test_db().await;

    db.insert_ssh_login_with_timestamp(
        "198.51.100.10",
        "alice",
        "agent-a",
        Some("2026-03-11T09:10:00+00:00"),
    )
    .await
    .unwrap();
    db.insert_ssh_login_with_timestamp(
        "198.51.100.11",
        "bob",
        "agent-a",
        Some("2026-03-11T09:00:00+00:00"),
    )
    .await
    .unwrap();

    let logins = db.list_ssh_logins(10).await.unwrap();
    assert_eq!(logins.len(), 2);
    assert_eq!(logins[0].ip, "198.51.100.10");
    assert_eq!(logins[0].created_at, "2026-03-11T09:10:00+00:00");
    assert_eq!(logins[1].ip, "198.51.100.11");
    assert_eq!(logins[1].created_at, "2026-03-11T09:00:00+00:00");
}

#[tokio::test]
async fn shared_risk_profile_exposes_campaign_category() {
    let db = test_db().await;

    db.insert_telemetry_event("10.0.0.1", "Invalid SSH user", "alert", "agent-a", None)
        .await
        .unwrap();
    db.insert_telemetry_event("10.0.0.2", "Invalid SSH user", "alert", "agent-b", None)
        .await
        .unwrap();
    db.insert_telemetry_event("10.0.0.3", "Invalid SSH user", "block", "agent-a", None)
        .await
        .unwrap();

    let profile = db.compute_shared_risk_profile(600).await.unwrap();
    let category = profile
        .categories
        .iter()
        .find(|row| row.category == "Invalid SSH user")
        .expect("campaign category should exist");

    assert_eq!(category.label, "shared:campaign");
    assert_eq!(category.force_threshold, Some(1));
    assert!(profile.global_risk_score > 0.0);
}

#[tokio::test]
async fn shared_risk_profile_exposes_cross_agent_surge() {
    let db = test_db().await;

    for idx in 0..5 {
        let agent = if idx % 2 == 0 { "agent-a" } else { "agent-b" };
        let ip = if idx % 2 == 0 {
            "192.0.2.10"
        } else {
            "192.0.2.20"
        };
        db.insert_telemetry_event(ip, "Web SQL Injection attempt", "alert", agent, None)
            .await
            .unwrap();
    }

    let profile = db.compute_shared_risk_profile(600).await.unwrap();
    let category = profile
        .categories
        .iter()
        .find(|row| row.category == "Web SQL Injection attempt")
        .expect("surge category should exist");

    assert_eq!(category.label, "shared:surge");
    assert_eq!(category.force_threshold, None);
}

#[tokio::test]
async fn shared_risk_profile_ignores_telemetry_outside_window() {
    let db = test_db().await;
    let recent = Utc::now() - ChronoDuration::seconds(30);
    let stale = Utc::now() - ChronoDuration::minutes(30);

    for idx in 0..5 {
        let agent = if idx % 2 == 0 { "agent-a" } else { "agent-b" };
        let ip = format!("198.51.100.{}", idx + 10);
        db.insert_telemetry_event_with_timestamp(
            &ip,
            "Web SQL Injection attempt",
            "alert",
            agent,
            None,
            Some(&recent.to_rfc3339()),
        )
        .await
        .unwrap();
    }

    db.insert_telemetry_event_with_timestamp(
        "198.51.100.250",
        "Web SQL Injection attempt",
        "block",
        "agent-a",
        None,
        Some(&stale.to_rfc3339()),
    )
    .await
    .unwrap();

    let profile = db.compute_shared_risk_profile(600).await.unwrap();
    let category = profile
        .categories
        .iter()
        .find(|row| row.category == "Web SQL Injection attempt")
        .expect("surge category should exist");

    assert_eq!(category.event_count, 5);
}

#[tokio::test]
async fn detect_campaign_ips_ignores_stale_events_and_existing_decisions() {
    let db = test_db().await;
    let recent = Utc::now() - ChronoDuration::seconds(30);
    let stale = Utc::now() - ChronoDuration::minutes(30);

    db.insert_telemetry_event_with_timestamp(
        "203.0.113.10",
        "Invalid SSH user",
        "alert",
        "agent-a",
        None,
        Some(&recent.to_rfc3339()),
    )
    .await
    .unwrap();
    db.insert_telemetry_event_with_timestamp(
        "203.0.113.11",
        "Invalid SSH user",
        "alert",
        "agent-b",
        None,
        Some(&recent.to_rfc3339()),
    )
    .await
    .unwrap();
    db.insert_telemetry_event_with_timestamp(
        "203.0.113.12",
        "Invalid SSH user",
        "alert",
        "agent-c",
        None,
        Some(&stale.to_rfc3339()),
    )
    .await
    .unwrap();
    db.insert_decision_with_timestamp(
        "203.0.113.10",
        "Campaign auto-block: Invalid SSH user",
        "block",
        "campaign",
        Some(&recent.to_rfc3339()),
    )
    .await
    .unwrap()
    .expect("decision should be inserted");

    let campaigns = db.detect_campaign_ips(600, 2, 2).await.unwrap();
    assert_eq!(
        campaigns,
        vec![("203.0.113.11".to_string(), "Invalid SSH user".to_string())]
    );
}

#[tokio::test]
async fn lookup_ip_activity_combines_local_and_community_history() {
    let db = test_db().await;

    let alpha_id = db
        .insert_agent("agent-alpha", "token-a", None)
        .await
        .unwrap();
    let beta_id = db
        .insert_agent("agent-beta", "token-b", None)
        .await
        .unwrap();
    db.update_agent_nickname(alpha_id, "Tokyo edge")
        .await
        .unwrap();

    db.insert_telemetry_event_with_timestamp(
        "203.0.113.44",
        "SSH repeated connection close",
        "alert",
        "agent-alpha",
        Some("/var/log/auth.log"),
        Some("2026-03-11T09:05:00+00:00"),
    )
    .await
    .unwrap();
    db.insert_telemetry_event_with_timestamp(
        "203.0.113.44",
        "Web SQL Injection attempt",
        "block",
        "agent-beta",
        Some("/var/log/nginx/access.log"),
        Some("2026-03-11T09:10:00+00:00"),
    )
    .await
    .unwrap();

    db.insert_decision_with_timestamp(
        "203.0.113.44",
        "SSH repeated connection close",
        "block",
        "agent-alpha",
        Some("2026-03-11T09:06:00+00:00"),
    )
    .await
    .unwrap()
    .expect("agent decision should be inserted");
    db.insert_decision_with_timestamp(
        "203.0.113.44",
        "Campaign auto-block: SSH brute force",
        "block",
        "campaign",
        Some("2026-03-11T09:12:00+00:00"),
    )
    .await
    .unwrap()
    .expect("campaign decision should be inserted");
    db.insert_decision_with_timestamp(
        "203.0.113.0/24",
        "firehol_level1",
        "block",
        "firehol_level1",
        Some("2026-03-11T08:00:00+00:00"),
    )
    .await
    .unwrap()
    .expect("community cidr decision should be inserted");
    db.insert_decision_with_timestamp(
        "203.0.113.44",
        "ipsum_feed",
        "block",
        "ipsum_feed",
        Some("2026-03-11T08:30:00+00:00"),
    )
    .await
    .unwrap()
    .expect("community exact decision should be inserted");
    db.insert_decision_with_timestamp(
        "198.51.100.0/24",
        "unrelated_feed",
        "block",
        "unrelated_feed",
        Some("2026-03-11T08:40:00+00:00"),
    )
    .await
    .unwrap()
    .expect("unrelated community decision should be inserted");

    let lookup = db.lookup_ip_activity("203.0.113.44", 50).await.unwrap();
    assert_eq!(lookup.ip, "203.0.113.44");
    assert_eq!(lookup.local_history.len(), 2);
    assert_eq!(lookup.local_history[0].source, "agent-beta");
    assert_eq!(lookup.local_history[0].source_label, "agent-beta");
    assert_eq!(lookup.local_history[1].source_label, "Tokyo edge");

    assert_eq!(lookup.machine_summaries.len(), 2);
    assert_eq!(lookup.machine_summaries[0].agent_id, Some(beta_id));
    assert_eq!(lookup.machine_summaries[0].block_count, 1);
    assert_eq!(lookup.machine_summaries[1].source_label, "Tokyo edge");
    assert_eq!(lookup.machine_summaries[1].alert_count, 1);

    assert_eq!(lookup.decision_history.len(), 2);
    assert_eq!(lookup.decision_history[0].source, "campaign");
    assert_eq!(
        lookup.decision_history[0].source_label,
        "Campaign auto-block"
    );
    assert_eq!(lookup.decision_history[1].source, "agent-alpha");

    assert_eq!(lookup.community_matches.len(), 2);
    assert!(lookup
        .community_matches
        .iter()
        .any(|row| row.source == "ipsum_feed" && row.matched_entry == "203.0.113.44"));
    assert!(lookup
        .community_matches
        .iter()
        .any(|row| row.source == "firehol_level1" && row.matched_entry == "203.0.113.0/24"));
}

#[tokio::test]
async fn whitelist_skips_new_decisions() {
    let db = test_db().await;

    db.upsert_whitelist_entry("203.0.113.44", Some("trusted admin"))
        .await
        .unwrap();

    let inserted = db
        .insert_decision("203.0.113.44", "Test reason", "block", "agent")
        .await
        .unwrap();
    assert_eq!(inserted, None);
    assert!(db.list_decisions(10).await.unwrap().is_empty());
}

#[tokio::test]
async fn cidr_whitelist_skips_covered_exact_decisions() {
    let db = test_db().await;

    db.upsert_whitelist_entry("203.0.113.44/24", Some("office"))
        .await
        .unwrap();

    let inserted = db
        .insert_decision("203.0.113.88", "Test reason", "block", "agent")
        .await
        .unwrap();
    assert_eq!(inserted, None);
}

#[tokio::test]
async fn whitelist_insert_removes_existing_decisions_for_same_ip() {
    let db = test_db().await;

    db.insert_decision("198.51.100.70", "Block me", "block", "agent")
        .await
        .unwrap()
        .expect("decision should be inserted");
    db.insert_decision("198.51.100.71", "Keep me", "block", "agent")
        .await
        .unwrap()
        .expect("decision should be inserted");

    let entry = db
        .upsert_whitelist_entry("198.51.100.70", Some("admin override"))
        .await
        .unwrap();
    assert_eq!(entry.ip, "198.51.100.70");

    let decisions = db.list_decisions(10).await.unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].ip, "198.51.100.71");
}

#[tokio::test]
async fn cidr_whitelist_removes_covered_exact_and_narrower_decisions_only() {
    let db = test_db().await;

    db.insert_decision("203.0.113.44", "Block host", "block", "agent")
        .await
        .unwrap()
        .expect("host decision should be inserted");
    db.insert_decision("203.0.113.0/25", "Block subnet", "block", "feed")
        .await
        .unwrap()
        .expect("narrow subnet should be inserted");
    db.insert_decision("203.0.113.0/24", "Keep broader subnet", "block", "feed")
        .await
        .unwrap()
        .expect("broader subnet should be inserted");

    let entry = db
        .upsert_whitelist_entry("203.0.113.99/25", Some("office half"))
        .await
        .unwrap();
    assert_eq!(entry.ip, "203.0.113.0/25");

    let decisions = db.list_decisions(10).await.unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].ip, "203.0.113.0/24");
}

#[tokio::test]
async fn exact_ip_whitelist_does_not_remove_broader_cidr_decision() {
    let db = test_db().await;

    db.insert_decision("203.0.113.0/24", "Keep subnet", "block", "feed")
        .await
        .unwrap()
        .expect("subnet decision should be inserted");

    db.upsert_whitelist_entry("203.0.113.44", Some("single host"))
        .await
        .unwrap();

    let decisions = db.list_decisions(10).await.unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].ip, "203.0.113.0/24");
}
