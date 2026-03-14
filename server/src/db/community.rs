use super::*;

impl Db {
    pub async fn list_community_ips(&self, limit: i64) -> anyhow::Result<Vec<CommunityIpRow>> {
        let rows = sqlx::query_as::<_, (String, String, Option<i64>, Option<String>, i64, String)>(
            r#"
            SELECT
                d.ip,
                d.source,
                a.id,
                a.nickname,
                COUNT(*) as sightings,
                MAX(d.created_at) as last_seen_at
            FROM decisions d
            LEFT JOIN agents a ON a.name = d.source
            GROUP BY d.ip, d.source
            ORDER BY last_seen_at DESC
            LIMIT ?
            "#,
        )
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(ip, source, agent_id, nickname, sightings, last_seen_at)| CommunityIpRow {
                    ip,
                    source_label: source_label(&source, nickname),
                    kind: source_kind(&source, agent_id).to_string(),
                    source,
                    sightings,
                    last_seen_at,
                },
            )
            .collect())
    }

    pub async fn list_community_feeds(&self) -> anyhow::Result<Vec<CommunityFeedRow>> {
        let rows = sqlx::query_as::<_, (String, Option<i64>, Option<String>, i64, String, String)>(
            r#"
            SELECT
                d.source,
                a.id,
                a.nickname,
                COUNT(DISTINCT d.ip) as ip_count,
                MIN(d.created_at) as first_seen_at,
                MAX(d.created_at) as last_seen_at
            FROM decisions d
            LEFT JOIN agents a ON a.name = d.source
            GROUP BY d.source, a.id, a.nickname
            ORDER BY
                CASE
                    WHEN d.source = 'campaign' THEN 0
                    WHEN a.id IS NOT NULL THEN 1
                    ELSE 2
                END,
                last_seen_at DESC
            "#,
        )
        .fetch_all(&self.0)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(source, agent_id, nickname, ip_count, first_seen_at, last_seen_at)| {
                    CommunityFeedRow {
                        source_label: source_label(&source, nickname),
                        kind: source_kind(&source, agent_id).to_string(),
                        source,
                        ip_count,
                        first_seen_at,
                        last_seen_at,
                    }
                },
            )
            .collect())
    }

    pub async fn list_community_feed_ips(
        &self,
        source: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<CommunityFeedIpRow>> {
        let rows = sqlx::query_as::<_, (String, String, i64, String, String)>(
            r#"
            SELECT
                d.ip,
                MAX(d.reason) as reason,
                COUNT(*) as sightings,
                MIN(d.created_at) as first_seen_at,
                MAX(d.created_at) as last_seen_at
            FROM decisions d
            WHERE d.source = ?
            GROUP BY d.ip
            ORDER BY last_seen_at DESC
            LIMIT ?
            "#,
        )
        .bind(source)
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(ip, reason, sightings, first_seen_at, last_seen_at)| CommunityFeedIpRow {
                    ip,
                    reason,
                    sightings,
                    first_seen_at,
                    last_seen_at,
                },
            )
            .collect())
    }

    pub async fn lookup_ip_activity(
        &self,
        ip: &str,
        history_limit: i64,
    ) -> anyhow::Result<IpLookupResponse> {
        let local_history_rows = sqlx::query_as::<
            _,
            (
                i64,
                String,
                String,
                String,
                Option<i64>,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                String,
            ),
        >(
            r#"
            SELECT
                t.id,
                t.source,
                t.reason,
                t.level,
                a.id,
                COALESCE(NULLIF(a.nickname, ''), a.name) as agent_display_name,
                t.log_path,
                t.country,
                t.asn_org,
                t.created_at
            FROM telemetry_events t
            LEFT JOIN agents a ON a.name = t.source
            WHERE t.ip = ?
            ORDER BY t.created_at DESC, t.id DESC
            LIMIT ?
            "#,
        )
        .bind(ip)
        .bind(history_limit)
        .fetch_all(&self.0)
        .await?;

        let local_history = local_history_rows
            .into_iter()
            .map(
                |(
                    id,
                    source,
                    reason,
                    level,
                    agent_id,
                    agent_display_name,
                    log_path,
                    country,
                    asn_org,
                    created_at,
                )| IpLookupEventRow {
                    id,
                    source: source.clone(),
                    source_label: source_label(&source, agent_display_name),
                    agent_id,
                    reason,
                    level,
                    log_path,
                    country: country.and_then(normalize_lookup_geo),
                    asn_org: asn_org.and_then(normalize_lookup_geo),
                    created_at,
                },
            )
            .collect::<Vec<_>>();

        let machine_summary_rows = sqlx::query_as::<
            _,
            (
                String,
                Option<i64>,
                Option<String>,
                i64,
                i64,
                i64,
                i64,
                String,
                String,
                Option<String>,
            ),
        >(
            r#"
            SELECT
                t.source,
                a.id,
                COALESCE(NULLIF(a.nickname, ''), a.name) as agent_display_name,
                COUNT(*) as event_count,
                SUM(CASE WHEN t.level = 'alert' THEN 1 ELSE 0 END) as alert_count,
                SUM(CASE WHEN t.level = 'listed' THEN 1 ELSE 0 END) as listed_count,
                SUM(CASE WHEN t.level = 'block' THEN 1 ELSE 0 END) as block_count,
                MIN(t.created_at) as first_seen_at,
                MAX(t.created_at) as last_seen_at,
                (
                    SELECT t2.reason
                    FROM telemetry_events t2
                    WHERE t2.ip = t.ip
                      AND t2.source = t.source
                    ORDER BY t2.created_at DESC, t2.id DESC
                    LIMIT 1
                ) as last_reason
            FROM telemetry_events t
            LEFT JOIN agents a ON a.name = t.source
            WHERE t.ip = ?
            GROUP BY t.source, a.id, a.nickname, a.name
            ORDER BY MAX(t.created_at) DESC, t.source ASC
            "#,
        )
        .bind(ip)
        .fetch_all(&self.0)
        .await?;

        let machine_summaries = machine_summary_rows
            .into_iter()
            .map(
                |(
                    source,
                    agent_id,
                    agent_display_name,
                    event_count,
                    alert_count,
                    listed_count,
                    block_count,
                    first_seen_at,
                    last_seen_at,
                    last_reason,
                )| IpLookupMachineSummaryRow {
                    agent_id,
                    source: source.clone(),
                    source_label: source_label(&source, agent_display_name),
                    event_count,
                    alert_count,
                    listed_count,
                    block_count,
                    first_seen_at,
                    last_seen_at,
                    last_reason: last_reason.unwrap_or_else(|| "Unknown".to_string()),
                },
            )
            .collect::<Vec<_>>();

        let decision_rows = sqlx::query_as::<
            _,
            (
                i64,
                String,
                String,
                String,
                Option<i64>,
                Option<String>,
                Option<String>,
                Option<String>,
                String,
                Option<String>,
            ),
        >(
            r#"
            SELECT
                d.id,
                d.source,
                d.reason,
                d.action,
                a.id,
                COALESCE(NULLIF(a.nickname, ''), a.name) as agent_display_name,
                d.country,
                d.asn_org,
                d.created_at,
                d.expires_at
            FROM decisions d
            LEFT JOIN agents a ON a.name = d.source
            WHERE d.ip = ?
              AND (a.id IS NOT NULL OR d.source = 'campaign')
            ORDER BY d.created_at DESC, d.id DESC
            LIMIT ?
            "#,
        )
        .bind(ip)
        .bind(history_limit)
        .fetch_all(&self.0)
        .await?;

        let decision_history = decision_rows
            .into_iter()
            .map(
                |(
                    id,
                    source,
                    reason,
                    action,
                    agent_id,
                    agent_display_name,
                    country,
                    asn_org,
                    created_at,
                    expires_at,
                )| IpLookupDecisionRow {
                    id,
                    source: source.clone(),
                    source_label: source_label(&source, agent_display_name),
                    agent_id,
                    reason,
                    action,
                    country: country.and_then(normalize_lookup_geo),
                    asn_org: asn_org.and_then(normalize_lookup_geo),
                    created_at,
                    expires_at,
                },
            )
            .collect::<Vec<_>>();

        let community_candidate_rows =
            sqlx::query_as::<_, (String, String, String, i64, String, String)>(
                r#"
                SELECT
                    d.ip,
                    d.source,
                    MAX(d.reason) as reason,
                    COUNT(*) as sightings,
                    MIN(d.created_at) as first_seen_at,
                    MAX(d.created_at) as last_seen_at
                FROM decisions d
                LEFT JOIN agents a ON a.name = d.source
                WHERE a.id IS NULL
                  AND d.source != 'campaign'
                  AND (d.ip = ? OR instr(d.ip, '/') > 0)
                GROUP BY d.ip, d.source
                ORDER BY last_seen_at DESC, d.source ASC
                "#,
            )
            .bind(ip)
            .fetch_all(&self.0)
            .await?;

        let mut community_matches = community_candidate_rows
            .into_iter()
            .filter(|(pattern, _, _, _, _, _)| pattern_covers_pattern(pattern, ip))
            .map(
                |(matched_entry, source, reason, sightings, first_seen_at, last_seen_at)| {
                    IpLookupCommunityMatchRow {
                        source,
                        matched_entry,
                        reason,
                        sightings,
                        first_seen_at,
                        last_seen_at,
                    }
                },
            )
            .collect::<Vec<_>>();

        community_matches.sort_by(|a, b| {
            b.last_seen_at
                .cmp(&a.last_seen_at)
                .then_with(|| a.source.cmp(&b.source))
                .then_with(|| a.matched_entry.cmp(&b.matched_entry))
        });

        let geo = geoip::lookup(ip);
        let country = local_history
            .iter()
            .find_map(|row| row.country.clone())
            .or_else(|| decision_history.iter().find_map(|row| row.country.clone()))
            .or_else(|| normalize_lookup_geo(geo.country));
        let asn_org = local_history
            .iter()
            .find_map(|row| row.asn_org.clone())
            .or_else(|| decision_history.iter().find_map(|row| row.asn_org.clone()))
            .or_else(|| normalize_lookup_geo(geo.asn_org));

        Ok(IpLookupResponse {
            ip: ip.to_string(),
            country,
            asn_org,
            local_history,
            decision_history,
            machine_summaries,
            community_matches,
        })
    }

    pub async fn detect_campaign_ips(
        &self,
        window_secs: i64,
        min_distinct_ips: usize,
        min_distinct_agents: usize,
    ) -> anyhow::Result<Vec<(String, String)>> {
        let rows = sqlx::query_as::<_, (String, String, String)>(
            r#"
            SELECT ip, reason, source
            FROM telemetry_events
            WHERE datetime(created_at) > datetime('now', '-' || ? || ' seconds')
              AND level IN ('alert', 'block')
            "#,
        )
        .bind(window_secs)
        .fetch_all(&self.0)
        .await?;

        use std::collections::{HashMap, HashSet};
        let mut cat_ips: HashMap<String, HashSet<String>> = HashMap::new();
        let mut cat_agents: HashMap<String, HashSet<String>> = HashMap::new();
        let mut ip_categories: HashMap<String, String> = HashMap::new();

        for (ip, reason, source) in &rows {
            let cat = normalize_reason_category(reason).to_string();
            cat_ips.entry(cat.clone()).or_default().insert(ip.clone());
            cat_agents
                .entry(cat.clone())
                .or_default()
                .insert(source.clone());
            ip_categories.insert(ip.clone(), cat);
        }

        let campaign_cats: HashSet<String> = cat_ips
            .iter()
            .filter(|(cat, ips)| {
                ips.len() >= min_distinct_ips
                    && cat_agents.get(*cat).map(|agents| agents.len()).unwrap_or(0)
                        >= min_distinct_agents
            })
            .map(|(cat, _)| cat.clone())
            .collect();

        if campaign_cats.is_empty() {
            return Ok(vec![]);
        }

        let mut candidates = Vec::new();
        for (ip, cat) in &ip_categories {
            if campaign_cats.contains(cat) {
                candidates.push((ip.clone(), cat.clone()));
            }
        }

        let already_blocked: HashSet<String> =
            sqlx::query_as::<_, (String,)>("SELECT DISTINCT ip FROM decisions")
                .fetch_all(&self.0)
                .await?
                .into_iter()
                .map(|(ip,)| ip)
                .collect();

        Ok(candidates
            .into_iter()
            .filter(|(ip, _)| !already_blocked.contains(ip))
            .collect())
    }

    pub async fn compute_shared_risk_profile(
        &self,
        window_secs: i64,
    ) -> anyhow::Result<SharedRiskProfileRow> {
        use std::collections::{HashMap, HashSet};

        let window_secs = window_secs.max(60);
        let rows = sqlx::query_as::<_, (String, String, String, String)>(
            r#"
            SELECT ip, reason, level, source
            FROM telemetry_events
            WHERE datetime(created_at) > datetime('now', '-' || ? || ' seconds')
              AND level IN ('alert', 'block', 'listed')
            "#,
        )
        .bind(window_secs)
        .fetch_all(&self.0)
        .await?;

        let mut global_weight = 0.0f64;
        let mut by_category: HashMap<String, (HashSet<String>, HashSet<String>, u32, f64)> =
            HashMap::new();

        for (ip, reason, level, source) in rows {
            let category = normalize_reason_category(&reason).to_string();
            let weight = telemetry_level_weight(&level);
            global_weight += weight;

            let entry = by_category
                .entry(category)
                .or_insert_with(|| (HashSet::new(), HashSet::new(), 0_u32, 0.0_f64));
            entry.0.insert(ip);
            entry.1.insert(source);
            entry.2 += 1;
            entry.3 += weight;
        }

        let global_risk_score = (global_weight / 30.0).clamp(0.0, 1.0);
        let global_threshold_multiplier = 1.0 - global_risk_score * 0.5;

        let mut categories = by_category
            .into_iter()
            .filter_map(|(category, (ips, agents, event_count, weighted_events))| {
                let distinct_ips = ips.len() as u32;
                let distinct_agents = agents.len() as u32;

                if distinct_agents < 2 {
                    return None;
                }

                if distinct_ips >= 3 {
                    return Some(SharedRiskCategoryRow {
                        category,
                        distinct_ips,
                        distinct_agents,
                        event_count,
                        threshold_multiplier: 0.25,
                        force_threshold: Some(1),
                        label: "shared:campaign".to_string(),
                    });
                }

                if event_count >= 5 || weighted_events >= 6.0 {
                    return Some(SharedRiskCategoryRow {
                        category,
                        distinct_ips,
                        distinct_agents,
                        event_count,
                        threshold_multiplier: 0.5,
                        force_threshold: None,
                        label: "shared:surge".to_string(),
                    });
                }

                None
            })
            .collect::<Vec<_>>();

        categories.sort_by(|a, b| {
            a.force_threshold
                .unwrap_or(u32::MAX)
                .cmp(&b.force_threshold.unwrap_or(u32::MAX))
                .then(b.event_count.cmp(&a.event_count))
                .then(a.category.cmp(&b.category))
        });

        Ok(SharedRiskProfileRow {
            generated_at: Utc::now().to_rfc3339(),
            window_secs,
            global_risk_score,
            global_threshold_multiplier,
            categories,
        })
    }
}
