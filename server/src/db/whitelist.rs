use super::*;

impl Db {
    pub async fn list_whitelist_entries(
        &self,
        limit: i64,
    ) -> anyhow::Result<Vec<WhitelistEntryRow>> {
        let rows = sqlx::query_as::<_, (i64, String, Option<String>, String)>(
            "SELECT id, ip, note, created_at FROM whitelist_entries ORDER BY created_at DESC, id DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(id, ip, note, created_at)| WhitelistEntryRow {
                id,
                ip,
                note,
                created_at,
            })
            .collect())
    }

    pub async fn is_ip_whitelisted(&self, ip: &str) -> anyhow::Result<bool> {
        let rows = sqlx::query_as::<_, (String,)>("SELECT ip FROM whitelist_entries")
            .fetch_all(&self.0)
            .await?;

        Ok(rows
            .into_iter()
            .any(|(pattern,)| pattern_covers_pattern(&pattern, ip)))
    }

    pub async fn upsert_whitelist_entry(
        &self,
        ip: &str,
        note: Option<&str>,
    ) -> anyhow::Result<WhitelistEntryRow> {
        let ip = canonicalize_ip_pattern(ip)
            .ok_or_else(|| anyhow::anyhow!("invalid whitelist IP/CIDR pattern: {}", ip))?;
        let created_at = Utc::now().to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO whitelist_entries (ip, note, created_at)
            VALUES (?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                note = excluded.note
            "#,
        )
        .bind(&ip)
        .bind(note)
        .bind(&created_at)
        .execute(&self.0)
        .await?;

        let decisions = sqlx::query_as::<_, (i64, String)>("SELECT id, ip FROM decisions")
            .fetch_all(&self.0)
            .await?;

        for (id, decision_ip) in decisions {
            let remove = if ip.contains('/') {
                pattern_covers_pattern(&ip, &decision_ip)
            } else {
                decision_ip == ip
            };
            if remove {
                sqlx::query("DELETE FROM decisions WHERE id = ?")
                    .bind(id)
                    .execute(&self.0)
                    .await?;
            }
        }

        let (id, ip, note, created_at) =
            sqlx::query_as::<_, (i64, String, Option<String>, String)>(
                "SELECT id, ip, note, created_at FROM whitelist_entries WHERE ip = ?",
            )
            .bind(&ip)
            .fetch_one(&self.0)
            .await?;

        Ok(WhitelistEntryRow {
            id,
            ip,
            note,
            created_at,
        })
    }

    pub async fn delete_whitelist_entry(&self, id: i64) -> anyhow::Result<bool> {
        let result = sqlx::query("DELETE FROM whitelist_entries WHERE id = ?")
            .bind(id)
            .execute(&self.0)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn backfill_decision_geoip_unknowns(&self) -> anyhow::Result<u64> {
        let ips = sqlx::query_as::<_, (String,)>(
            r#"
            SELECT DISTINCT ip
            FROM decisions
            WHERE country IS NULL
               OR asn_org IS NULL
               OR TRIM(country) = ''
               OR TRIM(asn_org) = ''
            "#,
        )
        .fetch_all(&self.0)
        .await?;

        let mut updated = 0u64;
        for (ip,) in ips {
            let geo = geoip::lookup(&ip);
            let result = sqlx::query(
                r#"
                UPDATE decisions
                SET
                    country = CASE WHEN country IS NULL OR TRIM(country) = '' THEN ? ELSE country END,
                    asn_org = CASE WHEN asn_org IS NULL OR TRIM(asn_org) = '' THEN ? ELSE asn_org END
                WHERE ip = ?
                  AND (
                    country IS NULL OR TRIM(country) = ''
                    OR asn_org IS NULL OR TRIM(asn_org) = ''
                  )
                "#,
            )
            .bind(geo.country)
            .bind(geo.asn_org)
            .bind(ip)
            .execute(&self.0)
            .await?;
            updated += result.rows_affected();
        }

        Ok(updated)
    }

    pub async fn backfill_decision_geoip_for_source(&self, source: &str) -> anyhow::Result<u64> {
        let ips = sqlx::query_as::<_, (String,)>(
            r#"
            SELECT DISTINCT ip
            FROM decisions
            WHERE source = ?
              AND (
                country IS NULL OR TRIM(country) = ''
                OR asn_org IS NULL OR TRIM(asn_org) = ''
              )
            "#,
        )
        .bind(source)
        .fetch_all(&self.0)
        .await?;

        let mut updated = 0u64;
        for (ip,) in ips {
            let geo = geoip::lookup(&ip);
            let result = sqlx::query(
                r#"
                UPDATE decisions
                SET
                    country = CASE WHEN country IS NULL OR TRIM(country) = '' THEN ? ELSE country END,
                    asn_org = CASE WHEN asn_org IS NULL OR TRIM(asn_org) = '' THEN ? ELSE asn_org END
                WHERE source = ?
                  AND ip = ?
                  AND (
                    country IS NULL OR TRIM(country) = ''
                    OR asn_org IS NULL OR TRIM(asn_org) = ''
                  )
                "#,
            )
            .bind(geo.country)
            .bind(geo.asn_org)
            .bind(source)
            .bind(ip)
            .execute(&self.0)
            .await?;
            updated += result.rows_affected();
        }

        Ok(updated)
    }
}
