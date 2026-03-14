use super::*;

impl Db {
    pub async fn insert_decision(
        &self,
        ip: &str,
        reason: &str,
        action: &str,
        source: &str,
    ) -> anyhow::Result<Option<i64>> {
        self.insert_decision_with_timestamp(ip, reason, action, source, None)
            .await
    }

    pub async fn insert_decision_with_timestamp(
        &self,
        ip: &str,
        reason: &str,
        action: &str,
        source: &str,
        timestamp: Option<&str>,
    ) -> anyhow::Result<Option<i64>> {
        if self.is_ip_whitelisted(ip).await? {
            return Ok(None);
        }

        let created_at = normalize_event_timestamp(timestamp);
        let geo = geoip::lookup(ip);
        let result = sqlx::query(
            r#"
            INSERT INTO decisions (ip, reason, action, source, country, asn_org, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(ip)
        .bind(reason)
        .bind(action)
        .bind(source)
        .bind(&geo.country)
        .bind(&geo.asn_org)
        .bind(&created_at)
        .execute(&self.0)
        .await?;

        Ok(Some(result.last_insert_rowid()))
    }

    pub async fn insert_telemetry_event(
        &self,
        ip: &str,
        reason: &str,
        level: &str,
        source: &str,
        log_path: Option<&str>,
    ) -> anyhow::Result<i64> {
        self.insert_telemetry_event_with_timestamp(ip, reason, level, source, log_path, None)
            .await
    }

    pub async fn insert_telemetry_event_with_timestamp(
        &self,
        ip: &str,
        reason: &str,
        level: &str,
        source: &str,
        log_path: Option<&str>,
        timestamp: Option<&str>,
    ) -> anyhow::Result<i64> {
        let created_at = normalize_event_timestamp(timestamp);
        let geo = geoip::lookup(ip);
        let result = sqlx::query(
            r#"
            INSERT INTO telemetry_events (ip, reason, level, source, log_path, country, asn_org, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(ip)
        .bind(reason)
        .bind(level)
        .bind(source)
        .bind(log_path)
        .bind(&geo.country)
        .bind(&geo.asn_org)
        .bind(&created_at)
        .execute(&self.0)
        .await?;

        Ok(result.last_insert_rowid())
    }

    pub async fn insert_ssh_login(
        &self,
        ip: &str,
        username: &str,
        agent_name: &str,
    ) -> anyhow::Result<i64> {
        self.insert_ssh_login_with_timestamp(ip, username, agent_name, None)
            .await
    }

    pub async fn insert_ssh_login_with_timestamp(
        &self,
        ip: &str,
        username: &str,
        agent_name: &str,
        timestamp: Option<&str>,
    ) -> anyhow::Result<i64> {
        let created_at = normalize_event_timestamp(timestamp);
        let geo = geoip::lookup(ip);
        let result = sqlx::query(
            r#"
            INSERT INTO ssh_logins (ip, username, agent_name, country, asn_org, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(ip)
        .bind(username)
        .bind(agent_name)
        .bind(&geo.country)
        .bind(&geo.asn_org)
        .bind(&created_at)
        .execute(&self.0)
        .await?;
        Ok(result.last_insert_rowid())
    }

    pub async fn list_ssh_logins(&self, limit: i64) -> anyhow::Result<Vec<SshLoginRow>> {
        let rows = sqlx::query_as::<
            _,
            (
                i64,
                String,
                String,
                String,
                Option<String>,
                Option<String>,
                String,
            ),
        >(
            "SELECT id, ip, username, agent_name, country, asn_org, created_at \
             FROM ssh_logins ORDER BY created_at DESC, id DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, ip, username, agent_name, country, asn_org, created_at)| SshLoginRow {
                    id,
                    ip,
                    username,
                    agent_name,
                    country,
                    asn_org,
                    created_at,
                },
            )
            .collect())
    }

    pub async fn list_decisions_since(
        &self,
        since_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<DecisionRow>> {
        let rows = sqlx::query_as::<
            _,
            (
                i64,
                String,
                String,
                String,
                String,
                Option<String>,
                Option<String>,
                String,
                Option<String>,
            ),
        >(
            "SELECT id, ip, reason, action, source, country, asn_org, created_at, expires_at FROM decisions \
             WHERE id > ? ORDER BY id ASC LIMIT ?",
        )
        .bind(since_id)
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, ip, reason, action, source, country, asn_org, created_at, expires_at)| {
                    DecisionRow {
                        id,
                        ip,
                        reason,
                        action,
                        source,
                        country,
                        asn_org,
                        created_at,
                        expires_at,
                    }
                },
            )
            .collect())
    }

    pub async fn list_local_decisions_since(
        &self,
        since_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<DecisionRow>> {
        let rows = sqlx::query_as::<
            _,
            (
                i64,
                String,
                String,
                String,
                String,
                Option<String>,
                Option<String>,
                String,
                Option<String>,
            ),
        >(
            r#"
            SELECT d.id, d.ip, d.reason, d.action, d.source, d.country, d.asn_org, d.created_at, d.expires_at
            FROM decisions d
            LEFT JOIN agents a ON a.name = d.source
            WHERE d.id > ? AND (a.id IS NOT NULL OR d.source = 'campaign')
            ORDER BY d.id ASC
            LIMIT ?
            "#,
        )
        .bind(since_id)
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, ip, reason, action, source, country, asn_org, created_at, expires_at)| {
                    DecisionRow {
                        id,
                        ip,
                        reason,
                        action,
                        source,
                        country,
                        asn_org,
                        created_at,
                        expires_at,
                    }
                },
            )
            .collect())
    }

    pub async fn list_decisions(&self, limit: i64) -> anyhow::Result<Vec<DecisionRow>> {
        let rows = sqlx::query_as::<
            _,
            (
                i64,
                String,
                String,
                String,
                String,
                Option<String>,
                Option<String>,
                String,
                Option<String>,
            ),
        >(
            "SELECT id, ip, reason, action, source, country, asn_org, created_at, expires_at FROM decisions ORDER BY created_at DESC, id DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, ip, reason, action, source, country, asn_org, created_at, expires_at)| {
                    DecisionRow {
                        id,
                        ip,
                        reason,
                        action,
                        source,
                        country,
                        asn_org,
                        created_at,
                        expires_at,
                    }
                },
            )
            .collect())
    }

    pub async fn list_local_decisions(&self, limit: i64) -> anyhow::Result<Vec<DecisionRow>> {
        let rows = sqlx::query_as::<
            _,
            (
                i64,
                String,
                String,
                String,
                String,
                Option<String>,
                Option<String>,
                String,
                Option<String>,
            ),
        >(
            r#"
            SELECT d.id, d.ip, d.reason, d.action, d.source, d.country, d.asn_org, d.created_at, d.expires_at
            FROM decisions d
            LEFT JOIN agents a ON a.name = d.source
            WHERE a.id IS NOT NULL OR d.source = 'campaign'
            ORDER BY d.created_at DESC, d.id DESC
            LIMIT ?
            "#,
        )
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, ip, reason, action, source, country, asn_org, created_at, expires_at)| {
                    DecisionRow {
                        id,
                        ip,
                        reason,
                        action,
                        source,
                        country,
                        asn_org,
                        created_at,
                        expires_at,
                    }
                },
            )
            .collect())
    }

    pub async fn list_decisions_by_source(
        &self,
        source: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<DecisionRow>> {
        let rows = sqlx::query_as::<
            _,
            (
                i64,
                String,
                String,
                String,
                String,
                Option<String>,
                Option<String>,
                String,
                Option<String>,
            ),
        >(
            "SELECT id, ip, reason, action, source, country, asn_org, created_at, expires_at FROM decisions WHERE source = ? ORDER BY created_at DESC, id DESC LIMIT ?",
        )
        .bind(source)
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, ip, reason, action, source, country, asn_org, created_at, expires_at)| {
                    DecisionRow {
                        id,
                        ip,
                        reason,
                        action,
                        source,
                        country,
                        asn_org,
                        created_at,
                        expires_at,
                    }
                },
            )
            .collect())
    }

    pub async fn list_telemetry_by_source(
        &self,
        source: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<TelemetryRow>> {
        let rows = sqlx::query_as::<
            _,
            (
                i64,
                String,
                String,
                String,
                String,
                Option<String>,
                Option<String>,
                Option<String>,
                String,
            ),
        >(
            "SELECT id, ip, reason, level, source, log_path, country, asn_org, created_at FROM telemetry_events WHERE source = ? ORDER BY created_at DESC, id DESC LIMIT ?",
        )
        .bind(source)
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, ip, reason, level, source, log_path, country, asn_org, created_at)| {
                    TelemetryRow {
                        id,
                        ip,
                        reason,
                        level,
                        source,
                        log_path,
                        country,
                        asn_org,
                        created_at,
                    }
                },
            )
            .collect())
    }

    pub async fn list_telemetry(&self, limit: i64) -> anyhow::Result<Vec<TelemetryRow>> {
        let rows = sqlx::query_as::<
            _,
            (
                i64,
                String,
                String,
                String,
                String,
                Option<String>,
                Option<String>,
                Option<String>,
                String,
            ),
        >(
            "SELECT id, ip, reason, level, source, log_path, country, asn_org, created_at FROM telemetry_events ORDER BY created_at DESC, id DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, ip, reason, level, source, log_path, country, asn_org, created_at)| {
                    TelemetryRow {
                        id,
                        ip,
                        reason,
                        level,
                        source,
                        log_path,
                        country,
                        asn_org,
                        created_at,
                    }
                },
            )
            .collect())
    }
}
