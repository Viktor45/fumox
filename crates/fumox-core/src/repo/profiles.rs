//! CRUD for the `profiles` and `profile_sources` tables.

use crate::db::DbPool;
use crate::models::Profile;
use sqlx::FromRow;

#[derive(FromRow)]
struct ProfileRow {
    id: String,
    slug: Option<String>,
    access_token: Option<String>,
    name: String,
    output_format: String,
    pipeline: Option<String>,
    countries: Option<String>,
    enabled: i64,
    created_at: i64,
    updated_at: i64,
}

impl TryFrom<ProfileRow> for Profile {
    type Error = crate::Error;

    fn try_from(row: ProfileRow) -> Result<Self, Self::Error> {
        Ok(Profile {
            id: row.id,
            slug: row.slug,
            access_token: row.access_token,
            name: row.name,
            output_format: row.output_format.parse()?,
            pipeline: row
                .pipeline
                .map(|text| super::text_to_json(&text, "profiles.pipeline"))
                .transpose()?,
            countries: row
                .countries
                .map(|text| {
                    super::text_to_json(&text, "profiles.countries")
                        .and_then(|value| {
                            serde_json::from_value::<Vec<String>>(value).map_err(|e| {
                                crate::Error::Parse(format!("corrupt profiles.countries JSON: {e}"))
                            })
                        })
                        .map(normalize_countries)
                })
                .transpose()?
                .unwrap_or_default(),
            enabled: row.enabled != 0,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

/// Trim, uppercase, drop blanks and duplicates (order-preserving).
fn normalize_countries(list: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    list.into_iter()
        .map(|code| code.trim().to_ascii_uppercase())
        .filter(|code| !code.is_empty())
        .filter(|code| seen.insert(code.clone()))
        .collect()
}

/// `Vec<String>` → stored TEXT: `None` when empty, else a JSON array.
fn countries_to_text(list: &[String]) -> crate::Result<Option<String>> {
    if list.is_empty() {
        return Ok(None);
    }
    let value = serde_json::to_value(list)
        .map_err(|e| crate::Error::Parse(format!("cannot serialize profiles.countries: {e}")))?;
    Ok(Some(super::json_to_text(&value)?))
}

const COLUMNS: &str = "id, slug, access_token, name, output_format, pipeline, countries, enabled, created_at, updated_at";

/// Insert a new profile. The caller assigns `id` (see [`crate::models::new_id`]).
pub async fn create(pool: &DbPool, profile: &Profile) -> crate::Result<()> {
    // sqlx 0.9 SqlSafeStr: {COLUMNS} is a compile-time constant; all data
    // flows through .bind().
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "INSERT INTO profiles ({COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )))
    .bind(&profile.id)
    .bind(&profile.slug)
    .bind(&profile.access_token)
    .bind(&profile.name)
    .bind(profile.output_format.as_str())
    .bind(
        profile
            .pipeline
            .as_ref()
            .map(super::json_to_text)
            .transpose()?,
    )
    .bind(countries_to_text(&profile.countries)?)
    .bind(profile.enabled)
    .bind(profile.created_at)
    .bind(profile.updated_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Update mutable profile fields. `id` and `created_at` are immutable.
pub async fn update(pool: &DbPool, profile: &Profile) -> crate::Result<()> {
    let affected = sqlx::query(
        "UPDATE profiles SET
            slug = ?, access_token = ?, name = ?, output_format = ?, pipeline = ?,
            countries = ?, enabled = ?, updated_at = ?
         WHERE id = ?",
    )
    .bind(&profile.slug)
    .bind(&profile.access_token)
    .bind(&profile.name)
    .bind(profile.output_format.as_str())
    .bind(
        profile
            .pipeline
            .as_ref()
            .map(super::json_to_text)
            .transpose()?,
    )
    .bind(countries_to_text(&profile.countries)?)
    .bind(profile.enabled)
    .bind(profile.updated_at)
    .bind(&profile.id)
    .execute(pool)
    .await?
    .rows_affected();
    if affected == 0 {
        return Err(crate::Error::Database(sqlx::Error::RowNotFound.to_string()));
    }
    Ok(())
}

pub async fn get(pool: &DbPool, id: &str) -> crate::Result<Option<Profile>> {
    let row: Option<ProfileRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM profiles WHERE id = ?"
    )))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    row.map(Profile::try_from).transpose()
}

pub async fn get_by_slug(pool: &DbPool, slug: &str) -> crate::Result<Option<Profile>> {
    let row: Option<ProfileRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM profiles WHERE slug = ?"
    )))
    .bind(slug)
    .fetch_optional(pool)
    .await?;
    row.map(Profile::try_from).transpose()
}

/// Resolve a `/sub/{token}` path segment: slug first, then raw id.
pub async fn resolve_token(pool: &DbPool, token: &str) -> crate::Result<Option<Profile>> {
    let row: Option<ProfileRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM profiles WHERE slug = ? OR id = ? ORDER BY slug IS NULL LIMIT 1"
    )))
    .bind(token)
    .bind(token)
    .fetch_optional(pool)
    .await?;
    row.map(Profile::try_from).transpose()
}

pub async fn list(pool: &DbPool, enabled_only: bool) -> crate::Result<Vec<Profile>> {
    let query = if enabled_only {
        format!("SELECT {COLUMNS} FROM profiles WHERE enabled = 1 ORDER BY created_at")
    } else {
        format!("SELECT {COLUMNS} FROM profiles ORDER BY created_at")
    };
    let rows: Vec<ProfileRow> = sqlx::query_as(sqlx::AssertSqlSafe(query.as_str()))
        .fetch_all(pool)
        .await?;
    rows.into_iter().map(Profile::try_from).collect()
}

pub async fn delete(pool: &DbPool, id: &str) -> crate::Result<bool> {
    let affected = sqlx::query("DELETE FROM profiles WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected();
    Ok(affected > 0)
}

/// Replace the full source composition of a profile in one transaction.
/// `sources` is `(source_id, position)` in merge order.
pub async fn set_sources(
    pool: &DbPool,
    profile_id: &str,
    sources: &[(String, i64)],
) -> crate::Result<()> {
    // BEGIN IMMEDIATE: grabs the WAL write lock up front instead of a
    // deferred read→write upgrade (which busy_timeout cannot cover, the
    // upgrade fails with SQLITE_BUSY_SNAPSHOT when another process
    // committed since our snapshot; see proxies::reconcile_source).
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    sqlx::query("DELETE FROM profile_sources WHERE profile_id = ?")
        .bind(profile_id)
        .execute(&mut *tx)
        .await?;
    for (source_id, position) in sources {
        sqlx::query(
            "INSERT INTO profile_sources (profile_id, source_id, position) VALUES (?, ?, ?)",
        )
        .bind(profile_id)
        .bind(source_id)
        .bind(position)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Source ids of a profile in merge order.
pub async fn get_sources(pool: &DbPool, profile_id: &str) -> crate::Result<Vec<(String, i64)>> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT source_id, position FROM profile_sources
         WHERE profile_id = ? ORDER BY position, source_id",
    )
    .bind(profile_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

// Admin profile screens
//
// Fixed-shape reads of the profiles list and card, typed so the admin
// handlers go through the repository like every other caller.

/// One row of the admin profiles list: the display columns plus the
/// composition size and the ready-proxy count ([`list_with_counts`]).
#[derive(Debug, FromRow)]
pub struct ProfileListRow {
    pub id: String,
    pub name: String,
    pub slug: Option<String>,
    pub output_format: String,
    pub enabled: bool,
    /// Whether the profile carries an access token.
    pub protected: bool,
    /// Number of sources in the composition.
    pub sources_count: i64,
    /// Ready proxies reachable through the profile's sources: `status =
    /// 'ready'`, i.e. the set the `/sub/{slug}` endpoint would actually
    /// emit right now. A proxy reachable through more than one source in
    /// the same profile is counted once.
    pub proxies_count: i64,
}

/// The admin profiles list, oldest profile first.
pub async fn list_with_counts(pool: &DbPool) -> crate::Result<Vec<ProfileListRow>> {
    let rows: Vec<ProfileListRow> = sqlx::query_as(
        "SELECT p.id, p.name, p.slug, p.output_format, p.enabled,
                p.access_token IS NOT NULL AS protected,
                (SELECT COUNT(*) FROM profile_sources ps WHERE ps.profile_id = p.id) AS sources_count,
                (SELECT COUNT(DISTINCT px.id)
                 FROM profile_sources ps
                 JOIN proxy_source_links l ON l.source_id = ps.source_id
                 JOIN proxies px ON px.id = l.proxy_id
                 WHERE ps.profile_id = p.id
                   AND px.status = 'ready') AS proxies_count
         FROM profiles p
         ORDER BY p.created_at",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// One row of the profile composition table: the linked source with its
/// merge position. `name`/`enabled` come from the LEFT JOIN and are
/// `None` when the source row is gone.
#[derive(Debug, FromRow)]
pub struct CompositionRow {
    pub source_id: String,
    pub position: i64,
    pub name: Option<String>,
    pub enabled: Option<bool>,
}

/// The composition of one profile in merge order (profile card).
pub async fn composition(pool: &DbPool, profile_id: &str) -> crate::Result<Vec<CompositionRow>> {
    let rows: Vec<CompositionRow> = sqlx::query_as(
        "SELECT ps.source_id, ps.position, s.name, s.enabled
         FROM profile_sources ps LEFT JOIN sources s ON s.id = ps.source_id
         WHERE ps.profile_id = ?
         ORDER BY ps.position, ps.source_id",
    )
    .bind(profile_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Dedup statistics across a profile's composition (profile card).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DedupStats {
    /// Total link rows reachable through the composition.
    pub total: i64,
    /// Distinct fingerprints among them.
    pub unique: i64,
}

/// The dedup statistics of one profile's composition: total link rows vs
/// distinct fingerprints.
pub async fn dedup_stats(pool: &DbPool, profile_id: &str) -> crate::Result<DedupStats> {
    let (total, unique): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COUNT(DISTINCT p.fingerprint)
         FROM profile_sources ps
         JOIN proxy_source_links l ON l.source_id = ps.source_id
         JOIN proxies p ON p.id = l.proxy_id
         WHERE ps.profile_id = ?",
    )
    .bind(profile_id)
    .fetch_one(pool)
    .await?;
    Ok(DedupStats { total, unique })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Encoding, OutputFormat, Source};
    use crate::repo::sources as sources_repo;
    use crate::repo::tests::temp_pool;

    fn sample_profile(id: &str) -> Profile {
        let now = crate::models::now_ts();
        Profile {
            id: id.to_string(),
            slug: Some(format!("slug-{id}")),
            access_token: Some("secret-token".into()),
            name: "Main profile".into(),
            output_format: OutputFormat::Base64,
            pipeline: Some(serde_json::json!({"version": 1, "steps": []})),
            countries: Vec::new(),
            enabled: true,
            created_at: now,
            updated_at: now,
        }
    }

    fn sample_source(id: &str) -> Source {
        let now = crate::models::now_ts();
        Source {
            id: id.to_string(),
            slug: None,
            name: "s".into(),
            url: "https://example.com".into(),
            enabled: true,
            encoding: Encoding::Auto,
            input_format: None,
            protocols: None,
            cache_ttl_seconds: 3600,
            tags: None,
            pipeline: None,
            headers: None,
            ip_family: None,
            created_at: now,
            updated_at: now,
            last_fetched_at: None,
            last_error: None,
            error_class: None,
        }
    }

    #[tokio::test]
    async fn profile_crud_round_trip() {
        let (_dir, pool) = temp_pool().await;
        let mut profile = sample_profile("prf1aaaaaaa");
        create(&pool, &profile).await.unwrap();
        assert_eq!(get(&pool, "prf1aaaaaaa").await.unwrap().unwrap(), profile);
        assert_eq!(
            resolve_token(&pool, "slug-prf1aaaaaaa")
                .await
                .unwrap()
                .unwrap()
                .id,
            "prf1aaaaaaa"
        );

        profile.name = "Renamed".into();
        profile.output_format = OutputFormat::UriList;
        profile.access_token = None;
        // Mixed case, blanks and duplicates normalize on the way out;
        // clearing the list stores NULL (= no filter).
        profile.countries = vec!["us".into(), " DE ".into(), "US".into(), "de".into()];
        update(&pool, &profile).await.unwrap();
        let loaded = get(&pool, "prf1aaaaaaa").await.unwrap().unwrap();
        assert_eq!(loaded.name, "Renamed");
        assert_eq!(loaded.output_format, OutputFormat::UriList);
        assert_eq!(loaded.access_token, None);
        assert_eq!(loaded.countries, vec!["US".to_string(), "DE".to_string()]);

        profile.countries = Vec::new();
        update(&pool, &profile).await.unwrap();
        let loaded = get(&pool, "prf1aaaaaaa").await.unwrap().unwrap();
        assert!(loaded.countries.is_empty());

        assert!(delete(&pool, "prf1aaaaaaa").await.unwrap());
        assert!(get(&pool, "prf1aaaaaaa").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn profile_sources_composition() {
        let (_dir, pool) = temp_pool().await;
        let profile = sample_profile("prf2bbbbbbb");
        create(&pool, &profile).await.unwrap();
        for id in ["srcA0000000", "srcB0000000"] {
            sources_repo::create(&pool, &sample_source(id))
                .await
                .unwrap();
        }

        set_sources(
            &pool,
            "prf2bbbbbbb",
            &[("srcB0000000".into(), 0), ("srcA0000000".into(), 1)],
        )
        .await
        .unwrap();
        assert_eq!(
            get_sources(&pool, "prf2bbbbbbb").await.unwrap(),
            vec![("srcB0000000".into(), 0), ("srcA0000000".into(), 1)]
        );

        // Replacement is full, not incremental.
        set_sources(&pool, "prf2bbbbbbb", &[("srcA0000000".into(), 0)])
            .await
            .unwrap();
        assert_eq!(
            get_sources(&pool, "prf2bbbbbbb").await.unwrap(),
            vec![("srcA0000000".into(), 0)]
        );

        // Deleting the profile cascades to the composition.
        delete(&pool, "prf2bbbbbbb").await.unwrap();
        assert!(get_sources(&pool, "prf2bbbbbbb").await.unwrap().is_empty());
    }

    /// Minimal proxies row for the admin list/card fixtures.
    async fn insert_proxy(pool: &DbPool, fingerprint: &str, status: &str) -> i64 {
        let now = crate::models::now_ts();
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential, status, created_at, updated_at)
             VALUES (?, 'vless', ?, ?, 443, 'u', ?, ?, ?) RETURNING id",
        )
        .bind(fingerprint)
        .bind(fingerprint)
        .bind(format!("{fingerprint}.example.com"))
        .bind(status)
        .bind(now)
        .bind(now)
        .fetch_one(pool)
        .await
        .unwrap();
        id
    }

    async fn link(pool: &DbPool, proxy_id: i64, source_id: &str) {
        sqlx::query(
            "INSERT INTO proxy_source_links (proxy_id, source_id, seen_at) VALUES (?, ?, 1)",
        )
        .bind(proxy_id)
        .bind(source_id)
        .execute(pool)
        .await
        .unwrap();
    }

    /// The admin profiles list counts the composition size and the
    /// ready-proxy set (deduplicated across sources), and the card reads
    /// resolve the composition and the dedup statistics.
    #[tokio::test]
    async fn admin_list_counts_and_card_stats() {
        let (_dir, pool) = temp_pool().await;
        let profile = sample_profile("prf3ccccccc");
        create(&pool, &profile).await.unwrap();
        for id in ["srcA0000000", "srcB0000000"] {
            sources_repo::create(&pool, &sample_source(id))
                .await
                .unwrap();
        }
        set_sources(
            &pool,
            "prf3ccccccc",
            &[("srcA0000000".into(), 0), ("srcB0000000".into(), 1)],
        )
        .await
        .unwrap();

        // X is ready and linked from both sources (counted once); Y is
        // alive and linked from srcA only (outside the ready count).
        let x = insert_proxy(&pool, "fp-x", "ready").await;
        let y = insert_proxy(&pool, "fp-y", "alive").await;
        link(&pool, x, "srcA0000000").await;
        link(&pool, x, "srcB0000000").await;
        link(&pool, y, "srcA0000000").await;

        let rows = list_with_counts(&pool).await.unwrap();
        let row = rows.iter().find(|r| r.id == "prf3ccccccc").unwrap();
        assert!(row.protected, "sample_profile carries an access token");
        assert!(row.enabled);
        assert_eq!(row.sources_count, 2);
        assert_eq!(row.proxies_count, 1, "only the ready proxy counts");
        assert_eq!(row.output_format, "base64");

        // Card: composition in merge order with resolved names.
        let composition = composition(&pool, "prf3ccccccc").await.unwrap();
        assert_eq!(
            composition
                .iter()
                .map(|r| (r.source_id.as_str(), r.position))
                .collect::<Vec<_>>(),
            vec![("srcA0000000", 0), ("srcB0000000", 1)]
        );
        assert_eq!(composition[0].name.as_deref(), Some("s"));
        assert_eq!(composition[0].enabled, Some(true));

        // Card: three link rows, two distinct fingerprints.
        let stats = dedup_stats(&pool, "prf3ccccccc").await.unwrap();
        assert_eq!(
            stats,
            DedupStats {
                total: 3,
                unique: 2
            }
        );
    }
}
