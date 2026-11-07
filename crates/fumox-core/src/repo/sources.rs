//! CRUD for the `sources` table.

use super::BindWhereFilter;
use crate::db::DbPool;
use crate::models::{ErrorClass, InputFormat, IpFamily, Scheme, Source};
use sqlx::{FromRow, Sqlite};
use std::collections::HashMap;

#[derive(FromRow)]
struct SourceRow {
    id: String,
    slug: Option<String>,
    access_token: Option<String>,
    name: String,
    url: String,
    enabled: i64,
    encoding: String,
    input_format: Option<String>,
    protocols: Option<String>,
    cache_ttl_seconds: i64,
    tags: Option<String>,
    pipeline: Option<String>,
    headers: Option<String>,
    ip_family: Option<String>,
    created_at: i64,
    updated_at: i64,
    last_fetched_at: Option<i64>,
    last_error: Option<String>,
    error_class: Option<String>,
}

impl TryFrom<SourceRow> for Source {
    type Error = crate::Error;

    fn try_from(row: SourceRow) -> Result<Self, Self::Error> {
        Ok(Source {
            // Cloned so the id can still name the row in the corrupt-JSON
            // errors the field mappings below may raise.
            id: row.id.clone(),
            slug: row.slug,
            access_token: row.access_token,
            name: row.name,
            url: row.url,
            enabled: row.enabled != 0,
            encoding: row.encoding.parse()?,
            input_format: row.input_format.map(|v| v.parse()).transpose()?,
            protocols: row
                .protocols
                .map(|text| {
                    let names: Vec<String> = serde_json::from_str(&text).map_err(|e| {
                        crate::Error::Parse(format!("corrupt sources.protocols JSON: {e}"))
                    })?;
                    names
                        .into_iter()
                        .map(|name| name.parse::<Scheme>())
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()?
                .filter(|list| !list.is_empty()),
            cache_ttl_seconds: row.cache_ttl_seconds,
            tags: row
                .tags
                .map(|text| {
                    serde_json::from_str(&text)
                        .map_err(|e| crate::Error::Parse(format!("corrupt sources.tags JSON: {e}")))
                })
                .transpose()?,
            pipeline: row
                .pipeline
                .map(|text| super::text_to_json(&text, "sources.pipeline", &row.id))
                .transpose()?,
            headers: row
                .headers
                .map(|text| {
                    serde_json::from_str(&text).map_err(|e| {
                        crate::Error::Parse(format!("corrupt sources.headers JSON: {e}"))
                    })
                })
                .transpose()?,
            ip_family: row
                .ip_family
                .filter(|v| !v.is_empty())
                .map(|v| v.parse())
                .transpose()?,
            created_at: row.created_at,
            updated_at: row.updated_at,
            last_fetched_at: row.last_fetched_at,
            last_error: row.last_error,
            error_class: row.error_class.map(|v| v.parse()).transpose()?,
        })
    }
}

/// The protocol allowlist as stored. An empty list means "no filter", the
/// same as `None`, so it is stored as NULL: a source with an empty
/// allowlist would drop every entry at ingest and fail every fetch.
fn protocols_json(protocols: &Option<Vec<Scheme>>) -> crate::Result<Option<String>> {
    let Some(list) = crate::models::normalize_protocols(protocols.clone()) else {
        return Ok(None);
    };
    let names: Vec<&str> = list.iter().map(|scheme| scheme.as_str()).collect();
    super::json_to_text(&serde_json::to_value(names).expect("scheme list serializes")).map(Some)
}

fn headers_json(
    headers: &Option<std::collections::BTreeMap<String, String>>,
) -> crate::Result<Option<String>> {
    headers
        .as_ref()
        .map(|map| super::json_to_text(&serde_json::to_value(map).expect("header map serializes")))
        .transpose()
}

fn tags_json(tags: &Option<Vec<String>>) -> crate::Result<Option<String>> {
    tags.as_ref()
        .map(|tags| super::json_to_text(&serde_json::to_value(tags).expect("tags serialize")))
        .transpose()
}

fn pipeline_json(pipeline: &Option<serde_json::Value>) -> crate::Result<Option<String>> {
    pipeline.as_ref().map(super::json_to_text).transpose()
}

const COLUMNS: &str =
    "id, slug, access_token, name, url, enabled, encoding, input_format, protocols,
    cache_ttl_seconds, tags, pipeline, headers, ip_family, created_at, updated_at,
    last_fetched_at, last_error, error_class";

/// Insert a new source. The caller assigns `id` (see [`crate::models::new_id`]).
///
/// The row is written on the caller's executor: the pool, or the
/// connection of an open transaction. A caller that has to write several
/// rows together passes the transaction's connection, so the whole batch
/// lands or none of it does.
pub async fn create<'c, E>(executor: E, source: &Source) -> crate::Result<()>
where
    E: sqlx::Executor<'c, Database = Sqlite>,
{
    // sqlx 0.9 SqlSafeStr: {COLUMNS} is a compile-time constant; all data
    // flows through .bind().
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "INSERT INTO sources ({COLUMNS})
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )))
    .bind(source.id.clone())
    .bind(source.slug.clone())
    // The endpoint token is stored as a hash, like the profile one: the
    // write is idempotent for an already-hashed value (an import carrying
    // the stored form), so the admin form and the import share the path.
    .bind(crate::token::stored(source.access_token.clone()))
    .bind(source.name.clone())
    .bind(source.url.clone())
    .bind(source.enabled)
    .bind(source.encoding.as_str())
    .bind(source.input_format.map(InputFormat::as_str))
    .bind(protocols_json(&source.protocols)?)
    .bind(source.cache_ttl_seconds)
    .bind(tags_json(&source.tags)?)
    .bind(pipeline_json(&source.pipeline)?)
    .bind(headers_json(&source.headers)?)
    .bind(source.ip_family.map(IpFamily::as_str))
    .bind(source.created_at)
    .bind(source.updated_at)
    .bind(source.last_fetched_at)
    .bind(source.last_error.clone())
    .bind(source.error_class.map(ErrorClass::as_str))
    .execute(executor)
    .await?;
    Ok(())
}

/// The fetch-stamp columns of a source row, as the raw values the
/// database stores.
///
/// [`update_settings`] reads the current row through this projection
/// instead of the [`TryFrom`] mapping: one corrupt enum string
/// (`encoding`, `input_format`, `ip_family`, …) would fail the mapped
/// read and with it the whole save, while the write below rewrites every
/// one of these columns — saving over the corruption is exactly how the
/// operator heals the row. The staleness comparison is a text-level diff
/// of the same projection (see [`fetch_stamp_stale`]), so a corrupt
/// stored value simply reads as "changed" and the next ingest re-fetches.
#[derive(Debug, PartialEq, Eq, FromRow)]
struct FetchStampRow {
    url: String,
    enabled: i64,
    encoding: String,
    input_format: Option<String>,
    protocols: Option<String>,
    cache_ttl_seconds: i64,
    pipeline: Option<String>,
    headers: Option<String>,
    ip_family: Option<String>,
}

impl FetchStampRow {
    /// The stored columns of the current row, read raw.
    async fn of_stored(pool: &DbPool, id: &str) -> crate::Result<Option<Self>> {
        let row: Option<Self> = sqlx::query_as(
            "SELECT url, enabled, encoding, input_format, protocols,
                    cache_ttl_seconds, pipeline, headers, ip_family
             FROM sources WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;
        Ok(row)
    }

    /// The same projection of the submitted row: what the write below
    /// stores.
    fn of_source(source: &Source) -> crate::Result<Self> {
        Ok(Self {
            url: source.url.clone(),
            enabled: i64::from(source.enabled),
            encoding: source.encoding.as_str().to_string(),
            input_format: source.input_format.map(|f| f.as_str().to_string()),
            protocols: protocols_json(&source.protocols)?,
            cache_ttl_seconds: source.cache_ttl_seconds,
            pipeline: pipeline_json(&source.pipeline)?,
            headers: headers_json(&source.headers)?,
            ip_family: source.ip_family.map(|f| f.as_str().to_string()),
        })
    }
}

/// The fields a change to which invalidates the freshness stamp
/// (`last_fetched_at`): the stored rows were reconciled from a payload
/// fetched under these settings, so after an edit the next ingest must
/// re-fetch instead of trusting the old stamp (the TTL short-circuit of the
/// server's `ingest::ingest_source` reads exactly this column). Cosmetic
/// edits (name, slug, tags) keep the stamp.
fn fetch_stamp_stale(old: &FetchStampRow, new: &FetchStampRow) -> bool {
    old.url != new.url
        || old.enabled != new.enabled
        || old.encoding != new.encoding
        || old.input_format != new.input_format
        || old.protocols != new.protocols
        || old.cache_ttl_seconds != new.cache_ttl_seconds
        || old.pipeline != new.pipeline
        || old.headers != new.headers
        || old.ip_family != new.ip_family
}

/// Update the admin-owned columns of a source row. `id` and `created_at`
/// are immutable; `updated_at` must be set by the caller.
///
/// The admin write path owns the settings columns only. The fetcher's
/// columns (`last_error`, `error_class`) are never written from here: a
/// fetch outcome that lands while an operator saves the form must not be
/// clobbered by the save. The freshness stamp is not written either, it
/// is only reset (see below).
///
/// The current row is read raw (no [`TryFrom`] mapping, see
/// [`FetchStampRow`]), so a corrupt enum string in the stored row cannot
/// stop the save that rewrites it.
///
/// A change to a fetch-relevant field (see [`fetch_stamp_stale`]) resets
/// `last_fetched_at`, so the next ingest re-fetches under the new settings
/// instead of riding out the TTL window on a payload reconciled under the
/// old ones.
pub async fn update_settings(pool: &DbPool, source: &Source) -> crate::Result<()> {
    let fresh = FetchStampRow::of_source(source)?;
    let stale = match FetchStampRow::of_stored(pool, &source.id).await? {
        Some(stored) => fetch_stamp_stale(&stored, &fresh),
        // The row is gone: the write below affects nothing and the
        // caller answers "not found".
        None => true,
    };
    let affected = sqlx::query(
        "UPDATE sources SET
            slug = ?, access_token = ?, name = ?, url = ?, enabled = ?, encoding = ?, input_format = ?,
            protocols = ?, cache_ttl_seconds = ?, tags = ?, pipeline = ?, headers = ?,
            ip_family = ?, updated_at = ?,
            last_fetched_at = CASE WHEN ? THEN NULL ELSE last_fetched_at END
         WHERE id = ?",
    )
    .bind(&source.slug)
    // Admin-owned, like the profile token: hashed on the way in (idempotent
    // for the stored hash the edit form hands back), and not fetch-relevant
    // — an endpoint-token change must not reset the freshness stamp.
    .bind(crate::token::stored(source.access_token.clone()))
    .bind(&source.name)
    .bind(&source.url)
    .bind(source.enabled)
    .bind(source.encoding.as_str())
    .bind(source.input_format.map(InputFormat::as_str))
    .bind(protocols_json(&source.protocols)?)
    .bind(source.cache_ttl_seconds)
    .bind(tags_json(&source.tags)?)
    .bind(pipeline_json(&source.pipeline)?)
    .bind(headers_json(&source.headers)?)
    .bind(source.ip_family.map(IpFamily::as_str))
    .bind(source.updated_at)
    .bind(stale as i64)
    .bind(&source.id)
    .execute(pool)
    .await?
    .rows_affected();
    if affected == 0 {
        // The row is gone, not the database: the caller can answer "not
        // found" instead of "the write failed".
        return Err(crate::Error::NotFound(format!("source {}", source.id)));
    }
    Ok(())
}

/// Flip the enabled flag of a source row.
///
/// The toggle is the one admin action that does not go through the
/// settings form, so it gets its own targeted write: the settings
/// columns keep the values they have, and the fetcher's columns are not
/// touched at all.
///
/// The flip is a fetch-relevant change, so the freshness stamp is reset:
/// the next ingest must fetch under the new state instead of riding out
/// the TTL window on a payload reconciled under the old one.
///
/// Returns whether the row was there.
pub async fn set_enabled(pool: &DbPool, id: &str, enabled: bool) -> crate::Result<bool> {
    let now = crate::models::now_ts();
    let affected = sqlx::query(
        "UPDATE sources SET enabled = ?, updated_at = ?, last_fetched_at = NULL WHERE id = ?",
    )
    .bind(enabled)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(affected > 0)
}

pub async fn get(pool: &DbPool, id: &str) -> crate::Result<Option<Source>> {
    let row: Option<SourceRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM sources WHERE id = ?"
    )))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    row.map(Source::try_from).transpose()
}

/// Load several sources by id in one `WHERE id IN (...)` read, keyed by id.
/// Ids with no row are absent from the map, duplicate ids read one row. A
/// row whose columns fail to map is skipped with a warning, not failed on:
/// one corrupt row must not break the whole subscription. The batched read
/// backs `/sub`'s member load, which walks a profile's
/// composition and would otherwise issue one indexed row-fetch per member
/// on the public serving path; callers that need the ids in composition
/// order order the results themselves from their link list.
pub async fn get_many(pool: &DbPool, ids: &[&str]) -> crate::Result<HashMap<String, Source>> {
    // `IN ()` is not valid SQLite; an empty request has an empty answer.
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let placeholders = vec!["?"; ids.len()].join(", ");
    let sql = format!("SELECT {COLUMNS} FROM sources WHERE id IN ({placeholders})");
    let mut query = sqlx::query_as::<_, SourceRow>(sqlx::AssertSqlSafe(sql.as_str()));
    for id in ids {
        query = query.bind(id);
    }
    let rows: Vec<SourceRow> = query.fetch_all(pool).await?;
    let mut by_id = HashMap::with_capacity(rows.len());
    for row in rows {
        match Source::try_from(row) {
            Ok(source) => {
                by_id.insert(source.id.clone(), source);
            }
            Err(error) => {
                tracing::warn!(%error, "sources::get_many: skipping a row with corrupt columns");
            }
        }
    }
    Ok(by_id)
}

pub async fn get_by_slug(pool: &DbPool, slug: &str) -> crate::Result<Option<Source>> {
    let row: Option<SourceRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM sources WHERE slug = ?"
    )))
    .bind(slug)
    .fetch_optional(pool)
    .await?;
    row.map(Source::try_from).transpose()
}

/// Resolve a `/src/{token}` path segment: slug first, then raw id.
///
/// The order is by the *match*, not by the NULL-ness of the slug: a
/// source whose slug collides with another source's id must lose
/// against the source that owns the slug, whatever the row order of the
/// table happens to be.
pub async fn resolve_token(pool: &DbPool, token: &str) -> crate::Result<Option<Source>> {
    let row: Option<SourceRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM sources WHERE slug = ? OR id = ? ORDER BY (slug = ?) DESC LIMIT 1"
    )))
    .bind(token)
    .bind(token)
    .bind(token)
    .fetch_optional(pool)
    .await?;
    row.map(Source::try_from).transpose()
}

/// Every source, newest-created last. A row whose columns fail to map
/// (a corrupt enum string) is skipped with a warning instead of failing
/// the whole listing: one broken row must not take every healthy source
/// out of the ingest rotation with it.
pub async fn list(pool: &DbPool, enabled_only: bool) -> crate::Result<Vec<Source>> {
    let query = if enabled_only {
        format!("SELECT {COLUMNS} FROM sources WHERE enabled = 1 ORDER BY created_at")
    } else {
        format!("SELECT {COLUMNS} FROM sources ORDER BY created_at")
    };
    let rows: Vec<SourceRow> = sqlx::query_as(sqlx::AssertSqlSafe(query.as_str()))
        .fetch_all(pool)
        .await?;
    let mut sources = Vec::with_capacity(rows.len());
    for row in rows {
        match Source::try_from(row) {
            Ok(source) => sources.push(source),
            Err(error) => {
                tracing::warn!(%error, "sources::list: skipping a row with corrupt columns");
            }
        }
    }
    Ok(sources)
}

/// Every slug of the table (`None` for a row without one), one column.
/// The import's collision check reads only these: mapping whole rows
/// would fetch every stored header and pipeline just to throw it away.
pub async fn list_slugs(pool: &DbPool) -> crate::Result<Vec<Option<String>>> {
    let rows: Vec<(Option<String>,)> =
        sqlx::query_as("SELECT slug FROM sources ORDER BY created_at")
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(|(slug,)| slug).collect())
}

// Admin sources list
//
// The dynamic list screen: filter clauses are whitelisted fragments
// assembled through the shared [`super::WhereFilter`], every value flows
// through a bind. The whole list is returned (no pagination; the screen
// renders every source), so one query serves count and rows.

/// One row of the admin sources list: the display columns plus the
/// linked-proxy count subquery.
#[derive(Debug, FromRow)]
pub struct SourceListRow {
    pub id: String,
    pub name: String,
    pub slug: Option<String>,
    pub url: String,
    pub enabled: bool,
    pub cache_ttl_seconds: i64,
    pub last_fetched_at: Option<i64>,
    pub error_class: Option<String>,
    /// Proxies currently linked to this source.
    pub proxies_count: i64,
}

/// Filter parameters of the admin sources list ([`list_filtered`]). An
/// empty string or `None` means "no constraint" for that field.
#[derive(Debug, Clone, Default)]
pub struct SourceListFilter {
    /// `Some(true)` = enabled only, `Some(false)` = disabled only.
    pub enabled: Option<bool>,
    /// Only sources whose last fetch ended in an error.
    pub with_errors: bool,
    /// Exact tag membership.
    pub tag: String,
    /// Case-insensitive substring match against name and url, compared in
    /// Rust after `to_lowercase` (the screen renders every source, so
    /// there is nothing to push into the SQL): the folding works beyond
    /// ASCII, which SQLite's `LIKE` does not, and the match is literal —
    /// `%`, `_` and `\` in the query mean themselves.
    pub query: String,
}

impl SourceListFilter {
    /// The WHERE fragment and bound values of the list: the one place the
    /// sources list's dynamic clause set is defined.
    fn where_filter(&self) -> super::WhereFilter {
        let mut wf = super::WhereFilter::new();
        match self.enabled {
            Some(true) => wf = wf.clause("s.enabled = 1"),
            Some(false) => wf = wf.clause("s.enabled = 0"),
            None => {}
        }
        if self.with_errors {
            wf = wf.clause("s.error_class IS NOT NULL");
        }
        if !self.tag.is_empty() {
            wf = wf.text(
                "EXISTS (SELECT 1 FROM json_each(CASE WHEN json_valid(s.tags) THEN s.tags END)
                        WHERE json_each.value = ?)",
                &self.tag,
            );
        }
        wf
    }
}

/// The admin sources list for `filter`, newest-created first. The
/// `query` filter is applied in Rust (see [`SourceListFilter::query`]),
/// the remaining clauses go into the SQL.
pub async fn list_filtered(
    pool: &DbPool,
    filter: &SourceListFilter,
) -> crate::Result<Vec<SourceListRow>> {
    let wf = filter.where_filter();
    let sql = format!(
        "SELECT s.id, s.name, s.slug, s.url, s.enabled, s.cache_ttl_seconds,
                s.last_fetched_at, s.error_class,
                (SELECT COUNT(*) FROM proxy_source_links l WHERE l.source_id = s.id) AS proxies_count
         FROM sources s{}
         ORDER BY s.created_at DESC",
        wf.sql()
    );
    let rows = sqlx::query_as::<_, SourceListRow>(sqlx::AssertSqlSafe(sql))
        .bind_where_filter(wf.values())
        .fetch_all(pool)
        .await?;
    if filter.query.is_empty() {
        return Ok(rows);
    }
    // Literal case-insensitive substring match: `contains` on the
    // lowercased strings has no wildcard syntax, so `%`, `_` and `\` in
    // the query mean themselves, and the folding covers non-ASCII.
    let needle = filter.query.to_lowercase();
    Ok(rows
        .into_iter()
        .filter(|row| {
            row.name.to_lowercase().contains(&needle) || row.url.to_lowercase().contains(&needle)
        })
        .collect())
}

/// Distinct tags stored across all sources, ascending; the tag filter
/// dropdown of the admin sources list. Unparsable tag JSON yields no tag:
/// the `json_valid` guard feeds `json_each` a NULL for such a row, so the
/// query skips it instead of failing on it.
pub async fn distinct_tags(pool: &DbPool) -> crate::Result<Vec<String>> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT json_each.value FROM sources,
            json_each(CASE WHEN json_valid(sources.tags) THEN sources.tags END)
         ORDER BY 1",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn delete(pool: &DbPool, id: &str) -> crate::Result<bool> {
    let affected = sqlx::query("DELETE FROM sources WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected();
    Ok(affected > 0)
}

/// Record the outcome of a fetch attempt: success stamps `last_fetched_at`
/// (and `updated_at`) and clears the error fields; failure stores the
/// message and its class and leaves the freshness stamp alone. Both
/// outcomes stamp `last_attempt_at` (migration 0015) with the moment of
/// the attempt, so a source that keeps failing still shows *when* it was
/// last tried.
pub async fn record_fetch_outcome(
    pool: &DbPool,
    id: &str,
    outcome: &FetchOutcome<'_>,
) -> crate::Result<()> {
    let (fetched_at, attempt_at, error, class): (
        Option<i64>,
        Option<i64>,
        Option<&str>,
        Option<&str>,
    ) = match outcome {
        FetchOutcome::Success { at } => (Some(*at), Some(*at), None, None),
        FetchOutcome::Failure { at, error, class } => {
            (None, Some(*at), Some(*error), Some(class.as_str()))
        }
    };
    sqlx::query(
        "UPDATE sources SET
            last_fetched_at = COALESCE(?, last_fetched_at),
            last_attempt_at = ?,
            last_error = ?,
            error_class = ?,
            updated_at = COALESCE(?, updated_at)
         WHERE id = ?",
    )
    .bind(fetched_at)
    .bind(attempt_at)
    .bind(error)
    .bind(class)
    .bind(fetched_at)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Result of one fetch attempt, as stored on the source row. `at` is Unix
/// time in seconds ([`crate::models::now_ts()`]).
#[derive(Debug, Clone)]
pub enum FetchOutcome<'a> {
    /// The payload came back: `at` stamps `last_fetched_at`,
    /// `last_attempt_at` and `updated_at`.
    Success { at: i64 },
    /// The fetch failed: `at` stamps `last_attempt_at` only — a failed
    /// attempt must not make the stored payload look fresh, so
    /// `last_fetched_at` and `updated_at` keep their values.
    Failure {
        at: i64,
        error: &'a str,
        class: ErrorClass,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Encoding;
    use crate::repo::tests::temp_pool;
    use std::collections::BTreeMap;

    fn sample_source(id: &str) -> Source {
        let now = crate::models::now_ts();
        Source {
            id: id.to_string(),
            slug: Some(format!("slug-{id}")),
            access_token: None,
            name: "Test source".into(),
            url: "https://example.com/sub".into(),
            enabled: true,
            encoding: Encoding::Auto,
            input_format: None,
            protocols: Some(vec![Scheme::Vless, Scheme::Trojan]),
            cache_ttl_seconds: 1800,
            tags: Some(vec!["paid".into(), "eu".into()]),
            pipeline: Some(serde_json::json!({"version": 1})),
            headers: Some(BTreeMap::from([("User-Agent".into(), "Fumox".into())])),
            ip_family: None,
            created_at: now,
            updated_at: now,
            last_fetched_at: None,
            last_error: None,
            error_class: None,
        }
    }

    #[tokio::test]
    async fn source_crud_round_trip() {
        let (_dir, pool) = temp_pool().await;
        let mut source = sample_source("src1aaaaaaaa");
        create(&pool, &source).await.unwrap();

        let loaded = get(&pool, "src1aaaaaaaa").await.unwrap().unwrap();
        assert_eq!(loaded, source);

        // Token resolution: slug wins, id works too.
        assert_eq!(
            resolve_token(&pool, "slug-src1aaaaaaaa")
                .await
                .unwrap()
                .unwrap()
                .id,
            "src1aaaaaaaa"
        );
        assert_eq!(
            resolve_token(&pool, "src1aaaaaaaa")
                .await
                .unwrap()
                .unwrap()
                .id,
            "src1aaaaaaaa"
        );
        assert!(resolve_token(&pool, "nope").await.unwrap().is_none());

        source.name = "Renamed".into();
        source.cache_ttl_seconds = 600;
        // NULL (inherit) → explicit family → back to NULL round trip.
        source.ip_family = Some(IpFamily::Ipv6);
        source.updated_at += 10;
        update_settings(&pool, &source).await.unwrap();
        let loaded = get(&pool, "src1aaaaaaaa").await.unwrap().unwrap();
        assert_eq!(loaded.name, "Renamed");
        assert_eq!(loaded.cache_ttl_seconds, 600);
        assert_eq!(loaded.ip_family, Some(IpFamily::Ipv6));

        source.ip_family = None;
        update_settings(&pool, &source).await.unwrap();
        let loaded = get(&pool, "src1aaaaaaaa").await.unwrap().unwrap();
        assert_eq!(loaded.ip_family, None);

        assert!(delete(&pool, "src1aaaaaaaa").await.unwrap());
        assert!(get(&pool, "src1aaaaaaaa").await.unwrap().is_none());
        assert!(!delete(&pool, "src1aaaaaaaa").await.unwrap());
    }

    #[tokio::test]
    async fn fetch_outcome_updates_error_fields() {
        let (_dir, pool) = temp_pool().await;
        let source = sample_source("src2bbbbbbbb");
        create(&pool, &source).await.unwrap();

        let now = crate::models::now_ts();
        record_fetch_outcome(
            &pool,
            "src2bbbbbbbb",
            &FetchOutcome::Failure {
                at: now,
                error: "connection reset",
                class: ErrorClass::Network,
            },
        )
        .await
        .unwrap();
        let loaded = get(&pool, "src2bbbbbbbb").await.unwrap().unwrap();
        assert_eq!(loaded.last_error.as_deref(), Some("connection reset"));
        assert_eq!(loaded.error_class, Some(ErrorClass::Network));
        assert_eq!(loaded.last_fetched_at, None);

        record_fetch_outcome(
            &pool,
            "src2bbbbbbbb",
            &FetchOutcome::Success { at: now + 60 },
        )
        .await
        .unwrap();
        let loaded = get(&pool, "src2bbbbbbbb").await.unwrap().unwrap();
        assert_eq!(loaded.last_fetched_at, Some(now + 60));
        assert_eq!(loaded.last_error, None);
        assert_eq!(loaded.error_class, None);
    }

    /// A failure after a success must not make the stored payload look
    /// fresh: `last_fetched_at` and `updated_at` keep the success's
    /// stamps while `last_attempt_at` follows every attempt. A success
    /// does move `updated_at`.
    #[tokio::test]
    async fn fetch_failure_after_success_keeps_the_freshness_stamps() {
        let (_dir, pool) = temp_pool().await;
        create(&pool, &sample_source("srcAtttttttt")).await.unwrap();

        // The success stamps the freshness columns.
        let success_at = crate::models::now_ts();
        record_fetch_outcome(
            &pool,
            "srcAtttttttt",
            &FetchOutcome::Success { at: success_at },
        )
        .await
        .unwrap();
        let loaded = get(&pool, "srcAtttttttt").await.unwrap().unwrap();
        assert_eq!(loaded.last_fetched_at, Some(success_at));
        assert_eq!(
            loaded.updated_at, success_at,
            "the success moves updated_at"
        );

        // The later failure leaves both freshness stamps alone and only
        // records the attempt moment.
        let failure_at = success_at + 120;
        record_fetch_outcome(
            &pool,
            "srcAtttttttt",
            &FetchOutcome::Failure {
                at: failure_at,
                error: "connection reset",
                class: ErrorClass::Network,
            },
        )
        .await
        .unwrap();
        let loaded = get(&pool, "srcAtttttttt").await.unwrap().unwrap();
        assert_eq!(
            loaded.last_fetched_at,
            Some(success_at),
            "the failure must not move last_fetched_at"
        );
        assert_eq!(
            loaded.updated_at, success_at,
            "the failure must not move updated_at"
        );
        assert_eq!(loaded.last_error.as_deref(), Some("connection reset"));
        let (last_attempt_at,): (Option<i64>,) =
            sqlx::query_as("SELECT last_attempt_at FROM sources WHERE id = ?")
                .bind("srcAtttttttt")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(last_attempt_at, Some(failure_at));
    }

    /// The sources search is a literal case-insensitive substring match,
    /// compared in Rust: `LIKE` wildcards in the query mean themselves
    /// (a `100%` plan is findable by `100%`), and the case folding works
    /// beyond ASCII, which SQLite's `LIKE` does not.
    #[tokio::test]
    async fn source_search_matches_literal_and_folds_case() {
        let (_dir, pool) = temp_pool().await;
        let mut percent = sample_source("srcPaaaaaaaa");
        percent.name = "100% Deal_DE".into();
        create(&pool, &percent).await.unwrap();
        let mut cyrillic = sample_source("srcRbbbbbbbb");
        cyrillic.name = "МОСКВА Feed".into();
        create(&pool, &cyrillic).await.unwrap();
        create(&pool, &sample_source("srcNcccccccc")).await.unwrap();

        async fn ids(pool: &DbPool, query: &str) -> Vec<String> {
            let mut found: Vec<String> = list_filtered(
                pool,
                &SourceListFilter {
                    query: query.into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.id)
            .collect();
            found.sort();
            found
        }

        // Wildcards match literally, case folds, and non-ASCII folds too.
        assert_eq!(ids(&pool, "100%").await, vec!["srcPaaaaaaaa"]);
        assert_eq!(ids(&pool, "%").await, vec!["srcPaaaaaaaa"]);
        assert_eq!(ids(&pool, "_").await, vec!["srcPaaaaaaaa"]);
        assert_eq!(ids(&pool, "deal_de").await, vec!["srcPaaaaaaaa"]);
        assert_eq!(ids(&pool, "москва").await, vec!["srcRbbbbbbbb"]);
        // A query with no literal match answers nothing.
        assert!(ids(&pool, "zzz").await.is_empty());
    }

    /// A change to a fetch-relevant field resets `last_fetched_at`, so the
    /// next ingest re-fetches under the new settings; a cosmetic edit keeps
    /// the stamp.
    #[tokio::test]
    async fn update_settings_resets_the_freshness_stamp_on_a_fetch_relevant_change() {
        let (_dir, pool) = temp_pool().await;
        let mut source = sample_source("src5eeeeeeee");
        source.last_fetched_at = Some(crate::models::now_ts());
        create(&pool, &source).await.unwrap();

        // Cosmetic edits: the stamp survives.
        source.name = "Renamed".into();
        source.slug = Some("renamed-slug".into());
        source.tags = Some(vec!["misc".into()]);
        source.updated_at += 5;
        update_settings(&pool, &source).await.unwrap();
        let loaded = get(&pool, "src5eeeeeeee").await.unwrap().unwrap();
        assert!(
            loaded.last_fetched_at.is_some(),
            "a cosmetic edit must keep the freshness stamp"
        );

        // A fetch-relevant edit resets the stamp; the rest of the row is
        // written exactly as given.
        source.url = "https://example.com/other".into();
        update_settings(&pool, &source).await.unwrap();
        let loaded = get(&pool, "src5eeeeeeee").await.unwrap().unwrap();
        assert_eq!(loaded.url, "https://example.com/other");
        assert_eq!(loaded.name, "Renamed");
        assert!(
            loaded.last_fetched_at.is_none(),
            "a fetch-relevant edit must reset the freshness stamp"
        );
    }

    /// Every field `fetch_stamp_stale` compares is exercised one at a time:
    /// the single mutated field alone must reset the freshness stamp, so no
    /// one comparison can rot silently while the others still pass.
    #[tokio::test]
    async fn every_fetch_relevant_field_resets_the_freshness_stamp() {
        let (_dir, pool) = temp_pool().await;
        type StampMutation = (&'static str, Box<dyn Fn(&mut Source)>);
        let mutations: Vec<StampMutation> = vec![
            (
                "url",
                Box::new(|s: &mut Source| s.url = "https://example.com/other".into()),
            ),
            ("enabled", Box::new(|s: &mut Source| s.enabled = false)),
            (
                "encoding",
                Box::new(|s: &mut Source| s.encoding = Encoding::Base64),
            ),
            (
                "input_format",
                Box::new(|s: &mut Source| s.input_format = Some(InputFormat::ClashYaml)),
            ),
            (
                "protocols",
                Box::new(|s: &mut Source| s.protocols = Some(vec![Scheme::Trojan])),
            ),
            (
                "cache_ttl_seconds",
                Box::new(|s: &mut Source| s.cache_ttl_seconds = 60),
            ),
            (
                "pipeline",
                Box::new(|s: &mut Source| s.pipeline = Some(serde_json::json!({"version": 2}))),
            ),
            (
                "headers",
                Box::new(|s: &mut Source| {
                    s.headers = Some(BTreeMap::from([("User-Agent".into(), "Other".into())]));
                }),
            ),
            (
                "ip_family",
                Box::new(|s: &mut Source| s.ip_family = Some(IpFamily::Ipv6)),
            ),
        ];
        assert_eq!(
            mutations.len(),
            9,
            "fetch_stamp_stale compares exactly these fields; a field added there belongs here too"
        );
        for (index, (field, mutate)) in mutations.iter().enumerate() {
            let id = format!("srcStale{index:04}");
            let mut source = sample_source(&id);
            source.last_fetched_at = Some(crate::models::now_ts());
            create(&pool, &source).await.unwrap();
            mutate(&mut source);
            source.updated_at += 1;
            update_settings(&pool, &source).await.unwrap();
            let loaded = get(&pool, &id).await.unwrap().unwrap();
            assert!(
                loaded.last_fetched_at.is_none(),
                "mutating only {field} must reset the freshness stamp"
            );
        }
    }

    /// A stored tag column that is not valid JSON must not fail the
    /// queries that read it: the `json_valid` guard feeds `json_each` a
    /// NULL for such a row, so the corrupt row yields no tag (and matches
    /// no tag filter) instead of failing the whole listing.
    #[tokio::test]
    async fn corrupt_tag_json_yields_no_tags_and_no_error() {
        let (_dir, pool) = temp_pool().await;
        let mut good = sample_source("src1aaaaaaaa");
        good.tags = Some(vec!["eu".into()]);
        create(&pool, &good).await.unwrap();
        let mut corrupt = sample_source("src2bbbbbbbb");
        corrupt.tags = Some(vec!["paid".into()]);
        create(&pool, &corrupt).await.unwrap();
        sqlx::query("UPDATE sources SET tags = '{oops' WHERE id = 'src2bbbbbbbb'")
            .execute(&pool)
            .await
            .unwrap();

        // The corrupt row contributes no tag and breaks nothing.
        assert_eq!(distinct_tags(&pool).await.unwrap(), vec!["eu"]);
        // The tag filter answers over the healthy rows without failing.
        let rows = list_filtered(
            &pool,
            &SourceListFilter {
                tag: "eu".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            rows.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["src1aaaaaaaa"]
        );
    }

    /// The admin write path owns the settings columns only: the fetcher's
    /// columns survive a save, so a fetch outcome that landed while the
    /// operator was editing the form is not clobbered by it.
    #[tokio::test]
    async fn update_settings_leaves_the_fetcher_columns_alone() {
        let (_dir, pool) = temp_pool().await;
        let mut source = sample_source("src9iiiiiiii");
        create(&pool, &source).await.unwrap();
        record_fetch_outcome(
            &pool,
            "src9iiiiiiii",
            &FetchOutcome::Failure {
                at: crate::models::now_ts(),
                error: "connection reset",
                class: ErrorClass::Network,
            },
        )
        .await
        .unwrap();

        // The save carries no error state of its own.
        source.name = "Renamed".into();
        source.last_error = None;
        source.error_class = None;
        update_settings(&pool, &source).await.unwrap();

        let loaded = get(&pool, "src9iiiiiiii").await.unwrap().unwrap();
        assert_eq!(loaded.name, "Renamed");
        assert_eq!(loaded.last_error.as_deref(), Some("connection reset"));
        assert_eq!(loaded.error_class, Some(ErrorClass::Network));
    }

    /// The toggle is a targeted write: it flips the flag, resets the
    /// freshness stamp (the flip is a fetch-relevant change) and leaves
    /// the settings columns exactly as they are.
    #[tokio::test]
    async fn set_enabled_flips_the_flag_without_rewriting_the_row() {
        let (_dir, pool) = temp_pool().await;
        let mut source = sample_source("src7jjjjjjjj");
        source.enabled = true;
        source.last_fetched_at = Some(crate::models::now_ts());
        create(&pool, &source).await.unwrap();

        assert!(set_enabled(&pool, "src7jjjjjjjj", false).await.unwrap());
        let loaded = get(&pool, "src7jjjjjjjj").await.unwrap().unwrap();
        assert!(!loaded.enabled);
        assert!(
            loaded.last_fetched_at.is_none(),
            "the flip resets the freshness stamp"
        );
        assert_eq!(loaded.url, source.url);
        assert_eq!(loaded.name, source.name);

        // A vanished row is reported, not written.
        assert!(!set_enabled(&pool, "nope", true).await.unwrap());
    }

    /// An empty protocol allowlist means "no filter", the same as `None`:
    /// a source that stored one dropped every entry at ingest and failed
    /// every fetch, so the empty list is normalised away on the way in
    /// and on the way out.
    #[tokio::test]
    async fn an_empty_protocol_allowlist_is_stored_as_no_filter() {
        let (_dir, pool) = temp_pool().await;
        let mut source = sample_source("src8hhhhhhhh");
        source.protocols = Some(Vec::new());
        create(&pool, &source).await.unwrap();

        let stored: (Option<String>,) =
            sqlx::query_as("SELECT protocols FROM sources WHERE id = 'src8hhhhhhhh'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stored.0, None, "an empty allowlist is stored as NULL");

        let loaded = get(&pool, "src8hhhhhhhh").await.unwrap().unwrap();
        assert_eq!(loaded.protocols, None);

        // A row that still carries an empty list reads back as "no filter"
        // too.
        sqlx::query("UPDATE sources SET protocols = '[]' WHERE id = 'src8hhhhhhhh'")
            .execute(&pool)
            .await
            .unwrap();
        let loaded = get(&pool, "src8hhhhhhhh").await.unwrap().unwrap();
        assert_eq!(loaded.protocols, None);
    }

    #[tokio::test]
    async fn list_filters_enabled() {
        let (_dir, pool) = temp_pool().await;
        let a = sample_source("src3cccccccc");
        let mut b = sample_source("src4dddddddd");
        b.enabled = false;
        b.slug = None;
        create(&pool, &a).await.unwrap();
        create(&pool, &b).await.unwrap();
        assert_eq!(list(&pool, false).await.unwrap().len(), 2);
        assert_eq!(list(&pool, true).await.unwrap().len(), 1);
    }

    /// The batched read behind `/sub`'s member load: several ids answer
    /// from one query, keyed by id with rows mapped whole, a vanished id
    /// is simply absent, duplicates collapse, and an empty request is an
    /// empty map (no `IN ()` round trip).
    #[tokio::test]
    async fn get_many_loads_by_id_in_one_query() {
        let (_dir, pool) = temp_pool().await;
        let mut a = sample_source("src6ffffffff");
        a.slug = None;
        let mut b = sample_source("src7gggggggg");
        b.slug = None;
        b.enabled = false;
        create(&pool, &a).await.unwrap();
        create(&pool, &b).await.unwrap();

        let loaded = get_many(&pool, &["src6ffffffff", "src7gggggggg"])
            .await
            .unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded["src6ffffffff"], a);
        assert!(!loaded["src7gggggggg"].enabled);

        // Missing ids are absent; duplicates collapse onto one row.
        let loaded = get_many(&pool, &["src6ffffffff", "nope", "src6ffffffff"])
            .await
            .unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded["src6ffffffff"], a);

        assert!(get_many(&pool, &[]).await.unwrap().is_empty());
    }

    /// The admin sources list: count/rows apply the same whitelist
    /// clauses, the linked-proxy subquery counts through the link table,
    /// and the tag dropdown enumerates every stored tag once.
    #[tokio::test]
    async fn admin_list_filter_and_tags() {
        let (_dir, pool) = temp_pool().await;
        let mut a = sample_source("src1aaaaaaaa"); // enabled, tags paid+eu
        a.created_at = 100;
        let mut b = sample_source("src2bbbbbbbb"); // disabled, untagged
        b.enabled = false;
        b.slug = None;
        b.tags = None;
        b.created_at = 200;
        let mut c = sample_source("src3cccccccc"); // enabled, erroring, tag eu
        c.name = "Gamma News".into();
        c.tags = Some(vec!["eu".into()]);
        c.error_class = Some(ErrorClass::Network);
        c.created_at = 300;
        create(&pool, &a).await.unwrap();
        create(&pool, &b).await.unwrap();
        create(&pool, &c).await.unwrap();

        // A proxy linked to `a` exercises the proxies_count subquery.
        let (pid,): (i64,) = sqlx::query_as(
            "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential, status, created_at, updated_at)
             VALUES ('fp-src', 'vless', 'fp-src', 'fp-src.example.com', 443, 'u', 'alive', 1, 1)
             RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO proxy_source_links (proxy_id, source_id, seen_at) VALUES (?, 'src1aaaaaaaa', 1)")
            .bind(pid)
            .execute(&pool)
            .await
            .unwrap();

        // Unfiltered: every source, newest created first.
        let rows = list_filtered(&pool, &SourceListFilter::default())
            .await
            .unwrap();
        assert_eq!(
            rows.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["src3cccccccc", "src2bbbbbbbb", "src1aaaaaaaa"]
        );
        assert_eq!(rows[2].proxies_count, 1, "the linked proxy counts on a");

        // Enabled / disabled toggles.
        let filter = SourceListFilter {
            enabled: Some(true),
            ..Default::default()
        };
        assert_eq!(
            list_filtered(&pool, &filter)
                .await
                .unwrap()
                .iter()
                .map(|r| r.id.as_str())
                .collect::<Vec<_>>(),
            vec!["src3cccccccc", "src1aaaaaaaa"]
        );
        let filter = SourceListFilter {
            enabled: Some(false),
            ..Default::default()
        };
        assert_eq!(
            list_filtered(&pool, &filter)
                .await
                .unwrap()
                .iter()
                .map(|r| r.id.as_str())
                .collect::<Vec<_>>(),
            vec!["src2bbbbbbbb"]
        );

        // Error filter.
        let filter = SourceListFilter {
            with_errors: true,
            ..Default::default()
        };
        assert_eq!(
            list_filtered(&pool, &filter)
                .await
                .unwrap()
                .iter()
                .map(|r| r.id.as_str())
                .collect::<Vec<_>>(),
            vec!["src3cccccccc"]
        );

        // Tag membership and substring query.
        let filter = SourceListFilter {
            tag: "eu".into(),
            ..Default::default()
        };
        assert_eq!(
            list_filtered(&pool, &filter)
                .await
                .unwrap()
                .iter()
                .map(|r| r.id.as_str())
                .collect::<Vec<_>>(),
            vec!["src3cccccccc", "src1aaaaaaaa"]
        );
        let filter = SourceListFilter {
            tag: "paid".into(),
            ..Default::default()
        };
        assert_eq!(
            list_filtered(&pool, &filter)
                .await
                .unwrap()
                .iter()
                .map(|r| r.id.as_str())
                .collect::<Vec<_>>(),
            vec!["src1aaaaaaaa"]
        );
        let filter = SourceListFilter {
            query: "gamma".into(),
            ..Default::default()
        };
        assert_eq!(
            list_filtered(&pool, &filter)
                .await
                .unwrap()
                .iter()
                .map(|r| r.id.as_str())
                .collect::<Vec<_>>(),
            vec!["src3cccccccc"]
        );

        // Tag dropdown: every stored tag once, ascending.
        assert_eq!(distinct_tags(&pool).await.unwrap(), vec!["eu", "paid"]);
    }
}
