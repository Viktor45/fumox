//! CRUD for the `sources` table.

use super::BindWhereFilter;
use crate::db::DbPool;
use crate::models::{ErrorClass, InputFormat, IpFamily, Scheme, Source};
use sqlx::FromRow;
use std::collections::HashMap;

#[derive(FromRow)]
struct SourceRow {
    id: String,
    slug: Option<String>,
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
            id: row.id,
            slug: row.slug,
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
                .transpose()?,
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
                .map(|text| super::text_to_json(&text, "sources.pipeline"))
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

fn protocols_json(protocols: &Option<Vec<Scheme>>) -> crate::Result<Option<String>> {
    protocols
        .as_ref()
        .map(|list| {
            let names: Vec<&str> = list.iter().map(|scheme| scheme.as_str()).collect();
            super::json_to_text(&serde_json::to_value(names).expect("scheme list serializes"))
        })
        .transpose()
}

fn headers_json(
    headers: &Option<std::collections::BTreeMap<String, String>>,
) -> crate::Result<Option<String>> {
    headers
        .as_ref()
        .map(|map| super::json_to_text(&serde_json::to_value(map).expect("header map serializes")))
        .transpose()
}

const COLUMNS: &str = "id, slug, name, url, enabled, encoding, input_format, protocols,
    cache_ttl_seconds, tags, pipeline, headers, ip_family, created_at, updated_at,
    last_fetched_at, last_error, error_class";

/// Insert a new source. The caller assigns `id` (see [`crate::models::new_id`]).
pub async fn create(pool: &DbPool, source: &Source) -> crate::Result<()> {
    // sqlx 0.9 SqlSafeStr: {COLUMNS} is a compile-time constant; all data
    // flows through .bind().
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "INSERT INTO sources ({COLUMNS})
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )))
    .bind(&source.id)
    .bind(&source.slug)
    .bind(&source.name)
    .bind(&source.url)
    .bind(source.enabled)
    .bind(source.encoding.as_str())
    .bind(source.input_format.map(InputFormat::as_str))
    .bind(protocols_json(&source.protocols)?)
    .bind(source.cache_ttl_seconds)
    .bind(
        source
            .tags
            .as_ref()
            .map(|tags| super::json_to_text(&serde_json::to_value(tags).expect("tags serialize")))
            .transpose()?,
    )
    .bind(
        source
            .pipeline
            .as_ref()
            .map(super::json_to_text)
            .transpose()?,
    )
    .bind(headers_json(&source.headers)?)
    .bind(source.ip_family.map(IpFamily::as_str))
    .bind(source.created_at)
    .bind(source.updated_at)
    .bind(source.last_fetched_at)
    .bind(&source.last_error)
    .bind(source.error_class.map(ErrorClass::as_str))
    .execute(pool)
    .await?;
    Ok(())
}

/// The fields a change to which invalidates the freshness stamp
/// (`last_fetched_at`): the stored rows were reconciled from a payload
/// fetched under these settings, so after an edit the next ingest must
/// re-fetch instead of trusting the old stamp (the TTL short-circuit of the
/// server's `ingest::ingest_source` reads exactly this column). Cosmetic
/// edits — name, slug, tags — keep the stamp.
fn fetch_stamp_stale(old: &Source, new: &Source) -> bool {
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

/// Update mutable source fields. `id` and `created_at` are immutable;
/// `updated_at` must be set by the caller.
///
/// A change to a fetch-relevant field (see [`fetch_stamp_stale`]) resets
/// `last_fetched_at`, so the next ingest re-fetches under the new settings
/// instead of riding out the TTL window on a payload reconciled under the
/// old ones.
pub async fn update(pool: &DbPool, source: &Source) -> crate::Result<()> {
    let last_fetched_at = match get(pool, &source.id).await? {
        Some(existing) if fetch_stamp_stale(&existing, source) => None,
        _ => source.last_fetched_at,
    };
    let affected = sqlx::query(
        "UPDATE sources SET
            slug = ?, name = ?, url = ?, enabled = ?, encoding = ?, input_format = ?,
            protocols = ?, cache_ttl_seconds = ?, tags = ?, pipeline = ?, headers = ?,
            ip_family = ?, updated_at = ?, last_fetched_at = ?, last_error = ?, error_class = ?
         WHERE id = ?",
    )
    .bind(&source.slug)
    .bind(&source.name)
    .bind(&source.url)
    .bind(source.enabled)
    .bind(source.encoding.as_str())
    .bind(source.input_format.map(InputFormat::as_str))
    .bind(protocols_json(&source.protocols)?)
    .bind(source.cache_ttl_seconds)
    .bind(
        source
            .tags
            .as_ref()
            .map(|tags| super::json_to_text(&serde_json::to_value(tags).expect("tags serialize")))
            .transpose()?,
    )
    .bind(
        source
            .pipeline
            .as_ref()
            .map(super::json_to_text)
            .transpose()?,
    )
    .bind(headers_json(&source.headers)?)
    .bind(source.ip_family.map(IpFamily::as_str))
    .bind(source.updated_at)
    .bind(last_fetched_at)
    .bind(&source.last_error)
    .bind(source.error_class.map(ErrorClass::as_str))
    .bind(&source.id)
    .execute(pool)
    .await?
    .rows_affected();
    if affected == 0 {
        return Err(crate::Error::Database(sqlx::Error::RowNotFound.to_string()));
    }
    Ok(())
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
/// Ids with no row are absent from the map, duplicate ids read one row. The
/// batched read backs `/sub`'s member load, which walks a profile's
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
        let source = Source::try_from(row)?;
        by_id.insert(source.id.clone(), source);
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
pub async fn resolve_token(pool: &DbPool, token: &str) -> crate::Result<Option<Source>> {
    let row: Option<SourceRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM sources WHERE slug = ? OR id = ? ORDER BY slug IS NULL LIMIT 1"
    )))
    .bind(token)
    .bind(token)
    .fetch_optional(pool)
    .await?;
    row.map(Source::try_from).transpose()
}

pub async fn list(pool: &DbPool, enabled_only: bool) -> crate::Result<Vec<Source>> {
    let query = if enabled_only {
        format!("SELECT {COLUMNS} FROM sources WHERE enabled = 1 ORDER BY created_at")
    } else {
        format!("SELECT {COLUMNS} FROM sources ORDER BY created_at")
    };
    let rows: Vec<SourceRow> = sqlx::query_as(sqlx::AssertSqlSafe(query.as_str()))
        .fetch_all(pool)
        .await?;
    rows.into_iter().map(Source::try_from).collect()
}

// Admin sources list
//
// The dynamic list screen: filter clauses are whitelisted fragments
// assembled through the shared [`super::WhereFilter`], every value flows
// through a bind. The whole list is returned (no pagination — the screen
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
    /// Substring match against name and url (`LIKE %q%`).
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
                "EXISTS (SELECT 1 FROM json_each(s.tags) WHERE json_each.value = ?)",
                &self.tag,
            );
        }
        if !self.query.is_empty() {
            let needle = format!("%{}%", self.query);
            wf = wf
                .text("(s.name LIKE ? OR s.url LIKE ?)", needle.clone())
                .text_value(needle);
        }
        wf
    }
}

/// The admin sources list for `filter`, newest-created first.
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
    Ok(rows)
}

/// Distinct tags stored across all sources, ascending; the tag filter
/// dropdown of the admin sources list. Unparsable tag JSON yields no tag.
pub async fn distinct_tags(pool: &DbPool) -> crate::Result<Vec<String>> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT json_each.value FROM sources, json_each(sources.tags) ORDER BY 1",
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
/// and clears the error fields; failure stores the message and its class.
pub async fn record_fetch_outcome(
    pool: &DbPool,
    id: &str,
    outcome: &FetchOutcome<'_>,
) -> crate::Result<()> {
    let (fetched_at, error, class): (Option<i64>, Option<&str>, Option<&str>) = match outcome {
        FetchOutcome::Success { at } => (Some(*at), None, None),
        FetchOutcome::Failure {
            at: _,
            error,
            class,
        } => (None, Some(*error), Some(class.as_str())),
    };
    sqlx::query(
        "UPDATE sources SET
            last_fetched_at = COALESCE(?, last_fetched_at),
            last_error = ?,
            error_class = ?,
            updated_at = COALESCE(?, updated_at)
         WHERE id = ?",
    )
    .bind(fetched_at)
    .bind(error)
    .bind(class)
    .bind(fetched_at)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Result of one fetch attempt, as stored on the source row.
#[derive(Debug, Clone)]
pub enum FetchOutcome<'a> {
    Success {
        at: i64,
    },
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
        update(&pool, &source).await.unwrap();
        let loaded = get(&pool, "src1aaaaaaaa").await.unwrap().unwrap();
        assert_eq!(loaded.name, "Renamed");
        assert_eq!(loaded.cache_ttl_seconds, 600);
        assert_eq!(loaded.ip_family, Some(IpFamily::Ipv6));

        source.ip_family = None;
        update(&pool, &source).await.unwrap();
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

    /// A change to a fetch-relevant field resets `last_fetched_at`, so the
    /// next ingest re-fetches under the new settings; a cosmetic edit keeps
    /// the stamp.
    #[tokio::test]
    async fn update_resets_the_freshness_stamp_on_a_fetch_relevant_change() {
        let (_dir, pool) = temp_pool().await;
        let mut source = sample_source("src5eeeeeeee");
        source.last_fetched_at = Some(crate::models::now_ts());
        create(&pool, &source).await.unwrap();

        // Cosmetic edits: the stamp survives.
        source.name = "Renamed".into();
        source.slug = Some("renamed-slug".into());
        source.tags = Some(vec!["misc".into()]);
        source.updated_at += 5;
        update(&pool, &source).await.unwrap();
        let loaded = get(&pool, "src5eeeeeeee").await.unwrap().unwrap();
        assert!(
            loaded.last_fetched_at.is_some(),
            "a cosmetic edit must keep the freshness stamp"
        );

        // A fetch-relevant edit resets the stamp; the rest of the row is
        // written exactly as given.
        source.url = "https://example.com/other".into();
        update(&pool, &source).await.unwrap();
        let loaded = get(&pool, "src5eeeeeeee").await.unwrap().unwrap();
        assert_eq!(loaded.url, "https://example.com/other");
        assert_eq!(loaded.name, "Renamed");
        assert!(
            loaded.last_fetched_at.is_none(),
            "a fetch-relevant edit must reset the freshness stamp"
        );
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
