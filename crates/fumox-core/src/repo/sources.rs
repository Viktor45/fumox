//! CRUD for the `sources` table.

use crate::db::DbPool;
use crate::models::{ErrorClass, InputFormat, Scheme, Source};
use sqlx::FromRow;

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
    cache_ttl_seconds, tags, pipeline, headers, created_at, updated_at,
    last_fetched_at, last_error, error_class";

/// Insert a new source. The caller assigns `id` (see [`crate::models::new_id`]).
pub async fn create(pool: &DbPool, source: &Source) -> crate::Result<()> {
    sqlx::query(&format!(
        "INSERT INTO sources ({COLUMNS})
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ))
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
    .bind(source.created_at)
    .bind(source.updated_at)
    .bind(source.last_fetched_at)
    .bind(&source.last_error)
    .bind(source.error_class.map(ErrorClass::as_str))
    .execute(pool)
    .await?;
    Ok(())
}

/// Update mutable source fields. `id` and `created_at` are immutable;
/// `updated_at` must be set by the caller.
pub async fn update(pool: &DbPool, source: &Source) -> crate::Result<()> {
    let affected = sqlx::query(
        "UPDATE sources SET
            slug = ?, name = ?, url = ?, enabled = ?, encoding = ?, input_format = ?,
            protocols = ?, cache_ttl_seconds = ?, tags = ?, pipeline = ?, headers = ?,
            updated_at = ?, last_fetched_at = ?, last_error = ?, error_class = ?
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
    .bind(source.updated_at)
    .bind(source.last_fetched_at)
    .bind(&source.last_error)
    .bind(source.error_class.map(ErrorClass::as_str))
    .bind(&source.id)
    .execute(pool)
    .await?
    .rows_affected();
    if affected == 0 {
        return Err(crate::Error::Database(sqlx::Error::RowNotFound));
    }
    Ok(())
}

pub async fn get(pool: &DbPool, id: &str) -> crate::Result<Option<Source>> {
    let row: Option<SourceRow> =
        sqlx::query_as(&format!("SELECT {COLUMNS} FROM sources WHERE id = ?"))
            .bind(id)
            .fetch_optional(pool)
            .await?;
    row.map(Source::try_from).transpose()
}

pub async fn get_by_slug(pool: &DbPool, slug: &str) -> crate::Result<Option<Source>> {
    let row: Option<SourceRow> =
        sqlx::query_as(&format!("SELECT {COLUMNS} FROM sources WHERE slug = ?"))
            .bind(slug)
            .fetch_optional(pool)
            .await?;
    row.map(Source::try_from).transpose()
}

/// Resolve a `/src/{token}` path segment: slug first, then raw id.
pub async fn resolve_token(pool: &DbPool, token: &str) -> crate::Result<Option<Source>> {
    let row: Option<SourceRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM sources WHERE slug = ? OR id = ? ORDER BY slug IS NULL LIMIT 1"
    ))
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
    let rows: Vec<SourceRow> = sqlx::query_as(&query).fetch_all(pool).await?;
    rows.into_iter().map(Source::try_from).collect()
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
/// and clears the error fields; failure stores the message and its class
/// (SPEC §10.2 vocabulary).
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
            created_at: now,
            updated_at: now,
            last_fetched_at: None,
            last_error: None,
            error_class: None,
        }
    }

    #[tokio::test]
    async fn source_crud_round_trip() {
        let pool = temp_pool().await;
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
        source.updated_at += 10;
        update(&pool, &source).await.unwrap();
        let loaded = get(&pool, "src1aaaaaaaa").await.unwrap().unwrap();
        assert_eq!(loaded.name, "Renamed");
        assert_eq!(loaded.cache_ttl_seconds, 600);

        assert!(delete(&pool, "src1aaaaaaaa").await.unwrap());
        assert!(get(&pool, "src1aaaaaaaa").await.unwrap().is_none());
        assert!(!delete(&pool, "src1aaaaaaaa").await.unwrap());
    }

    #[tokio::test]
    async fn fetch_outcome_updates_error_fields() {
        let pool = temp_pool().await;
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

    #[tokio::test]
    async fn list_filters_enabled() {
        let pool = temp_pool().await;
        let a = sample_source("src3cccccccc");
        let mut b = sample_source("src4dddddddd");
        b.enabled = false;
        b.slug = None;
        create(&pool, &a).await.unwrap();
        create(&pool, &b).await.unwrap();
        assert_eq!(list(&pool, false).await.unwrap().len(), 2);
        assert_eq!(list(&pool, true).await.unwrap().len(), 1);
    }
}
