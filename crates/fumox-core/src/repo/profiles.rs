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
    sqlx::query(&format!(
        "INSERT INTO profiles ({COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ))
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
        return Err(crate::Error::Database(sqlx::Error::RowNotFound));
    }
    Ok(())
}

pub async fn get(pool: &DbPool, id: &str) -> crate::Result<Option<Profile>> {
    let row: Option<ProfileRow> =
        sqlx::query_as(&format!("SELECT {COLUMNS} FROM profiles WHERE id = ?"))
            .bind(id)
            .fetch_optional(pool)
            .await?;
    row.map(Profile::try_from).transpose()
}

pub async fn get_by_slug(pool: &DbPool, slug: &str) -> crate::Result<Option<Profile>> {
    let row: Option<ProfileRow> =
        sqlx::query_as(&format!("SELECT {COLUMNS} FROM profiles WHERE slug = ?"))
            .bind(slug)
            .fetch_optional(pool)
            .await?;
    row.map(Profile::try_from).transpose()
}

/// Resolve a `/sub/{token}` path segment: slug first, then raw id.
pub async fn resolve_token(pool: &DbPool, token: &str) -> crate::Result<Option<Profile>> {
    let row: Option<ProfileRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM profiles WHERE slug = ? OR id = ? ORDER BY slug IS NULL LIMIT 1"
    ))
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
    let rows: Vec<ProfileRow> = sqlx::query_as(&query).fetch_all(pool).await?;
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
    let mut tx = pool.begin().await?;
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
        let pool = temp_pool().await;
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
        let pool = temp_pool().await;
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
}
