//! Pipeline builder endpoints (PIPELINE.md §3): server-side generation and
//! validation for the admin form widget. All of them are POSTs inside the
//! protected admin router, so session auth and the CSRF middleware apply
//! exactly like to every other admin action; the builder fields ride in the
//! urlencoded body (`ped_*` names, see [`crate::admin::pipeline_editor`]).
//! Rendering itself (widget, preview, rows) lives in the editor module —
//! these handlers are HTTP glue only.

use super::FormMap;
use crate::admin::pipeline_editor::{
    BuilderState, BuilderView, Ingest, RowsFragment, WidgetFragment, preset, preview_body,
};
use crate::admin::render_html;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::admin::AdminState;

/// `#ped-preview` content: the generated JSON plus its validation outcome
/// (the same `CompiledPipeline::from_json` the save path uses).
pub async fn pipeline_preview(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Form(form): Form<Vec<(String, String)>>,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let body = preview_body(&lang, &BuilderState::from_form(&form));
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response()
}

/// `#ped-rows` content: the rule lines after add/remove. `section` picks
/// the container (`rename` — default — or `drop`), `remove` carries the
/// index of the line to delete; without `remove` a fresh empty line is
/// appended. The whole container is re-rendered from the posted fields,
/// so nothing the administrator typed into the other lines is lost.
pub async fn pipeline_rows(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(params): Query<FormMap>,
    Form(form): Form<Vec<(String, String)>>,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let mut built = BuilderState::from_form(&form);
    let index = params
        .get("remove")
        .and_then(|index| index.parse::<usize>().ok());
    match (params.get("section").map(String::as_str), index) {
        (Some("drop"), Some(index)) => {
            if index < built.drop.len() {
                built.drop.remove(index);
            }
        }
        (Some("drop"), None) => built.drop.push(Default::default()),
        (_, Some(index)) => {
            if index < built.rename.len() {
                built.rename.remove(index);
            }
        }
        (_, None) => built.rename.push(Default::default()),
    }
    let section = params.get("section").cloned().unwrap_or_default();
    let fragment = RowsFragment::for_section(lang.clone(), BuilderView::new(&built), &section);
    render_html(lang, &fragment, StatusCode::OK)
}

/// Mode switch (PIPELINE.md §2.2): the asymmetric builder ⇄ raw toggle.
/// Builder → raw is always safe — the JSON is generated from the fields.
/// Raw → builder only when the textarea parses into the builder; otherwise
/// the widget stays in raw mode with the warning and the JSON untouched.
pub async fn pipeline_mode(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(params): Query<FormMap>,
    Form(form): Form<Vec<(String, String)>>,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let csrf = state.csrf_for(&headers);
    let profile = params.get("profile").map(|v| v == "1").unwrap_or(false);
    let get = |key: &str| {
        form.iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_default()
    };

    let widget = if params.get("to").map(String::as_str) == Some("raw") {
        let json = BuilderState::from_form(&form)
            .emit()
            .map(|value| serde_json::to_string_pretty(&value).unwrap_or_default())
            .unwrap_or_default();
        WidgetFragment::raw_mode(lang, &csrf, json, false, None)
    } else if form.iter().any(|(k, _)| k.starts_with("ped_")) {
        // Already in builder mode (no textarea on the form): keep the fields.
        WidgetFragment::builder_mode(lang, &csrf, &BuilderState::from_form(&form), profile, None)
    } else {
        let raw = get("pipeline");
        if raw.is_empty() {
            WidgetFragment::builder_mode(lang, &csrf, &BuilderState::new(), profile, None)
        } else {
            match serde_json::from_str::<serde_json::Value>(&raw) {
                Ok(value) => match BuilderState::ingest(Some(&value)) {
                    Ingest::Builder(built) => {
                        WidgetFragment::builder_mode(lang, &csrf, &built, profile, None)
                    }
                    Ingest::Raw => WidgetFragment::raw_mode(lang, &csrf, raw, true, None),
                },
                Err(_) => WidgetFragment::raw_mode(lang, &csrf, raw, true, None),
            }
        }
    };
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        widget.html(),
    )
        .into_response()
}

/// A preset (PIPELINE.md §6): re-render the whole widget with the ready-made
/// state; the preview is refreshed with it (it is part of the widget).
pub async fn pipeline_preset(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(params): Query<FormMap>,
    Form(_form): Form<Vec<(String, String)>>,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let csrf = state.csrf_for(&headers);
    let profile = params.get("profile").map(|v| v == "1").unwrap_or(false);
    let built = preset(params.get("name").map(String::as_str).unwrap_or("blank"));
    let widget = WidgetFragment::builder_mode(lang, &csrf, &built, profile, None);
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        widget.html(),
    )
        .into_response()
}
