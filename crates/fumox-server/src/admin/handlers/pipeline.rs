//! Pipeline builder endpoints: server-side generation and
//! validation for the admin form widget. All of them are POSTs inside the
//! protected admin router, so session auth and the CSRF middleware apply
//! exactly like to every other admin action; the builder fields ride in the
//! urlencoded body (`ped_*` names, see [`crate::admin::pipeline_editor`]).
//! Rendering itself (widget, preview, rows) lives in the editor module ,
//! these handlers are HTTP glue only.

use super::{FormMap, not_found};
use crate::admin::html_response;
use crate::admin::i18n::Lang;
use crate::admin::pipeline_editor::{
    BuilderState, BuilderView, RowsFragment, WidgetFragment, preset, preview_body,
    widget_from_mode_switch,
};
use askama::Template;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;

use crate::admin::AdminState;

/// The response every `#ped-*` fragment endpoint answers with: the
/// rendered fragment as `text/html` with a 200. A fragment that fails to
/// render is a server bug like a full page that does, so the failure
/// takes the same logged-500 path [`render_html`] takes — the handlers
/// share one helper instead of four hand-written response tuples.
fn html_fragment(lang: Lang, name: &'static str, fragment: &impl Template) -> Response {
    html_response(lang, name, StatusCode::OK, fragment.render())
}

/// `#ped-preview` content: the generated JSON plus its validation outcome
/// (the same `CompiledPipeline::from_json` the save path uses).
pub async fn pipeline_preview(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Form(form): Form<Vec<(String, String)>>,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    // `preview_body` has already handled its own rendering failure (logged,
    // empty region), so the body arrives pre-rendered.
    let body = preview_body(&lang, &BuilderState::from_form(&form));
    html_response(lang, "pipeline/_preview.html", StatusCode::OK, Ok(body))
}

/// `#ped-rows` content: the rule lines after add/remove. `section` picks
/// the container (`rename`, default, or `drop`), `remove` carries the
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
    apply_rows_request(&mut built, &params);
    let section = params.get("section").cloned().unwrap_or_default();
    // An absent section is the rename container (the *Add rule* button
    // posts without one). An unknown name is a broken request, not the
    // rename rows: the caller asked for a container the widget does not
    // render.
    let section = if section.is_empty() {
        "rename"
    } else {
        &section
    };
    let Some(fragment) = RowsFragment::for_section(lang.clone(), BuilderView::new(&built), section)
    else {
        return not_found(lang, "err.section_not_found");
    };
    html_fragment(lang, "pipeline/_rows.html", &fragment)
}

/// What the `remove` parameter asks the rows endpoint for.
///
/// Absent means "add a line" (the *Add rule* button), an index means
/// "drop that line", and a value that does not parse is a broken
/// request: it changes nothing at all. The two used to collapse into
/// one, so a malformed `remove` appended a fresh line instead of
/// leaving the rows as they were.
#[derive(Debug, PartialEq, Eq)]
enum Remove {
    Absent,
    Index(usize),
    Broken,
}

/// Read the `remove` parameter of a rows request.
fn remove_request(params: &FormMap) -> Remove {
    match params.get("remove") {
        None => Remove::Absent,
        Some(raw) => match raw.parse::<usize>() {
            Ok(index) => Remove::Index(index),
            Err(_) => Remove::Broken,
        },
    }
}

/// Apply a rows request to the builder state: drop the named line, or
/// append a fresh empty one.
fn apply_rows_request(built: &mut BuilderState, params: &FormMap) {
    // `?render=1` is the change-trigger from a target select: the
    // browser already has the row count it wants, the round-trip only
    // has to repaint the row layout (regex ↔ ASN switch). Without this
    // flag every change would append a fresh empty row, exactly like the
    // explicit *Add rule* button does.
    let append = !params.contains_key("render");
    match (
        params.get("section").map(String::as_str),
        remove_request(params),
        append,
    ) {
        // A `remove` that does not parse is a broken request: the rows
        // stay as they are, no line is appended.
        (_, Remove::Broken, _) => {}
        (Some("drop"), Remove::Index(index), _) => {
            if index < built.drop.len() {
                built.drop.remove(index);
            }
        }
        (Some("drop"), Remove::Absent, true) => built.drop.push(Default::default()),
        (_, Remove::Index(index), _) => {
            if index < built.rename.len() {
                built.rename.remove(index);
            }
        }
        (_, Remove::Absent, true) => built.rename.push(Default::default()),
        _ => {}
    }
}

/// Mode switch: the asymmetric builder ⇄ raw toggle. The mode decision
/// and the form parsing live in the editor module
/// ([`widget_from_mode_switch`]); this handler is HTTP glue only.
pub async fn pipeline_mode(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(params): Query<FormMap>,
    Form(form): Form<Vec<(String, String)>>,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let csrf = state.csrf_for(&headers);
    let profile = params.get("profile").map(|v| v == "1").unwrap_or(false);
    let widget = widget_from_mode_switch(
        lang.clone(),
        &csrf,
        params.get("to").map(String::as_str),
        &form,
        profile,
    );
    html_fragment(lang, "pipeline/_widget.html", &widget)
}

/// A preset: re-render the whole widget with the ready-made
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
    // A preset name the widget does not know is refused with an explicit
    // error instead of silently rendering the empty state: the operator
    // asked for a ready-made configuration and must not lose the built
    // one to a typo in a link.
    let built = match preset(params.get("name").map(String::as_str).unwrap_or("blank")) {
        Some(built) => built,
        None => return not_found(lang, "err.preset_not_found"),
    };
    let widget = WidgetFragment::builder_mode(lang.clone(), &csrf, &built, profile, None);
    html_fragment(lang, "pipeline/_widget.html", &widget)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::pipeline_editor::{DropRow, RenameRow};

    fn params(pairs: &[(&str, &str)]) -> FormMap {
        pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    /// A state with `rename` rename rows and `drop` drop rows.
    fn state_with_rows(rename: usize, drop: usize) -> BuilderState {
        BuilderState {
            rename: vec![RenameRow::default(); rename],
            drop: vec![DropRow::default(); drop],
            ..BuilderState::new()
        }
    }

    /// A `remove` that does not parse is a broken request: the rows stay
    /// as they are. It used to read as "no remove at all", which
    /// appended a fresh line to the section.
    #[test]
    fn a_broken_remove_changes_nothing() {
        for broken in ["abc", "", "1.5", "-1"] {
            let mut built = state_with_rows(2, 2);
            apply_rows_request(&mut built, &params(&[("remove", broken)]));
            assert_eq!(built.rename.len(), 2, "remove={broken:?}");
            assert_eq!(built.drop.len(), 2, "remove={broken:?}");
        }
    }

    /// A `remove` that does not parse in the drop section changes
    /// nothing either.
    #[test]
    fn a_broken_remove_in_the_drop_section_changes_nothing() {
        let mut built = state_with_rows(1, 3);
        apply_rows_request(
            &mut built,
            &params(&[("section", "drop"), ("remove", "abc")]),
        );
        assert_eq!(built.rename.len(), 1);
        assert_eq!(built.drop.len(), 3);
    }

    /// An absent `remove` is the *Add rule* button: a fresh empty line
    /// is appended to the section.
    #[test]
    fn an_absent_remove_appends_a_line() {
        let mut built = state_with_rows(1, 0);
        apply_rows_request(&mut built, &params(&[]));
        assert_eq!(built.rename.len(), 2);

        let mut built = state_with_rows(0, 1);
        apply_rows_request(&mut built, &params(&[("section", "drop")]));
        assert_eq!(built.drop.len(), 2);
    }

    /// A `remove` with an index drops that line and leaves the others
    /// alone.
    #[test]
    fn a_remove_with_an_index_drops_the_line() {
        let mut built = state_with_rows(3, 0);
        apply_rows_request(&mut built, &params(&[("remove", "1")]));
        assert_eq!(built.rename.len(), 2);

        let mut built = state_with_rows(0, 3);
        apply_rows_request(&mut built, &params(&[("section", "drop"), ("remove", "2")]));
        assert_eq!(built.drop.len(), 2);
    }

    /// An index past the end of the section changes nothing: there is no
    /// such line to drop.
    #[test]
    fn a_remove_past_the_end_changes_nothing() {
        let mut built = state_with_rows(2, 0);
        apply_rows_request(&mut built, &params(&[("remove", "9")]));
        assert_eq!(built.rename.len(), 2);
    }
}
