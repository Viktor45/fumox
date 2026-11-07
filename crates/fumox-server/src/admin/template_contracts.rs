//! Contract tests between the admin script (`static/app.js`) and the
//! templates it drives.
//!
//! The script addresses the rendered markup by attribute names and id
//! schemes; a rename on one side silently breaks the behaviour of the
//! other (a selector that matches nothing toggles nothing). These tests
//! read both sources as text and assert the shared tokens line up, so
//! the drift is a red test instead of a broken page.

/// The single admin script, loaded with `defer` on every page.
const APP_JS: &str = include_str!("../../static/app.js");

/// The pipeline widget templates the script's tri-state logic drives.
const WIDGET: &str = include_str!("../../templates/pipeline/_widget.html");

/// One `'…'` string constant of the script, as `var NAME = '…';`.
/// Panics with `name` in the message when the constant is gone: the
/// test then fails loudly instead of comparing against nothing.
fn js_string_constant(js: &str, name: &str) -> String {
    let needle = format!("{name} = '");
    let start = js
        .find(&needle)
        .unwrap_or_else(|| panic!("app.js no longer defines {name}"))
        + needle.len();
    let rest = &js[start..];
    let end = rest
        .find('\'')
        .unwrap_or_else(|| panic!("app.js constant {name} is not a '…' string"));
    rest[..end].to_string()
}

/// Every value the markup binds to `attr`, as `attr="value"`.
fn attr_values(html: &str, attr: &str) -> Vec<String> {
    let needle = format!("{attr}=\"");
    let mut values = Vec::new();
    let mut rest = html;
    while let Some(at) = rest.find(&needle) {
        let tail = &rest[at + needle.len()..];
        match tail.find('"') {
            Some(end) => {
                values.push(tail[..end].to_string());
                rest = &tail[end..];
            }
            None => break,
        }
    }
    values.sort();
    values.dedup();
    values
}

/// The tokens of the tri-state widget are one contract: the script's
/// attribute constants (`PED_SECTION_ATTR`, `PED_INNER_ATTR`,
/// `PED_INPUT_PREFIX`) must be the very names the widget renders, or
/// the show/hide logic silently matches nothing.
#[test]
fn app_js_ped_tokens_are_the_ones_the_widget_renders() {
    let section_attr = js_string_constant(APP_JS, "PED_SECTION_ATTR");
    let inner_attr = js_string_constant(APP_JS, "PED_INNER_ATTR");
    let input_prefix = js_string_constant(APP_JS, "PED_INPUT_PREFIX");

    // Both attributes the script queries are emitted by the widget, and
    // the radio-group prefix names inputs the widget renders.
    assert!(
        WIDGET.contains(&format!("{section_attr}=")),
        "app.js queries {section_attr:?} but pipeline/_widget.html never emits it"
    );
    assert!(
        WIDGET.contains(&format!("{inner_attr}=")),
        "app.js queries {inner_attr:?} but pipeline/_widget.html never emits it"
    );
    assert!(
        WIDGET.contains(&format!("name=\"{input_prefix}")),
        "app.js builds names with the prefix {input_prefix:?} but pipeline/_widget.html renders none"
    );
}

/// Every section of the widget renders all three tokens together: the
/// section marker the script walks, the inner block it toggles and the
/// radio group that drives the state. A section missing one of them is
/// rendered but dead (never synced after a swap).
#[test]
fn every_ped_section_renders_its_inner_block_and_radio_group() {
    let input_prefix = js_string_constant(APP_JS, "PED_INPUT_PREFIX");
    let sections = attr_values(WIDGET, "data-ped-section");
    let inners = attr_values(WIDGET, "data-ped-inner");

    assert!(
        !sections.is_empty(),
        "pipeline/_widget.html renders no data-ped-section markers"
    );
    assert_eq!(
        sections, inners,
        "every data-ped-section must have the matching data-ped-inner block"
    );
    for section in &sections {
        let group = format!("name=\"{input_prefix}{section}\"");
        assert!(
            WIDGET.contains(&group),
            "section {section:?} has no `{input_prefix}{section}` radio group in pipeline/_widget.html"
        );
    }
}
