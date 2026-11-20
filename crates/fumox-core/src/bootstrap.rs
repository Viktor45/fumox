//! The boot sequence `fumox-server` and `fumox-probe` share: install the
//! crypto provider reqwest needs, load the configuration (printing it and
//! exiting for `--print-config`), install tracing at their own `[log]` level,
//! and report what the configuration resolved to. The steps live here so a
//! change to the wording or the report fields cannot drift between the two
//! journals (the operator reads them together).
//!
//! The binaries keep what differs at its own place: the `Cli` structs and the
//! tracing level are theirs, the server's `--health-check` runs between
//! [`load_or_print`] and the tracing half (a probe must not install a
//! subscriber, open the database or run the migrations just to be measured),
//! and the server's config-writer cleanup stays between the two reports.

use std::path::Path;

/// The shared head of both `main`s: install the crypto provider, load the
/// configuration and handle `--print-config` (the resolved TOML is printed
/// and `None` comes back, which the caller answers with its exit). A normal
/// load hands out the config and the file it came from (see
/// [`crate::config::LoadedConfig`]).
pub fn load_or_print(
    cli_config: Option<&Path>,
    print_config: bool,
) -> crate::Result<Option<crate::config::LoadedConfig>> {
    // Before anything builds an HTTP client: reqwest is compiled without a
    // crypto provider, so one has to be installed first
    crate::tls::install_crypto_provider();
    let loaded = crate::config::load(cli_config)?;
    if print_config {
        print!("{}", crate::config::dump(&loaded.config)?);
        return Ok(None);
    }
    Ok(Some(loaded))
}

/// The loader cannot log (its own level comes from the config), so the report
/// runs once tracing is up: call it after `logging::init_tracing`.
pub fn report_config_file(path: &crate::config::ResolvedConfigPath) {
    match path {
        crate::config::ResolvedConfigPath::Loaded(file) => {
            tracing::info!(config = %file.display(), "config file loaded");
        }
        crate::config::ResolvedConfigPath::Missing => {
            tracing::info!(
                "no config file found (looked at {} or {}); using built-in defaults",
                crate::config::CONFIG_PATH_ENV,
                crate::DEFAULT_CONFIG_PATH
            );
        }
    }
}

/// Reports the resolved database path and the count of the `FUMOX_*`
/// variables figment layered over the file, so a surprise override is
/// attributable; names and values stay out of the log. The path matters to
/// both binaries: pointing the probe at a different file than the server
/// would be invisible until the journals diverge, and on the server the path
/// is otherwise only visible on /admin/settings.
pub fn report_database(config: &crate::config::AppConfig) {
    let env_overrides = std::env::vars()
        .filter(|(key, _)| key.starts_with("FUMOX_"))
        .count();
    tracing::info!(
        path = %config.database.path.display(),
        env_overrides,
        "database configured"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_config_consumes_the_run_a_load_hands_out_the_config() {
        let dir = std::env::temp_dir().join(format!("fumox-bootstrap-{}", crate::models::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("app.toml");
        std::fs::write(&path, "[log]\nprobe = \"debug\"\n").unwrap();

        let printed = load_or_print(Some(&path), true).expect("the document must parse");
        assert!(printed.is_none(), "--print-config must consume the run");

        let loaded = load_or_print(Some(&path), false)
            .expect("the document must parse")
            .expect("a normal load");
        assert_eq!(loaded.path, crate::config::ResolvedConfigPath::Loaded(path));
        assert_eq!(
            loaded.config.log.probe,
            crate::config::LogLevel::Debug,
            "the file's value must reach the resolved config"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
