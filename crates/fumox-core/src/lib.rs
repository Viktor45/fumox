//! fumox-core — shared library for the Fumox proxy-subscription service.
//!
//! Contains configuration loading, database access helpers, domain models,
//! fingerprinting, protocol parsers, geo enrichment and output-format
//! encoders used by both `fumox-server` and `fumox-probe`.

pub mod config;
pub mod db;
pub mod error;
pub mod fingerprint;
pub mod formats;
pub mod geo;
pub mod logging;
pub mod models;
pub mod parsers;
pub mod repo;

pub use config::{AppConfig, DEFAULT_CONFIG_PATH};
pub use error::{Error, Result};
pub use models::{ProxyEntry, Scheme};
