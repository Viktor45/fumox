//! What an ingest may do to the proxies that left their feed. Two paths
//! retire a proxy without a verdict, the refresh of a source
//! ([`crate::repo::proxies::reconcile_source`]) and the admin's source-delete
//! click ([`crate::repo::proxies::mark_source_orphans_removed`]); both read
//! their rules from [`IngestPolicy`], so the two cannot disagree.

/// The lifecycle policy of one ingest, decided by two inputs:
/// `[ingest].drop_gate` (the global gate) and whether the source has drop
/// rules of its own. A source's rules define what its feed contains, so only
/// such a source may retire the proxies its rules discarded; without them
/// upstream churn must not end a node that has not failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngestPolicy {
    /// `[ingest].drop_gate`: the global gate.
    drop_gate: bool,
    has_drop_rules: bool,
}

impl IngestPolicy {
    /// The policy of a source refresh.
    pub const fn refresh(drop_gate: bool, has_drop_rules: bool) -> Self {
        Self {
            drop_gate,
            has_drop_rules,
        }
    }

    /// The policy of the admin's source-delete path: the source is gone,
    /// its own drop rules have nothing left to say.
    pub const fn from_drop_gate(drop_gate: bool) -> Self {
        Self {
            drop_gate,
            has_drop_rules: false,
        }
    }

    /// Whether a proxy that vanished from the feed keeps its link and
    /// its lifecycle: only the probe's own verdict may end it.
    pub const fn keep_alive_linger(self) -> bool {
        !(self.drop_gate && self.has_drop_rules)
    }

    /// The statuses the admin's source-delete path must not retire: empty
    /// with the gate open, `ready` and `unknown` with the gate closed.
    pub fn protected_statuses(self) -> &'static [&'static str] {
        if self.drop_gate {
            &[]
        } else {
            &["ready", "unknown"]
        }
    }

    /// The live tiers a refresh keeps linked: the statuses the probe
    /// still owns, so a feed that dropped them does not end them.
    pub fn live_tiers(self) -> &'static [&'static str] {
        &["alive", "ready", "unknown", "quarantine"]
    }

    /// The `status IN (…)` fragment over the live tiers. The statuses are
    /// compile-time literals of this crate, so they can be inlined; caller
    /// text never reaches the SQL.
    pub fn live_tiers_clause(&self) -> String {
        let list = self
            .live_tiers()
            .iter()
            .map(|status| format!("'{status}'"))
            .collect::<Vec<_>>()
            .join(", ");
        format!("status IN ({list})")
    }
}
