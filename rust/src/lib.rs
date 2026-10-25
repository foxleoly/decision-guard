//! decision-guard: judges an agent's shell command before it runs. Subcommands: `hook <agent>`, `web`, `archive`,
//! `check`, `service`.
//!
//! Modules: [`rules`] (deterministic rules), [`judge`] (service, requests, cache, thresholds), [`store`] (SQLite audit
//! log), [`decide`] (the order of everything), [`hook`] (agent adapters), [`web`] (the viewer), [`archive`] (log
//! rotation), [`service`] (which decision service answers), [`jsc`] (JavaScript-compatible primitives), [`readonly`]
//! (the read-only fast path).

pub mod archive;
pub mod decide;
pub mod fsx;
pub mod hook;
pub mod jsc;
pub mod judge;
pub mod live;
pub mod pyproof;
pub mod readonly;
pub mod rules;
pub mod rules_cmd;
pub mod service;
pub mod store;
pub mod web;
pub mod web_live;
