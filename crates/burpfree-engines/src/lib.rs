//! Engines built on top of the proxy + storage.
//!
//! * [`client`]    — HTTP client used by Repeater, Intruder, and Active Scanner.
//! * [`repeater`]  — tabs with request/response history.
//! * [`intruder`]  — attack engine (sniper/BR/pitchfork/clusterbomb).
//! * [`scanner`]   — passive scanner + active scanner framework.
//! * [`sitemap`]   — Target/Site Map.
//! * [`session`]   — cookie jar.
//! * [`tools`]     — Decoder (facade), Comparer, Sequencer-style analysis.

pub mod bambda;
pub mod bambda_library;
pub mod bchecks;
pub mod client;
pub mod crawler;
pub mod discovery;
pub mod comparer;
pub mod graphql;
pub mod intruder;
pub mod macros;
pub mod payloads;
pub mod poc;
pub mod repeater;
pub mod scanner;
pub mod sequencer;
pub mod session;
pub mod sitemap;
pub mod well_known;

pub use client::{send_once, HttpClient, HttpClientConfig};
pub use comparer::{
    compare_json, compare_text, DiffLine, DiffOp, DiffReport, JsonDiffEntry,
    JsonDiffKind, JsonDiffReport,
};
pub use intruder::{AttackMode, AttackResult, IntruderConfig, IntruderJob, JobHandle, JobStatus};
pub use macros::{
    expand_vars, validate_macro, ExtractSource, Macro, MacroContext, MacroExtractor, MacroRunner,
    MacroStep, RuleScope, SessionRule, SessionRuleRegistry, SpliceAction, TranscriptEntry,
};
pub use payloads::library::{catalog as payload_library_catalog, load as payload_library_load, LibraryEntry as PayloadLibraryEntry};
pub use payloads::{PayloadProvider, SimpleListProvider, NumbersProvider, FileProvider, CharsetProvider};
pub use poc::{clickjacking_poc, csrf_poc, cors_poc, generate_clickjacking_html, generate_csrf_html};
pub use repeater::{Repeater, RepeaterTab, RepeaterSend};
pub use scanner::{active, passive, passive_ws, Finding, Severity, Confidence};
pub use sequencer::{analyze_tokens, TokenAnalysis};
pub use session::CookieJar;
pub use sitemap::{SiteMap, SiteNode};
pub use well_known::{
    import as well_known_import, parse_robots_txt, parse_sitemap_xml, RobotsParsed,
    SitemapParsed, WellKnownReport,
};
