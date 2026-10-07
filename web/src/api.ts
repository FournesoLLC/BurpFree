// Typed wrappers around Tauri commands.
// All backend calls go through this module so the UI never calls `invoke`
// directly with stringly-typed command names.

import { invoke } from "@tauri-apps/api/core";

export type ProjectInfo = {
  root: string;
  name: string;
  listeners: string[];
  tx_count: number;
  scope_rules: number;
};

export type HistoryFilter = {
  /** Inclusive wall-clock lower bound (ms since epoch). From toolbar
   *  date input or a `Last Nm` preset. */
  ts_min_ms?: number;
  /** Inclusive wall-clock upper bound (ms since epoch). */
  ts_max_ms?: number;
  /** Inclusive lower bound on response body size in bytes. Rows
   *  whose response hasn't landed yet (status/response_blob = NULL)
   *  are excluded by the lower bound — matches Burp's "size" filter
   *  which only looks at completed txns. */
  resp_size_min?: number;
  /** Inclusive upper bound on response body size in bytes. */
  resp_size_max?: number;
  /** Response MIME quick-filter: each entry is a substring probed
   *  against `content_type` and the entries OR together in the SQL
   *  predicate (vs `content_type_contains` which stays single-valued
   *  and ANDs). Mirrors Burp's MIME chip row. Empty vec = no filter. */
  content_type_classes?: string[];
  /** Keep only transactions whose `error` column is non-NULL —
   *  network drops, TLS handshake failures, parse errors, or any
   *  upstream fault that stopped a response from being recorded.
   *  Mirrors Burp's "Only show responses with errors" checkbox. */
  error_only?: boolean;
  host_contains?: string;
  method?: string;
  status_min?: number;
  status_max?: number;
  /** Multi-select status-class chip row (Burp's HTTP history filter
   *  supports simultaneous 2xx + 4xx + 5xx selection). Each entry is
   *  a hundreds-digit (1 through 5); the backend ORs them together.
   *  Values outside 1..=5 are silently dropped. Empty array = no
   *  filter. Lives alongside `status_min`/`status_max` for backwards
   *  compat with saved bambda filters. */
  status_classes?: number[];
  /** Keep only transactions whose `highlight` column is non-NULL.
   *  Mirrors Burp's "Show only highlighted items" annotation filter. */
  highlighted_only?: boolean;
  /** Keep only transactions whose `comment` column is non-empty.
   *  Mirrors Burp's "Show only commented items" annotation filter. */
  commented_only?: boolean;
  content_type_contains?: string;
  source?: string;
  in_scope_only?: boolean;
  search_text?: string;
  tag?: string;
  limit?: number;
  offset?: number;
  after_id?: number;
};

export type StoredSummary = {
  id: number;
  ts_ms: number;
  method: string;
  scheme: string;
  host: string;
  port: number;
  path: string;
  status?: number;
  content_length?: number;
  content_type?: string;
  elapsed_ms?: number;
  tags: string[];
  in_scope: boolean;
  source: string;
  tls_summary?: string;
  comment: string;
  error?: string;
  /** Number of query + form-body params observed on this request. */
  param_count?: number;
  /** First `<title>` extracted from an HTML response (<=160 chars). */
  title?: string | null;
  /** Burp-style row highlight — a named colour or null. */
  highlight?: string | null;
  /** R133: On-wire protocol token (`HTTP/1.0` / `HTTP/1.1` /
   *  `HTTP/2` / `HTTP/3`). Pre-R133 rows may still be null until the
   *  index is rebuilt from live traffic. Burp's HTTP history shows
   *  this as the "Protocol" column — we honour the same label. */
  http_version?: string | null;
};

export type PocResult = {
  html: string;
  suggested_name: string;
};

export type McpToolView = {
  name: string;
  description: string;
  input_schema: unknown;
};

export type McpStatus = {
  protocol_version: string;
  server_name: string;
  server_version: string;
  exe_path: string;
  project_path: string | null;
  command_argv: string[];
  claude_config_json: string;
  tools: McpToolView[];
};

export type McpTestResult = {
  ok: boolean;
  summary: string;
  stderr_tail: string[];
};

export type BambdaFilterResult = {
  rows: StoredSummary[];
  total_scanned: number;
  kept: number;
  error: string | null;
  elapsed_ms: number;
};

/** One row in the structural JSON diff. `left` / `right` are null
 *  when the field is missing on that side. */
export type JsonDiffEntry = {
  path: string;
  kind: "added" | "removed" | "changed" | "same";
  left: unknown;
  right: unknown;
};

export type JsonDiffReport = {
  entries: JsonDiffEntry[];
  similarity: number;
  left_total: number;
  right_total: number;
  parse_error_left: string | null;
  parse_error_right: string | null;
  truncated: boolean;
};

/** One saved Bambda filter expression. Scope lets each UI picker
 *  (history vs logger) surface only its own saved rows. */
export type BambdaSavedQuery = {
  name: string;
  expression: string;
  scope: string;
  created_at_ms: number;
};

export type DashboardTask = {
  id: string;
  name: string;
  kind: "live_passive_crawl";
  capturing: boolean;
  interval_s: number;
  scope: "all" | "in_scope";
  stats: {
    items_added: number;
    responses_processed: number;
    last_run_at_ms: number | null;
    last_run_findings: number;
    responses_queued: number;
  };
  log: Array<{ ts_ms: number; message: string }>;
  created_at_ms: number;
};

export type TransactionView = {
  summary: StoredSummary;
  request_raw: string;
  response_raw?: string;
};

export type ProxyStatsView = {
  running: boolean;
  listeners: string[];
  conns_accepted: number;
  requests_forwarded: number;
  responses_recorded: number;
  errors: number;
  tls_mitm: number;
};

export type CaInfo = {
  subject: string;
  serial: string;
  not_before: string;
  not_after: string;
  sha256_fingerprint: string;
};

export type ScopeRule = {
  match_kind: "include" | "exclude";
  protocol: string;
  host: string;
  port?: number;
  path: string;
  regex: boolean;
  enabled: boolean;
};

export type CatalogEntry = {
  name: string;
  version: string;
  author: string;
  description: string;
  permissions: string[];
  source_url: string;
  category: string;
  available: boolean;
  installed: boolean;
};

export type GraphQLOperationKind = "query" | "mutation" | "subscription" | "anonymous";
export type GraphQLOperation = {
  kind: GraphQLOperationKind;
  name: string | null;
  text: string;
  offset: number;
};
export type GraphQLEndpoint = {
  transaction_id: number;
  method: string;
  url: string;
  status: number | null;
  operations: GraphQLOperation[];
};
export type GraphQLSchemaArg = {
  name: string;
  type_label: string;
  default_value: string | null;
};
export type GraphQLSchemaField = {
  name: string;
  type_label: string;
  args: GraphQLSchemaArg[];
  description: string | null;
  deprecated: boolean;
};
export type GraphQLSchemaType = {
  kind: string;
  name: string;
  description: string | null;
  fields: GraphQLSchemaField[];
  enum_values: string[];
};
export type GraphQLSchemaView = {
  query_type: string | null;
  mutation_type: string | null;
  subscription_type: string | null;
  types: GraphQLSchemaType[];
};
export type GraphQLIntrospectResult = {
  status: number;
  body_text: string;
  elapsed_ms: number;
  schema: GraphQLSchemaView | null;
  error: string | null;
};

export type CrawlCandidate = {
  url: string;
  source: string;
  referrer: string;
};
export type CrawlResult = {
  by_host: Record<string, CrawlCandidate[]>;
  pages_scanned: number;
  unique_candidates: number;
  skipped_known: number;
};

export type Scope = {
  rules: ScopeRule[];
  default_in_scope_when_empty: boolean;
};

export type PassiveDetectorInfo = {
  /** Stable detector id (matches `Finding.detector`). */
  id: string;
  /** Current enablement state for the open project. False means
   *  the detector id is in `ProjectConfig::disabled_passive_detectors`
   *  and run_all_filtered skips it on every record. */
  enabled: boolean;
};

export type ActiveProbeInfo = {
  /** Stable kebab-case probe id (matches `Probe::id()` on the Rust
   *  side; e.g. "reflected-xss", "blind-sql-time"). */
  id: string;
  /** Current enablement for the open project. False means the id is
   *  in `ProjectConfig::disabled_active_probes` and the active-scan
   *  dispatcher will skip it. */
  enabled: boolean;
  /** True when the probe ships default-disabled (opt-in). The UI
   *  marks these rows with an "opt-in" hint since they usually have
   *  a wall-clock cost — currently just BlindSqlTime (~2 s per
   *  probed parameter). */
  default_disabled: boolean;
};

export type ActiveScanReport = {
  /** Number of Findings persisted via history.insert_finding
   *  (fingerprint upsert — repeats on the same tx dedupe). */
  findings_added: number;
  /** How many probes the scanner actually dispatched. Equals the
   *  size of the enabled probe set at the moment the cmd fired. */
  probes_run: number;
  /** False when the target host wasn't in the project scope. The
   *  dispatcher short-circuits with `skipped_reason` instead of
   *  erroring so the UI shows a quiet notice. */
  in_scope: boolean;
  /** Populated when the scan was deliberately not run (no probes
   *  enabled, target out of scope). Null on a normal completion
   *  (even if `findings_added === 0`). */
  skipped_reason: string | null;
};

export type StoredFinding = {
  id: number;
  ts_ms: number;
  transaction_id?: number;
  detector: string;
  title: string;
  description: string;
  severity: string;
  confidence: string;
  evidence: string;
  remediation: string;
  fingerprint?: string;
  status?: string;
  verification?: string;
  tags?: string[];
  references?: string[];
  assignee?: string | null;
  note?: string;
  insertion_point?: string | null;
  updated_at_ms?: number;
  observation_count?: number;
};

export type FindingFilter = {
  severity?: string;
  status?: string;
  detector?: string;
  tag?: string;
  transaction_id?: number;
  search?: string;
  limit?: number;
  offset?: number;
};

export type RepeaterTab = {
  id: number;
  name: string;
  template: any;
  history: Array<{
    id: number;
    request: any;
    response?: any;
    error?: string;
    elapsed_ms: number;
    ts_ms: number;
  }>;
  comment: string;
  color?: string | null;
  /** Per-tab override of the client redirect policy. `null` defers
   *  to the globally-configured policy (which is `never`). */
  follow_redirects?: "never" | "on_site" | "in_scope" | "always" | null;
  /** Optional group label. Tabs sharing a label cluster under a
   *  single header in the tab bar and can be fired as a batch. */
  group?: string | null;
  /** Explicit display order. list_tabs sorts by `(order, id)` so a
   *  dragged order survives restarts. Defaulted to 0; new tabs land
   *  at max+1000. */
  order?: number;
  /** When the tab was created via "Send to Repeater" from HTTP
   *  history, this is the id of the source transaction. The
   *  Repeater UI uses it to surface a "Jump to parent in HTTP
   *  history" button so operators can trace a tab back to its
   *  origin. Null for blank tabs + intercepted Proxy handoffs. */
  source_tx_id?: number | null;
  /** Pinned tabs float left of unpinned peers and are skipped by
   *  bulk-close context-menu actions. */
  pinned?: boolean;
};

/** Lightweight view of a saved Intruder recipe. */
export type IntruderRecipeView = {
  name: string;
  created_at_ms: number;
  payload_count: number;
  mode: string;
};

/** One entry in the built-in Intruder payload library. */
export type PayloadLibraryEntry = {
  id: string;
  name: string;
  description: string;
  category: string;
  size: number;
};

export type Transform =
  | { op: "url_encode" }
  | { op: "url_decode" }
  | { op: "base64_encode" }
  | { op: "base64_decode" }
  | { op: "base64_url_encode" }
  | { op: "base64_url_decode" }
  | { op: "hex_encode" }
  | { op: "hex_decode" }
  | { op: "html_encode" }
  | { op: "html_decode" }
  | { op: "unicode_escape_encode" }
  | { op: "unicode_escape_decode" }
  | { op: "gzip_decode" }
  | { op: "deflate_decode" }
  | { op: "brotli_decode" }
  | { op: "jwt_decode" }
  | { op: "uppercase" }
  | { op: "lowercase" }
  | { op: "reverse" }
  | { op: "md5" }
  | { op: "sha1" }
  | { op: "sha256" }
  | { op: "blake3" }
  | { op: "hmac_sha1"; key: string }
  | { op: "hmac_sha256"; key: string }
  | { op: "hmac_sha384"; key: string }
  | { op: "hmac_sha512"; key: string };

export type ChainStep = {
  transform: Transform;
  output: string;
  binary: boolean;
  error?: string;
};

export const api = {
  // ------------- Project --------------------------------------------------
  projectOpenOrCreate: (path: string) =>
    invoke<ProjectInfo>("project_open_or_create", { path }),
  projectInfo: () => invoke<ProjectInfo>("project_info"),
  defaultProjectPath: () => invoke<string>("default_project_path"),

  // ------------- Proxy ----------------------------------------------------
  proxyStart: () => invoke<string[]>("proxy_start"),
  proxyStop: () => invoke<void>("proxy_stop"),
  proxyStats: () => invoke<ProxyStatsView>("proxy_stats"),

  // ------------- CA -------------------------------------------------------
  caExport: (path: string) => invoke<void>("ca_export", { path }),
  caInfo: () => invoke<CaInfo>("ca_info"),

  // ------------- History --------------------------------------------------
  historyList: (filter?: HistoryFilter) => invoke<StoredSummary[]>("history_list", { filter }),
  historyCount: (filter?: HistoryFilter) => invoke<number>("history_count", { filter }),
  historyShow: (id: number) => invoke<TransactionView>("history_show", { id }),
  historyClear: () => invoke<void>("history_clear"),
  historySetHighlight: (id: number, color: string | null) =>
    invoke<void>("history_set_highlight", { args: { id, color } }),
  historySetComment: (id: number, comment: string) =>
    invoke<void>("history_set_comment", { args: { id, comment } }),
  /** R320: Replace a transaction's tag set. The frontend handles
   *  merge semantics (read current → union → set) for a "+ Add tag"
   *  flow; backend is a plain setter. Matches the R312 Scanner
   *  `+ Add tag` bulk-op shape over `finding_set_tags`. */
  historySetTags: (id: number, tags: string[]) =>
    invoke<void>("history_set_tags", { args: { id, tags } }),
  historyDelete: (ids: number[]) =>
    invoke<number>("history_delete", { args: { ids } }),
  /** Re-fire a stored request through the shared HTTP client and
   *  record the paired result as a fresh history row. Returns the
   *  new transaction id so the caller can scroll it into view. */
  historyReplay: (id: number) => invoke<number>("history_replay", { id }),
  historySummaries: (ids: number[]) => invoke<StoredSummary[]>("history_summaries", { ids }),

  // ------------- Attack PoC generators -----------------------------------
  pocCsrf: (id: number) => invoke<PocResult>("poc_csrf", { id }),
  pocClickjack: (url: string, overlayLabel = "Click to win!") =>
    invoke<PocResult>("poc_clickjack", { args: { url, overlay_label: overlayLabel } }),

  // ------------- MCP server surface --------------------------------------
  mcpStatus: () => invoke<McpStatus>("mcp_status"),
  mcpTest: () => invoke<McpTestResult>("mcp_test"),

  // ------------- Bambda history filter ----------------------------------
  bambdaFilter: (expression: string, filter?: HistoryFilter) =>
    invoke<BambdaFilterResult>("bambda_filter", { args: { expression, filter } }),

  // ------------- Dashboard tasks ----------------------------------------
  tasksList: () => invoke<DashboardTask[]>("tasks_list"),
  tasksSet: (tasks: DashboardTask[]) => invoke<void>("tasks_set", { tasks }),

  // ------------- Scope ----------------------------------------------------
  scopeGet: () => invoke<Scope>("scope_get"),
  scopeAddRule: (rule: ScopeRule) => invoke<Scope>("scope_add_rule", { rule }),
  scopeRemoveRule: (index: number) => invoke<Scope>("scope_remove_rule", { index }),
  scopeSet: (scope: Scope) => invoke<Scope>("scope_set", { scope }),

  // ------------- Match/Replace -------------------------------------------
  matchReplaceGet: () => invoke<MatchReplaceEngine>("match_replace_get"),
  matchReplaceSet: (engine: MatchReplaceEngine) =>
    invoke<void>("match_replace_set", { engine }),
  // Dry-run the currently *saved* match/replace rules against a
  // synthesised sample. Returns a per-rule hit list + before/after
  // UTF-8 lossy wire snapshots so the UI can show a diff. Operators
  // use this to validate a rule chain before enabling it against
  // live traffic.
  matchReplacePreview: (args: {
    direction: "request" | "response";
    url: string;
    method?: string;
    body?: string;
    content_type?: string;
  }) => invoke<MatchReplacePreview>("match_replace_preview", { args }),
  // Snapshot every match/replace rule's live fire count. Missing
  // keys mean the rule hasn't fired yet — the UI renders those as
  // 0. Polled every 2 s by MatchReplacePane so operators see which
  // rules are earning their keep against real traffic.
  matchReplaceHits: () =>
    invoke<Record<string, number>>("match_replace_hits"),
  // Snapshot every match/replace rule's last-fire epoch (ms).
  // Absent keys mean the rule hasn't fired this session — the UI
  // renders those as "—". Polled alongside matchReplaceHits so the
  // Hits count and the humanized "Last fire" column stay in step.
  matchReplaceLastFires: () =>
    invoke<Record<string, number>>("match_replace_last_fires"),
  matchReplaceHitsClear: () => invoke<void>("match_replace_hits_clear"),

  // ------------- Interceptor ---------------------------------------------
  interceptorSet: (request: boolean, response: boolean) =>
    invoke<void>("interceptor_set", { args: { request, response } }),
  interceptorStatus: () =>
    invoke<{ request: boolean; response: boolean; pending: number }>(
      "interceptor_status",
    ),
  interceptorPending: () => invoke<any[]>("interceptor_pending"),
  interceptorResolve: (id: number, action: "forward" | "drop", raw?: string) =>
    invoke<void>("interceptor_resolve", { args: { id, action, raw } }),
  // Bulk-resolve every queued intercept with `action`. Mirrors Burp's
  // "Forward all" / "Drop all" buttons. Returns tabs resolved.
  interceptorResolveAll: (action: "forward" | "drop") =>
    invoke<number>("interceptor_resolve_all", { action }),
  // Peek at a queued intercept's raw bytes without resolving it, so
  // the operator can Send-to-Repeater / Comparer without consuming
  // the intercept slot.
  interceptorShow: (id: number) => invoke<string>("interceptor_show", { id }),
  interceptorRulesGet: () => invoke<InterceptRulesView>("interceptor_rules_get"),
  interceptorRulesSet: (direction: "request" | "response", rules: InterceptRules) =>
    invoke<void>("interceptor_rules_set", { args: { direction, rules } }),
  // Dry-run the currently *saved* ruleset against a synthesised
  // sample. Returns a per-rule matched/effect breakdown + aggregate
  // decision. The UI shows a hint when the editor is dirty so
  // operators know the preview may reflect pre-edit state.
  interceptorRulesPreview: (args: {
    direction: "request" | "response";
    url: string;
    method?: string;
    in_scope: boolean;
  }) => invoke<PreviewReport>("interceptor_rules_preview", { args }),
  // Snapshot every intercept rule's live firing count (request +
  // response rules share one map because rule IDs are unique).
  // Polled every 2 s by the Intercept Rules editor so operators can
  // see which rules in a chain are actually firing — mirrors the
  // match/replace hits counter from R60.
  interceptorRulesHits: () =>
    invoke<Record<string, number>>("interceptor_rules_hits"),
  interceptorRulesHitsClear: () =>
    invoke<void>("interceptor_rules_hits_clear"),

  // ------------- Cookie Jar ----------------------------------------------
  // Shared project jar harvested from every proxy response's
  // Set-Cookie headers. CookieJarPanel polls the list every 2 s and
  // offers Delete / Clear / Add actions.
  cookieJarList: () => invoke<Cookie[]>("cookie_jar_list"),
  cookieJarClear: () => invoke<void>("cookie_jar_clear"),
  cookieJarDelete: (name: string, domain: string, path: string) =>
    invoke<boolean>("cookie_jar_delete", { args: { name, domain, path } }),
  cookieJarSet: (cookie: Cookie) =>
    invoke<void>("cookie_jar_set", { cookie }),

  // ------------- Automatic project backup --------------------------------
  // Periodic timestamped bundle snapshots mirroring Burp's
  // automatic_project_backup. Config lives on `ProjectConfig`,
  // scheduler runs on a tokio task that respawns on every
  // backup_config_set so a tightened interval takes effect
  // immediately.
  backupConfigGet: () => invoke<AutoBackupConfig>("backup_config_get"),
  backupConfigSet: (cfg: AutoBackupConfig) =>
    invoke<void>("backup_config_set", { cfg }),
  backupList: () => invoke<BackupInfo[]>("backup_list"),
  backupNow: () => invoke<BackupInfo>("backup_now"),
  backupDelete: (filename: string) =>
    invoke<boolean>("backup_delete", { args: { filename } }),

  hostOverridesGet: () => invoke<HostOverridesView>("host_overrides_get"),
  hostOverridesSet: (args: { overrides: HostOverride[]; follow_redirects?: string | null }) =>
    invoke<void>("host_overrides_set", { args }),

  // ------------- Repeater -------------------------------------------------
  repeaterList: () => invoke<RepeaterTab[]>("repeater_list"),
  repeaterAddTab: (name: string, url: string, method = "GET") =>
    invoke<number>("repeater_add_tab", { args: { name, url, method } }),
  repeaterUpdate: (id: number, template: any) =>
    invoke<void>("repeater_update", { args: { id, template } }),
  repeaterSend: (id: number) => invoke<any>("repeater_send", { id }),
  // Fire a cancel at any in-flight send() / follow_redirect() for the
  // tab. Returns true when a Notify waiter was woken (something was
  // mid-flight). The pending `repeaterSend` promise still resolves —
  // the engine returns a normal RepeaterSend with
  // `error = "send cancelled"` so the UI appends a cancelled row to
  // history instead of rejecting the Promise.
  repeaterCancel: (id: number) => invoke<boolean>("repeater_cancel", { id }),
  // Cancel every in-flight send across every tab. Returns the number
  // of tabs that had a parked Notify. Panic button for when
  // send_group_parallel over 10+ tabs starts starving the target.
  repeaterCancelAll: () => invoke<number>("repeater_cancel_all"),
  // Snapshot of every tab currently mid-flight — the UI calls this
  // on panel mount so the per-tab Cancel buttons re-highlight
  // correctly even for sends started before the panel mounted
  // (reload / navigation / tab switch).
  repeaterInflightIds: () => invoke<number[]>("repeater_inflight_ids"),
  repeaterRemove: (id: number) => invoke<void>("repeater_remove", { id }),
  repeaterRename: (id: number, name: string) =>
    invoke<void>("repeater_rename", { args: { id, name } }),
  /** Replace a tab's free-form comment. Empty string clears it.
   *  Shown as a tooltip on the tab chip + a 💬 indicator glyph. */
  repeaterSetComment: (id: number, comment: string) =>
    invoke<void>("repeater_set_comment", { args: { id, comment } }),
  repeaterDuplicateTab: (id: number, name?: string) =>
    invoke<number>("repeater_duplicate_tab", {
      args: { id, name: name ?? null },
    }),
  // Wipe one tab's response history without destroying the tab
  // itself. Backs the "Clear history" button in the HistoryStrip +
  // the matching tab-context-menu entry. Returns true iff the tab
  // existed; the UI uses that to skip the UI refresh on a stale id.
  repeaterTabClearHistory: (id: number) =>
    invoke<boolean>("repeater_tab_clear_history", { id }),
  repeaterSetColor: (id: number, color: string | null) =>
    invoke<void>("repeater_set_color", { args: { id, color } }),
  repeaterChangeMethod: (id: number, method: string) =>
    invoke<void>("repeater_change_method", { args: { id, method } }),
  repeaterBurstSend: (id: number, count: number, gap_ms: number) =>
    invoke<any[]>("repeater_burst_send", { args: { id, count, gap_ms } }),
  repeaterAddFromHistory: (tx_id: number, name?: string) =>
    invoke<number>("repeater_add_from_history", { args: { tx_id, name: name ?? null } }),
  /** Create a Repeater tab from raw on-the-wire request bytes. Used
   *  by the Proxy → Repeater handoff so the operator gets a byte-
   *  exact copy of what was mid-flight (headers / cookies / body
   *  preserved), not a stripped URL + method shell. */
  repeaterAddFromWire: (args: {
    name: string;
    wire: number[];
    host: string;
    port: number;
    scheme: string;
  }) => invoke<number>("repeater_add_from_wire", { args }),
  repeaterSetBodyEncoding: (id: number, kind: "plain" | "gzip" | "chunked") =>
    invoke<void>("repeater_set_body_encoding", { args: { id, kind } }),
  repeaterSetFollowRedirects: (
    id: number,
    policy: "inherit" | "never" | "on_site" | "in_scope" | "always",
  ) => invoke<void>("repeater_set_follow_redirects", { args: { id, policy } }),
  repeaterSetUrl: (id: number, url: string) =>
    invoke<void>("repeater_set_url", { args: { id, url } }),
  repeaterFollowRedirect: (id: number, location: string) =>
    invoke<any>("repeater_follow_redirect", { args: { id, location } }),
  // ----- Repeater tab groups ---------------------------------------------
  // Assign (or clear) the tab's group. Blank / whitespace clears.
  repeaterSetGroup: (id: number, group: string | null) =>
    invoke<void>("repeater_set_group", { args: { id, group } }),
  // Rename every member of `old` to be in `new` (blank clears).
  repeaterRenameGroup: (old: string, new_: string) =>
    invoke<number>("repeater_rename_group", { args: { old, new: new_ } }),
  // Clear the group on every member — tabs survive.
  repeaterDeleteGroup: (group: string) =>
    invoke<number>("repeater_delete_group", { group }),
  // Alphabetical list of every group currently in use.
  repeaterListGroups: () => invoke<string[]>("repeater_list_groups"),
  // Fire every tab in `group` sequentially or in parallel.
  repeaterSendGroup: (group: string, mode: "sequential" | "parallel") =>
    invoke<any[]>("repeater_send_group", { args: { group, mode } }),
  // Reorder tabs: `ids` walked in display order; each known tab gets
  // `order = (i+1)*1000`. Unknown ids are skipped and untouched tabs
  // keep their previous order so a drag-reorder of one section does
  // not flatten the rest of the tab bar. Returns tabs updated.
  repeaterReorder: (ids: number[]) =>
    invoke<number>("repeater_reorder", { ids }),
  // Burp's Pin tab / Unpin tab. Pinned tabs float left of unpinned
  // peers in `repeater_list` and are protected from bulk closes.
  repeaterSetPinned: (id: number, pinned: boolean) =>
    invoke<void>("repeater_set_pinned", { args: { id, pinned } }),

  // ------------- Intruder -------------------------------------------------
  intruderStart: (config: any) => invoke<number>("intruder_start", { args: { config } }),
  intruderCancel: (id: number) => invoke<void>("intruder_cancel", { id }),
  // Freeze new dispatches without dropping in-flight ones; mirrors
  // Burp's Pause attack toolbar button. Returns false when the id
  // isn't known (job already finished / cancelled). Idempotent.
  intruderPause: (id: number) => invoke<boolean>("intruder_pause", { id }),
  intruderResume: (id: number) => invoke<boolean>("intruder_resume", { id }),
  intruderPoll: (id: number) =>
    invoke<{
      status: string;
      done: number;
      total: number;
      new_results: any[];
      paused: boolean;
    }>("intruder_poll", { id }),
  intruderResultToRepeater: (config: any, payloads: string[], tab_name?: string) =>
    invoke<number>("intruder_result_to_repeater", {
      args: { config, payloads, tab_name: tab_name ?? null },
    }),
  intruderRecipeSave: (name: string, config: any) =>
    invoke<void>("intruder_recipe_save", { args: { name, config } }),
  intruderRecipeList: () =>
    invoke<IntruderRecipeView[]>("intruder_recipe_list"),
  intruderRecipeLoad: (name: string) =>
    invoke<any>("intruder_recipe_load", { args: { name } }),
  intruderRecipeDelete: (name: string) =>
    invoke<void>("intruder_recipe_delete", { args: { name } }),
  hostNoteSet: (host: string, note: string) =>
    invoke<void>("host_note_set", { args: { host, note } }),
  hostNoteGet: (host: string) =>
    invoke<string>("host_note_get", { args: { host } }),
  hostNotesList: () =>
    invoke<Record<string, string>>("host_notes_list"),
  payloadsLibraryList: () =>
    invoke<PayloadLibraryEntry[]>("payloads_library_list"),
  payloadsLibraryLoad: (id: string) =>
    invoke<string>("payloads_library_load", { args: { id } }),

  // ------------- Site map -------------------------------------------------
  sitemapSnapshot: () => invoke<any>("sitemap_snapshot"),
  // Auto-import /robots.txt + /sitemap.xml for a base URL. Returns
  // a WellKnownReport with parsed structures + raw bodies + a
  // flat sorted/deduped discovered_urls list. Non-fatal: any
  // fetch / parse error lands in `report.errors` and partial
  // results are still returned.
  targetImportWellKnown: (baseUrl: string) =>
    invoke<WellKnownReport>("target_import_well_known", { baseUrl }),

  // ------------- Tools ----------------------------------------------------
  decoderApply: (input: string, chain: Transform[]) =>
    invoke<ChainStep[]>("decoder_apply", { args: { input, chain } }),
  decoderSmart: (input: string, max_depth = 6) =>
    invoke<ChainStep[]>("decoder_smart", { args: { input, max_depth } }),
  comparerDiff: (
    left: string,
    right: string,
    ignoreWhitespace: boolean,
    mode: "line" | "word" = "line",
  ) =>
    invoke<any>("comparer_diff", {
      args: { left, right, ignore_whitespace: ignoreWhitespace, mode },
    }),
  // Structural JSON diff — parses both sides and walks them in
  // parallel, surfacing per-path Added/Removed/Changed/Same rows.
  comparerDiffJson: (left: string, right: string) =>
    invoke<JsonDiffReport>("comparer_diff_json", { args: { left, right } }),
  sequencerAnalyze: (tokens: string[]) => invoke<any>("sequencer_analyze", { tokens }),

  // ------------- Scanner --------------------------------------------------
  passiveRunNow: () => invoke<number>("passive_run_now"),
  /** R139: Run passive detectors over a filtered subset of history.
   *  Any HistoryFilter shape is accepted — a Scanner-side chip
   *  configuration can be forwarded verbatim so operators focus
   *  the audit on in-scope hosts, status classes, or any
   *  combination. Returns the count of findings inserted. */
  passiveRunFiltered: (filter: HistoryFilter) =>
    invoke<number>("passive_run_filtered", { filter }),
  passiveWsRunNow: () => invoke<number>("passive_ws_run_now"),
  // Live passive scan — when enabled, every new in-scope transaction
  // recorded by the proxy sink is passed through the passive scanner
  // and resulting findings are persisted automatically (dedupe via
  // fingerprint upsert).
  liveScanGet: () => invoke<boolean>("live_scan_get"),
  liveScanSet: (enabled: boolean) => invoke<void>("live_scan_set", { enabled }),
  /** R131: Pause-history-recording toggle. When off, the proxy
   *  sink skips the sitemap observe + history upsert + live
   *  passive scan so credentials-flow traffic doesn't persist.
   *  Extensions still run. Session-ephemeral — a restart resets
   *  to on so a forgotten "off" doesn't silently stop capturing
   *  the next session's traffic. */
  historyRecordingGet: () => invoke<boolean>("history_recording_get"),
  historyRecordingSet: (enabled: boolean) =>
    invoke<void>("history_recording_set", { enabled }),
  // Per-passive-detector enable toggle. The engine's run_all_filtered
  // path consumes the disabled set so flipping a checkbox takes
  // effect on the next recorded transaction — no scanner restart.
  scannerPassiveDetectorsList: () =>
    invoke<PassiveDetectorInfo[]>("scanner_passive_detectors_list"),
  scannerPassiveDetectorSet: (id: string, enabled: boolean) =>
    invoke<void>("scanner_passive_detector_set", { args: { id, enabled } }),
  // Per-active-probe enable toggle. Mirrors the passive side but the
  // info rows carry an extra `default_disabled` flag so the UI can
  // mark opt-in probes (currently just BlindSqlTime, which adds ~2 s
  // per probed parameter). A future active-scan dispatcher will
  // filter the probe list via `AppState.disabled_active_probes`.
  scannerActiveProbesList: () =>
    invoke<ActiveProbeInfo[]>("scanner_active_probes_list"),
  scannerActiveProbeSet: (id: string, enabled: boolean) =>
    invoke<void>("scanner_active_probe_set", { args: { id, enabled } }),
  // Fire every enabled active probe against a stored transaction.
  // Returns an `ActiveScanReport` instead of raising for the "no
  // probes enabled" / "target out of scope" cases so the UI can
  // show a quiet notice rather than an alert. Findings land in the
  // project history via fingerprint upsert so repeat invocations
  // on the same tx are safe.
  scannerActiveRunTx: (id: number) =>
    invoke<ActiveScanReport>("scanner_active_run_tx", { id }),
  // TLS pass-through host list. CONNECT targets whose host contains any
  // (case-insensitive) pattern on this list bypass MITM entirely — the
  // proxy opens a raw TCP tunnel so cert-pinned mobile apps / IoT
  // clients that reject our root CA can still be observed at the TCP
  // layer (bytes still count against stats, but the TLS is end-to-end).
  tlsPassthroughGet: () => invoke<string[]>("tls_passthrough_get"),
  tlsPassthroughSet: (list: string[]) => invoke<void>("tls_passthrough_set", { list }),
  // Bambda saved queries. `scope` is `"history"` or `"logger"` so
  // each UI bar sees only its own saved filters.
  bambdaQueriesList: (scope: string) =>
    invoke<BambdaSavedQuery[]>("bambda_queries_list", { scope }),
  bambdaQueriesSave: (name: string, expression: string, scope: string) =>
    invoke<void>("bambda_queries_save", { args: { name, expression, scope } }),
  bambdaQueriesDelete: (name: string, scope: string) =>
    invoke<boolean>("bambda_queries_delete", { args: { name, scope } }),
  findingsList: () => invoke<StoredFinding[]>("findings_list"),
  /** Operator-authored finding. Mirrors Burp's "Add manual issue"
   *  action — pentesters add findings for things no detector catches
   *  (business-logic abuse, chained exploits, client-side XSS proven
   *  in-browser). Backend validates severity (critical/high/medium/
   *  low/info) + title length and sets sensible defaults (confidence
   *  firm, verification verified, status new). Returns the new row's
   *  TrafficId so the UI can pop it into the detail pane. */
  findingAddManual: (args: {
    title: string;
    severity: "critical" | "high" | "medium" | "low" | "info";
    description?: string;
    detector?: string;
    transaction_id?: number;
    evidence?: string;
    remediation?: string;
    tags?: string[];
  }) => invoke<number>("finding_add_manual", { args }),
  findingsListFiltered: (filter?: FindingFilter) =>
    invoke<StoredFinding[]>("findings_list_filtered", { filter }),
  /** Per-host severity count breakdown. Backs the Target → SiteMap
   *  per-host issue badges. Shape: `{ host: { severity: count } }`,
   *  severity key is lower-cased (critical / high / medium / low / info).
   *  Findings without a transaction_id are omitted (no host to join on). */
  findingsCountByHost: () =>
    invoke<Record<string, Record<string, number>>>("findings_count_by_host"),
  findingSetStatus: (id: number, status: string) =>
    invoke<void>("finding_set_status", { args: { id, status } }),
  findingSetVerification: (id: number, verification: string) =>
    invoke<void>("finding_set_verification", { args: { id, verification } }),
  findingSetTags: (id: number, tags: string[]) =>
    invoke<void>("finding_set_tags", { args: { id, tags } }),
  /** R344: Replace a finding's operator-side note. Standalone from
   *  `findingSetStatus` so operators can annotate without moving
   *  the finding through the triage lifecycle. Empty string clears. */
  findingSetNote: (id: number, note: string) =>
    invoke<void>("finding_set_note", { args: { id, note } }),
  // R164: Operator-driven severity override. `severity` must be one
  // of critical / high / medium / low / info — the backend validates
  // and rejects anything else so the stored string stays canonical.
  findingSetSeverity: (id: number, severity: string) =>
    invoke<void>("finding_set_severity", { args: { id, severity } }),
  findingDelete: (id: number) => invoke<void>("finding_delete", { id }),
  // Bulk delete by id. Backed by one `DELETE … IN(?,?,…)` statement
  // for the floating-action-strip "Delete N findings" entry.
  findingsDeleteMany: (ids: number[]) =>
    invoke<number>("findings_delete_many", { args: { ids } }),

  // ------------- Dashboard aggregate -------------------------------------
  dashboardStats: () => invoke<DashboardStats>("dashboard_stats"),

  // ------------- Settings -------------------------------------------------
  upstreamSet: (upstream: { url: string; username?: string; password?: string }) =>
    invoke<void>("upstream_set", { upstream }),
  settingsGet: () => invoke<any>("settings_get"),
  settingsSave: (config: any) => invoke<void>("settings_save", { config }),

  // Suppress out-of-scope items from HTTP history / sitemap /
  // events — Burp's "drop out-of-scope items" option. True = those
  // items are hidden from recording (proxy still forwards them;
  // only persistence + observability is affected). Backed by the
  // same ProjectConfig field as the SettingsPanel checkbox so edits
  // through either surface stay in sync. The setter writes to disk
  // AND flips a shared AtomicBool so the proxy picks up the new
  // value on the next request — no restart.
  historySuppressOosGet: () => invoke<boolean>("history_suppress_oos_get"),
  historySuppressOosSet: (suppress: boolean) =>
    invoke<void>("history_suppress_oos_set", { suppress }),

  // HTTP history column visibility. The backend stores the list of
  // HIDDEN column ids on ProjectConfig::history_hidden_columns so
  // the default (empty) means "show everything" and legacy projects
  // round-trip through serde cleanly. The HistoryPanel's
  // Columns-dropdown fetches this on mount and persists on every
  // checkbox toggle. Known ids: `highlight` / `id` / `method` /
  // `status` / `host` / `path` / `size` / `time` / `comment`.
  historyColumnsGet: () => invoke<string[]>("history_columns_get"),
  historyColumnsSet: (hidden: string[]) =>
    invoke<void>("history_columns_set", { hidden }),

  // Comparer item collection — Burp's numbered list of saved
  // snippets that persist across restarts. `add` upserts by id so
  // a "send to Comparer" from the same source twice doesn't bloat
  // the collection with duplicates.
  comparerItemsList: () => invoke<ComparerItem[]>("comparer_items_list"),
  comparerItemsAdd: (item: ComparerItem) =>
    invoke<void>("comparer_items_add", { item }),
  comparerItemsRemove: (id: string) =>
    invoke<boolean>("comparer_items_remove", { id }),
  comparerItemsClear: () => invoke<void>("comparer_items_clear"),

  // Platform authentication — Burp's `Settings → Network →
  // Platform authentication`. When upstream returns 401
  // WWW-Authenticate for a supported scheme, the proxy consults
  // this list for a host-pattern + scheme match and re-dispatches
  // once with an Authorization header, invisible to the client.
  // Setter persists to `ProjectConfig::platform_auth` (opaque JSON)
  // AND updates the shared Arc the proxy reads, so edits take
  // effect on the next request without a proxy restart.
  platformAuthList: () =>
    invoke<PlatformAuthCredential[]>("platform_auth_list"),
  platformAuthSet: (credentials: PlatformAuthCredential[]) =>
    invoke<void>("platform_auth_set", { credentials }),

  // BChecks — Burp's declarative active-scan rules. `bchecksList`
  // returns one row per YAML file in `project/bchecks/` (with parse
  // status + metadata or an error); `bchecksRun` fires every valid
  // rule against the hosts observed in HTTP history and persists
  // the generated findings via the usual passive-scan path.
  bchecksList: () => invoke<BCheckLoadRow[]>("bchecks_list"),
  bchecksRun: () => invoke<BCheckRunReport>("bchecks_run"),
  /** Validate a YAML BCheck snippet without touching the project.
   *  Returns parsed metadata on success + the error chain on
   *  failure. Backs the Validator composer in BChecksPanel. */
  bchecksValidate: (yaml: string) =>
    invoke<BCheckValidateResult>("bchecks_validate", { yaml }),
  /** Save a validated BCheck YAML to `project/bchecks/<filename>`.
   *  Re-validates server-side before touching disk, so the composer
   *  can't persist a broken YAML. Returns the absolute written path. */
  bchecksSave: (filename: string, yaml: string, overwrite: boolean) =>
    invoke<string>("bchecks_save", {
      args: { filename, yaml, overwrite },
    }),
  /** Delete a BCheck YAML from the project. Returns `true` iff the
   *  file actually existed on disk; the UI uses that to skip a
   *  redundant refresh on stale ids. */
  bchecksDelete: (filename: string) =>
    invoke<boolean>("bchecks_delete", { filename }),
  /** Read the raw YAML of a BCheck file. Backs "Edit in composer"
   *  — pre-fills the R103 composer textarea with the on-disk YAML
   *  so the operator can tweak + re-save via R104. */
  bchecksRead: (filename: string) =>
    invoke<string>("bchecks_read", { filename }),

  // Scanner report export — produces client-ready HTML, machine-
  // readable JSON, or CI-friendly SARIF 2.1.0 at the given absolute
  // path. `findingIds` is an optional subset ("Report selected
  // issues"); omit or pass [] to report every finding. Backend
  // validates the format BEFORE touching disk so a typo never
  // leaves an empty file behind.
  scannerReportWrite: (args: {
    path: string;
    format: "html" | "json" | "sarif" | "markdown" | "csv";
    findingIds?: number[];
  }) =>
    invoke<ScannerReportResult>("scanner_report_write", {
      args: {
        path: args.path,
        format: args.format,
        finding_ids: args.findingIds ?? null,
      },
    }),

  // Open an HTTP response body in the OS default browser. The
  // backend writes to a temp file with an extension picked from
  // Content-Type (text/html → .html, application/json → .json, …)
  // and spawns the platform-specific opener (cmd /c start on
  // Windows, open on macOS, xdg-open on Linux). Operators get a
  // one-click "render this response" workflow matching Burp's
  // response-pane "Open in browser" entry.
  /** Open the current project root in the OS file manager. Mirror
   *  of Burp's "Open project folder" action. Returns the opened
   *  path so the UI can echo it in a toast if desired. */
  projectOpenFolder: () => invoke<string>("project_open_folder"),

  /** Open an http/https URL in the OS default browser. Mirrors
   *  Burp's "Request in browser → in current session" affordance.
   *  Backend validates scheme / length / control chars. Returns
   *  the opened URL so a toast can echo it (handy when it was
   *  derived from a stored row). */
  shellOpenUrl: (url: string) => invoke<string>("shell_open_url", { args: { url } }),

  /** Binary-safe response-body save. Writes the stored response
   *  bytes directly to `path` without a String round-trip — PDFs /
   *  PNGs / MP4s download correct. `include_headers=true` writes
   *  the full raw-wire dump (status + headers + body); false
   *  writes just the body. Returns the final path + byte count. */
  historySaveResponseBody: (args: {
    tx_id: number;
    path: string;
    include_headers?: boolean;
  }) =>
    invoke<{ path: string; bytes_written: number }>(
      "history_save_response_body",
      {
        args: {
          tx_id: args.tx_id,
          path: args.path,
          include_headers: !!args.include_headers,
        },
      },
    ),

  responseOpenInBrowser: (args: {
    content: string;
    contentType?: string;
    label?: string;
  }) =>
    invoke<{
      path: string;
      extension: string;
      bytes_written: number;
      opener: string;
    }>("response_open_in_browser", {
      args: {
        content: args.content,
        content_type: args.contentType ?? null,
        label: args.label ?? null,
      },
    }),

  // ------------- Extensions -----------------------------------------------
  extensionsList: () => invoke<Array<{ name: string; version: string; author: string; description: string; permissions: string[] }>>("extensions_list"),
  extensionsSetEnabled: (name: string, enabled: boolean) =>
    invoke<void>("extensions_set_enabled", { args: { name, enabled } }),
  extensionsCatalogList: () => invoke<CatalogEntry[]>("extensions_catalog_list"),
  extensionsInstall: (name: string) => invoke<CatalogEntry[]>("extensions_install", { name }),
  extensionsUninstall: (name: string) => invoke<CatalogEntry[]>("extensions_uninstall", { name }),

  // ------------- Organizer ------------------------------------------------
  organizerAdd: (args: {
    transaction_id?: number;
    title: string;
    note?: string;
    tags?: string[];
    collection_id?: number | null;
  }) => invoke<number>("organizer_add", { args }),
  /** Pass `collection_id` null = Inbox, undefined = every item. */
  organizerList: (args?: { collection_id?: number | null }) =>
    invoke<OrganizerItem[]>("organizer_list", { args: args ?? {} }),
  organizerUpdate: (id: number, note: string, tags: string[], status: string) =>
    invoke<void>("organizer_update", { args: { id, note, tags, status } }),
  organizerMove: (id: number, collection_id: number | null) =>
    invoke<void>("organizer_move", { args: { id, collection_id } }),
  organizerDelete: (id: number) => invoke<void>("organizer_delete", { id }),
  collectionsList: () => invoke<CollectionsView>("collections_list"),
  collectionCreate: (name: string) => invoke<number>("collection_create", { name }),
  collectionRename: (id: number, name: string) =>
    invoke<void>("collection_rename", { args: { id, name } }),
  collectionDelete: (id: number) => invoke<void>("collection_delete", { id }),

  // ------------- Browser --------------------------------------------------
  browserLaunch: (url?: string) =>
    invoke<{ browser: string; pid?: number; command: string; note?: string }>(
      "browser_launch",
      { url }
    ),

  // ------------- Logger ---------------------------------------------------
  loggerRecent: (limit?: number) =>
    invoke<Array<{ seq: number; event: { ts_ms: number; kind: any } }>>(
      "logger_recent",
      { limit }
    ),
  loggerDrainSince: (cursor: number) =>
    invoke<Array<{ seq: number; event: { ts_ms: number; kind: any } }>>(
      "logger_drain_since",
      { cursor }
    ),
  loggerClear: () => invoke<void>("logger_clear"),

  // ------------- Bundle ---------------------------------------------------
  bundleExport: (opts: {
    out: string;
    include_ca_key?: boolean;
    include_extensions?: boolean;
    include_blobs?: boolean;
    compress?: boolean;
  }) =>
    invoke<{
      manifest: any;
      file_count: number;
      total_bytes: number;
      out_bytes: number;
      out_path: string;
    }>("bundle_export", { opts }),
  bundleImport: (opts: { file: string; dest: string; open_after?: boolean }) =>
    invoke<any>("bundle_import", { opts }),

  // ------------- HAR (HTTP Archive) ---------------------------------------
  harImport: (file: string) =>
    invoke<{ imported: number; skipped: number; errors: string[] }>("har_import", {
      opts: { file },
    }),
  harExport: (out: string) =>
    invoke<{ entries: number; bytes_written: number }>("har_export", {
      opts: { out },
    }),
  /** Export a specific set of history ids as a HAR 1.2 file. Backs
   *  the HistoryPanel "Export selected as HAR" bulk action — unlike
   *  `harExport` which exports the whole project, this one scopes
   *  the dump to the ids the operator picked. Order is preserved. */
  harExportIds: (out: string, ids: number[]) =>
    invoke<{ entries: number; bytes_written: number }>("har_export_ids", {
      opts: { out, ids },
    }),

  // ------------- GraphQL -------------------------------------------------
  graphqlListEndpoints: () =>
    invoke<GraphQLEndpoint[]>("graphql_list_endpoints"),
  graphqlIntrospect: (url: string, headers: Array<[string, string]> = []) =>
    invoke<GraphQLIntrospectResult>("graphql_introspect", {
      args: { url, headers },
    }),
  graphqlParseSchemaJson: (json: string) =>
    invoke<GraphQLSchemaView>("graphql_parse_schema_json", { json }),

  // ------------- Crawler -------------------------------------------------
  crawlerRunNow: () => invoke<CrawlResult>("crawler_run_now"),

  // ------------- OOB (Collaborator) ---------------------------------------
  oobStatus: () => invoke<OobStatus>("oob_status"),
  oobStart: (args?: {
    http_bind?: string;
    dns_bind?: string | null;
    public_host?: string;
    capacity?: number;
  }) => invoke<OobStatus>("oob_start", { args: args ?? {} }),
  oobStop: () => invoke<void>("oob_stop"),
  oobMintBatch: (count: number) =>
    invoke<OobToken[]>("oob_mint_batch", { count }),
  oobPollBatch: (args: { correlation_ids: string[]; timeout_ms?: number }) =>
    invoke<OobBatchHit[]>("oob_poll_batch", { args }),
  oobInteractionsAll: () => invoke<OobInteraction[]>("oob_interactions_all"),
  /** R132: Clear every stored OOB interaction. Returns the count
   *  removed. The id counter stays monotonic so correlation
   *  references remain unambiguous after a clear. */
  oobInteractionsClear: () => invoke<number>("oob_interactions_clear"),

  // ------------- Session rules / macros ---------------------------------
  sessionMacrosList: () => invoke<SessionMacro[]>("session_macros_list"),
  sessionRulesList: () => invoke<SessionRule[]>("session_rules_list"),
  sessionMacroUpsert: (m: SessionMacro) =>
    invoke<void>("session_macro_upsert", { macro: m }),
  sessionMacroDelete: (id: string) =>
    invoke<void>("session_macro_delete", { id }),
  sessionRuleUpsert: (rule: SessionRule) =>
    invoke<void>("session_rule_upsert", { rule }),
  sessionRuleDelete: (id: string) =>
    invoke<void>("session_rule_delete", { id }),
  sessionMacroRun: (id: string) =>
    invoke<MacroRunReport>("session_macro_run", { id }),

  // ------------- WebSocket -----------------------------------------------
  wsSessionsList: (limit?: number) =>
    invoke<WsSessionRow[]>("ws_sessions_list", { limit }),
  wsSessionGet: (id: number) =>
    invoke<WsSessionRow | null>("ws_session_get", { id }),
  wsMessagesList: (sessionId: number) =>
    invoke<WsMessageRow[]>("ws_messages_list", { sessionId }),
  wsReplay: (input: WsReplayInput) =>
    invoke<WsReplayResult>("ws_replay", { input }),
  wsInterceptStatus: () => invoke<boolean>("ws_intercept_status"),
  wsInterceptSetEnabled: (enabled: boolean) =>
    invoke<boolean>("ws_intercept_set_enabled", { enabled }),
  wsInterceptPending: () =>
    invoke<Array<{
      id: number;
      session_id: number;
      direction: "outbound" | "inbound";
      opcode: number;
      payload_size: number;
      preview_text: string | null;
      payload_base64: string;
      queued_at_ms: number;
    }>>("ws_intercept_pending"),
  wsInterceptRelease: (id: number, text: string | null, base64: string | null) =>
    invoke<boolean>("ws_intercept_release", { args: { id, text, base64 } }),
  wsInterceptDrop: (id: number) => invoke<boolean>("ws_intercept_drop", { id }),
  wsInterceptReleaseAll: () => invoke<number>("ws_intercept_release_all"),
  // Mirror of release_all — resolves every queued submit with
  // `Verdict::Drop`. Backs the WebSocketPanel "Drop all" button.
  wsInterceptDropAll: () => invoke<number>("ws_intercept_drop_all"),

  // ------------- REST API management (R930) ----------------------------------
  restApiConfigGet: () =>
    invoke<{
      enabled: boolean;
      port: number;
      listen_address: string;
      api_keys: Array<{ name: string; key: string; enabled: boolean }>;
      allow_without_key: boolean;
    }>("rest_api_config_get"),
  restApiConfigSet: (config: {
    enabled: boolean;
    port: number;
    listen_address: string;
    api_keys: Array<{ name: string; key: string; enabled: boolean }>;
    allow_without_key: boolean;
  }) => invoke<void>("rest_api_config_set", { config }),
  restApiKeyCreate: (name: string) =>
    invoke<{ name: string; key: string; enabled: boolean }>(
      "rest_api_key_create",
      { name },
    ),
  restApiKeyList: () =>
    invoke<Array<{ name: string; enabled: boolean; key_prefix: string }>>(
      "rest_api_key_list",
    ),
  restApiKeyDelete: (name: string) =>
    invoke<boolean>("rest_api_key_delete", { name }),

  // ------------- Bambda library + Scan profiles + KB (R961) ----------------
  bambdaPresetsList: () =>
    invoke<Array<{
      id: string;
      name: string;
      description: string;
      category: string;
      expression: string;
    }>>("bambda_presets_list"),
  scanProfilesList: () =>
    invoke<Array<{
      id: string;
      name: string;
      description: string;
      category: string;
      crawl_depth: number;
      rate_limit: number;
    }>>("scan_profiles_list"),
  kbIssuesList: () =>
    invoke<Array<{
      id: string;
      name: string;
      severity: string;
      cwe: string[];
      owasp: string[];
    }>>("kb_issues_list"),
  kbIssueDetail: (id: string) =>
    invoke<{
      id: string;
      name: string;
      description: string;
      remediation: string;
      severity: string;
      cwe: string[];
      owasp: string[];
      references: string[];
    }>("kb_issue_detail", { id }),
};

export type WsSessionRow = {
  id: number;
  handshake_id: number;
  host: string;
  port: number;
  path: string;
  opened_at_ms: number;
  closed_at_ms?: number | null;
  close_code?: number | null;
  close_reason?: string | null;
  message_count: number;
};

export type WsMessageRow = {
  id: number;
  session_id: number;
  direction: string;
  opcode: number;
  opcode_label: string;
  size: number;
  ts_ms: number;
  text?: string | null;
  base64?: string | null;
  truncated: boolean;
};

export type WsReplayFrame = {
  kind?: "text" | "binary" | "ping" | "pong" | "close";
  text?: string;
  base64?: string;
  delay_ms?: number;
};

export type WsReplayInput = {
  url: string;
  frames: WsReplayFrame[];
  headers?: Array<[string, string]>;
  drain_ms?: number;
};

export type WsReplayResult = {
  session_id: number;
  sent: number;
  received: number;
  closed: boolean;
  close_code?: number | null;
  close_reason?: string | null;
  error?: string | null;
};

export type OobStatus = {
  running: boolean;
  http_addr?: string | null;
  dns_addr?: string | null;
  public_host?: string | null;
  interaction_count: number;
};

export type OobToken = {
  correlation_id: string;
  http_url: string;
  dns_name: string;
};

export type OobInteraction = {
  id: number;
  ts_ms: number;
  kind: string;
  correlation_id: string;
  remote_addr: string;
  summary: string;
  preview: string;
};

export type OobBatchHit = {
  correlation_id: string;
  interactions: OobInteraction[];
};

export type MatchReplaceRuleScope = "request" | "response" | "both";
export type MatchReplaceRuleTarget =
  | "method"
  | "url"
  | "path"
  | "header_name"
  | "header_value"
  | "body"
  | "first_line"
  | "add_header"
  | "remove_header"
  | "set_body";

export type MatchReplaceRule = {
  id: string;
  name: string;
  enabled: boolean;
  scope: MatchReplaceRuleScope;
  target: MatchReplaceRuleTarget;
  match_: string;
  replace: string;
  regex: boolean;
  host_filter?: string | null;
  predicate_script?: string | null;
};

export type MatchReplaceEngine = {
  rules: MatchReplaceRule[];
};

export type MatchReplaceRuleHit = {
  id: string;
  name: string;
  enabled: boolean;
  /** True when the rule's gates (enabled + scope + host_filter +
   *  predicate_script) all passed and apply was attempted. */
  scope_matched: boolean;
  /** True when the rule actually mutated the message (e.g. the
   *  match pattern was found). */
  fired: boolean;
};

export type MatchReplacePreview = {
  before_wire: string;
  after_wire: string;
  rules_applied: MatchReplaceRuleHit[];
  net_mutations: number;
};

export type InterceptRuleOperator = "and" | "or";
export type InterceptRuleRelationship = "matches" | "does_not_match";
export type InterceptRuleMatchType =
  | "method"
  | "url"
  | "host"
  | "file_extension"
  | "has_params"
  | "has_body"
  | "in_scope"
  | "header_present";

export type InterceptRule = {
  id: string;
  enabled: boolean;
  operator: InterceptRuleOperator;
  match_type: InterceptRuleMatchType;
  relationship: InterceptRuleRelationship;
  condition: string;
};

export type InterceptRules = {
  rules: InterceptRule[];
};

export type InterceptRulesView = {
  request: InterceptRules;
  response: InterceptRules;
};

export type RulePreview = {
  id: string;
  enabled: boolean;
  operator: InterceptRuleOperator;
  match_type: InterceptRuleMatchType;
  relationship: InterceptRuleRelationship;
  condition: string;
  matched: boolean;
  effect: boolean;
};

export type PreviewReport = {
  /** Aggregate decision — `null` when no rules are enabled, `true`
   *  to hold (intercept), `false` to forward. */
  decision: boolean | null;
  rules: RulePreview[];
};

export type OrganizerItem = {
  id: number;
  transaction_id?: number;
  title: string;
  note: string;
  tags: string[];
  status: string;
  ts_ms: number;
  updated_at_ms: number;
  collection_id?: number | null;
};

export type OrganizerCollection = {
  id: number;
  name: string;
  created_at_ms: number;
  item_count: number;
};

export type CollectionsView = {
  collections: OrganizerCollection[];
  inbox_count: number;
};

// Cookie Jar entry. Shape mirrors `burpfree_engines::session::Cookie`
// with camelCase ↔ snake_case handled by serde's default rename.
// `same_site` / `expires_at` / `max_age` are nullable so the UI can
// render "—" for cookies the server didn't specify them on.
export type Cookie = {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  http_only: boolean;
  same_site?: string | null;
  /// Unix millis when the cookie expires; absent means session-only.
  expires_at?: number | null;
  max_age?: number | null;
  /// true when the cookie was set WITHOUT a Domain= attribute — it
  /// only matches the exact host that set it.
  host_only: boolean;
};

// Automatic project backup. Shape mirrors
// `burpfree_storage::AutoBackupConfig`. Defaults match Burp's
// built-in: enabled, 30-min interval, 20 copies kept.
export type AutoBackupConfig = {
  enabled: boolean;
  /// Minutes between automatic snapshots. Backend clamps to
  /// `[1, 1440]` so a stray 0 can't hot-spin and a huge value
  /// can't silently disable the feature.
  interval_min: number;
  /// How many timestamped backups to keep on disk at any time.
  /// The pruner drops oldest first after every successful write.
  keep_count: number;
  /// Wipe every backup zip when the project closes.
  delete_on_shutdown: boolean;
};

// Comparer item — one entry in the operator's Comparer collection
// (Burp's numbered items list). The id is generated client-side via
// crypto.randomUUID() and used as the upsert key. `label` is a
// short human-readable tag the UI builds from the source (host +
// path or a free-form string); `text` is the actual payload.
export type ComparerItem = {
  id: string;
  label: string;
  text: string;
  created_at_ms: number;
};

// Scanner report-export result — returned by scanner_report_write
// so the UI can show a success toast ("Wrote N findings to <path>,
// K bytes") without a second disk round-trip.
export type ScannerReportResult = {
  path: string;
  format: string;
  bytes_written: number;
  findings_count: number;
};

// BChecks — Burp's declarative active-scan rule format. One YAML
// doc per rule lives in `project/bchecks/`. The backend loader
// surfaces each file as a BCheckLoadRow (parse status + metadata
// when ok, error string when not); the runner evaluates every
// valid rule against the unique (scheme, host, port) tuples seen
// in HTTP history and returns a BCheckRunReport. The UI mirrors
// Burp's BChecks tab: list on top, Run-all button below, per-file
// error diagnostics inline.
export type BCheckLoadRow = {
  path: string;
  ok: boolean;
  name: string | null;
  severity: string | null;
  candidates: number;
  error: string | null;
};
export type BCheckValidateResult = {
  ok: boolean;
  /** Error chain when parsing failed (serde_yaml context). */
  error: string | null;
  name: string | null;
  description: string | null;
  author: string | null;
  version: string | null;
  severity: string | null;
  tags: string[];
  /** How many `candidates:` entries the YAML carries. Zero == the
   *  BCheck is parse-valid but the runner won't dispatch it. */
  candidates: number;
};
export type BCheckRunReport = {
  rules_loaded: number;
  rules_ok: number;
  targets: number;
  findings: number;
  elapsed_ms: number;
  load_errors: string[];
};

// Platform-authentication credential — Burp's `Settings → Network
// → Platform authentication` row shape. Mirrors
// `burpfree_proxy::platform_auth::PlatformAuthCredential`. R73
// ships Basic end-to-end; Digest round-trips through serde but the
// proxy retry path logs TODO and falls through.
export type AuthScheme = "basic" | "digest";
export type PlatformAuthCredential = {
  host_pattern: string;
  scheme: AuthScheme;
  username: string;
  password: string;
  enabled: boolean;
};

// Metadata about a single `<project>/backups/*.zip` entry.
export type BackupInfo = {
  filename: string;
  size_bytes: number;
  created_at_ms: number;
};

// Well-known import result. Shape mirrors
// `burpfree_engines::well_known::WellKnownReport`. Partial results
// are always returned — any fetch / parse failure lands in `errors`
// and the corresponding `robots` / `sitemap` field stays `null`.
export type WellKnownReport = {
  base_url: string;
  robots?: RobotsParsed | null;
  sitemap?: SitemapParsed | null;
  /// First 64 KB of the raw robots.txt body — surfaced for an
  /// inline preview pane. Null when the fetch failed.
  robots_body?: string | null;
  sitemap_body?: string | null;
  /// Sorted + deduped flat list of every URL discovered across
  /// both files. `<loc>` entries from the sitemap plus `Sitemap:`
  /// refs from robots.txt.
  discovered_urls: string[];
  /// Non-fatal errors (bad base URL, 4xx/5xx on either file,
  /// connect refused, etc.). Empty on a clean import.
  errors: string[];
};

export type RobotsParsed = {
  user_agents: string[];
  disallow: string[];
  allow: string[];
  sitemaps: string[];
  extras: string[];
};

export type SitemapParsed = {
  /// URLs from `<url><loc>…</loc></url>` entries.
  urls: string[];
  /// URLs from sitemap-index entries (`<sitemap><loc>…`). The
  /// import doesn't recurse automatically; operators can re-run
  /// against each one from the UI.
  nested: string[];
};

export type HostOverride = {
  enabled: boolean;
  hostname: string;
  ip: string;
};

export type HostOverridesView = {
  overrides: HostOverride[];
  follow_redirects: string;
};

export type DashboardStats = {
  project: ProjectInfo;
  proxy: ProxyStatsView;
  findings_by_severity: Record<string, number>;
  findings_total: number;
  oob: OobStatus;
  ws_sessions: number;
  ws_messages: number;
  organizer_items: number;
  macros: number;
  session_rules: number;
  extensions: number;
  custom_rules: number;
  passive_scan_running: boolean;
  passive_scan_findings_last_run?: number | null;
  passive_scan_started_ms?: number | null;
  passive_scan_finished_ms?: number | null;
};

export type ExtractSource =
  | { source: "body" }
  | { source: "status" }
  | { source: "header"; name: string };

export type MacroExtractor = {
  var: string;
  source: ExtractSource;
  pattern: string;
};

export type SessionMacroStep = {
  method: string;
  url: string;
  headers: Array<[string, string]>;
  body: string;
  extract: MacroExtractor[];
};

export type SessionMacro = {
  id: string;
  name: string;
  notes?: string;
  steps: SessionMacroStep[];
};

export type SpliceAction = {
  header: string;
  template: string;
};

export type RuleScope = {
  host_suffix: string;
  path_prefix: string;
};

export type SessionRule = {
  id: string;
  name: string;
  macro_id: string;
  scope: RuleScope;
  splice: SpliceAction[];
  apply_cookies: boolean;
  enabled: boolean;
};

export type MacroRunReport = {
  vars: Record<string, string>;
  cookies: Array<{
    name: string;
    value: string;
    domain: string;
    path: string;
    secure: boolean;
    http_only: boolean;
    same_site?: string | null;
    expires_at?: number | null;
    max_age?: number | null;
    host_only: boolean;
  }>;
  transcript: Array<{
    step_index: number;
    method: string;
    url: string;
    status?: number | null;
    elapsed_ms?: number | null;
    error?: string | null;
    extracted: Record<string, string>;
  }>;
  error?: string | null;
};
