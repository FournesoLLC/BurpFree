// Scope quick-action helpers — shared logic for the right-click menus
// in ProxyPanel history, HistoryPanel, and TargetPanel. Keeps the
// three callsites consistent on how a host/path gets inserted or
// removed from the project scope.
//
// All functions take the current `Scope` object (fetched via
// `api.scopeGet()`) + the host / path from the row the operator
// right-clicked, and either produce a rule to add via
// `api.scopeAddRule(rule)` or a new rules array to push through
// `api.scopeSet(scope)`.

import { Scope, ScopeRule } from "./api";

/** Does the scope already contain an *include* rule that matches
 *  this bare host? Used to grey out "Add host to scope" when it
 *  would be a no-op. The comparison is case-insensitive and ignores
 *  disabled rules. */
export function hasHostIncludeRule(scope: Scope | null, host: string): boolean {
  if (!scope || !host) return false;
  const h = host.toLowerCase();
  return scope.rules.some(
    (r) =>
      r.enabled &&
      r.match_kind === "include" &&
      r.host.toLowerCase() === h &&
      (!r.path || r.path === "*"),
  );
}

/** Does the scope have an include rule for exactly this host + path? */
export function hasPathIncludeRule(
  scope: Scope | null,
  host: string,
  path: string,
): boolean {
  if (!scope || !host) return false;
  const h = host.toLowerCase();
  // Normalise path — strip query so the rule matches on the endpoint,
  // not on specific param values.
  const bare = pathWithoutQuery(path);
  return scope.rules.some(
    (r) =>
      r.enabled &&
      r.match_kind === "include" &&
      r.host.toLowerCase() === h &&
      r.path === bare,
  );
}

/** Build an "include host" rule for `host`. Mirrors the Rust
 *  `ScopeRule::include_host` constructor. */
export function buildHostIncludeRule(host: string): ScopeRule {
  return {
    match_kind: "include",
    protocol: "any",
    host: host.trim(),
    port: null as unknown as undefined,
    path: "*",
    regex: false,
    enabled: true,
  };
}

/** Build an "include host + exact path" rule. Query string is stripped
 *  so the rule stays stable across varying parameters. */
export function buildPathIncludeRule(host: string, path: string): ScopeRule {
  return {
    match_kind: "include",
    protocol: "any",
    host: host.trim(),
    port: null as unknown as undefined,
    path: pathWithoutQuery(path) || "/",
    regex: false,
    enabled: true,
  };
}

/** Produce a copy of `scope` with every enabled rule referencing the
 *  given host removed. The disabled-rule side of the list is left
 *  alone so the operator doesn't silently lose paused rules. */
export function withoutHost(scope: Scope, host: string): Scope {
  const h = host.toLowerCase();
  return {
    ...scope,
    rules: scope.rules.filter(
      (r) => !(r.enabled && r.host.toLowerCase() === h),
    ),
  };
}

function pathWithoutQuery(p: string): string {
  const i = p.indexOf("?");
  return i < 0 ? p : p.slice(0, i);
}
