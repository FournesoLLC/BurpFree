// CookieJarPanel — Burp-style Cookie Jar view.
//
// Reads the shared project jar via `api.cookieJarList()`, which the
// proxy sink + ProjectSink feed on every recorded response. Operators
// can:
//   - sort by any column (click a header, click again to reverse);
//   - filter by substring across every text column;
//   - add a cookie manually (useful for injecting a token captured
//     out-of-band);
//   - delete a single cookie (`✕` button) or clear everything;
//   - right-click a row to copy `name=value` or the full
//     `Set-Cookie`-style representation.
//
// The jar's internal `Arc<RwLock<Vec<Cookie>>>` makes `snapshot()`
// cheap, so polling every 2 s is fine. Live traffic bumps up here
// without any explicit refresh.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { api, Cookie } from "../api";
import { FloatingMenu, MenuState } from "../FloatingMenu";
import { copyToClipboard } from "../copyAs";

type SortKey =
  | "domain"
  | "path"
  | "name"
  | "value"
  | "secure"
  | "http_only"
  | "same_site"
  | "expires_at";

const DESC_FIRST_KEYS: ReadonlySet<SortKey> = new Set(["expires_at"]);

function cookieKey(c: Cookie): string {
  // Stable key for React — the (domain, path, name) triple is the
  // uniqueness guarantee the backend enforces in observe_response.
  return `${c.domain}|${c.path}|${c.name}`;
}

function formatExpiry(ms: number | null | undefined): string {
  if (ms == null) return "session";
  const date = new Date(ms);
  const now = Date.now();
  if (ms < now) return `expired · ${date.toISOString().slice(0, 19).replace("T", " ")}`;
  const deltaS = Math.floor((ms - now) / 1000);
  if (deltaS < 60) return `${deltaS}s`;
  if (deltaS < 3600) return `${Math.floor(deltaS / 60)}m`;
  if (deltaS < 86400) return `${Math.floor(deltaS / 3600)}h`;
  if (deltaS < 2592000) return `${Math.floor(deltaS / 86400)}d`;
  return date.toISOString().slice(0, 10);
}

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max - 1) + "…";
}

export function CookieJarPanel() {
  const [cookies, setCookies] = useState<Cookie[]>([]);
  const [sortKey, setSortKey] = useState<SortKey>("domain");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [filter, setFilter] = useState("");
  const [busy, setBusy] = useState(false);
  const [showAdd, setShowAdd] = useState(false);
  const [menu, setMenu] = useState<MenuState<Cookie> | null>(null);
  // R125: Hidden file input for the "⬆ Import" button. Pattern
  // matches R118-R121 / R124 file-loaders — one native OS picker,
  // reset-after-pick so repeat selections still fire onChange.
  const cookieFileRef = useRef<HTMLInputElement | null>(null);
  // R517: Second hidden file input for the "⬆ Import (Netscape)"
  // button — parallel to cookieFileRef but accepts .txt files
  // in the Netscape cookies.txt format. Kept separate so the
  // JSON and Netscape import paths don't share a MIME filter
  // (JSON accepts .json / application/json; Netscape accepts
  // .txt / text/plain).
  const netscapeFileRef = useRef<HTMLInputElement | null>(null);

  const refresh = useCallback(async () => {
    try {
      const next = await api.cookieJarList();
      setCookies(next ?? []);
    } catch {
      // No project yet, or a transient cmd race — keep the previous
      // snapshot visible rather than blanking the table.
    }
  }, []);

  // Initial load + 2 s poller. Live traffic through the proxy appends
  // cookies to the shared jar; this surfaces them without an explicit
  // refresh click.
  useEffect(() => {
    void refresh();
    const t = setInterval(refresh, 2000);
    return () => clearInterval(t);
  }, [refresh]);

  function toggleSort(k: SortKey) {
    if (sortKey === k) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(k);
      setSortDir(DESC_FIRST_KEYS.has(k) ? "desc" : "asc");
    }
  }

  // R436: Alt+C clears the search filter when it's non-empty.
  // Mirrors the cross-panel Alt+C clear-filter family (R349
  // History / R392 Decoder / R409 Collaborator / R410 Logger /
  // R412 Target Issues). CookieJar's filter is a simple text
  // box, so a one-key reset is useful when operators pivot
  // between host-scoped and name-scoped lookups. **Letter choice**
  // C = Clear. **Guards** plain Alt only, text-input focus skip
  // — critical because operators often focus the filter input.
  // **No-op silent** when filter is empty.
  useEffect(() => {
    function onClearKey(e: KeyboardEvent) {
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      if (e.key !== "c" && e.key !== "C") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (filter.length === 0) return;
      e.preventDefault();
      setFilter("");
    }
    document.addEventListener("keydown", onClearKey);
    return () => document.removeEventListener("keydown", onClearKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter]);

  // R450: Alt+Shift+C fires the "Clear jar" destructive action —
  // reuses `clearAll()` so the confirm dialog, the backend
  // `api.cookieJarClear()` call, the refresh, and the busy-state
  // bookkeeping all stay identical to the visible button. Extends
  // the Alt+Shift+C clear-results family to a sixth panel —
  // R418 Intruder (clear attack results) / R435 Sequencer (clear
  // tokens + report) / R446 Logger (clear stored events) / R447
  // Collaborator (clear OOB interactions) / R448 BChecks (clear
  // last run artifacts) / R450 CookieJar (clear jar). The
  // deliberate separation from R436 Alt+C stays identical:
  // Alt+C clears the search filter (lightweight state reset,
  // no backend call), Alt+Shift+C is the destructive variant
  // (backend `cookieJarClear()` behind confirm). Shift distinguishes
  // the two so operators who just wanted the filter cleared don't
  // accidentally wipe the entire cookie store. **Guards** plain
  // Alt+Shift only (rejects Ctrl/Meta), text-input focus skip,
  // and a short-circuit when `cookies.length === 0` so a stray
  // keystroke on a fresh jar is a no-op.
  useEffect(() => {
    function onClearJarKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key !== "C" && e.key !== "c") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (cookies.length === 0) return;
      e.preventDefault();
      void clearAll();
    }
    document.addEventListener("keydown", onClearJarKey);
    return () => document.removeEventListener("keydown", onClearJarKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cookies.length]);

  const sorted = useMemo(() => {
    const q = filter.trim().toLowerCase();
    const filtered = q
      ? cookies.filter((c) => {
          const hay = [
            c.name,
            c.value,
            c.domain,
            c.path,
            c.same_site ?? "",
          ]
            .join(" ")
            .toLowerCase();
          return hay.includes(q);
        })
      : cookies.slice();
    filtered.sort((a, b) => {
      const dir = sortDir === "asc" ? 1 : -1;
      const av = a[sortKey];
      const bv = b[sortKey];
      // Null / undefined sorts last regardless of direction.
      if (av == null && bv == null) return 0;
      if (av == null) return 1;
      if (bv == null) return -1;
      if (typeof av === "number" && typeof bv === "number") {
        return (av - bv) * dir;
      }
      if (typeof av === "boolean" && typeof bv === "boolean") {
        return (Number(av) - Number(bv)) * dir;
      }
      return String(av).localeCompare(String(bv), undefined, { numeric: true }) * dir;
    });
    return filtered;
  }, [cookies, sortKey, sortDir, filter]);

  async function deleteCookie(c: Cookie) {
    setBusy(true);
    try {
      const existed = await api.cookieJarDelete(c.name, c.domain, c.path);
      if (existed) await refresh();
    } catch (e) {
      alert(`Delete failed: ${e}`);
    } finally {
      setBusy(false);
    }
  }

  async function clearAll() {
    if (cookies.length === 0) return;
    if (
      !confirm(
        `Clear ${cookies.length} cookie${cookies.length === 1 ? "" : "s"} from the jar? Set-Cookie headers already stored in HTTP history keep their copies — only the shared jar is wiped.`,
      )
    )
      return;
    setBusy(true);
    try {
      await api.cookieJarClear();
      await refresh();
    } catch (e) {
      alert(`Clear failed: ${e}`);
    } finally {
      setBusy(false);
    }
  }

  /** R151: Delete every "session cookie" — a cookie with neither
   *  Expires nor Max-Age set, which real browsers wipe on close.
   *  No single backend cmd for this because the proxy sink's job
   *  is to track Set-Cookie observations faithfully, not reason
   *  about session-vs-persistent — but a batch of per-cookie
   *  deletes via `cookieJarDelete` matches the shape of R125's
   *  import and R130's bulk prune. Promise.allSettled so one
   *  bad delete doesn't strand the rest. */
  async function expireSessionCookies() {
    const sessions = cookies.filter(
      (c) => c.expires_at == null && c.max_age == null,
    );
    if (sessions.length === 0) return;
    if (
      !confirm(
        `Delete ${sessions.length} session cookie${sessions.length === 1 ? "" : "s"} from the jar? Cookies with Expires or Max-Age attributes stay.`,
      )
    )
      return;
    setBusy(true);
    try {
      const results = await Promise.allSettled(
        sessions.map((c) => api.cookieJarDelete(c.name, c.domain, c.path)),
      );
      const failures = results.filter((r) => r.status === "rejected");
      await refresh();
      if (failures.length > 0) {
        alert(
          `Expired ${sessions.length - failures.length} / ${sessions.length}. ${failures.length} failed — first error: ${(failures[0] as PromiseRejectedResult).reason}`,
        );
      }
    } catch (e) {
      alert(`Expire session failed: ${e}`);
    } finally {
      setBusy(false);
    }
  }

  // R151: Count of session cookies (no Expires + no Max-Age) so
  // the button renders its live tally and disables when nothing
  // would be deleted. Recomputed on every cookies-array change
  // via useMemo so the badge stays in sync with the 2 s poll.
  const sessionCookieCount = useMemo(
    () => cookies.filter((c) => c.expires_at == null && c.max_age == null).length,
    [cookies],
  );

  const copyPair = async (c: Cookie) => {
    try {
      await navigator.clipboard.writeText(`${c.name}=${c.value}`);
    } catch (e) {
      alert(`${e}`);
    }
  };

  const copySetCookie = async (c: Cookie) => {
    const parts: string[] = [`${c.name}=${c.value}`];
    if (!c.host_only) parts.push(`Domain=${c.domain}`);
    if (c.path && c.path !== "/") parts.push(`Path=${c.path}`);
    else parts.push(`Path=/`);
    if (c.secure) parts.push("Secure");
    if (c.http_only) parts.push("HttpOnly");
    if (c.same_site) parts.push(`SameSite=${c.same_site}`);
    if (c.expires_at)
      parts.push(`Expires=${new Date(c.expires_at).toUTCString()}`);
    if (c.max_age != null) parts.push(`Max-Age=${c.max_age}`);
    try {
      await navigator.clipboard.writeText(parts.join("; "));
    } catch (e) {
      alert(`${e}`);
    }
  };

  const totalBadge = `${cookies.length} cookie${cookies.length === 1 ? "" : "s"}`;
  const filteredBadge =
    sorted.length !== cookies.length
      ? ` · showing ${sorted.length}`
      : "";

  return (
    <div className="cookie-jar-panel" style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
      <div
        className="toolbar"
        style={{
          display: "flex",
          gap: 6,
          alignItems: "center",
          padding: "6px 10px",
          borderBottom: "1px solid var(--border)",
          flexWrap: "wrap",
        }}
      >
        <strong>Cookie Jar</strong>
        <span className="dim" style={{ fontSize: 11 }}>
          Shared across Proxy, Repeater, Intruder, Scanner — populated from Set-Cookie headers on every recorded response.
        </span>
        {/* R471: CookieJar stats badge "📊 N cookies · D domains · S  */}
        {/* session". 7th panel to carry a toolbar "📊" quick-stats     */}
        {/* chip — joins R440 Repeater workspace stats + R442 History  */}
        {/* hosts + R451 Collaborator kind-split + R452 Target Issues  */}
        {/* severity-split + R466 Decoder chain stats + R469           */}
        {/* Sequencer tokens badge. Operators auditing a long          */}
        {/* engagement want a one-glance read of the jar's shape:      */}
        {/* total cookie count, how many distinct hosts they span,     */}
        {/* and how many are session cookies (no Expires + no Max-Age, */}
        {/* so they'd die on browser close). The latter is particularly */}
        {/* useful for scope-pass triage ("most of this jar is         */}
        {/* persistent auth cookies, 3 are ephemeral session ones").   */}
        {/* **Visibility gate** `cookies.length > 0` — hides for a     */}
        {/* fresh / cleared jar. Session count reuses the existing     */}
        {/* `sessionCookieCount` useMemo (zero new memoization). The   */}
        {/* unique-domain Set is a one-pass accumulation per render    */}
        {/* — same cost as R442's hosts set.                           */}
        {cookies.length > 0 && (() => {
          const domains = new Set(cookies.map((c) => c.domain)).size;
          return (
            <span
              className="mono"
              title={`${cookies.length} cookie${cookies.length === 1 ? "" : "s"} across ${domains} distinct domain${domains === 1 ? "" : "s"} · ${sessionCookieCount} session cookie${sessionCookieCount === 1 ? "" : "s"} (no Expires + no Max-Age, die on browser close)`}
              style={{ fontSize: 10.5, color: "var(--text-faint)", marginLeft: 8 }}
            >
              📊
              <span style={{ color: "var(--text)", marginLeft: 4 }}>
                {cookies.length}
              </span>
              <span style={{ color: "var(--text-dim)", margin: "0 4px" }}>·</span>
              <span style={{ color: "var(--accent)" }}>
                {domains} domain{domains === 1 ? "" : "s"}
              </span>
              {sessionCookieCount > 0 && (
                <>
                  <span style={{ color: "var(--text-dim)", margin: "0 4px" }}>·</span>
                  <span style={{ color: "var(--amber, #e0a040)" }}>
                    {sessionCookieCount} session
                  </span>
                </>
              )}
            </span>
          );
        })()}
        <span className="spacer" style={{ flex: 1 }} />
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="filter (host / name / value)"
          style={{ width: 220 }}
        />
        <button
          onClick={() => void refresh()}
          disabled={busy}
          title="Re-read the jar snapshot (also polled every 2 s)"
        >
          Refresh
        </button>
        <button
          onClick={() => setShowAdd((s) => !s)}
          title="Insert a cookie manually — useful for injecting a token captured out-of-band without faking a proxy response"
        >
          {showAdd ? "Cancel add" : "+ Add"}
        </button>
        {/* ------------------------------------------------------- */}
        {/* R125: Export + import. Burp exposes an "Export cookies" */}
        {/* affordance on the shared jar for teammate hand-off +    */}
        {/* snapshot-before-exploit workflows. Export dumps the     */}
        {/* current filtered-ignored jar array as JSON; import      */}
        {/* reads JSON back and calls `cookieJarSet` per entry so    */}
        {/* the backend's unique-triple guard (domain, path, name)   */}
        {/* applies the same way as a live Set-Cookie would.         */}
        <button
          disabled={cookies.length === 0}
          onClick={() => {
            try {
              const payload = JSON.stringify(cookies, null, 2);
              const blob = new Blob([payload], {
                type: "application/json;charset=utf-8",
              });
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a");
              const stamp = new Date()
                .toISOString()
                .replace(/[:T]/g, "-")
                .replace(/\..*$/, "");
              a.href = url;
              a.download = `burpfree-cookies-${stamp}.json`;
              document.body.appendChild(a);
              a.click();
              a.remove();
              URL.revokeObjectURL(url);
            } catch (e) {
              alert(`${e}`);
            }
          }}
          title={
            cookies.length === 0
              ? "Jar is empty — nothing to export."
              : `Export ${cookies.length} cookie${cookies.length === 1 ? "" : "s"} to a JSON file`
          }
        >
          ⬇ Export
        </button>
        {/* R657: Clipboard-only JSON counterpart to R125 ⬇ Export.
            9th entry in cross-panel Copy-as-JSON family (History
            R605 / Scanner R606 / Intruder R607 / Target R611 /
            Collaborator R612 / Decoder R647 / Sequencer R648 /
            Comparer R649 / CookieJar R657). Operators pasting the
            jar into a chat / test fixture / API payload want JSON
            on the clipboard directly without the file-save
            roundtrip. Byte-identical to the R125 Export JSON file
            content (both JSON.stringify of `cookies` array). */}
        <button
          onClick={() =>
            void copyToClipboard(JSON.stringify(cookies, null, 2))
          }
          disabled={cookies.length === 0}
          title={
            cookies.length === 0
              ? "Jar is empty — nothing to copy."
              : `Copy ${cookies.length} cookie${cookies.length === 1 ? "" : "s"} as a JSON array to clipboard (2-space indent, pretty-printed). Byte-identical to ⬇ Export JSON. Great for sharing in a chat or seeding a test fixture.`
          }
        >
          📋 Copy JSON
        </button>
        {/* R721: CookieJar "📋 Copy domain counts" — tally
            variant. Groups cookies by domain, counts per domain,
            sorted desc. Operators auditing "which domain has
            the most cookies in my jar?" want this one-line
            format. Mirror of R673 HistoryPanel Copy host counts
            + R673's Target host counts. First counts tally op
            on CookieJar. */}
        <button
          disabled={cookies.length === 0}
          onClick={() => {
            const counts: Record<string, number> = {};
            for (const c of cookies) {
              const d = (c.domain || "(none)").toLowerCase();
              counts[d] = (counts[d] ?? 0) + 1;
            }
            const sorted = Object.entries(counts).sort(
              (a, b) => b[1] - a[1],
            );
            const text = sorted.map(([d, n]) => `${d}: ${n}`).join(", ");
            void copyToClipboard(text);
          }}
          title={
            cookies.length === 0
              ? "Jar is empty — nothing to tally."
              : `Copy cookie-count tally per domain across ${cookies.length} cookie${cookies.length === 1 ? "" : "s"} as a one-line summary (sorted desc by count). Great for a quick "which domain dominates the jar?" audit.`
          }
        >
          📋 Copy domain counts
        </button>
        {/* R722: CookieJar "📋 Copy stats" — 8th panel in the
            metadata summary family (History/Scanner/Target/
            Collaborator/Logger/Intruder/Repeater/CookieJar).
            Cookie-jar-focused shape: Cookies / Unique domains
            / Unique paths / Secure / HttpOnly / Session (no
            expiry) / Persistent. Great for a cookie audit
            summary. Zero backend. */}
        <button
          disabled={cookies.length === 0}
          onClick={() => {
            const domains = new Set<string>();
            const paths = new Set<string>();
            let secure = 0;
            let httpOnly = 0;
            let session = 0;
            let persistent = 0;
            for (const c of cookies) {
              if (c.domain) domains.add(c.domain.toLowerCase());
              if (c.path) paths.add(c.path);
              if (c.secure) secure += 1;
              if (c.http_only) httpOnly += 1;
              const hasExpiry =
                typeof (c as any).expires_ms === "number" &&
                (c as any).expires_ms > 0;
              if (hasExpiry) persistent += 1;
              else session += 1;
            }
            const total = cookies.length;
            const pct = (n: number) =>
              total === 0
                ? "0%"
                : (n / total) * 100 < 1
                  ? "<1%"
                  : `${((n / total) * 100).toFixed(((n / total) * 100) < 10 ? 1 : 0)}%`;
            const lines: string[] = [];
            lines.push(`Cookies: ${total}`);
            lines.push(`Unique domains: ${domains.size}`);
            lines.push(`Unique paths: ${paths.size}`);
            lines.push(`Secure: ${secure} (${pct(secure)})`);
            lines.push(`HttpOnly: ${httpOnly} (${pct(httpOnly)})`);
            lines.push(`Session (no expiry): ${session} (${pct(session)})`);
            lines.push(`Persistent: ${persistent} (${pct(persistent)})`);
            void copyToClipboard(lines.join("\n"));
          }}
          title={
            cookies.length === 0
              ? "Jar is empty — nothing to summarize."
              : `Copy a multi-line KV summary across ${cookies.length} cookie${cookies.length === 1 ? "" : "s"} (Cookies / Unique domains / Unique paths / Secure / HttpOnly / Session / Persistent). 8th panel in the metadata summary family — great for a cookie audit ticket summary.`
          }
        >
          📋 Copy stats
        </button>
        {/* R481: "⬇ Export (Netscape)" — the widely-supported         */}
        {/* cookies.txt format used by curl (--cookie-jar / --cookie), */}
        {/* wget (--load-cookies / --save-cookies), browsers (Firefox */}
        {/* / Chrome via extensions), and most HTTP clients. Operators */}
        {/* bridging between BurpFree and a shell / replay pipeline    */}
        {/* get a one-click export in the format curl is already       */}
        {/* happy to consume — no JSON → cookies.txt translation step. */}
        {/* **Format** per curl + Netscape convention: 7 tab-separated */}
        {/* fields per line (domain / flag / path / secure / expires  */}
        {/* / name / value). The `flag` field is "TRUE" when the      */}
        {/* cookie's domain starts with a dot (subdomain-wide), FALSE */}
        {/* for host-only. The `expires` field is Unix epoch seconds   */}
        {/* — 0 for session cookies with no Expires/Max-Age set, which */}
        {/* curl treats as "already expired" (same convention Firefox  */}
        {/* and Chrome use when exporting). HttpOnly cookies get the   */}
        {/* leading `#HttpOnly_` marker that curl + Chrome recognize.  */}
        {/* **Comments** header follows the curl convention — operators */}
        {/* dropping the file into a curl command recognize the shape  */}
        {/* immediately.                                                */}
        <button
          disabled={cookies.length === 0}
          onClick={() => {
            try {
              const stamp = new Date()
                .toISOString()
                .replace(/[:T]/g, "-")
                .replace(/\..*$/, "");
              const header =
                "# Netscape HTTP Cookie File\n" +
                "# Exported by BurpFree. Compatible with curl / wget / most HTTP clients.\n" +
                "# https://curl.se/docs/http-cookies.html\n\n";
              const body = cookies
                .map((c) => {
                  const prefix = c.http_only ? "#HttpOnly_" : "";
                  const domain = prefix + c.domain;
                  // "TRUE" means cookie applies to subdomains too; "FALSE"
                  // means host-only. The Netscape convention keys on
                  // whether `domain` starts with a dot — a trailing-dot
                  // host-only cookie reads as FALSE, a leading-dot
                  // subdomain-wide cookie reads as TRUE. BurpFree's
                  // `host_only` field inverts that so we flip.
                  const flag = c.host_only ? "FALSE" : "TRUE";
                  const path = c.path || "/";
                  const secure = c.secure ? "TRUE" : "FALSE";
                  // `expires` in epoch seconds. For session cookies with
                  // neither Expires nor Max-Age, use 0 (curl / Firefox
                  // convention: 0 = session / expired).
                  let expires = 0;
                  if (c.expires_at != null) {
                    expires = Math.floor(c.expires_at / 1000);
                  } else if (c.max_age != null) {
                    expires = Math.floor(Date.now() / 1000) + c.max_age;
                  }
                  return [
                    domain,
                    flag,
                    path,
                    secure,
                    String(expires),
                    c.name,
                    c.value,
                  ].join("\t");
                })
                .join("\n");
              const payload = header + body + "\n";
              const blob = new Blob([payload], {
                type: "text/plain;charset=utf-8",
              });
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a");
              a.href = url;
              a.download = `burpfree-cookies-${stamp}.txt`;
              document.body.appendChild(a);
              a.click();
              a.remove();
              URL.revokeObjectURL(url);
            } catch (e) {
              alert(`${e}`);
            }
          }}
          title={
            cookies.length === 0
              ? "Jar is empty — nothing to export."
              : `Export ${cookies.length} cookie${cookies.length === 1 ? "" : "s"} as Netscape cookies.txt — paste into curl --cookie / wget --load-cookies / Chrome / Firefox. HttpOnly cookies get the #HttpOnly_ prefix curl + Chrome recognize. Session cookies (no Expires + no Max-Age) get expires=0 which curl treats as session-scoped.`
          }
        >
          ⬇ Export (Netscape)
        </button>
        {/* R517: "⬆ Import (Netscape)" — round-trip counterpart to  */}
        {/* R481's "⬇ Export (Netscape)". Operators coming from       */}
        {/* curl's --cookie-jar / wget's --save-cookies / a browser   */}
        {/* extension that dumps cookies.txt get a one-click path     */}
        {/* back into BurpFree's shared jar without a JSON transcode  */}
        {/* step. Also closes the loop with R481 — operators can     */}
        {/* export cookies before an exploit, run the exploit via a   */}
        {/* separate shell, then re-import the resulting cookies.txt  */}
        {/* to pick back up where they left off. **Format** 7 TSV     */}
        {/* fields per line (domain / flag / path / secure / expires  */}
        {/* / name / value), matches the Netscape convention R481     */}
        {/* writes. **HttpOnly recognition** domains with the         */}
        {/* leading `#HttpOnly_` marker lose the prefix and the       */}
        {/* parsed Cookie record gets `http_only: true`. **Comments** */}
        {/* lines starting with `#` (except `#HttpOnly_`) and blank   */}
        {/* lines are skipped. **Domain → host_only** mirrors R481's  */}
        {/* flip: FALSE flag → host_only=true. **Expires 0** → omit    */}
        {/* expires_at + max_age so the backend treats the entry as   */}
        {/* a session cookie, same as R481's export convention.       */}
        <input
          ref={netscapeFileRef}
          type="file"
          accept=".txt,text/plain"
          style={{ display: "none" }}
          onChange={async (e) => {
            const file = e.currentTarget.files?.[0];
            e.currentTarget.value = "";
            if (!file) return;
            if (file.size > 5 * 1024 * 1024) {
              alert(
                `File is ${(file.size / 1024 / 1024).toFixed(1)} MB — Netscape cookies.txt import caps at 5 MB.`,
              );
              return;
            }
            try {
              const text = await file.text();
              const parsed: Cookie[] = [];
              const errors: string[] = [];
              const lines = text.split(/\r?\n/);
              for (let i = 0; i < lines.length; i++) {
                const raw = lines[i];
                if (!raw) continue;
                const trimmed = raw.trim();
                if (!trimmed) continue;
                // # comment, but #HttpOnly_ is a cookie line marker.
                let line = raw;
                let httpOnly = false;
                if (line.startsWith("#HttpOnly_")) {
                  httpOnly = true;
                  line = line.slice(10);
                } else if (trimmed.startsWith("#")) {
                  continue;
                }
                const fields = line.split("\t");
                if (fields.length < 7) {
                  errors.push(
                    `Line ${i + 1}: expected 7 tab-separated fields, got ${fields.length}.`,
                  );
                  continue;
                }
                const [
                  domainRaw,
                  flag,
                  path,
                  secureRaw,
                  expiresRaw,
                  name,
                  value,
                ] = fields;
                if (!name || !domainRaw || !path) {
                  errors.push(
                    `Line ${i + 1}: name / domain / path required.`,
                  );
                  continue;
                }
                // Netscape convention: TRUE flag = subdomain-wide
                // (not host-only), FALSE = host-only (R481's export
                // writes host_only=true as FALSE).
                const hostOnly = flag.toUpperCase() === "FALSE";
                const secure = secureRaw.toUpperCase() === "TRUE";
                const expiresSec = parseInt(expiresRaw, 10);
                // expires=0 is Netscape convention for session /
                // already-expired. Omit expires_at + max_age so the
                // backend treats it as a session cookie.
                const expiresMs =
                  Number.isFinite(expiresSec) && expiresSec > 0
                    ? expiresSec * 1000
                    : null;
                parsed.push({
                  name,
                  value,
                  domain: domainRaw,
                  path,
                  secure,
                  http_only: httpOnly,
                  host_only: hostOnly,
                  expires_at: expiresMs,
                  max_age: null,
                  same_site: null,
                });
              }
              if (parsed.length === 0) {
                alert(
                  errors.length > 0
                    ? `No usable lines. First error: ${errors[0]}`
                    : "No cookie lines found in the file.",
                );
                return;
              }
              if (
                cookies.length > 0 &&
                !confirm(
                  `Import ${parsed.length} cookie${parsed.length === 1 ? "" : "s"} alongside the ${cookies.length} already in the jar? Same (domain, path, name) triples get overwritten.${errors.length > 0 ? ` (${errors.length} malformed line${errors.length === 1 ? "" : "s"} skipped.)` : ""}`,
                )
              ) {
                return;
              }
              setBusy(true);
              const results = await Promise.allSettled(
                parsed.map((c) => api.cookieJarSet(c)),
              );
              const failures = results.filter((r) => r.status === "rejected");
              await refresh();
              const okCount = parsed.length - failures.length;
              const parts: string[] = [
                `Imported ${okCount} / ${parsed.length}.`,
              ];
              if (failures.length > 0) {
                parts.push(
                  `${failures.length} rejected — first: ${(failures[0] as PromiseRejectedResult).reason}`,
                );
              }
              if (errors.length > 0) {
                parts.push(
                  `${errors.length} malformed line${errors.length === 1 ? "" : "s"} skipped.`,
                );
              }
              alert(parts.join(" "));
            } catch (err) {
              alert(`Import failed: ${err}`);
            } finally {
              setBusy(false);
            }
          }}
        />
        <button
          onClick={() => netscapeFileRef.current?.click()}
          disabled={busy}
          title="Import cookies from a Netscape cookies.txt file (curl --cookie-jar, wget --save-cookies, browser-extension exports). Entries with existing (domain, path, name) triples get overwritten; new ones get added. Round-trip counterpart to ⬇ Export (Netscape)."
        >
          ⬆ Import (Netscape)
        </button>
        <input
          ref={cookieFileRef}
          type="file"
          accept=".json,application/json"
          style={{ display: "none" }}
          onChange={async (e) => {
            const file = e.currentTarget.files?.[0];
            e.currentTarget.value = "";
            if (!file) return;
            if (file.size > 5 * 1024 * 1024) {
              alert(
                `File is ${(file.size / 1024 / 1024).toFixed(1)} MB — Cookie import caps at 5 MB.`,
              );
              return;
            }
            try {
              const text = await file.text();
              const parsed = JSON.parse(text);
              if (!Array.isArray(parsed)) {
                alert(
                  "Not a cookie export — expected a JSON array of Cookie objects.",
                );
                return;
              }
              // Lightly validate the first element so a mis-pick
              // (array of findings, array of history rows) bails
              // with a clear error rather than silently upserting
              // nothing. Empty-array imports are a no-op.
              if (parsed.length > 0) {
                const sample = parsed[0];
                if (
                  !sample ||
                  typeof sample !== "object" ||
                  typeof sample.name !== "string" ||
                  typeof sample.domain !== "string" ||
                  typeof sample.path !== "string"
                ) {
                  alert(
                    "Entries must have at least {name, domain, path} string fields.",
                  );
                  return;
                }
              }
              if (
                cookies.length > 0 &&
                !confirm(
                  `Import ${parsed.length} cookie${parsed.length === 1 ? "" : "s"} alongside the ${cookies.length} already in the jar? Same (domain, path, name) triples get overwritten.`,
                )
              ) {
                return;
              }
              setBusy(true);
              // Promise.allSettled so one bad cookie doesn't strand
              // the rest. The backend's cookieJarSet validates each
              // entry independently.
              const results = await Promise.allSettled(
                parsed.map((c: Cookie) => api.cookieJarSet(c)),
              );
              const failures = results.filter((r) => r.status === "rejected");
              await refresh();
              const okCount = parsed.length - failures.length;
              if (failures.length > 0) {
                alert(
                  `Imported ${okCount} / ${parsed.length}. ${failures.length} rejected — first error: ${(failures[0] as PromiseRejectedResult).reason}`,
                );
              } else {
                alert(`Imported ${okCount} cookie${okCount === 1 ? "" : "s"}.`);
              }
            } catch (err) {
              alert(`Import failed: ${err}`);
            } finally {
              setBusy(false);
            }
          }}
        />
        <button
          onClick={() => cookieFileRef.current?.click()}
          disabled={busy}
          title="Import cookies from a JSON file. Entries with existing (domain, path, name) triples get overwritten; new ones get added."
        >
          ⬆ Import
        </button>
        {/* ------------------------------------------------------- */}
        {/* R151: "Expire session" quick action. Deletes every       */}
        {/* cookie without an Expires/Max-Age (i.e. session cookies  */}
        {/* that would die when a real browser closes). Operators    */}
        {/* use this between test runs to simulate a browser         */}
        {/* restart — stale persistent cookies survive but          */}
        {/* ephemeral auth tokens get flushed. Burp Pro's Cookie Jar */}
        {/* lets you right-click "Delete session cookies" per host;  */}
        {/* this is the global jar-wide equivalent.                  */}
        <button
          className="danger"
          onClick={() => void expireSessionCookies()}
          disabled={busy || sessionCookieCount === 0}
          title={
            sessionCookieCount === 0
              ? "No session cookies to expire (every cookie has an Expires or Max-Age attribute)."
              : `Delete ${sessionCookieCount} session cookie${sessionCookieCount === 1 ? "" : "s"} (no Expires + no Max-Age). Persistent cookies stay.`
          }
        >
          ⌛ Expire session ({sessionCookieCount})
        </button>
        <button
          className="danger"
          onClick={() => void clearAll()}
          disabled={busy || cookies.length === 0}
          title="Wipe every cookie from the shared jar. HTTP history keeps its copies."
        >
          Clear all
        </button>
        <span className="badge">
          {totalBadge}
          {filteredBadge}
        </span>
      </div>

      {showAdd && (
        <AddCookieBar
          onCancel={() => setShowAdd(false)}
          onSaved={async () => {
            setShowAdd(false);
            await refresh();
          }}
        />
      )}

      <div style={{ overflow: "auto", flex: 1 }}>
        <table className="mono" style={{ width: "100%", fontSize: 11 }}>
          <colgroup>
            <col style={{ width: 180 }} />
            <col style={{ width: 100 }} />
            <col style={{ width: 150 }} />
            <col />
            <col style={{ width: 60 }} />
            <col style={{ width: 70 }} />
            <col style={{ width: 80 }} />
            <col style={{ width: 110 }} />
            <col style={{ width: 36 }} />
          </colgroup>
          <thead>
            <tr>
              <SortHeader label="Domain" k="domain" cur={sortKey} dir={sortDir} onClick={toggleSort} />
              <SortHeader label="Path" k="path" cur={sortKey} dir={sortDir} onClick={toggleSort} />
              <SortHeader label="Name" k="name" cur={sortKey} dir={sortDir} onClick={toggleSort} />
              <SortHeader label="Value" k="value" cur={sortKey} dir={sortDir} onClick={toggleSort} />
              <SortHeader label="Sec" k="secure" cur={sortKey} dir={sortDir} onClick={toggleSort} title="Secure flag: cookie only sent over HTTPS" />
              <SortHeader label="HttpOnly" k="http_only" cur={sortKey} dir={sortDir} onClick={toggleSort} title="HttpOnly flag: not accessible to document.cookie" />
              <SortHeader label="SameSite" k="same_site" cur={sortKey} dir={sortDir} onClick={toggleSort} />
              <SortHeader label="Expires" k="expires_at" cur={sortKey} dir={sortDir} onClick={toggleSort} />
              <th />
            </tr>
          </thead>
          <tbody>
            {sorted.map((c) => {
              const expired = c.expires_at != null && c.expires_at < Date.now();
              return (
                <tr
                  key={cookieKey(c)}
                  onContextMenu={(e) => {
                    e.preventDefault();
                    setMenu({ x: e.clientX, y: e.clientY, data: c });
                  }}
                  style={{ cursor: "context-menu", opacity: expired ? 0.5 : 1 }}
                  title={expired ? "This cookie has expired and would not be sent." : undefined}
                >
                  <td>{c.host_only ? c.domain : `.${c.domain}`}</td>
                  <td>{c.path}</td>
                  <td style={{ fontWeight: 600 }}>{c.name}</td>
                  <td
                    title={c.value}
                    style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 0 }}
                  >
                    {truncate(c.value, 120)}
                  </td>
                  <td style={{ textAlign: "center", color: c.secure ? "var(--green, #4caf50)" : "var(--text-faint)" }}>
                    {c.secure ? "✓" : ""}
                  </td>
                  <td style={{ textAlign: "center", color: c.http_only ? "var(--green, #4caf50)" : "var(--text-faint)" }}>
                    {c.http_only ? "✓" : ""}
                  </td>
                  <td style={{ color: c.same_site ? undefined : "var(--text-faint)" }}>
                    {c.same_site ?? "—"}
                  </td>
                  <td style={{ color: expired ? "var(--red, #e04444)" : "var(--text-dim)" }}>
                    {formatExpiry(c.expires_at)}
                  </td>
                  <td style={{ textAlign: "center" }}>
                    <button
                      className="ghost danger"
                      onClick={() => void deleteCookie(c)}
                      disabled={busy}
                      title={`Remove this cookie (${c.name} @ ${c.domain}${c.path})`}
                    >
                      ✕
                    </button>
                  </td>
                </tr>
              );
            })}
            {sorted.length === 0 && (
              <tr>
                <td
                  colSpan={9}
                  style={{ textAlign: "center", padding: 20, color: "var(--text-dim)" }}
                >
                  {cookies.length === 0
                    ? "No cookies in the jar yet. Browse through the proxy — Set-Cookie headers land here automatically."
                    : "No cookies match the filter."}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {menu && (
        <FloatingMenu
          state={menu}
          onClose={() => setMenu(null)}
          items={[
            {
              label: "Copy name=value",
              onClick: () => void copyPair(menu.data!),
              hint: "clipboard",
            },
            {
              label: "Copy as Set-Cookie",
              onClick: () => void copySetCookie(menu.data!),
              hint: "full attrs",
            },
            // R503: Targeted copy ops — operators often want just one
            // field without the =value prefix or the full Set-Cookie
            // envelope. Common pivots: paste the value into a JWT
            // decoder, paste the domain into a scope rule, paste
            // the whole record into a scratch note. Extends the
            // existing R125-era "copy name=value / copy Set-Cookie"
            // pair with targeted single-field + full-record options.
            { separator: true },
            {
              label: `Copy value only`,
              hint:
                menu.data!.value.length > 32
                  ? `${menu.data!.value.length} chars`
                  : menu.data!.value,
              onClick: () => void copyToClipboard(menu.data!.value),
            },
            {
              label: `Copy domain: ${menu.data!.domain}`,
              onClick: () => void copyToClipboard(menu.data!.domain),
            },
            {
              label: "Copy as JSON",
              hint: "clipboard · raw Cookie record",
              onClick: () =>
                void copyToClipboard(JSON.stringify(menu.data!, null, 2)),
            },
            { separator: true },
            {
              label: "Delete this cookie",
              onClick: () => void deleteCookie(menu.data!),
              danger: true,
            },
          ]}
        />
      )}
    </div>
  );
}

function SortHeader({
  label,
  k,
  cur,
  dir,
  onClick,
  title,
}: {
  label: string;
  k: SortKey;
  cur: SortKey;
  dir: "asc" | "desc";
  onClick: (k: SortKey) => void;
  title?: string;
}) {
  const active = cur === k;
  return (
    <th
      style={{ cursor: "pointer", userSelect: "none" }}
      onClick={() => onClick(k)}
      title={title ?? `Sort by ${label.toLowerCase()}`}
    >
      {label}
      {active && (
        <span style={{ color: "var(--accent)", marginLeft: 4 }}>
          {dir === "asc" ? "▲" : "▼"}
        </span>
      )}
    </th>
  );
}

/** Inline add-cookie bar. Collapsed by default; shown when the
 *  toolbar's `+ Add` is clicked. Minimal shape: name / value /
 *  domain / path + the four flags. Submit calls `cookieJarSet`. */
function AddCookieBar({
  onCancel,
  onSaved,
}: {
  onCancel: () => void;
  onSaved: () => Promise<void> | void;
}) {
  const [name, setName] = useState("");
  const [value, setValue] = useState("");
  const [domain, setDomain] = useState("");
  const [path, setPath] = useState("/");
  const [secure, setSecure] = useState(false);
  const [httpOnly, setHttpOnly] = useState(false);
  const [sameSite, setSameSite] = useState("");
  const [busy, setBusy] = useState(false);
  const nameRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    nameRef.current?.focus();
  }, []);

  async function submit() {
    if (!name.trim() || !domain.trim()) {
      alert("Name and domain are required.");
      return;
    }
    setBusy(true);
    try {
      await api.cookieJarSet({
        name: name.trim(),
        value,
        domain: domain.trim().replace(/^\./, ""),
        path: path.trim() || "/",
        secure,
        http_only: httpOnly,
        same_site: sameSite || null,
        expires_at: null,
        max_age: null,
        host_only: !domain.trim().startsWith("."),
      });
      await onSaved();
    } catch (e) {
      alert(`${e}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      style={{
        padding: "6px 10px",
        borderBottom: "1px solid var(--border)",
        background: "var(--bg-raised)",
        display: "flex",
        gap: 6,
        alignItems: "center",
        flexWrap: "wrap",
        fontSize: 11,
      }}
    >
      <input
        ref={nameRef}
        value={name}
        onChange={(e) => setName(e.target.value)}
        placeholder="name"
        style={{ width: 120 }}
      />
      <input
        value={value}
        onChange={(e) => setValue(e.target.value)}
        placeholder="value"
        style={{ width: 200 }}
      />
      <input
        value={domain}
        onChange={(e) => setDomain(e.target.value)}
        placeholder="domain (prefix . for scope)"
        style={{ width: 180 }}
      />
      <input
        value={path}
        onChange={(e) => setPath(e.target.value)}
        placeholder="/path"
        style={{ width: 100 }}
      />
      <label title="Only sent over HTTPS">
        <input type="checkbox" checked={secure} onChange={(e) => setSecure(e.target.checked)} /> Secure
      </label>
      <label title="Not accessible to document.cookie">
        <input type="checkbox" checked={httpOnly} onChange={(e) => setHttpOnly(e.target.checked)} /> HttpOnly
      </label>
      <select
        value={sameSite}
        onChange={(e) => setSameSite(e.target.value)}
        title="SameSite attribute"
      >
        <option value="">SameSite: —</option>
        <option value="Strict">Strict</option>
        <option value="Lax">Lax</option>
        <option value="None">None</option>
      </select>
      <span className="spacer" style={{ flex: 1 }} />
      <button className="primary" onClick={() => void submit()} disabled={busy}>
        Add
      </button>
      <button onClick={onCancel} disabled={busy}>
        Cancel
      </button>
    </div>
  );
}
