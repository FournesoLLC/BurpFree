// BChecksPanel.tsx
//
// Top-level BChecks tab — the UI counterpart to the backend's
// bchecks_list + bchecks_run commands. Mirrors Burp's BChecks
// panel: operators drop YAML files into `project/bchecks/`, see
// them listed with parse status, click Run All to fire every valid
// rule against the hosts observed in HTTP history.
//
// The engine side (burpfree-engines::bchecks) has been shipped
// since early rounds; R74 is purely about surfacing it. Every
// generated finding lands in the same findings table the Scanner
// / Target panels read, so the operator sees them in the standard
// issue flow after a run.

import { useEffect, useMemo, useRef, useState } from "react";
import { api, BCheckLoadRow, BCheckRunReport, BCheckValidateResult } from "../api";
import { FloatingMenu, MenuState } from "../FloatingMenu";
import { copyToClipboard } from "../copyAs";

/** Pastel + bold palette for the severity badges — matches the
 *  Scanner issue list treatment so Low / Medium / High / Critical
 *  read consistently across panels. */
const SEVERITY_COLORS: Record<string, { bg: string; fg: string }> = {
  critical: { bg: "rgba(224, 68, 68, 0.22)", fg: "#ff5c5c" },
  high:     { bg: "rgba(240, 140, 60, 0.22)", fg: "#f09040" },
  medium:   { bg: "rgba(240, 210, 60, 0.22)", fg: "#f0c030" },
  low:      { bg: "rgba(100, 170, 220, 0.22)", fg: "#5fa0dc" },
  info:     { bg: "rgba(140, 140, 150, 0.22)", fg: "#9898a0" },
};

export function BChecksPanel() {
  const [rows, setRows] = useState<BCheckLoadRow[]>([]);
  // R487: Right-click menu state for a BCheck rule row — carries the
  // full BCheckLoadRow so menu handlers can reach every field
  // (path / name / severity / ok / candidates / error) without extra
  // plumbing. First row-right-click surface on BChecks — previously
  // the panel was mouse-left + Ctrl+Enter only.
  const [ruleMenu, setRuleMenu] = useState<MenuState<BCheckLoadRow> | null>(
    null,
  );
  const [loaded, setLoaded] = useState(false);
  const [running, setRunning] = useState(false);
  const [lastReport, setLastReport] = useState<BCheckRunReport | null>(null);
  const [runError, setRunError] = useState<string | null>(null);
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  // Live YAML validator composer — R103. Paste YAML into the
  // textarea; a debounced bchecks_validate call parses it and
  // returns the metadata (success) or the parse error (failure).
  // The composer is collapsible so idle operators don't lose the
  // vertical real estate.
  const [composerOpen, setComposerOpen] = useState(false);
  const [composerYaml, setComposerYaml] = useState("");
  const [validateResult, setValidateResult] =
    useState<BCheckValidateResult | null>(null);
  const [validating, setValidating] = useState(false);
  const validateTimer = useRef<number | null>(null);
  const [savingComposer, setSavingComposer] = useState(false);
  const [composerSaveNotice, setComposerSaveNotice] = useState<string | null>(null);
  const [deletingRule, setDeletingRule] = useState(false);
  const [editingRule, setEditingRule] = useState(false);

  // Load a BCheck file's YAML into the R103 composer so the operator
  // can tweak + re-save via R104. Opens the composer if closed +
  // scrolls the panel to the top so the newly-populated textarea is
  // visible. Pre-filling the name in composerYaml fires the debounced
  // validate useEffect automatically — the parse-result pane updates
  // without needing a manual tap.
  async function editSelectedRule() {
    if (!selectedPath) return;
    const basename = selectedPath.replace(/\\/g, "/").split("/").pop() ?? selectedPath;
    setEditingRule(true);
    try {
      const yaml = await api.bchecksRead(basename);
      setComposerYaml(yaml);
      setComposerOpen(true);
      setComposerSaveNotice(null);
      // Scroll the composer into view; the top of the panel holds
      // the toolbar, so a window-level scroll to top also works.
      requestAnimationFrame(() => {
        const el = document.querySelector(".panel textarea") as HTMLElement | null;
        el?.scrollIntoView({ block: "nearest", behavior: "smooth" });
      });
    } catch (e) {
      alert(`Could not read ${basename}: ${e}`);
    } finally {
      setEditingRule(false);
    }
  }

  // Delete the currently-selected BCheck file from the project.
  // Mirrors R104's save flow: validates filename via the shared
  // basename extraction, confirms, fires bchecks_delete, refreshes.
  async function deleteSelectedRule() {
    if (!selectedPath) return;
    // Extract bare basename for the filename arg + the confirm prompt.
    const basename = selectedPath.replace(/\\/g, "/").split("/").pop() ?? selectedPath;
    if (
      !confirm(
        `Delete BCheck file "${basename}"?\n\nThe file will be removed from project/bchecks/. Runs after this won't dispatch it. Cannot be undone.`,
      )
    )
      return;
    setDeletingRule(true);
    try {
      const existed = await api.bchecksDelete(basename);
      if (!existed) {
        // Stale selection — the file was already gone. Fall through
        // to refresh so the row disappears from the list.
      }
      setSelectedPath(null);
      await refresh();
    } catch (e) {
      alert(`Delete failed: ${e}`);
    } finally {
      setDeletingRule(false);
    }
  }

  // Save the composer YAML to project/bchecks/<filename>. The
  // backend re-validates before touching disk; the composer's live
  // check is UI-only. On "file exists" error we re-prompt for a
  // confirm + resend with overwrite=true. Refreshes the panel list
  // on success so the new file shows up immediately.
  async function saveComposerYaml() {
    if (!validateResult?.ok) return;
    // Derive a sensible default filename from the parsed name
    // (lowercase, hyphenate whitespace, strip non-filename chars).
    const defaultBase = (validateResult.name ?? "custom-bcheck")
      .toLowerCase()
      .replace(/\s+/g, "-")
      .replace(/[^a-z0-9\-_]/g, "");
    const defaultName = `${defaultBase || "custom-bcheck"}.yaml`;
    const fname = prompt(
      "Save BCheck to project/bchecks/<filename>:\n\nMust end .yaml or .yml. No path separators.",
      defaultName,
    );
    if (!fname) return;
    const trimmed = fname.trim();
    if (!trimmed) return;
    setSavingComposer(true);
    setComposerSaveNotice(null);
    try {
      let written: string;
      try {
        written = await api.bchecksSave(trimmed, composerYaml, false);
      } catch (e) {
        const msg = `${e}`;
        if (msg.includes("already exists")) {
          if (!confirm(`${msg}\n\nOverwrite?`)) return;
          written = await api.bchecksSave(trimmed, composerYaml, true);
        } else {
          throw e;
        }
      }
      setComposerSaveNotice(`Wrote ${written}`);
      await refresh();
    } catch (e) {
      alert(`Save failed: ${e}`);
    } finally {
      setSavingComposer(false);
    }
  }

  async function refresh() {
    try {
      const list = await api.bchecksList();
      setRows(list ?? []);
      setLoaded(true);
    } catch (e) {
      setRows([]);
      setLoaded(true);
      setRunError(`Could not list BChecks: ${e}`);
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  // Debounced live validation. Fires 400 ms after the operator
  // stops typing — avoids re-parsing on every keystroke while
  // staying snappy on paste. Empty YAML clears the result.
  useEffect(() => {
    if (!composerOpen) return;
    if (validateTimer.current) {
      window.clearTimeout(validateTimer.current);
      validateTimer.current = null;
    }
    const trimmed = composerYaml.trim();
    if (trimmed.length === 0) {
      setValidateResult(null);
      setValidating(false);
      return;
    }
    setValidating(true);
    validateTimer.current = window.setTimeout(() => {
      void api
        .bchecksValidate(composerYaml)
        .then((r) => setValidateResult(r))
        .catch((e) =>
          setValidateResult({
            ok: false,
            error: `${e}`,
            name: null,
            description: null,
            author: null,
            version: null,
            severity: null,
            tags: [],
            candidates: 0,
          }),
        )
        .finally(() => setValidating(false));
    }, 400);
    return () => {
      if (validateTimer.current) {
        window.clearTimeout(validateTimer.current);
        validateTimer.current = null;
      }
    };
  }, [composerYaml, composerOpen]);

  async function runAll() {
    if (running) return;
    setRunning(true);
    setRunError(null);
    try {
      const report = await api.bchecksRun();
      setLastReport(report);
      // Re-list so the error row count / metadata reflects any
      // YAML changes the operator made between runs.
      await refresh();
    } catch (e) {
      setRunError(`${e}`);
    } finally {
      setRunning(false);
    }
  }

  const okCount = rows.filter((r) => r.ok).length;
  const errCount = rows.length - okCount;
  const selected = rows.find((r) => r.path === selectedPath) ?? null;
  // R282: BChecks substring search — case-insensitive match against
  // the rule's parsed `name` (when ok) + the file basename (when
  // parse failed and name is null, the operator can still find the
  // file by its disk name). Esc clears per the Esc-clear-search
  // family (R201 / R219 / R223 / R224 / R227 / R260 / R281). Not
  // persisted — scratch filter.
  const [rulesSearch, setRulesSearch] = useState("");
  const filteredRows = useMemo(() => {
    const q = rulesSearch.trim().toLowerCase();
    if (!q) return rows;
    return rows.filter((r) => {
      const name = (r.name ?? "").toLowerCase();
      const basename = r.path
        .replace(/\\/g, "/")
        .split("/")
        .pop()
        ?.toLowerCase() ?? "";
      return name.includes(q) || basename.includes(q);
    });
  }, [rows, rulesSearch]);

  // R272: J / K vim-style row cursor plus ArrowUp/Down/Home/End —
  // seventh J/K panel after Scanner (R197), History (R208),
  // Organizer (R212), Target Issues (R222), Logger (R258), and
  // Collaborator (R266). BChecks is single-select (clicking a row
  // sets `selectedPath`), so the cursor is defined as the current
  // selectedPath; from "nothing selected" J / ↓ lands on the first
  // row and K / ↑ on the last — matches the Logger / Collaborator
  // pattern. The move replaces the selection with the new row's
  // path and scrolls into view via a `data-row-path` lookup.
  // Guards against modifiers + typing in inputs so the composer
  // textarea and the validator timer stay unaffected.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.altKey || e.ctrlKey || e.metaKey) return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      const key = e.key;
      const isJ = key === "j" || key === "J";
      const isK = key === "k" || key === "K";
      if (
        key !== "ArrowUp" &&
        key !== "ArrowDown" &&
        key !== "Home" &&
        key !== "End" &&
        !isJ &&
        !isK
      )
        return;
      // R282: J/K walks the filtered row set so operators tabbing
      // through a search-narrowed list only visit matching rules.
      if (filteredRows.length === 0) return;
      const curIdx = selectedPath
        ? filteredRows.findIndex((r) => r.path === selectedPath)
        : -1;
      let nextIdx = curIdx;
      if (key === "ArrowUp" || isK) {
        nextIdx =
          curIdx < 0 ? filteredRows.length - 1 : Math.max(0, curIdx - 1);
      } else if (key === "ArrowDown" || isJ) {
        nextIdx = curIdx < 0 ? 0 : Math.min(filteredRows.length - 1, curIdx + 1);
      } else if (key === "Home") {
        nextIdx = 0;
      } else if (key === "End") {
        nextIdx = filteredRows.length - 1;
      }
      if (nextIdx === curIdx || nextIdx < 0) return;
      e.preventDefault();
      const next = filteredRows[nextIdx];
      setSelectedPath(next.path);
      requestAnimationFrame(() => {
        // CSS.escape protects path separators + spaces in the
        // selector string — basename-only lookups would collide
        // when two files share a basename across subdirectories.
        const tr = document.querySelector(
          `tr[data-row-path="${CSS.escape(next.path)}"]`,
        ) as HTMLElement | null;
        tr?.scrollIntoView({ block: "nearest" });
      });
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [filteredRows, selectedPath]);

  // R441: Alt+C clears the rules search filter — joins the
  // cross-panel Alt+C clear-filter family (R349 History / R392
  // Decoder / R409 Collaborator / R410 Logger / R412 Target
  // Issues / R436 Cookie jar / R441 BChecks — 7 panels now
  // share the same muscle memory). BChecks' filter is a simple
  // text box; a one-key reset is useful when operators pivot
  // between rule categories (SSRF rules → XSS rules → auth
  // rules) during a scope-pass. **Letter choice** C = Clear.
  // **Guards** plain Alt only, text-input focus skip. **No-op
  // silent** when filter is empty.
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
      if (rulesSearch.length === 0) return;
      e.preventDefault();
      setRulesSearch("");
    }
    document.addEventListener("keydown", onClearKey);
    return () => document.removeEventListener("keydown", onClearKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rulesSearch]);

  // R448: Alt+Shift+C drops the last run's artifacts — `lastReport`
  // (the per-rule hits + timing table), `runError` (the failed-run
  // banner, if any), and `selectedPath` (the rule-detail selection
  // bound to the right pane). Mirror of R446 Logger / R447
  // Collaborator / R418 Intruder / R435 Sequencer — Alt+Shift+C
  // clear-results family now spans five panels. Separation from the
  // R441 Alt+C above stays the same: Alt+C clears the rules-search
  // filter (lightweight state reset), Alt+Shift+C wipes the run
  // output (so the next run starts from a clean right-pane).
  // **No backend call** — findings are already persisted on-disk by
  // the Scanner's finding store at run time, so this only drops the
  // local scratch view, not the project's stored issues. Operators
  // who ran BChecks against the current scope + want to re-pass a
  // modified ruleset without the stale per-rule hit counts
  // confusing the comparison are the primary audience. **Guards**
  // plain Alt+Shift only (rejects Ctrl/Meta), text-input focus
  // skip, and a short-circuit when there is nothing to clear
  // (`!lastReport && !runError && !selectedPath`) so a stray
  // keystroke on a fresh panel is a no-op.
  useEffect(() => {
    function onClearResultsKey(e: KeyboardEvent) {
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
      if (!lastReport && !runError && !selectedPath) return;
      e.preventDefault();
      setLastReport(null);
      setRunError(null);
      setSelectedPath(null);
    }
    document.addEventListener("keydown", onClearResultsKey);
    return () => document.removeEventListener("keydown", onClearResultsKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lastReport, runError, selectedPath]);

  // R460: Alt+Shift+E saves the last run's report to a JSON file —
  // extends the Alt+Shift+E save-visible-artifact keyboard family
  // (R456 Scanner evidence / R457 Target Issues evidence) to a
  // third panel (R460 BChecks run report). The `lastReport`
  // (BCheckRunReport) carries the full run summary: rules_ok /
  // rules_loaded / targets / findings / elapsed_ms / load_errors.
  // Operators archiving an engagement's BCheck pass or attaching
  // the run metadata to a ticket want this JSON blob on disk
  // rather than a clipboard paste (clipboard-size caps aside,
  // JSON needs tooling — jq / grep — that works better on files).
  // **Letter choice** E = Evidence; matches R456/R457 so the
  // save-visible-artifact family stays mnemonic. **Filename
  // pattern** `bchecks-report-<timestamp>.json` — timestamp
  // disambiguates multiple saves of the same run (operators
  // typically re-save after re-running), ISO-8601 with Z suffix.
  // **Content** `JSON.stringify(lastReport, null, 2)` so the
  // output is diff-friendly + pipable to jq. **Scope** `lastReport`
  // only — if no run has completed, nothing to save. **Guards**
  // `lastReport != null` short-circuit, Alt+Shift only (no
  // Ctrl/Meta), text-input focus skip. **No-op silent** when no
  // run has completed yet.
  useEffect(() => {
    function onSaveReportKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key !== "E" && e.key !== "e") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (!lastReport) return;
      e.preventDefault();
      const stamp = new Date()
        .toISOString()
        .replace(/[:T]/g, "-")
        .replace(/\..*$/, "");
      const name = `bchecks-report-${stamp}.json`;
      try {
        const body = JSON.stringify(lastReport, null, 2);
        const blob = new Blob([body], {
          type: "application/json;charset=utf-8",
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = name;
        a.click();
        URL.revokeObjectURL(url);
      } catch (err) {
        alert(`${err}`);
      }
    }
    document.addEventListener("keydown", onSaveReportKey);
    return () => document.removeEventListener("keydown", onSaveReportKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lastReport]);

  // R397: Ctrl+Enter fires "Run all BChecks" — keyboard version
  // of the primary toolbar button. Mirrors R331's Intruder
  // Ctrl+Enter attack-toggle pattern. Operators iterating on a
  // BCheck YAML (edit → save → reload → re-run) need a one-key
  // re-run that doesn't drag the mouse to the toolbar after
  // every YAML tweak. **Semantics** fires only when `okCount > 0`
  // and not currently running — matches the toolbar button's
  // disabled gate exactly. **Mechanism** delegates to `runAll()`
  // so target-tuple selection + progress updates + findings
  // routing all stay identical. **Guards** Ctrl/Meta required
  // (no plain Enter so operators pressing Enter in the composer
  // textarea stay unaffected), no Alt/Shift (Alt+Enter stays
  // available for future "run selected" shortcuts), text-input
  // focus skip. **No-op** silent when nothing to run or already
  // running — keystroke stays safe to spam during iteration.
  useEffect(() => {
    function onRunKey(e: KeyboardEvent) {
      if (!(e.ctrlKey || e.metaKey)) return;
      if (e.altKey || e.shiftKey) return;
      if (e.key !== "Enter") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (running || okCount === 0) return;
      e.preventDefault();
      void runAll();
    }
    document.addEventListener("keydown", onRunKey);
    return () => document.removeEventListener("keydown", onRunKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [running, okCount]);

  return (
    <div className="panel">
      <div className="toolbar">
        <strong style={{ fontSize: 13 }}>BChecks</strong>
        <span className="dim" style={{ fontSize: 11 }}>
          Declarative active-scan rules. Drop YAML files into{" "}
          <code>project/bchecks/</code>.
        </span>
        <span className="spacer" style={{ flex: 1 }} />
        {rows.length > 0 && (
          <input
            type="text"
            value={rulesSearch}
            onChange={(e) => setRulesSearch(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Escape" && rulesSearch) {
                e.preventDefault();
                e.stopPropagation();
                setRulesSearch("");
              }
            }}
            placeholder="Filter rules…"
            title="Case-insensitive substring match on rule name + file basename. Esc clears."
            style={{
              fontSize: 11,
              padding: "2px 6px",
              width: 160,
              background: "var(--bg)",
              border: "1px solid var(--border)",
              borderRadius: 3,
              color: "var(--text)",
            }}
          />
        )}
        <span className="badge">
          {rulesSearch.trim()
            ? `${filteredRows.length} / ${rows.length} shown`
            : `${okCount} valid`}
        </span>
        {errCount > 0 && (
          <span
            className="badge"
            style={{
              background: "rgba(224, 68, 68, 0.18)",
              color: "#ff6060",
              borderColor: "rgba(224, 68, 68, 0.4)",
            }}
            title={`${errCount} YAML file${errCount === 1 ? "" : "s"} failed to parse — see the Issues column for details`}
          >
            {errCount} broken
          </span>
        )}
        {/* R268: Last-run findings count badge in the toolbar.    */}
        {/* The full Last-run strip below the toolbar carries the  */}
        {/* complete telemetry (rules_ok / targets / elapsed_ms /  */}
        {/* load_errors), but a compact badge next to the parse-   */}
        {/* status badges gives operators a glance-value "did my   */}
        {/* last run find anything?" without having to parse the   */}
        {/* strip. Tint-promotes to accent + bold when findings>0  */}
        {/* so a non-zero result pops visually; dim when 0 so a    */}
        {/* no-finding run doesn't shout. Only renders after at    */}
        {/* least one run has completed (lastReport != null).      */}
        {lastReport && (
          <span
            className="badge"
            style={
              lastReport.findings > 0
                ? {
                    background: "rgba(90, 160, 220, 0.18)",
                    color: "var(--accent)",
                    borderColor: "rgba(90, 160, 220, 0.4)",
                    fontWeight: 600,
                  }
                : undefined
            }
            title={
              lastReport.findings > 0
                ? `Last run added ${lastReport.findings} finding${lastReport.findings === 1 ? "" : "s"} across ${lastReport.targets} target${lastReport.targets === 1 ? "" : "s"} in ${lastReport.elapsed_ms} ms`
                : `Last run completed cleanly (${lastReport.rules_ok}/${lastReport.rules_loaded} rules × ${lastReport.targets} target${lastReport.targets === 1 ? "" : "s"}, ${lastReport.elapsed_ms} ms) — no new findings. See Scanner for existing issues this run upserted.`
            }
          >
            last run: {lastReport.findings} finding{lastReport.findings === 1 ? "" : "s"}
          </span>
        )}
        <button onClick={() => void refresh()} title="Re-read every YAML in the bchecks directory">
          Refresh
        </button>
        <button
          onClick={() => setComposerOpen((v) => !v)}
          title={
            composerOpen
              ? "Hide the YAML composer"
              : "Open a composer with live parse feedback — paste YAML to validate before saving to project/bchecks/"
          }
        >
          {composerOpen ? "▴ Hide composer" : "▾ Validate YAML…"}
        </button>
        <button
          className={running || okCount === 0 ? "" : "primary"}
          onClick={() => void runAll()}
          disabled={running || okCount === 0}
          title={
            okCount === 0
              ? "No valid BChecks to run — add YAML files or fix parse errors"
              : "Run every valid BCheck against the (scheme, host, port) tuples observed in HTTP history. Generated findings land in Scanner / Target."
          }
        >
          {running ? "Running…" : "Run all BChecks"}
        </button>
        {/* R315: Export rules list as JSONL — tenth entry in the  */}
        {/* JSONL family (R193 Collab interactions, R284 Logger,   */}
        {/* R285 History bulk, R286 Intruder, R288 Scanner bulk,   */}
        {/* R311 Target Issues, R313 Organizer, R314 Collab        */}
        {/* tokens, R315 BChecks rules). Scope respects the R282   */}
        {/* search filter — operators audit-exporting a specific    */}
        {/* subset of their BChecks catalog get just the matches.  */}
        {/* **Why operators want this** sharing a BChecks folder    */}
        {/* across teammates / machines: parse-status (ok / err)    */}
        {/* + severity assignment + candidate count per rule is a   */}
        {/* repo-health snapshot that lives alongside the YAMLs    */}
        {/* in CI pipelines — jq .ok burpfree-bchecks-*.jsonl       */}
        {/* lists the broken rules. **Streaming-friendly** no      */}
        {/* top-level array wrapper. **No column loss** `JSON       */}
        {/* .stringify(r)` over the BCheckLoadRow preserves the    */}
        {/* nested error field so CI diffs see parse-error churn.  */}
        <button
          disabled={filteredRows.length === 0}
          onClick={() => {
            try {
              const body = filteredRows.map((r) => JSON.stringify(r)).join("\n");
              const blob = new Blob([body + "\n"], {
                type: "application/x-ndjson;charset=utf-8",
              });
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a");
              const stamp = new Date()
                .toISOString()
                .replace(/[:T]/g, "-")
                .replace(/\..*$/, "");
              a.href = url;
              a.download = `burpfree-bchecks-${stamp}.jsonl`;
              document.body.appendChild(a);
              a.click();
              a.remove();
              URL.revokeObjectURL(url);
            } catch (err) {
              alert(`${err}`);
            }
          }}
          title={
            filteredRows.length === 0
              ? "No rules to export"
              : `Export ${filteredRows.length} rule${filteredRows.length === 1 ? "" : "s"} as JSONL (one JSON object per line${filteredRows.length !== rows.length ? ` — respects the current search filter` : ""}). Preserves parse status (ok / error), severity assignment, candidate count — great for CI / repo-health audits.`
          }
          style={{ marginLeft: 2 }}
        >
          ⬇ Export JSONL
        </button>
      </div>

      {composerOpen && (
        <div
          style={{
            display: "flex",
            gap: 10,
            padding: "8px 10px",
            borderBottom: "1px solid var(--border)",
            background: "var(--bg-raised)",
            minHeight: 180,
            maxHeight: 320,
          }}
        >
          <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 4 }}>
            <label
              className="dim"
              style={{ fontSize: 10.5, textTransform: "uppercase", letterSpacing: 0.4 }}
            >
              YAML composer
            </label>
            <textarea
              value={composerYaml}
              onChange={(e) => setComposerYaml(e.target.value)}
              placeholder={`metadata:\n  name: "Example BCheck"\n  description: "What this detects"\ncandidates:\n  - "/"\nmatch:\n  status: [200]\n  body_contains: [""]\nreport:\n  title: "Example"\n  severity: info\n  detail: "Describe the finding"\n`}
              spellCheck={false}
              style={{
                flex: 1,
                fontFamily: "var(--mono)",
                fontSize: 11.5,
                lineHeight: 1.4,
                padding: 6,
                background: "var(--bg)",
                color: "var(--text)",
                border: "1px solid var(--border)",
                borderRadius: 3,
                resize: "none",
              }}
            />
          </div>
          <div style={{ width: 320, display: "flex", flexDirection: "column", gap: 4 }}>
            <label
              className="dim"
              style={{ fontSize: 10.5, textTransform: "uppercase", letterSpacing: 0.4 }}
            >
              Parse result
              {validating && <span className="dim" style={{ marginLeft: 6 }}>validating…</span>}
            </label>
            <div
              style={{
                flex: 1,
                overflow: "auto",
                padding: 8,
                background: "var(--bg)",
                border: `1px solid ${
                  !validateResult
                    ? "var(--border)"
                    : validateResult.ok
                      ? "rgba(63, 180, 100, 0.55)"
                      : "rgba(224, 68, 68, 0.55)"
                }`,
                borderRadius: 3,
                fontSize: 11.5,
              }}
            >
              {!validateResult && composerYaml.trim().length === 0 && (
                <div className="dim" style={{ fontStyle: "italic" }}>
                  Paste YAML on the left — this pane updates on each pause.
                </div>
              )}
              {validateResult && validateResult.ok && (
                <>
                  <div
                    style={{
                      color: "#3fb464",
                      fontWeight: 600,
                      marginBottom: 6,
                    }}
                  >
                    ✓ Valid BCheck
                  </div>
                  {validateResult.name && (
                    <div style={{ marginBottom: 4 }}>
                      <strong>Name:</strong> {validateResult.name}
                    </div>
                  )}
                  {validateResult.description && (
                    <div style={{ marginBottom: 4 }} className="dim">
                      {validateResult.description}
                    </div>
                  )}
                  {validateResult.severity && (
                    <div style={{ marginBottom: 4 }}>
                      <strong>Severity:</strong>{" "}
                      <span
                        style={{
                          padding: "1px 6px",
                          borderRadius: 3,
                          fontSize: 10.5,
                          fontWeight: 600,
                          background:
                            SEVERITY_COLORS[validateResult.severity]?.bg ??
                            SEVERITY_COLORS.info.bg,
                          color:
                            SEVERITY_COLORS[validateResult.severity]?.fg ??
                            SEVERITY_COLORS.info.fg,
                        }}
                      >
                        {validateResult.severity}
                      </span>
                    </div>
                  )}
                  <div style={{ marginBottom: 4 }}>
                    <strong>Candidates:</strong>{" "}
                    <span
                      className="mono"
                      style={{
                        color:
                          validateResult.candidates === 0
                            ? "#f0c030"
                            : "var(--text)",
                      }}
                      title={
                        validateResult.candidates === 0
                          ? "Zero candidates means the runner has no paths to probe — add at least one entry under candidates:"
                          : undefined
                      }
                    >
                      {validateResult.candidates}
                      {validateResult.candidates === 0 && " (runner will skip)"}
                    </span>
                  </div>
                  {validateResult.author && (
                    <div className="dim" style={{ marginBottom: 2 }}>
                      Author: {validateResult.author}
                    </div>
                  )}
                  {validateResult.version && (
                    <div className="dim" style={{ marginBottom: 2 }}>
                      Version: {validateResult.version}
                    </div>
                  )}
                  {validateResult.tags.length > 0 && (
                    <div style={{ marginTop: 6, display: "flex", flexWrap: "wrap", gap: 3 }}>
                      {validateResult.tags.map((t) => (
                        <span
                          key={t}
                          className="mono"
                          style={{
                            fontSize: 10,
                            padding: "0 5px",
                            borderRadius: 8,
                            background: "var(--bg-elev)",
                            color: "var(--text-dim)",
                            border: "1px solid var(--border)",
                          }}
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  )}
                  <div style={{ marginTop: 10, display: "flex", gap: 6 }}>
                    <button
                      className="primary"
                      disabled={savingComposer}
                      onClick={() => void saveComposerYaml()}
                      title="Save this YAML to project/bchecks/<filename> so the Run All path picks it up"
                      style={{ fontSize: 11 }}
                    >
                      {savingComposer ? "Saving…" : "💾 Save to project…"}
                    </button>
                  </div>
                  {composerSaveNotice && (
                    <div
                      className="dim"
                      style={{
                        marginTop: 6,
                        fontSize: 10.5,
                        padding: 4,
                        background: "rgba(63, 180, 100, 0.08)",
                        border: "1px solid rgba(63, 180, 100, 0.35)",
                        borderRadius: 3,
                        wordBreak: "break-all",
                      }}
                      title="Click Refresh on the toolbar to pick up the new row"
                    >
                      → {composerSaveNotice}
                    </div>
                  )}
                </>
              )}
              {validateResult && !validateResult.ok && (
                <>
                  <div
                    style={{
                      color: "#ff6060",
                      fontWeight: 600,
                      marginBottom: 6,
                    }}
                  >
                    ✗ Parse error
                  </div>
                  <pre
                    className="mono"
                    style={{
                      margin: 0,
                      fontSize: 10.5,
                      color: "#ff8080",
                      whiteSpace: "pre-wrap",
                      wordBreak: "break-word",
                    }}
                  >
                    {validateResult.error}
                  </pre>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {runError && (
        <div
          style={{
            padding: "6px 10px",
            background: "rgba(224, 68, 68, 0.12)",
            borderBottom: "1px solid rgba(224, 68, 68, 0.4)",
            color: "#ff6060",
            fontSize: 12,
          }}
        >
          {runError}
        </div>
      )}

      {lastReport && (
        <div
          style={{
            padding: "6px 10px",
            background: "var(--bg-raised)",
            borderBottom: "1px solid var(--border)",
            fontSize: 12,
            display: "flex",
            gap: 14,
            flexWrap: "wrap",
          }}
        >
          <span>
            <strong>Last run:</strong> {lastReport.rules_ok}/{lastReport.rules_loaded}{" "}
            rule{lastReport.rules_loaded === 1 ? "" : "s"}
          </span>
          <span>
            against <strong>{lastReport.targets}</strong>{" "}
            target{lastReport.targets === 1 ? "" : "s"}
          </span>
          <span
            style={{
              color: lastReport.findings > 0 ? "var(--accent)" : "var(--text-dim)",
              fontWeight: lastReport.findings > 0 ? 600 : 400,
            }}
          >
            → <strong>{lastReport.findings}</strong>{" "}
            finding{lastReport.findings === 1 ? "" : "s"} added
          </span>
          <span className="dim">· {lastReport.elapsed_ms} ms</span>
          {lastReport.load_errors.length > 0 && (
            <span
              style={{ color: "#ff6060" }}
              title={lastReport.load_errors.join("\n")}
            >
              · {lastReport.load_errors.length} load error
              {lastReport.load_errors.length === 1 ? "" : "s"}
            </span>
          )}
          {/* R462: Visible mirror of R460's Alt+Shift+E keyboard —    */}
          {/* mouse-first operators get a one-click save of the        */}
          {/* lastReport without hunting for the keyboard shortcut.    */}
          {/* Mirrors R460's save flow byte-for-byte so keyboard-and-  */}
          {/* mouse paths produce identical files (filename pattern    */}
          {/* `bchecks-report-<timestamp>.json`, pretty-printed JSON). */}
          {/* Lives at the end of the Last-run strip so operators     */}
          {/* seeing the summary stats are one click away from the    */}
          {/* on-disk artifact. Ghost styling to match the strip's    */}
          {/* compact feel + 10.5px font so it doesn't dominate.      */}
          <span className="spacer" style={{ flex: 1 }} />
          <button
            className="ghost"
            onClick={() => {
              const stamp = new Date()
                .toISOString()
                .replace(/[:T]/g, "-")
                .replace(/\..*$/, "");
              const name = `bchecks-report-${stamp}.json`;
              try {
                const body = JSON.stringify(lastReport, null, 2);
                const blob = new Blob([body], {
                  type: "application/json;charset=utf-8",
                });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = name;
                a.click();
                URL.revokeObjectURL(url);
              } catch (err) {
                alert(`${err}`);
              }
            }}
            title={`Save the last BChecks run report (rules_ok=${lastReport.rules_ok}, rules_loaded=${lastReport.rules_loaded}, targets=${lastReport.targets}, findings=${lastReport.findings}, elapsed=${lastReport.elapsed_ms}ms, load_errors=${lastReport.load_errors.length}) to a diff-friendly JSON file for engagement archives / ticket attachments / jq pipelines. Keyboard shortcut: Alt+Shift+E (R460).`}
            style={{ fontSize: 10.5, padding: "1px 6px" }}
          >
            ⬇ Save report
          </button>
        </div>
      )}

      <div style={{ display: "flex", flex: 1, minHeight: 0 }}>
        <div style={{ flex: 1, minWidth: 0, overflow: "auto" }}>
          {!loaded ? (
            <div className="empty">Loading…</div>
          ) : rows.length === 0 ? (
            <div
              className="dim"
              style={{
                padding: 20,
                margin: 10,
                textAlign: "center",
                border: "1px dashed var(--border)",
                borderRadius: 4,
              }}
            >
              <div style={{ fontSize: 13, marginBottom: 4 }}>
                No BChecks yet
              </div>
              <div style={{ fontSize: 11 }}>
                Add YAML files to <code>project/bchecks/</code> and click Refresh.
                The repo includes two example rules you can copy:{" "}
                <code>admin-exposure.yaml</code> and{" "}
                <code>verbose-error-paths.yaml</code>.
              </div>
            </div>
          ) : (
            <table className="mono" style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr>
                  <th style={{ width: 28, textAlign: "center" }}>·</th>
                  <th style={{ textAlign: "left" }}>File</th>
                  <th style={{ textAlign: "left" }}>Name</th>
                  <th style={{ textAlign: "left", width: 90 }}>Severity</th>
                  <th style={{ textAlign: "right", width: 90 }}>Candidates</th>
                  <th style={{ textAlign: "left" }}>Issues</th>
                </tr>
              </thead>
              <tbody>
                {filteredRows.map((r) => {
                  const sev = r.severity ?? "info";
                  const sevColors = SEVERITY_COLORS[sev] ?? SEVERITY_COLORS.info;
                  const basename = r.path
                    .replace(/\\/g, "/")
                    .split("/")
                    .pop();
                  const isSelected = r.path === selectedPath;
                  // R300: Parse-status row tint — sixth entry in
                  // the row-tint family (R294/R295 status, R297
                  // Logger kind, R298/R299 sev). BChecks axis is
                  // parse status: broken rules tint red so parse
                  // errors stand out even when the YAML composer
                  // is collapsed; ok rules stay default so the
                  // happy path doesn't shout. Selected row still
                  // gets the `.selected` className treatment, so
                  // the operator always sees which row the right-
                  // pane detail is bound to.
                  const brokenBg = !r.ok ? "rgba(224, 68, 68, 0.08)" : undefined;
                  return (
                    <tr
                      key={r.path}
                      data-row-path={r.path}
                      className={isSelected ? "selected" : ""}
                      onClick={() => setSelectedPath(r.path)}
                      onContextMenu={(evt) => {
                        evt.preventDefault();
                        setSelectedPath(r.path);
                        setRuleMenu({ x: evt.clientX, y: evt.clientY, data: r });
                      }}
                      style={{ cursor: "pointer", background: brokenBg }}
                      title={r.path}
                    >
                      <td
                        style={{
                          textAlign: "center",
                          color: r.ok ? "var(--green, #4bbf6b)" : "#ff6060",
                          fontWeight: 700,
                        }}
                        title={r.ok ? "Parsed successfully" : "Parse error — see Issues column"}
                      >
                        {r.ok ? "✓" : "✕"}
                      </td>
                      <td className="mono">{basename}</td>
                      <td>{r.name ?? <span className="dim">—</span>}</td>
                      <td>
                        {r.severity ? (
                          <span
                            style={{
                              padding: "1px 7px",
                              borderRadius: 10,
                              background: sevColors.bg,
                              color: sevColors.fg,
                              fontWeight: 600,
                              fontSize: 10,
                              textTransform: "uppercase",
                            }}
                          >
                            {r.severity}
                          </span>
                        ) : (
                          <span className="dim">—</span>
                        )}
                      </td>
                      <td className="mono" style={{ textAlign: "right" }}>
                        {r.ok ? r.candidates : <span className="dim">—</span>}
                      </td>
                      <td
                        style={{
                          color: r.ok ? "var(--text-faint)" : "#ff6060",
                          maxWidth: 360,
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {r.error ?? "ok"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        {selected && (
          <div
            style={{
              width: 360,
              borderLeft: "1px solid var(--border)",
              padding: 10,
              overflow: "auto",
            }}
          >
            <div style={{ fontSize: 11, color: "var(--text-dim)", marginBottom: 6 }}>
              RULE DETAIL
            </div>
            <div
              className="mono"
              style={{
                fontSize: 11,
                color: "var(--text-dim)",
                wordBreak: "break-all",
                marginBottom: 10,
              }}
            >
              {selected.path}
            </div>
            <div style={{ display: "flex", gap: 6, marginBottom: 10, flexWrap: "wrap" }}>
              <button
                disabled={editingRule}
                onClick={() => void editSelectedRule()}
                title="Read this file into the composer so you can tweak + re-save"
                style={{ fontSize: 11 }}
              >
                {editingRule ? "Loading…" : "✎ Edit in composer"}
              </button>
              <button
                className="danger"
                disabled={deletingRule}
                onClick={() => void deleteSelectedRule()}
                title="Remove this file from project/bchecks/. The runner won't dispatch it on the next Run All."
                style={{ fontSize: 11 }}
              >
                {deletingRule ? "Deleting…" : "🗑 Delete file"}
              </button>
            </div>
            {selected.ok ? (
              <>
                <div style={{ marginBottom: 8 }}>
                  <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 0.4 }}>
                    Name
                  </div>
                  <div style={{ fontSize: 13 }}>{selected.name}</div>
                </div>
                <div style={{ marginBottom: 8 }}>
                  <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 0.4 }}>
                    Severity
                  </div>
                  <div style={{ fontSize: 13 }}>{selected.severity}</div>
                </div>
                <div style={{ marginBottom: 8 }}>
                  <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 0.4 }}>
                    Candidate paths
                  </div>
                  <div style={{ fontSize: 13 }}>
                    {selected.candidates}{" "}
                    <span className="dim" style={{ fontSize: 11 }}>
                      path{selected.candidates === 1 ? "" : "s"} per target
                    </span>
                  </div>
                </div>
                <div
                  className="dim"
                  style={{ fontSize: 11, marginTop: 10, lineHeight: 1.5 }}
                >
                  Edit the YAML directly in your editor — a Refresh picks up changes without an app restart.
                </div>
              </>
            ) : (
              <>
                <div
                  style={{
                    fontSize: 11,
                    color: "#ff6060",
                    marginBottom: 4,
                    textTransform: "uppercase",
                    letterSpacing: 0.4,
                  }}
                >
                  Parse error
                </div>
                <pre
                  className="mono"
                  style={{
                    fontSize: 11,
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-word",
                    background: "var(--bg-raised)",
                    padding: 8,
                    borderRadius: 3,
                    border: "1px solid rgba(224, 68, 68, 0.3)",
                    color: "#ff8080",
                  }}
                >
                  {selected.error}
                </pre>
                <div
                  className="dim"
                  style={{ fontSize: 11, marginTop: 10, lineHeight: 1.5 }}
                >
                  Fix the YAML in your editor and click Refresh. The validator
                  rejects documents missing <code>metadata.name</code>,{" "}
                  <code>candidates</code>, or <code>report.title</code>.
                </div>
              </>
            )}
          </div>
        )}
      </div>
      {/* R487: FloatingMenu for row right-click — mirrors the        */}
      {/* FloatingMenu pattern used by Scanner / HistoryPanel /       */}
      {/* Target / Logger / Decoder / Collaborator (where it's rendered*/}
      {/* at the panel's root level so the menu floats above every   */}
      {/* other UI element). Menu entries read `ruleMenu.data`        */}
      {/* (BCheckLoadRow) and copy / navigate without touching       */}
      {/* backend state — all four actions are clipboard-only or     */}
      {/* filter-state writes.                                        */}
      <FloatingMenu
        state={ruleMenu}
        onClose={() => setRuleMenu(null)}
        items={
          ruleMenu?.data
            ? [
                {
                  label: `Copy name: ${ruleMenu.data.name ?? "<unnamed>"}`,
                  disabled: !ruleMenu.data.name,
                  onClick: () =>
                    void copyToClipboard(ruleMenu.data!.name ?? ""),
                },
                {
                  label: "Copy file path",
                  hint: ruleMenu.data.path,
                  onClick: () =>
                    void copyToClipboard(ruleMenu.data!.path),
                },
                {
                  label: `Copy severity: ${ruleMenu.data.severity ?? "info"}`,
                  onClick: () =>
                    void copyToClipboard(ruleMenu.data!.severity ?? "info"),
                },
                { separator: true },
                {
                  label: ruleMenu.data.ok
                    ? "✓ Rule parsed OK"
                    : "✕ Parse error — see Issues column",
                  disabled: true,
                },
                ...(ruleMenu.data.ok
                  ? []
                  : [
                      {
                        label: "Copy parse error",
                        disabled: !ruleMenu.data.error,
                        onClick: () =>
                          void copyToClipboard(ruleMenu.data!.error ?? ""),
                      },
                    ]),
                { separator: true },
                {
                  label: `Filter rules to "${ruleMenu.data.name ?? ruleMenu.data.path.split(/[\\/]/).pop() ?? ""}"`,
                  disabled: !(ruleMenu.data.name || ruleMenu.data.path),
                  onClick: () => {
                    const q =
                      ruleMenu.data!.name ||
                      ruleMenu.data!.path.split(/[\\/]/).pop() ||
                      "";
                    setRulesSearch(q);
                  },
                },
              ]
            : []
        }
      />
    </div>
  );
}
