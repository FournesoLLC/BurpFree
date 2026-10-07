import React, { useEffect, useMemo, useState } from "react";
import { ActiveProbeInfo, api, PassiveDetectorInfo, StoredFinding, TransactionView } from "../api";
import { FloatingMenu, MenuState } from "../FloatingMenu";
import { MessageEditor } from "../MessageEditor";
import { buildHostIncludeRule, buildPathIncludeRule } from "../scopeHelpers";
import {
  buildCurl,
  buildFetch,
  buildHarEntry,
  buildHarLog,
  buildPowerShell,
  buildPython,
  copyToClipboard,
  fromSummaryAndRaw,
  urlFromSummary,
} from "../copyAs";

/** Burp's Scanner issue detail pane is a 3-tab layout: Advisory
 *  (prose + remediation + references), Request + Response (the
 *  original transaction bytes). R80 mirrors it so operators triage
 *  findings without flipping back to the HTTP history tab for the
 *  evidence request. */
type IssueDetailTab = "advisory" | "request" | "response";

/** R145: Humanise a backend timestamp (ms since epoch) as a short
 *  relative string: `just now` / `12s` / `3m` / `2h` / `4d`. Falls
 *  back to ISO date when the gap > 30 days. Mirror of DashboardPanel's
 *  helper so operators get a consistent "age" format across panels. */
function humanizeAge(tsMs: number): string {
  if (!tsMs || tsMs <= 0) return "—";
  const now = Date.now();
  const diff = Math.max(0, now - tsMs);
  if (diff < 2_000) return "now";
  const s = Math.floor(diff / 1_000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d}d`;
  return new Date(tsMs).toISOString().slice(0, 10);
}

/*  R149: Issue aging tint — operators triaging a long-running
 *  scan want "stale findings" to pop visually. Burp Pro doesn't
 *  tint the age column, but Burp's own Dashboard uses red/amber
 *  for performance outliers (R126 mirror), so we extend that
 *  colour language to Scanner findings. Thresholds match our
 *  Dashboard Error-rate card (R146): red = investigate, amber =
 *  watch, neutral = fine. Returns the inline-style fragment
 *  callers merge into the existing td style so we don't have to
 *  thread 2 separate style objects. */
function ageTintStyle(tsMs: number): React.CSSProperties {
  if (!tsMs || tsMs <= 0) return { color: "var(--text-dim)" };
  const diffDays = (Date.now() - tsMs) / 86_400_000;
  if (diffDays >= 30) return { color: "var(--red)", fontWeight: 600 };
  if (diffDays >= 7) return { color: "var(--amber)" };
  return { color: "var(--text-dim)" };
}

export function ScannerPanel() {
  const [findings, setFindings] = useState<StoredFinding[]>([]);
  const [selected, setSelected] = useState<StoredFinding | null>(null);
  // Issue-detail sub-tab + the paired transaction fetched for the
  // Request / Response tabs. Fetched lazily on selection change via
  // the existing `historyShow` cmd — scanner findings carry a
  // `transaction_id` on the StoredFinding so we never need a new
  // backend cmd for this. Null means either "no tx linked" (passive
  // finding without a transaction) or "fetch failed" (storage race).
  const [issueTab, setIssueTab] = useState<IssueDetailTab>("advisory");
  const [issueTx, setIssueTx] = useState<TransactionView | null>(null);
  const [issueTxBusy, setIssueTxBusy] = useState(false);
  useEffect(() => {
    // Reset tab to Advisory + clear the previous tx on every
    // selection change so a stale fetch doesn't flash the wrong
    // bytes when the operator clicks a different row quickly.
    setIssueTab("advisory");
    setIssueTx(null);
    if (!selected?.transaction_id) return;
    let alive = true;
    setIssueTxBusy(true);
    api
      .historyShow(selected.transaction_id)
      .then((tx) => {
        if (alive) setIssueTx(tx);
      })
      .catch(() => {
        if (alive) setIssueTx(null);
      })
      .finally(() => {
        if (alive) setIssueTxBusy(false);
      });
    return () => {
      alive = false;
    };
  }, [selected?.id, selected?.transaction_id]);
  const [menu, setMenu] = useState<MenuState<StoredFinding> | null>(null);
  const [busy, setBusy] = useState(false);
  const [busyWs, setBusyWs] = useState(false);
  // Live-passive-scan toggle. Polled every 2s so flips from the CLI /
  // another session surface in this panel too.
  const [liveScan, setLiveScan] = useState(true);
  const [liveBusy, setLiveBusy] = useState(false);
  // Per-detector enable grid. Loaded once on mount; a flipped
  // checkbox optimistically updates local state + fires the set cmd,
  // reverting on failure so the UI never drifts from the backend.
  const [detectors, setDetectors] = useState<PassiveDetectorInfo[]>([]);
  const [detectorsOpen, setDetectorsOpen] = useState(false);
  // Active-probe enable grid — mirror of the passive one, with the
  // extra `default_disabled` hint rendered next to opt-in probes.
  const [probes, setProbes] = useState<ActiveProbeInfo[]>([]);
  const [probesOpen, setProbesOpen] = useState(false);
  // Multi-select state for bulk ops. Mirrors HistoryPanel's pattern:
  // Ctrl/Shift click accumulates, plain click resets to single.
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [lastClickedId, setLastClickedId] = useState<number | null>(null);

  // Burp-style chip filter strip — mirror of the TargetPanel Issues
  // chip strip R81 established. Multi-select Set state, empty = any.
  // The ScannerPanel used to render every finding unfiltered; this
  // adds a severity + status filter row below the toolbar so an
  // operator triaging a 300-finding scan can pivot to just "high +
  // critical" or "new + triaging" with one click.
  type SevKey = "critical" | "high" | "medium" | "low" | "info";
  const [sevFilter, setSevFilter] = useState<Set<SevKey>>(() => new Set());
  // R177: cross-panel bus — Dashboard severity chips dispatch
  // `burpfree:scanner-sev-focus` with `{severity}` to snap this
  // panel's chip-strip filter to just that level. Also handy for
  // palette commands + future deep-links.
  useEffect(() => {
    const onFocus = (e: Event) => {
      const detail = (e as CustomEvent<{ severity?: string }>).detail;
      const s = (detail?.severity ?? "").toLowerCase();
      if (!s) return;
      if (
        s === "critical" ||
        s === "high" ||
        s === "medium" ||
        s === "low" ||
        s === "info"
      ) {
        setSevFilter(new Set<SevKey>([s as SevKey]));
      }
    };
    window.addEventListener("burpfree:scanner-sev-focus", onFocus as EventListener);
    return () =>
      window.removeEventListener("burpfree:scanner-sev-focus", onFocus as EventListener);
  }, []);
  // R221: cross-panel bus — Dashboard "Recent findings" card
  // dispatches `burpfree:scanner-finding-focus` with `{ id }` so
  // the ScannerPanel can select that specific finding on mount.
  // Different from the sev-focus event (which snaps the chip
  // filter): this one targets a single row. Clearing chip filters
  // means the target is visible even if the current chip set
  // would hide it, so the focus always lands.
  useEffect(() => {
    const onFindingFocus = (e: Event) => {
      const detail = (e as CustomEvent<{ id?: number }>).detail;
      const id = detail?.id;
      if (id == null) return;
      // Clear chip filters so the finding is guaranteed visible —
      // operators coming from the Dashboard Recent-findings card
      // expect to land on the row they clicked, not an empty list.
      setSevFilter(new Set());
      setIssueStatusFilter(new Set());
      setTagFilter(new Set());
      // Lookup against the current findings; if the finding isn't
      // loaded yet (newly minted), fall back to a refresh then try
      // again on the next tick. We don't block the UI on it.
      void (async () => {
        let list = findings;
        let target = list.find((f) => f.id === id);
        if (!target) {
          try {
            list = await api.findingsList();
            setFindings(list);
            target = list.find((f) => f.id === id);
          } catch {
            /* silent — Scanner refresh will pick it up on the next poll */
          }
        }
        if (target) {
          setSelected(target);
          // Scroll the row into view post-render.
          setTimeout(() => {
            document
              .querySelector("tr.selected")
              ?.scrollIntoView({ block: "nearest" });
          }, 0);
        }
      })();
    };
    window.addEventListener(
      "burpfree:scanner-finding-focus",
      onFindingFocus as EventListener,
    );
    return () =>
      window.removeEventListener(
        "burpfree:scanner-finding-focus",
        onFindingFocus as EventListener,
      );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [findings]);
  const [issueStatusFilter, setIssueStatusFilter] = useState<Set<string>>(
    () => new Set(),
  );
  // Tag filter — R91 landed per-finding tag editing; R93 lets the
  // operator pivot the list by tag membership. Empty set = any tag
  // (same convention as the severity + status Sets). Only renders
  // when at least one finding on the current page carries a tag,
  // so empty-tag scans don't eat vertical space.
  const [tagFilter, setTagFilter] = useState<Set<string>>(() => new Set());
  // R200: tri-state group mode. Burp Pro's Scanner offers "No
  // grouping / Group by host / Group by detector"; we had just
  // the on/off host toggle (R116). The upgrade folds detector-
  // grouping into the same render path — each bucket keyed by a
  // host string OR a detector id, with severity-count pills in
  // the header and per-group collapse state identical to the host
  // version. `host` mode fetches a tx→host map via R90's bulk
  // historySummaries call; `detector` mode reads `f.detector`
  // directly (no backend lookup needed). Expand / collapse state
  // is persisted alongside the mode so a reload restores the
  // layout the operator chose. Migration: an existing
  // `scanner.groupByHost === "1"` landed before R200 flips the
  // new key to "host" on first mount so no operator loses their
  // layout across the upgrade.
  type GroupMode = "none" | "host" | "detector";
  const [groupMode, setGroupMode] = useState<GroupMode>(() => {
    try {
      const direct = localStorage.getItem("scanner.groupMode");
      if (direct === "none" || direct === "host" || direct === "detector") {
        return direct;
      }
      // R116 → R200 migration: carry the old boolean into the new enum.
      const legacy = localStorage.getItem("scanner.groupByHost");
      if (legacy === "1") return "host";
      return "none";
    } catch {
      return "none";
    }
  });
  // Map tx_id → host for the current findings. Rebuilt on findings
  // change via one bulk `historySummaries` call. Missing tx_ids
  // (deleted transactions) stay unmapped and surface in the "(no
  // transaction)" group.
  const [hostByTxId, setHostByTxId] = useState<Map<number, string>>(() => new Map());
  // Per-group expand/collapse state. The key is whatever the
  // active mode uses — a host for "host" mode, a detector id for
  // "detector" mode. New groups default to expanded because a
  // hidden-by-default group would hide fresh findings during an
  // active scan. localStorage persists so a reload keeps whichever
  // state the operator settled on. R200 renamed from
  // `collapsedHosts` + reused the key with a one-shot migration
  // read of the old `scanner.collapsedHosts` so existing operators
  // keep their collapse state across the enum upgrade.
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(() => {
    try {
      const raw =
        localStorage.getItem("scanner.collapsedGroups") ||
        localStorage.getItem("scanner.collapsedHosts");
      if (!raw) return new Set();
      const arr = JSON.parse(raw) as string[];
      return new Set(Array.isArray(arr) ? arr : []);
    } catch {
      return new Set();
    }
  });
  // Baseline counts (unfiltered) feed the chip badges so numbers
  // reflect the whole scan, not the post-chip view. Matches R81.
  const sevCounts = useMemo(() => {
    const c: Record<SevKey, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    for (const f of findings) {
      const k = (f.severity || "info").toLowerCase() as SevKey;
      if (k in c) c[k]++;
    }
    return c;
  }, [findings]);
  const statusCounts = useMemo(() => {
    const c: Record<string, number> = {
      new: 0,
      triaging: 0,
      confirmed: 0,
      false_positive: 0,
      fixed: 0,
      wontfix: 0,
    };
    for (const f of findings) {
      const s = (f.status || "new").toLowerCase();
      c[s] = (c[s] ?? 0) + 1;
    }
    return c;
  }, [findings]);
  // Tag inventory: distinct tags across findings + per-tag count.
  // Alphabetised for a stable chip order so toggling one chip doesn't
  // reshuffle the row on the next render.
  const tagInventory = useMemo(() => {
    const counts = new Map<string, number>();
    for (const f of findings) {
      for (const t of f.tags ?? []) {
        counts.set(t, (counts.get(t) ?? 0) + 1);
      }
    }
    return Array.from(counts.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([tag, count]) => ({ tag, count }));
  }, [findings]);
  const filteredFindings = useMemo(() => {
    if (
      sevFilter.size === 0 &&
      issueStatusFilter.size === 0 &&
      tagFilter.size === 0
    )
      return findings;
    return findings.filter((f) => {
      const sev = (f.severity || "info").toLowerCase() as SevKey;
      if (sevFilter.size > 0 && !sevFilter.has(sev)) return false;
      const st = (f.status || "new").toLowerCase();
      if (issueStatusFilter.size > 0 && !issueStatusFilter.has(st)) return false;
      if (tagFilter.size > 0) {
        const tags = f.tags ?? [];
        // Finding must carry at least one of the selected tags.
        if (!tags.some((t) => tagFilter.has(t))) return false;
      }
      return true;
    });
  }, [findings, sevFilter, issueStatusFilter, tagFilter]);
  function toggleSev(k: SevKey) {
    setSevFilter((prev) => {
      const next = new Set(prev);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      return next;
    });
  }
  function toggleIssueStatus(v: string) {
    setIssueStatusFilter((prev) => {
      const next = new Set(prev);
      if (next.has(v)) next.delete(v);
      else next.add(v);
      return next;
    });
  }
  function toggleTagFilter(t: string) {
    setTagFilter((prev) => {
      const next = new Set(prev);
      if (next.has(t)) next.delete(t);
      else next.add(t);
      return next;
    });
  }
  function clearChipFilters() {
    setSevFilter(new Set());
    setIssueStatusFilter(new Set());
    setTagFilter(new Set());
  }
  const anyChipActive =
    sevFilter.size > 0 || issueStatusFilter.size > 0 || tagFilter.size > 0;
  // When group-by-host flips on, bulk-fetch summaries for every
  // finding's transaction so the grouper has a tx→host map. Done
  // on findings change too so a fresh scan surfaces its new hosts
  // without a manual toggle. We hit `historySummaries` once per
  // findings update (not per render) — the backend is a single
  // SELECT with an IN clause so this scales to thousands of
  // findings without feeling slow.
  useEffect(() => {
    // Only host-mode needs the tx→host lookup; detector-mode reads
    // f.detector directly + none-mode doesn't group at all.
    if (groupMode !== "host") return;
    const ids = Array.from(
      new Set(
        findings
          .map((f) => f.transaction_id)
          .filter((id): id is number => typeof id === "number"),
      ),
    );
    if (ids.length === 0) {
      setHostByTxId(new Map());
      return;
    }
    let alive = true;
    api
      .historySummaries(ids)
      .then((rows) => {
        if (!alive) return;
        const m = new Map<number, string>();
        for (const r of rows) m.set(r.id, r.host);
        setHostByTxId(m);
      })
      .catch(() => {
        // Silent — group header will say "(no transaction)" for
        // every row, which is still better than crashing the panel.
      });
    return () => {
      alive = false;
    };
  }, [findings, groupMode]);
  // Persist the group-mode so a reload restores the layout.
  // localStorage swallows errors so a quota-full browser doesn't
  // crash the panel.
  useEffect(() => {
    try {
      localStorage.setItem("scanner.groupMode", groupMode);
    } catch {}
  }, [groupMode]);
  // Persist the collapsed-groups set alongside the mode so an
  // operator who collapses "example.com" / a detector id + reloads
  // keeps those groups collapsed. The set is serialised as an
  // array because localStorage can't round-trip Set/Map directly.
  useEffect(() => {
    try {
      localStorage.setItem(
        "scanner.collapsedGroups",
        JSON.stringify([...collapsedGroups]),
      );
    } catch {}
  }, [collapsedGroups]);
  function toggleGroupCollapsed(key: string) {
    setCollapsedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }
  // Grouped view memo. Each entry is `{key, findings, sevCounts}`
  // sorted (a) by critical-count desc so the scariest group pops
  // to the top, then (b) by key asc so a tie breaks on a stable
  // ordering. R200 generalised the per-host memo to tri-state
  // (none / host / detector) — the bucket key is a host string for
  // "host" mode and a detector id for "detector" mode. "none"
  // short-circuits to an empty array (flat render path is used).
  const groupedFindings = useMemo(() => {
    if (groupMode === "none") return [];
    const buckets = new Map<string, StoredFinding[]>();
    for (const f of filteredFindings) {
      let key: string;
      if (groupMode === "host") {
        key =
          (f.transaction_id != null && hostByTxId.get(f.transaction_id)) ||
          "(no transaction)";
      } else {
        key = f.detector || "(unknown detector)";
      }
      const arr = buckets.get(key) ?? [];
      arr.push(f);
      buckets.set(key, arr);
    }
    const out = Array.from(buckets.entries()).map(([key, items]) => {
      const sc: Record<SevKey, number> = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      };
      for (const f of items) {
        const sk = (f.severity || "info").toLowerCase() as SevKey;
        if (sk in sc) sc[sk]++;
      }
      return { key, findings: items, sevCounts: sc };
    });
    out.sort((a, b) => {
      const d = b.sevCounts.critical - a.sevCounts.critical;
      if (d !== 0) return d;
      const d2 = b.sevCounts.high - a.sevCounts.high;
      if (d2 !== 0) return d2;
      return a.key.localeCompare(b.key);
    });
    return out;
  }, [groupMode, filteredFindings, hostByTxId]);

  async function refresh() {
    setFindings(await api.findingsList());
  }
  async function refreshDetectors() {
    try {
      const list = await api.scannerPassiveDetectorsList();
      setDetectors(list);
    } catch {
      /* project not loaded yet — leave the grid empty */
    }
  }
  async function refreshProbes() {
    try {
      const list = await api.scannerActiveProbesList();
      setProbes(list);
    } catch {
      /* project not loaded yet — leave the grid empty */
    }
  }
  useEffect(() => {
    refresh();
    void refreshDetectors();
    void refreshProbes();
    let alive = true;
    const pull = async () => {
      try {
        const v = await api.liveScanGet();
        if (alive) setLiveScan(v);
      } catch {
        /* ignore — project may not be loaded yet */
      }
    };
    void pull();
    const t = setInterval(pull, 2000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  /// Optimistically flip a detector's enable state. On failure we
  /// re-fetch so the grid stays truthful about backend state.
  async function toggleDetector(id: string, next: boolean) {
    setDetectors((prev) =>
      prev.map((d) => (d.id === id ? { ...d, enabled: next } : d)),
    );
    try {
      await api.scannerPassiveDetectorSet(id, next);
    } catch (e) {
      alert(`Could not toggle detector: ${e}`);
      await refreshDetectors();
    }
  }

  /// Optimistically flip an active probe's enable state. Mirrors
  /// toggleDetector — the grid shape is identical save for the
  /// opt-in hint rendered on default-disabled rows.
  async function toggleProbe(id: string, next: boolean) {
    setProbes((prev) =>
      prev.map((p) => (p.id === id ? { ...p, enabled: next } : p)),
    );
    try {
      await api.scannerActiveProbeSet(id, next);
    } catch (e) {
      alert(`Could not toggle probe: ${e}`);
      await refreshProbes();
    }
  }

  async function toggleLiveScan() {
    const next = !liveScan;
    setLiveBusy(true);
    // Optimistic — reverts on failure.
    setLiveScan(next);
    try {
      await api.liveScanSet(next);
      // Refresh findings since turning it on may already have queued some.
      await refresh();
    } catch (e) {
      setLiveScan(!next);
      alert(`Could not toggle live scan: ${e}`);
    } finally {
      setLiveBusy(false);
    }
  }

  async function runPassive() {
    setBusy(true);
    try {
      const n = await api.passiveRunNow();
      alert(`${n} finding(s) added.`);
      await refresh();
    } finally {
      setBusy(false);
    }
  }

  // Ctrl/Shift click accumulates selection; plain click resets to
  // single. The right pane always previews the last-clicked row.
  function onRowClick(e: React.MouseEvent, f: StoredFinding) {
    setSelected(f);
    if (e.ctrlKey || e.metaKey) {
      setSelectedIds((prev) => {
        const next = new Set(prev);
        if (next.has(f.id)) next.delete(f.id);
        else next.add(f.id);
        return next;
      });
      setLastClickedId(f.id);
    } else if (e.shiftKey && lastClickedId != null) {
      // Range select from last click to this click in current order.
      // Operates on filteredFindings so shift-select-after-chip
      // doesn't silently pick up invisible rows between the anchors.
      const ids = filteredFindings.map((x) => x.id);
      const a = ids.indexOf(lastClickedId);
      const b = ids.indexOf(f.id);
      if (a >= 0 && b >= 0) {
        const [lo, hi] = a < b ? [a, b] : [b, a];
        setSelectedIds((prev) => {
          const next = new Set(prev);
          for (let i = lo; i <= hi; i++) next.add(ids[i]);
          return next;
        });
      }
    } else {
      setSelectedIds(new Set());
      setLastClickedId(f.id);
    }
  }

  const bulkRows = findings.filter((f) => selectedIds.has(f.id));

  async function bulkSetStatus(status: string) {
    await Promise.all(bulkRows.map((f) => api.findingSetStatus(f.id, status)));
    await refresh();
  }

  // R265: Mark every "new" finding in the current filtered view
  // as "triaging" — the one-click "I've seen all of these, come
  // back later" bulk op. Operators finishing a scan want to pin
  // the whole list to signal "nothing here is unseen", without
  // having to select-all-then-set-status. Operates on the
  // post-chip-filter view (filteredFindings) so a chip-narrowed
  // list (e.g. "only high severity") is respected — the operator
  // can promote just the slice they're staring at. Only touches
  // rows currently at status "new" so repeated clicks are a no-op
  // and operators don't accidentally re-triage already-triaged
  // rows back from "confirmed" / "wontfix". Fires behind a
  // confirm because many-row writes should always surface the
  // row count up front.
  const [markingTriaging, setMarkingTriaging] = useState(false);
  async function markFilteredAsTriaging() {
    const targets = filteredFindings.filter(
      (f) => (f.status || "new").toLowerCase() === "new",
    );
    if (targets.length === 0) return;
    if (
      !confirm(
        `Mark ${targets.length} "new" finding${targets.length === 1 ? "" : "s"} as "triaging"? Rows already at other statuses (confirmed, false_positive, fixed, wontfix) stay untouched.`,
      )
    )
      return;
    setMarkingTriaging(true);
    try {
      await Promise.all(
        targets.map((f) => api.findingSetStatus(f.id, "triaging")),
      );
      await refresh();
    } finally {
      setMarkingTriaging(false);
    }
  }

  // R287: Second step in the triage pipeline — promote every
  // "triaging" finding in the current filtered view to
  // "confirmed". Operators finishing a review session batch-
  // confirm the rows they've verified without having to select-
  // all-then-set-status. Mirror of R265 but for the next status
  // transition. Only touches rows currently at "triaging" so a
  // mis-fire can't promote "new" rows past the review step or
  // flip "false_positive" rows back to confirmed. Operates on
  // filteredFindings so a chip-narrowed view (e.g. "triaging +
  // high severity") is respected — the operator can confirm just
  // the slice they're staring at.
  const [confirmingTriaging, setConfirmingTriaging] = useState(false);
  async function confirmFilteredTriaging() {
    const targets = filteredFindings.filter(
      (f) => (f.status || "new").toLowerCase() === "triaging",
    );
    if (targets.length === 0) return;
    if (
      !confirm(
        `Promote ${targets.length} "triaging" finding${targets.length === 1 ? "" : "s"} to "confirmed"? Rows already at other statuses (new, false_positive, fixed, wontfix) stay untouched.`,
      )
    )
      return;
    setConfirmingTriaging(true);
    try {
      await Promise.all(
        targets.map((f) => api.findingSetStatus(f.id, "confirmed")),
      );
      await refresh();
    } finally {
      setConfirmingTriaging(false);
    }
  }

  // Fire every enabled active probe against the finding's parent
  // transaction and refresh the findings list so freshly-generated /
  // re-verified issues surface. Mirror of HistoryPanel's
  // `activeScanRow` — the operator who stares at a finding they
  // suspect is a false positive clicks here and watches the issue
  // either stay (re-fingerprinted via upsert so observation_count
  // bumps) or disappear (if the current state no longer trips the
  // detector). Guards on `transaction_id` because passive findings
  // without a tx can't be re-probed.
  const [rerunBusy, setRerunBusy] = useState(false);
  async function rerunActiveScan(f: StoredFinding) {
    if (!f.transaction_id) {
      alert("This finding isn't tied to a specific transaction — nothing to re-probe.");
      return;
    }
    setRerunBusy(true);
    try {
      const report = await api.scannerActiveRunTx(f.transaction_id);
      await refresh();
      if (report.skipped_reason) {
        alert(`Active scan skipped: ${report.skipped_reason}`);
        return;
      }
      // Quiet confirmation with the fresh counts so the operator
      // knows the probe ran even when no new findings landed.
      const n = report.findings_added;
      alert(
        `Active scan complete: ${n} new finding${n === 1 ? "" : "s"} added (existing issues de-dup via fingerprint upsert, ${report.probes_run} probe${report.probes_run === 1 ? "" : "s"} dispatched).`,
      );
    } catch (e) {
      alert(`Rerun failed: ${e}`);
    } finally {
      setRerunBusy(false);
    }
  }

  async function bulkSetVerification(v: string) {
    await Promise.all(bulkRows.map((f) => api.findingSetVerification(f.id, v)));
    await refresh();
  }

  // R389: Markdown-document builder for the bulk selection, shared
  // between R369's "📋 Copy Markdown" toolbar button and R389's
  // Alt+Shift+M keyboard shortcut. Factored out of the toolbar
  // onClick to avoid duplicating ~55 lines of ticket-ready
  // Markdown formatting. **Format** H3 header per finding with
  // emoji sev prefix, bulleted metadata (severity / confidence /
  // status / verification / detector / transaction), description
  // / evidence (fenced ``` block, operator-safe `'''` escape for
  // triple-backtick-containing evidence) / remediation /
  // references sections, `---` separators between findings.
  // **No-op silent** when empty — the keyboard caller spam-safes,
  // the button caller already guards via disabled state.
  async function bulkCopyMarkdown() {
    if (bulkRows.length === 0) return;
    const sevEmojiFor = (sev: string) =>
      sev === "critical" ? "🔴"
      : sev === "high" ? "🟠"
      : sev === "medium" ? "🟡"
      : sev === "low" ? "🟢"
      : "⚪";
    const parts: string[] = [];
    for (const f of bulkRows) {
      const sevEmoji = sevEmojiFor(f.severity);
      parts.push(`### ${sevEmoji} ${f.title}`);
      parts.push("");
      parts.push(`- **Severity**: ${sevEmoji} ${f.severity}`);
      parts.push(`- **Confidence**: ${f.confidence}`);
      parts.push(`- **Status**: ${f.status ?? "new"}`);
      if (f.verification && f.verification !== "unverified") {
        parts.push(`- **Verification**: ${f.verification}`);
      }
      if (f.detector) parts.push(`- **Detector**: \`${f.detector}\``);
      if (f.transaction_id) parts.push(`- **Transaction**: #${f.transaction_id}`);
      parts.push("");
      if (f.description) {
        parts.push("**Description**");
        parts.push("");
        parts.push(f.description);
        parts.push("");
      }
      if (f.evidence) {
        parts.push("**Evidence**");
        parts.push("");
        parts.push("```");
        parts.push(f.evidence.replace(/```/g, "'''"));
        parts.push("```");
        parts.push("");
      }
      if (f.remediation) {
        parts.push("**Remediation**");
        parts.push("");
        parts.push(f.remediation);
        parts.push("");
      }
      if (f.references && f.references.length > 0) {
        parts.push("**References**");
        parts.push("");
        for (const r of f.references) parts.push(`- <${r}>`);
        parts.push("");
      }
      parts.push("---");
      parts.push("");
    }
    try {
      await navigator.clipboard.writeText(parts.join("\n"));
    } catch (e) {
      alert(`${e}`);
    }
  }

  // R293: Bulk re-run active-scan probes across the current
  // selection. Fires scannerActiveRunTx on each finding's
  // transaction_id (findings without a tx are skipped — matches
  // the single-row rerunActiveScan guard). Confirms pre-fire
  // with the exact victim count because this issues N extra
  // outbound requests to the target per finding (one per active
  // probe × N findings) — potentially a lot of traffic for a
  // large selection. Toast at the end sums the findings_added
  // across every tx so operators see "verified 12, added 2 new
  // findings" without clicking into each row.
  const [bulkVerifying, setBulkVerifying] = useState(false);
  async function bulkRerunActiveScan() {
    const targets = bulkRows.filter((f) => f.transaction_id != null);
    if (targets.length === 0) {
      alert(
        bulkRows.length === 0
          ? "No findings selected — select one or more rows first."
          : "None of the selected findings have a transaction_id — passive-only findings can't be re-probed.",
      );
      return;
    }
    const skipped = bulkRows.length - targets.length;
    if (
      !confirm(
        `Re-run active-scan probes against ${targets.length} finding${targets.length === 1 ? "" : "s"}? Each fires every enabled active probe at the finding's parent transaction — expect a ${targets.length}× traffic bump. ${skipped > 0 ? `${skipped} passive finding${skipped === 1 ? "" : "s"} without a tx will be skipped. ` : ""}Fingerprint upsert means existing findings get their observation_count bumped rather than duplicated.`,
      )
    )
      return;
    setBulkVerifying(true);
    let totalAdded = 0;
    let probesRun = 0;
    let errors = 0;
    try {
      const reports = await Promise.allSettled(
        targets.map((f) => api.scannerActiveRunTx(f.transaction_id!)),
      );
      for (const r of reports) {
        if (r.status === "fulfilled") {
          totalAdded += r.value.findings_added ?? 0;
          probesRun += r.value.probes_run ?? 0;
        } else {
          errors += 1;
        }
      }
      await refresh();
      alert(
        `Bulk verify complete: ${targets.length} tx probed, ${probesRun} probe${probesRun === 1 ? "" : "s"} dispatched, ${totalAdded} new finding${totalAdded === 1 ? "" : "s"} added.${errors > 0 ? ` ${errors} tx failed — see the Logger for details.` : ""}`,
      );
    } finally {
      setBulkVerifying(false);
    }
  }

  /** R130: Prune every finding whose status is `false_positive`. The
   *  companion to R129's HTTP-history prune — operators who go
   *  through a scan + mark the obvious noise as false_positive end
   *  up with a shortlist of real work mixed with a long tail of
   *  dismissed rows. This button zaps the dismissed tail in one
   *  click without touching anything still marked `new` or
   *  `confirmed`. */
  async function pruneFalsePositives() {
    const fps = findings.filter(
      (f) => (f.status || "new").toLowerCase() === "false_positive",
    );
    if (fps.length === 0) {
      alert("No findings marked `false_positive` — nothing to prune.");
      return;
    }
    if (
      !confirm(
        `Delete ${fps.length} finding${fps.length === 1 ? "" : "s"} marked as false_positive? Rows marked \`new\`, \`triaging\`, \`confirmed\`, \`fixed\`, or \`wontfix\` stay untouched. Cannot be undone.`,
      )
    ) {
      return;
    }
    try {
      const removed = await api.findingsDeleteMany(fps.map((f) => f.id));
      await refresh();
      alert(
        `Pruned ${removed} false-positive finding${removed === 1 ? "" : "s"}.`,
      );
    } catch (err) {
      alert(`Prune failed: ${err}`);
      return;
    }
  }

  /*  R195: Prune info-severity findings — companion to R130
   *  (false-positive prune). Many detectors emit info-level
   *  findings for every quirky header or minor misconfig; after
   *  the operator triages the medium+ findings, the info tail
   *  stays as decoration. One-click prune drops them so the
   *  report + chip strip read cleaner. Doesn't touch findings
   *  whose severity was manually bumped from info to something
   *  higher — only the current `severity === 'info'` row.
   *  Resumes the function body with the shared return path. */
  async function pruneInfoFindings() {
    const infos = findings.filter(
      (f) => (f.severity || "info").toLowerCase() === "info",
    );
    if (infos.length === 0) {
      alert("No info-severity findings — nothing to prune.");
      return;
    }
    if (
      !confirm(
        `Delete ${infos.length} info-severity finding${infos.length === 1 ? "" : "s"}? Low / medium / high / critical findings stay untouched. Cannot be undone.`,
      )
    ) {
      return;
    }
    try {
      const removed = await api.findingsDeleteMany(infos.map((f) => f.id));
      await refresh();
      alert(`Pruned ${removed} info finding${removed === 1 ? "" : "s"}.`);
    } catch (err) {
      alert(`Prune failed: ${err}`);
    }
  }

  async function bulkDelete() {
    if (bulkRows.length === 0) return;
    if (
      !confirm(
        `Delete ${bulkRows.length} finding${bulkRows.length === 1 ? "" : "s"}? This cannot be undone.`,
      )
    )
      return;
    await api.findingsDeleteMany(bulkRows.map((f) => f.id));
    setSelectedIds(new Set());
    setSelected(null);
    await refresh();
  }

  // R138: Delete key fires bulk-delete when a selection exists.
  // Mirror of R96 (history delete-key). Scoped at the document
  // level since the issues table doesn't accept focus directly —
  // the bulk-selection chip strip only populates when operators
  // Ctrl-click rows. Guarded on an empty selection so a stray
  // Delete press doesn't cost the operator a modal they'd just
  // have to cancel. Text-input skip so Delete inside a comment /
  // tag editor doesn't fire the destructive path.
  useEffect(() => {
    function onDel(e: KeyboardEvent) {
      if (e.key !== "Delete") return;
      if (selectedIds.size === 0) return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      e.preventDefault();
      void bulkDelete();
    }
    document.addEventListener("keydown", onDel);
    return () => document.removeEventListener("keydown", onDel);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedIds]);

  // R378: Alt+Shift+N pops the note editor for the currently-
  // selected finding — keyboard version of the R344 detail-pane
  // "+ Note" / "✎ Note" button. Operators J/K-walk → Alt+Shift+N
  // → jot context → Enter to save. **Guards + text-input skip**
  // mirror R337. **No-op when nothing selected** short-circuits
  // so the keystroke doesn't open an orphan prompt.
  useEffect(() => {
    function onNoteKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key !== "N" && e.key !== "n") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (!selected) return;
      e.preventDefault();
      const next = prompt(
        `Note for finding "${selected.title.length > 50 ? selected.title.slice(0, 47) + "…" : selected.title}":\n\n(Empty string clears the note.)`,
        selected.note ?? "",
      );
      if (next === null) return;
      void api
        .findingSetNote(selected.id, next)
        .then(() => api.findingsList().then(setFindings))
        .catch((err) => alert(`${err}`));
    }
    document.addEventListener("keydown", onNoteKey);
    return () => document.removeEventListener("keydown", onNoteKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected?.id]);

  // R375: Alt+Shift+C clears the current bulk selection — mirror
  // of R328 Ctrl+A select-all-filtered. Operators pivoting
  // between bulk-op flows want a one-key reset so they don't have
  // to mouse to "Clear selection" after each pass. **Guards +
  // text-input skip** mirror R328. **No-op when empty** short-
  // circuits so the keystroke doesn't trigger a wasteful state
  // update on an already-empty selection.
  useEffect(() => {
    function onClearKey(e: KeyboardEvent) {
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
      if (selectedIds.size === 0) return;
      e.preventDefault();
      setSelectedIds(new Set());
    }
    document.addEventListener("keydown", onClearKey);
    return () => document.removeEventListener("keydown", onClearKey);
  }, [selectedIds]);

  // R366: Alt+Shift+F marks every bulk-selected finding as false
  // positive — closes the bulk-status keyboard trio with R364
  // Alt+Shift+T and R358 Alt+Shift+V. Operators triaging a noisy
  // detector's output can select-all → one key to dismiss the
  // whole chatter batch at once. **Scope + guards** identical to
  // R364 / R358.
  useEffect(() => {
    function onBulkFalsePositiveKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key !== "F" && e.key !== "f") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (bulkRows.length === 0) return;
      e.preventDefault();
      void bulkSetStatus("false_positive");
    }
    document.addEventListener("keydown", onBulkFalsePositiveKey);
    return () => document.removeEventListener("keydown", onBulkFalsePositiveKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [bulkRows]);

  // R420: Alt+Shift+H pivots the selected finding's parent tx into
  // HTTP history (focuses the row + navigates to the History tab).
  // Keyboard version of R161's detail-pane "→ History" button +
  // R419's row-right-click entry. Triage pivot trio with R416
  // (Alt+Shift+S → Repeater) + R413 (Alt+Shift+R rerun active scan)
  // + R420 (Alt+Shift+H → History). **Letter choice** H = History.
  // **Scope** `selected` (single finding). **Guards** `selected !=
  // null && selected.transaction_id != null`. Alt+Shift only (no
  // Ctrl so Ctrl+Shift+H history-panel in browsers stays intact),
  // text-input focus skip. **No-op silent** when no selection or
  // tx-less. **Mechanism** mirrors R161 / R419 exactly: dispatch
  // `burpfree:history-focus` (HistoryPanel highlights + scrolls)
  // + `burpfree:navigate` (chrome switches section).
  useEffect(() => {
    function onPivotHistoryKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key !== "H" && e.key !== "h") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (!selected || !selected.transaction_id) return;
      e.preventDefault();
      window.dispatchEvent(
        new CustomEvent("burpfree:history-focus", {
          detail: { id: selected.transaction_id },
        }),
      );
      window.dispatchEvent(
        new CustomEvent("burpfree:navigate", {
          detail: { target: "history" },
        }),
      );
    }
    document.addEventListener("keydown", onPivotHistoryKey);
    return () => document.removeEventListener("keydown", onPivotHistoryKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected]);

  // R416: Alt+Shift+S sends the currently-selected finding's parent
  // request to a new Repeater tab + navigates the UI to Repeater.
  // Keyboard version of R316's row-right-click "Send request to
  // Repeater" entry. Operators triaging a finding often want a
  // one-key pivot into Repeater for exploit-development work:
  // open finding in detail pane → Alt+Shift+S → land on Repeater
  // tab seeded with the finding's parent request → tweak + fire.
  // **Letter choice** S = Send. **Scope** `selected` (single
  // finding). **Guards** `selected != null && selected.transaction_id != null`
  // (passive-only findings skipped — they can't be sent since there's
  // no parent tx to replay). Alt+Shift only (no Ctrl/Meta so
  // Ctrl+Shift+S "save all" muscle memory stays untouched), text-
  // input focus skip. **No-op silent** when no selection or tx-less.
  // **Mechanism** mirrors R316's inline onClick exactly: fire
  // `repeaterAddFromHistory(txId, title)` + CustomEvent navigate.
  useEffect(() => {
    function onSendRepeaterKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key !== "S" && e.key !== "s") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (!selected || !selected.transaction_id) return;
      e.preventDefault();
      const txId = selected.transaction_id;
      const title = selected.title;
      void (async () => {
        try {
          await api.repeaterAddFromHistory(txId, title);
          window.dispatchEvent(
            new CustomEvent("burpfree:navigate", {
              detail: { target: "repeater" },
            }),
          );
        } catch (err) {
          alert(`Send to Repeater failed: ${err}`);
        }
      })();
    }
    document.addEventListener("keydown", onSendRepeaterKey);
    return () => document.removeEventListener("keydown", onSendRepeaterKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected]);

  // R456: Alt+Shift+E saves the currently-selected finding's evidence
  // blob to a file — keyboard version of R401's "⬇ Save" button in
  // the detail pane. Evidence blobs can run large (full raw response,
  // multi-line stack traces, dumped headers) and operators building
  // a PoC bundle or ticket attachment often want an on-disk copy
  // rather than a clipboard paste — the file survives app restarts,
  // attaches cleanly to tickets, and sidesteps clipboard-size caps.
  // Extends the Alt+Shift save-visible-artifact family across panels:
  // R401 Scanner "⬇ Save" (visible button), R438 Decoder Alt+Shift+S
  // (keyboard), R454 Repeater Alt+Shift+S (keyboard), R456 Scanner
  // Alt+Shift+E (keyboard). **Letter choice** E = Evidence; distinct
  // from Alt+Shift+S which is already taken by R416 (send to
  // Repeater) in this panel scope — the E vs S distinction keeps
  // the Scanner triage pivot trio (R→rerun, S→Repeater, H→History)
  // intact while adding a fourth leg (E→save Evidence to disk).
  // **Mechanism** mirrors R401's onClick exactly: build a slug from
  // the finding title, assemble the filename `evidence-<id>-<slug>.txt`,
  // produce a text/plain Blob + anchor click. Byte-identical output
  // to the button so a mixed keystroke-and-mouse workflow doesn't
  // produce inconsistent files. **Scope** `selected` (single
  // finding). **Guards** `selected != null && selected.evidence`
  // (no-op when the finding has no evidence blob to save — some
  // info-level passive findings are title-only), Alt+Shift only
  // (no Ctrl/Meta so Ctrl+Shift+E "export to editor" muscle memory
  // stays untouched), text-input focus skip. **No-op silent**
  // when no selection or no evidence.
  useEffect(() => {
    function onSaveEvidenceKey(e: KeyboardEvent) {
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
      if (!selected || !selected.evidence) return;
      e.preventDefault();
      const slug =
        (selected.title || "")
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, "-")
          .replace(/^-|-$/g, "")
          .slice(0, 40) || "evidence";
      const name = `evidence-${selected.id}-${slug}.txt`;
      try {
        const blob = new Blob([selected.evidence], {
          type: "text/plain;charset=utf-8",
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
    document.addEventListener("keydown", onSaveEvidenceKey);
    return () => document.removeEventListener("keydown", onSaveEvidenceKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected]);

  // R415: Alt+Shift+I inverts the bulk selection across the current
  // filtered view — operators who want "everything EXCEPT these
  // three" workflow (narrow-filter → J/K-walk to the 3 outliers →
  // click to select each → Alt+Shift+I to get the inverse set).
  // Natural extension of R328 Ctrl+A (select all filtered) and
  // R375 Alt+Shift+C (clear selection). **Scope** `filteredFindings`
  // so operators who narrowed via chips get the invert within just
  // the visible subset — matches R328 scope. **Mechanism** build
  // next = `new Set(filteredFindings.filter(f => !selectedIds.has(f.id)).map(f => f.id))`
  // so rows currently in bulkRows drop out and the rest come in.
  // Rows outside `filteredFindings` (hidden by chip filter) stay
  // untouched — matches the "operates on visible subset" muscle
  // memory established by R328. **Guards** Alt+Shift only, text-
  // input focus skip. **No-op silent** when `filteredFindings` is
  // empty.
  useEffect(() => {
    function onInvertKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key !== "I" && e.key !== "i") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (filteredFindings.length === 0) return;
      e.preventDefault();
      setSelectedIds((prev) => {
        const next = new Set<number>();
        for (const f of filteredFindings) {
          if (!prev.has(f.id)) next.add(f.id);
        }
        return next;
      });
    }
    document.addEventListener("keydown", onInvertKey);
    return () => document.removeEventListener("keydown", onInvertKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filteredFindings]);

  // R413: Alt+Shift+R reruns active-scan probes on the currently-
  // selected finding — keyboard version of the detail-pane
  // "Rerun active scan" button + the row-right-click entry.
  // Operators triaging a probe finding want a one-key re-fire to
  // check reproducibility ("did it really come from THIS tx?") or
  // confirm a fix landed ("same tx, different result after the
  // dev's deploy"). **Letter choice** R = Rerun. Alt+Shift
  // modifier differentiates from any plain-R text-editor muscle
  // memory. **Scope** `selected` (single finding) — the bulk
  // version has its own toolbar button + confirms with a traffic
  // bump warning, so a bulk keyboard shortcut would be too
  // dangerous (one keystroke → 50× backend active-scan dispatch
  // against a target). Single-row only via keyboard. **Guards**
  // `selected != null && selected.transaction_id != null`
  // (passive-only findings skipped), `!rerunBusy` to prevent
  // double-fires. Alt+Shift only, text-input focus skip. **No-op
  // silent** when selected finding lacks tx or no selection.
  useEffect(() => {
    function onRerunKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key !== "R" && e.key !== "r") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (!selected || !selected.transaction_id || rerunBusy) return;
      e.preventDefault();
      void rerunActiveScan(selected);
    }
    document.addEventListener("keydown", onRerunKey);
    return () => document.removeEventListener("keydown", onRerunKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected, rerunBusy]);

  // R398: Alt+Shift+L copies the bulk-selected findings' locations
  // (insertion_point → fallback title) to clipboard — keyboard
  // companion to R356's "📋 Copy locations" toolbar button. Pairs
  // with R389 Alt+Shift+M (Markdown dump) so the Scanner Alt+Shift
  // family grows a coherent "copy formats" set: M = Markdown,
  // L = Locations, T/V/F/K/C = status/triage ops. **Letter choice**
  // L = Locations; distinct enough from the status-op letters that
  // operators can mentally classify "copy ops vs status ops" at a
  // glance. **Format** matches R356 — `insertion_point || title`
  // per row, deduped via `Set`, sorted alpha for diff-friendly
  // stable output. **Scope** `bulkRows`. **Guards** Alt+Shift
  // only, text-input focus skip. **No-op silent** when empty.
  useEffect(() => {
    function onBulkCopyLocationsKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key !== "L" && e.key !== "l") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (bulkRows.length === 0) return;
      e.preventDefault();
      void (async () => {
        try {
          const uniq = Array.from(
            new Set(bulkRows.map((f) => f.insertion_point || f.title)),
          ).sort();
          await navigator.clipboard.writeText(uniq.join("\n"));
        } catch (err) {
          alert(`${err}`);
        }
      })();
    }
    document.addEventListener("keydown", onBulkCopyLocationsKey);
    return () => document.removeEventListener("keydown", onBulkCopyLocationsKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [bulkRows]);

  // R389: Alt+Shift+M copies the bulk-selected findings as a
  // Markdown document to the clipboard — keyboard companion to
  // R369's "📋 Copy Markdown" toolbar button. Joins the cross-
  // panel Alt+Shift+U family (R386/R387/R388) in spirit:
  // "dump the current working set to clipboard without a mouse
  // pivot". **Letter choice** M = Markdown — avoids conflict
  // with Alt+Shift+U (used across the app for URL dumps) and
  // sits next to Alt+Shift+N (R378 note editor) so the "Markdown
  // / Note" annotation shortcuts live adjacent. **Mechanism**
  // reuses the shared `bulkCopyMarkdown()` helper so the keystroke
  // and button produce byte-identical output. **Guards** Alt+Shift
  // only, text-input focus skip. **No-op when empty** silent,
  // same as the helper.
  useEffect(() => {
    function onBulkCopyMarkdownKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key !== "M" && e.key !== "m") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (bulkRows.length === 0) return;
      e.preventDefault();
      void bulkCopyMarkdown();
    }
    document.addEventListener("keydown", onBulkCopyMarkdownKey);
    return () => document.removeEventListener("keydown", onBulkCopyMarkdownKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [bulkRows]);

  // R379: Alt+Shift+K marks every bulk-selected finding as wontfix
  // — extends the bulk-status keyboard group (R358 Alt+Shift+V,
  // R364 Alt+Shift+T, R366 Alt+Shift+F) to a quartet with a
  // dismissal keystroke for issues that won't be patched: inherited
  // third-party CVEs, deliberate design tradeoffs, risk-accepted
  // items. Pairs with the "Mark wontfix" button from R361's bulk
  // status sextet. **Letter choice**: K is right next to J (vim
  // down) which operators already use for row-walking, so the
  // whole "walk → Ctrl+A → Alt+Shift+K" flow stays on the home
  // row. "W" would've been more mnemonic but it's already consumed
  // by browser Ctrl+W close-tab muscle memory. **Guards + scope**
  // identical to R366 / R364 / R358 — Alt+Shift only, text-input
  // focus skip, bulkRows (not selected), no-op when empty.
  useEffect(() => {
    function onBulkWontfixKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key !== "K" && e.key !== "k") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (bulkRows.length === 0) return;
      e.preventDefault();
      void bulkSetStatus("wontfix");
    }
    document.addEventListener("keydown", onBulkWontfixKey);
    return () => document.removeEventListener("keydown", onBulkWontfixKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [bulkRows]);

  // R364: Alt+Shift+T marks every bulk-selected finding as triaging
  // — keyboard version of the bulk "Mark triaging" button. Pairs
  // with R358 Alt+Shift+V so operators get a two-keystroke
  // promotion pipeline: Ctrl+A → Alt+Shift+T (bulk promote to
  // triaging) and Ctrl+A → Alt+Shift+V (bulk promote to verified).
  // Mirror of R358: same guards (Alt+Shift only, text-input skip),
  // same scope (bulkRows not selected — that's R338 Alt+T's role),
  // same no-op-when-empty short-circuit.
  useEffect(() => {
    function onBulkTriagingKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key !== "T" && e.key !== "t") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (bulkRows.length === 0) return;
      e.preventDefault();
      void bulkSetStatus("triaging");
    }
    document.addEventListener("keydown", onBulkTriagingKey);
    return () => document.removeEventListener("keydown", onBulkTriagingKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [bulkRows]);

  // R358: Alt+Shift+V marks every bulk-selected finding as verified
  // — keyboard version of the bulk "Verify" button in the toolbar.
  // Operators J/K-walk + Ctrl+A to select every filtered row (R328)
  // then one key promotes the whole set to verified. Natural pipe:
  // filter down → Ctrl+A → Alt+Shift+V. **Scope** `bulkRows` not
  // `selected` (that's R337 Alt+V's role). **Guards** mirror R337:
  // Alt+Shift (no Ctrl/Meta), text-input focus skip. **No-op** when
  // bulk selection is empty.
  useEffect(() => {
    function onBulkVerifyKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key !== "V" && e.key !== "v") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (bulkRows.length === 0) return;
      e.preventDefault();
      void bulkSetVerification("verified");
    }
    document.addEventListener("keydown", onBulkVerifyKey);
    return () => document.removeEventListener("keydown", onBulkVerifyKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [bulkRows]);

  // R342: Alt+F marks the current `selected` finding as false
  // positive — completes the status-marking trio alongside R337
  // Alt+V (verified) and R338 Alt+T (triaging). Operators J/K-
  // walking a noisy detector's output want a one-key dismissal
  // for the inevitable chatter. **Confirm pre-fire** false
  // positive is a reversible-but-sticky status so a mid-walk
  // typo (Alt+T → Alt+F slip) would be annoying — mirror the
  // row-right-click behaviour by just firing without confirm,
  // since Alt+V / Alt+T don't confirm either and the operator
  // can re-mark with Alt+T to recover. **Mechanism + guards
  // identical to R337/R338** reuses findingSetStatus(id,
  // "false_positive"), plain Alt only, text-input focus skip,
  // no-op when nothing selected.
  useEffect(() => {
    function onFKey(e: KeyboardEvent) {
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      if (e.key !== "f" && e.key !== "F") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (!selected) return;
      e.preventDefault();
      void api
        .findingSetStatus(selected.id, "false_positive")
        .then(() => api.findingsList().then(setFindings))
        .catch((err) => alert(`${err}`));
    }
    document.addEventListener("keydown", onFKey);
    return () => document.removeEventListener("keydown", onFKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected?.id]);

  // R338: Alt+T marks the current `selected` finding as triaging —
  // keyboard companion to R337 Alt+V. The two together give
  // operators J/K-walking the triage list a two-key promotion
  // pipeline: J → inspect → Alt+T (promote to triaging) → J →
  // Alt+V (promote to verified) → J → next. Mirrors the status
  // write pattern from the row-right-click "Mark as triaging"
  // entry — same `findingSetStatus(id, "triaging")` call.
  // **Guards + scope** identical to R337: plain Alt only, text-
  // input skip, no-op when nothing selected.
  useEffect(() => {
    function onTKey(e: KeyboardEvent) {
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      if (e.key !== "t" && e.key !== "T") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (!selected) return;
      e.preventDefault();
      void api
        .findingSetStatus(selected.id, "triaging")
        .then(() => api.findingsList().then(setFindings))
        .catch((err) => alert(`${err}`));
    }
    document.addEventListener("keydown", onTKey);
    return () => document.removeEventListener("keydown", onTKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected?.id]);

  // R426: Alt+Shift+Y marks the current `selected` finding's
  // verification axis back to "unverified" — undo-ish companion
  // to R337's Alt+V (verified). Operators misclicking Alt+V on
  // the wrong row (one-off keystroke slip during a J/K-walk pass)
  // want a fast rollback without walking to the detail-pane
  // dropdown. **Letter choice** Y = Yank (unverify). Alt+Shift
  // modifier reserves the plain-Alt letter space for different
  // ops. **Mechanism** reuses `findingSetVerification(id,
  // "unverified")` — mirrors R337 Alt+V's write path exactly but
  // with the opposite enum value. **Guards** Alt+Shift only, text-
  // input focus skip, no-op when nothing selected. No confirm
  // pre-fire — mirrors R337 Alt+V (reversible via another
  // keystroke).
  useEffect(() => {
    function onYKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      if (e.key !== "y" && e.key !== "Y") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (!selected) return;
      e.preventDefault();
      void api
        .findingSetVerification(selected.id, "unverified")
        .then(() => api.findingsList().then(setFindings))
        .catch((err) => alert(`${err}`));
    }
    document.addEventListener("keydown", onYKey);
    return () => document.removeEventListener("keydown", onYKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected?.id]);

  // R423: Alt+W marks the current `selected` finding as wontfix —
  // single-row companion to R379's Alt+Shift+K bulk. Completes the
  // single-row status quartet alongside R337 Alt+V (verified),
  // R338 Alt+T (triaging), R342 Alt+F (false positive). Operators
  // J/K-walking a scope-pass's issue list often need to flip a
  // specific inherited-CVE / risk-accepted finding to wontfix
  // without walking the row-right-click menu. **Letter choice**
  // W = Wontfix. **Mechanism + guards identical to R337/R338/R342**:
  // reuses `findingSetStatus(id, "wontfix")`, plain Alt only (no
  // Ctrl/Meta/Shift so Alt+Shift+W stays free), text-input focus
  // skip, no-op when nothing selected. No confirm pre-fire — same
  // policy as R337/R338/R342 since the single-row status flips are
  // reversible via another Alt+T/V/F keystroke.
  useEffect(() => {
    function onWKey(e: KeyboardEvent) {
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      if (e.key !== "w" && e.key !== "W") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (!selected) return;
      e.preventDefault();
      void api
        .findingSetStatus(selected.id, "wontfix")
        .then(() => api.findingsList().then(setFindings))
        .catch((err) => alert(`${err}`));
    }
    document.addEventListener("keydown", onWKey);
    return () => document.removeEventListener("keydown", onWKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected?.id]);

  // R337: Alt+V marks the current `selected` finding as verified —
  // keyboard version of the row-right-click "Verify" entry. Lets
  // operators J/K-walk the triage list and smash Alt+V on
  // confirmed findings without a mouse pivot. **Mechanism** reuses
  // `findingSetVerification(id, "verified")` + refreshes the list.
  // **Guards** plain Alt only (no Ctrl/Meta/Shift), text-input
  // focus skip so Alt+V inside a comment-ish box keeps native
  // paste behavior. **No-op** when nothing is selected.
  useEffect(() => {
    function onVKey(e: KeyboardEvent) {
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      if (e.key !== "v" && e.key !== "V") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (!selected) return;
      e.preventDefault();
      void api
        .findingSetVerification(selected.id, "verified")
        .then(() => api.findingsList().then(setFindings))
        .catch((err) => alert(`${err}`));
    }
    document.addEventListener("keydown", onVKey);
    return () => document.removeEventListener("keydown", onVKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected?.id]);

  // R328: Ctrl+A selects every row in the current filtered view —
  // match the standard spreadsheet / IDE / mail client affordance
  // so operators triaging a filtered list can one-key fan out to
  // every row before applying a bulk op (R265 mark triaging, R287
  // confirm triaging, R293 verify, R312 add tag, R288 bulk JSONL,
  // etc.). Scoped to `filteredFindings` so operators who filtered
  // down to a specific sev × detector × status subset get just
  // those rows into the selection — matches what Burp's own
  // Scanner "Select all visible" context-menu does. Guards mirror
  // the R138 Delete + R197 J/K shortcuts: no Meta/Alt/Shift
  // combinations, bail inside text inputs so Ctrl+A in a
  // commenting modal still selects the text instead of nuking it.
  useEffect(() => {
    function onCtrlA(e: KeyboardEvent) {
      if (!(e.ctrlKey || e.metaKey)) return;
      if (e.altKey || e.shiftKey) return;
      if (e.key !== "a" && e.key !== "A") return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (filteredFindings.length === 0) return;
      e.preventDefault();
      setSelectedIds(new Set(filteredFindings.map((f) => f.id)));
    }
    document.addEventListener("keydown", onCtrlA);
    return () => document.removeEventListener("keydown", onCtrlA);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filteredFindings]);

  // R197: J / K vim-style navigation across the filtered findings
  // list. Mirrors the "next / previous row" convention that Burp
  // Pro + GitHub + Gmail all use. Operators scanning a long post-
  // scan triage list want to breeze through without the mouse.
  //
  // Semantics:
  //  - j → next finding in `filteredFindings`
  //  - k → previous finding
  //  - no modifier combinations (Ctrl/Meta/Alt/Shift bail out so
  //    we don't collide with Ctrl+J  — DevTools, Ctrl+K — URL bar,
  //    Shift+J — select-extend, etc.)
  //  - text-input / textarea / contenteditable skip (standard
  //    guard — matches R96, R138, R194)
  //  - no-wrap: at the top K stays put, at the bottom J stays
  //    put. Vim behaviour; avoids the "I pressed J one too many
  //    times and jumped to the first row" footgun.
  //  - no-selection start: J picks the first finding, K picks the
  //    last — gives operators a one-key way to "focus the list"
  //    before they start navigating.
  //  - scrollIntoView on the newly-selected row post-render so J/K
  //    through a long list keeps the active row visible.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      // R362: ArrowDown / ArrowUp are aliases for J / K — matches
      // the dual-navigation convention HistoryPanel R208 shipped
      // (both arrows and vim keys). Operators coming from Burp
      // Pro expect arrow nav, operators coming from Vim / Gmail /
      // GitHub expect J/K. One handler, four keys. Shift+arrow
      // would normally extend selection; we don't support it here
      // (bail on any modifier) because Scanner's bulk selection
      // is Ctrl/Shift-click driven, not keyboard.
      const isDown = e.key === "j" || e.key === "ArrowDown";
      const isUp = e.key === "k" || e.key === "ArrowUp";
      if (!isDown && !isUp) return;
      if (e.ctrlKey || e.metaKey || e.altKey || e.shiftKey) return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (filteredFindings.length === 0) return;
      e.preventDefault();
      const curIdx = selected
        ? filteredFindings.findIndex((f) => f.id === selected.id)
        : -1;
      let nextIdx: number;
      if (curIdx < 0) {
        nextIdx = isDown ? 0 : filteredFindings.length - 1;
      } else {
        nextIdx = isDown
          ? Math.min(curIdx + 1, filteredFindings.length - 1)
          : Math.max(curIdx - 1, 0);
      }
      const next = filteredFindings[nextIdx];
      if (next) {
        setSelected(next);
        // Let React render the new .selected class, then scroll.
        setTimeout(() => {
          document
            .querySelector("tr.selected")
            ?.scrollIntoView({ block: "nearest" });
        }, 0);
      }
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filteredFindings, selected]);

  // R230: Alt+1..5 toggles the matching severity chip filter.
  // Mapping: 1=critical / 2=high / 3=medium / 4=low / 5=info —
  // matches the ordering of the sev-chip strip in the toolbar.
  // Operators triaging a long findings list can hop between
  // severity cuts without mouse pivots. Guards mirror R197 J/K:
  //   - plain Alt only (no Ctrl/Meta/Shift co-modifiers)
  //   - text-input / textarea / contenteditable focus skip
  //   - digit 1..5 only (0 could clear everything but we have Esc
  //     for that already from R202 — avoid two paths to the same
  //     thing)
  useEffect(() => {
    const SEV_BY_DIGIT: Record<string, SevKey> = {
      "1": "critical",
      "2": "high",
      "3": "medium",
      "4": "low",
      "5": "info",
    };
    function onKey(e: KeyboardEvent) {
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      // R290: Alt+6 toggles the R167 "actionable" sev preset
      // (sev chip set = {critical, high, medium}, hides low +
      // info noise). Mirror of R289's Alt+Shift+8 untriaged
      // preset but on the sev axis — "pick a semantic group" slot
      // sits past the digits that map to individual sev chips
      // (1..5) for a clean visual separation.
      if (e.key === "6") {
        e.preventDefault();
        const actionable: SevKey[] = ["critical", "high", "medium"];
        const allOn = actionable.every((s) => sevFilter.has(s));
        const nothingElse = !sevFilter.has("low") && !sevFilter.has("info");
        const alreadyActionable = allOn && nothingElse;
        setSevFilter(
          alreadyActionable ? new Set() : new Set(actionable),
        );
        return;
      }
      // R334: Alt+9 toggles the "info-only" sev preset — mirror of
      // R290's Alt+6 actionable preset but on the opposite end of
      // the severity spectrum. Operators doing final-pass sanity
      // triage want to zoom in on just the info-level findings to
      // confirm nothing high-impact got mis-classified as info or
      // that the auto-detectors aren't drowning the signal in low-
      // priority chatter. One click arms it (sev chip set = {info},
      // hides every other sev), second click clears.
      if (e.key === "9") {
        e.preventDefault();
        const alreadyInfoOnly =
          sevFilter.has("info") &&
          !sevFilter.has("critical") &&
          !sevFilter.has("high") &&
          !sevFilter.has("medium") &&
          !sevFilter.has("low");
        setSevFilter(
          alreadyInfoOnly ? new Set() : new Set<SevKey>(["info"]),
        );
        return;
      }
      const sev = SEV_BY_DIGIT[e.key];
      if (!sev) return;
      e.preventDefault();
      toggleSev(sev);
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sevFilter]);

  // R270: Alt+Shift+1..6 toggles the matching status chip filter —
  // sibling of R230's Alt+1..5 for severity, same pattern R262
  // used on HistoryPanel to layer status-class filters alongside
  // the existing Alt+digit highlight shortcut. Mapping matches
  // the status chip strip order below (1=new, 2=triaging,
  // 3=confirmed, 4=false_positive, 5=fixed, 6=wontfix). Alt+Shift+0
  // clears every status chip in one key for a quick reset.
  // Guards: Alt+Shift only (no Ctrl / Meta co-modifiers), digit
  // 0..6 only, text-input / textarea / contenteditable focus skip.
  useEffect(() => {
    const STATUS_BY_DIGIT: Record<string, string> = {
      "1": "new",
      "2": "triaging",
      "3": "confirmed",
      "4": "false_positive",
      "5": "fixed",
      "6": "wontfix",
    };
    function onKey(e: KeyboardEvent) {
      if (!e.altKey || !e.shiftKey || e.ctrlKey || e.metaKey) return;
      const digit = e.key;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      if (digit === "0") {
        e.preventDefault();
        setIssueStatusFilter(new Set());
        return;
      }
      // R289: Alt+Shift+8 toggles the R196 "untriaged" preset
      // (status chip set = {new, triaging}, hides every other
      // status). Picking "8" because 1..6 are the individual
      // status chips (R270), 0 clears, 7/9 stay reserved for
      // future preset chips. Operator chord ergonomics: Alt+Shift
      // digit sits alongside R270's row of status toggles so the
      // "set of statuses" axis stays mentally grouped.
      // R335: Alt+Shift+9 toggles the "closed" status preset —
      // mirror of R289's Alt+Shift+8 untriaged preset but on the
      // other half of the status axis. Operators auditing the
      // "already handled" bucket (confirmed-and-shipped + false
      // positives + fixed + wontfix) want a one-key preset to
      // scan whether anything was mis-closed. Set = {confirmed,
      // false_positive, fixed, wontfix}. Status new + triaging
      // stay hidden so operators focus on the handled bucket.
      if (digit === "9") {
        e.preventDefault();
        const closed = ["confirmed", "false_positive", "fixed", "wontfix"];
        const current = issueStatusFilter;
        const allOn = closed.every((s) => current.has(s));
        const nothingElse =
          !current.has("new") && !current.has("triaging");
        const alreadyClosed = allOn && nothingElse;
        setIssueStatusFilter(
          alreadyClosed ? new Set() : new Set(closed),
        );
        return;
      }
      if (digit === "8") {
        e.preventDefault();
        const untriaged = ["new", "triaging"];
        const current = issueStatusFilter;
        const allOn = untriaged.every((s) => current.has(s));
        const nothingElse =
          !current.has("confirmed") &&
          !current.has("false_positive") &&
          !current.has("fixed") &&
          !current.has("wontfix");
        const alreadyUntriaged = allOn && nothingElse;
        setIssueStatusFilter(
          alreadyUntriaged ? new Set() : new Set(untriaged),
        );
        return;
      }
      const status = STATUS_BY_DIGIT[digit];
      if (!status) return;
      e.preventDefault();
      toggleIssueStatus(status);
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [issueStatusFilter]);

  // R202: Esc clears every chip filter (sev + status + tag) when
  // the operator isn't typing in an input. Mirror of R201's
  // History Esc-clears-search but at the panel level — the panel
  // doesn't have a focusable "chip bar", so this is a document-
  // scoped handler like R138 Delete + R197 J/K.
  //
  // Guards:
  //  - no-op when no chip is active (so Esc elsewhere — modals,
  //    popovers, context menus — can still react normally without
  //    the Scanner stealing it)
  //  - no-op when focus is inside an input / textarea /
  //    contenteditable (so Esc inside a comment editor can clear
  //    the field, not nuke the filters)
  //  - no modifier keys (Ctrl/Meta/Alt/Shift bail out — pure Esc
  //    only)
  useEffect(() => {
    function onEsc(e: KeyboardEvent) {
      if (e.key !== "Escape") return;
      if (e.ctrlKey || e.metaKey || e.altKey || e.shiftKey) return;
      if (!anyChipActive) return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName ?? "";
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable
      )
        return;
      e.preventDefault();
      clearChipFilters();
    }
    document.addEventListener("keydown", onEsc);
    return () => document.removeEventListener("keydown", onEsc);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [anyChipActive]);

  function bulkExportCsv() {
    if (bulkRows.length === 0) return;
    const headers = [
      "id",
      "severity",
      "confidence",
      "detector",
      "title",
      "status",
      "verification",
      "evidence",
      "transaction_id",
    ];
    const esc = (v: unknown) => {
      const s = v == null ? "" : String(v);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const body = bulkRows
      .map((f) =>
        [
          f.id,
          f.severity,
          f.confidence,
          f.detector,
          f.title,
          f.status,
          f.verification,
          f.evidence ?? "",
          f.transaction_id ?? "",
        ]
          .map(esc)
          .join(","),
      )
      .join("\n");
    const csv = [headers.join(","), body].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `findings-${new Date().toISOString().replace(/[:.]/g, "-")}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  // R601: Clipboard-only CSV counterpart to bulkExportCsv on Scanner.
  // Mirrors R600 HistoryPanel pattern — operators pasting into
  // Excel / Sheets want the finding table directly on the clipboard
  // without the file-save + open roundtrip. Byte-identical column
  // shape to bulkExportCsv (same 9 columns + same esc rules) so
  // clipboard and file outputs stay interchangeable.
  function bulkCopyCsv() {
    if (bulkRows.length === 0) return;
    const headers = [
      "id",
      "severity",
      "confidence",
      "detector",
      "title",
      "status",
      "verification",
      "evidence",
      "transaction_id",
    ];
    const esc = (v: unknown) => {
      const s = v == null ? "" : String(v);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const body = bulkRows
      .map((f) =>
        [
          f.id,
          f.severity,
          f.confidence,
          f.detector,
          f.title,
          f.status,
          f.verification,
          f.evidence ?? "",
          f.transaction_id ?? "",
        ]
          .map(esc)
          .join(","),
      )
      .join("\n");
    const csv = [headers.join(","), body].join("\n");
    void navigator.clipboard.writeText(csv);
  }

  // R288: Bulk JSONL export — fourth entry in the JSONL family
  // after R284 (Logger), R285 (History), R286 (Intruder). The
  // existing bulkExportCsv flattens findings to 9 columns and
  // drops the nested fields (tags: string[], references: string[],
  // insertion_point, remediation, description, note, assignee).
  // JSONL preserves the full StoredFinding shape so operators
  // piping into jq / grep / Jira CSV import / Linear API can keep
  // every field accessible by key. Scope matches CSV: current
  // multi-selection. One JSON object per line — no top-level
  // array wrapper — so streaming consumers (jq, ELK ingest,
  // import pipelines) can start processing before download
  // finishes. Separate from the R122 Report path (which emits
  // JSON / SARIF / Markdown / HTML / CSV via the backend) because
  // this one operates on the already-selected shortlist without
  // needing a backend round-trip.
  function bulkExportJsonl() {
    if (bulkRows.length === 0) return;
    const body = bulkRows.map((f) => JSON.stringify(f)).join("\n");
    const blob = new Blob([body + "\n"], {
      type: "application/x-ndjson;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `findings-${new Date().toISOString().replace(/[:.]/g, "-")}.jsonl`;
    a.click();
    URL.revokeObjectURL(url);
  }

  // R606: Clipboard-only JSON array counterpart to bulkExportJsonl —
  // second entry in the cross-panel "📋 Copy as JSON" family after
  // HistoryPanel R605. Operators dropping finding records into
  // test fixtures / detector-tuning datasets / jq pipelines want a
  // top-level JSON array (not JSONL) on the clipboard directly.
  // Pretty-printed with 2-space indent for diff-friendly paste.
  // Preserves every StoredFinding field (tags, references,
  // insertion_point, remediation, description, note, assignee) via
  // JSON.stringify of the row objects.
  function bulkCopyJson() {
    if (bulkRows.length === 0) return;
    void navigator.clipboard.writeText(JSON.stringify(bulkRows, null, 2));
  }

  // R615: Clipboard-only JSONL counterpart to bulkExportJsonl —
  // second entry in cross-panel "Copy as JSONL" family after
  // HistoryPanel R614. Streaming-friendly dense format for jq /
  // ELK consumers. Byte-identical to the file export.
  function bulkCopyJsonl() {
    if (bulkRows.length === 0) return;
    const body = bulkRows.map((f) => JSON.stringify(f)).join("\n");
    void navigator.clipboard.writeText(body);
  }

  function clearSelection() {
    setSelectedIds(new Set());
  }

  // ---- Report export (HTML / JSON / SARIF) --------------------------
  //
  // Burp-style "Report selected issues" / "Report all issues" with
  // three output formats. The subset is driven by the current bulk
  // selection: when selectedIds is empty, the export covers every
  // finding; otherwise just those rows. A tiny inline popover under
  // the Export-report button exposes the three formats; the native
  // save-path dialog is replaced by a `prompt()` because this app
  // doesn't ship tauri-plugin-dialog yet — the backend validates the
  // path before touching disk.
  const [reportMenuOpen, setReportMenuOpen] = useState(false);
  const [reportBusy, setReportBusy] = useState(false);
  // R123: Manual-issue composer state. One modal with fields +
  // Save / Cancel. Draft fields live here so the operator can
  // partially fill the form, flip to a different panel, come back,
  // and keep their edits (modal stays mounted when `manualIssueOpen`
  // is true; closing clears the fields via `resetManualIssue`).
  const [manualIssueOpen, setManualIssueOpen] = useState(false);
  const [manualTitle, setManualTitle] = useState("");
  const [manualSeverity, setManualSeverity] = useState<
    "critical" | "high" | "medium" | "low" | "info"
  >("medium");
  const [manualDescription, setManualDescription] = useState("");
  const [manualEvidence, setManualEvidence] = useState("");
  const [manualRemediation, setManualRemediation] = useState("");
  const [manualDetector, setManualDetector] = useState("manual");
  const [manualTxId, setManualTxId] = useState("");
  const [manualTags, setManualTags] = useState("");
  const [manualBusy, setManualBusy] = useState(false);
  function resetManualIssue() {
    setManualTitle("");
    setManualSeverity("medium");
    setManualDescription("");
    setManualEvidence("");
    setManualRemediation("");
    setManualDetector("manual");
    setManualTxId("");
    setManualTags("");
  }
  async function saveManualIssue() {
    const title = manualTitle.trim();
    if (title.length === 0) {
      alert("Title is required.");
      return;
    }
    const tags = manualTags
      .split(",")
      .map((t) => t.trim())
      .filter((t) => t.length > 0);
    const tx = manualTxId.trim();
    let txId: number | undefined;
    if (tx.length > 0) {
      const n = Number(tx);
      if (!Number.isFinite(n) || !Number.isInteger(n) || n <= 0) {
        alert(`Transaction id must be a positive integer (got: ${tx})`);
        return;
      }
      txId = n;
    }
    setManualBusy(true);
    try {
      const newId = await api.findingAddManual({
        title,
        severity: manualSeverity,
        description: manualDescription.trim() || undefined,
        detector: manualDetector.trim() || undefined,
        transaction_id: txId,
        evidence: manualEvidence.trim() || undefined,
        remediation: manualRemediation.trim() || undefined,
        tags: tags.length > 0 ? tags : undefined,
      });
      await refresh();
      // Pop the fresh row into the detail pane so the operator can
      // review + extend immediately. If the chip filters hide the
      // new row the find-by-id below falls back to a direct fetch.
      let fresh = (await api.findingsList()).find((f) => f.id === newId);
      if (fresh) setSelected(fresh);
      setManualIssueOpen(false);
      resetManualIssue();
    } catch (err) {
      alert(`Add failed: ${err}`);
    } finally {
      setManualBusy(false);
    }
  }
  useEffect(() => {
    if (!reportMenuOpen) return;
    const onDocClick = (e: MouseEvent) => {
      const t = e.target as Node;
      const btn = document.querySelector("[data-scanner-report-btn]");
      const pop = document.querySelector("[data-scanner-report-popover]");
      if (btn && btn.contains(t)) return;
      if (pop && pop.contains(t)) return;
      setReportMenuOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setReportMenuOpen(false);
    };
    document.addEventListener("mousedown", onDocClick);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDocClick);
      document.removeEventListener("keydown", onKey);
    };
  }, [reportMenuOpen]);
  async function exportReport(format: "html" | "json" | "sarif" | "markdown" | "csv") {
    setReportMenuOpen(false);
    if (reportBusy) return;
    // Suggest a filename that already carries the format extension
    // and a timestamp so operators get something sensible on the
    // first keypress; they can edit the full path before accepting.
    const ts = new Date().toISOString().replace(/[:.]/g, "-");
    // Markdown gets the `.md` extension (shorter + convention) while
    // the others keep `.html` / `.json` / `.sarif` / `.csv` as the
    // format id.
    const ext = format === "markdown" ? "md" : format;
    const defaultName = `burpfree-findings-${ts}.${ext}`;
    const path = prompt(
      `Save ${format.toUpperCase()} report to… (absolute path)`,
      defaultName,
    );
    if (!path || !path.trim()) return;
    setReportBusy(true);
    try {
      const findingIds =
        selectedIds.size > 0 ? Array.from(selectedIds) : undefined;
      const result = await api.scannerReportWrite({
        path: path.trim(),
        format,
        findingIds,
      });
      const scope =
        findingIds && findingIds.length > 0
          ? `${result.findings_count} selected finding${result.findings_count === 1 ? "" : "s"}`
          : `${result.findings_count} finding${result.findings_count === 1 ? "" : "s"}`;
      alert(
        `Wrote ${scope} to\n${result.path}\n(${result.bytes_written.toLocaleString()} bytes · ${result.format.toUpperCase()})`,
      );
    } catch (e) {
      alert(`Report export failed: ${e}`);
    } finally {
      setReportBusy(false);
    }
  }

  async function runPassiveWs() {
    setBusyWs(true);
    try {
      const n = await api.passiveWsRunNow();
      alert(`${n} WebSocket finding(s) added.`);
      await refresh();
    } finally {
      setBusyWs(false);
    }
  }

  return (
    <div className="panel">
      <div className="toolbar">
        {/* R774: Burp-identical primary action chrome on Scanner's
            principal entry point — "Run passive scan over history".
            Mirrors the red/orange `.burp-send` treatment applied to
            Repeater (Send R732), Intruder (Start attack R753),
            Proxy (Forward R754), and Collaborator (Start listener
            R755). Keeps the Burp primary-action language consistent
            across every panel: the single most-used action in each
            tool wears the Burp red regardless of its label. The
            busy-state fallback still disables the button; chrome
            just signals "this is the one you want" at a glance. */}
        <button
          className="burp-send"
          disabled={busy}
          onClick={runPassive}
          title="Run every passive detector across the stored HTTP history. Primary Scanner action — adds findings for leaks, auth gaps, info-disclosure, misconfig, header hygiene, and more."
        >
          Run passive scan over history
        </button>
        {/* R139: Run passive on in-scope only — tight audit path. */}
        <button
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            try {
              const n = await api.passiveRunFiltered({ in_scope_only: true });
              alert(`${n} finding(s) added (in-scope only).`);
              await refresh();
            } catch (e) {
              alert(`${e}`);
            } finally {
              setBusy(false);
            }
          }}
          title="Run passive detectors over in-scope transactions only — tighter audit focus for noisy projects"
        >
          Run passive (in-scope only)
        </button>
        <button disabled={busyWs} onClick={runPassiveWs} title="Scan stored WebSocket frames for leaked secrets / tokens / PII">
          Scan WebSocket frames
        </button>
        <button
          disabled={liveBusy}
          onClick={toggleLiveScan}
          title={
            liveScan
              ? "Live passive scan is ON — new in-scope traffic is scanned as it arrives. Click to disable."
              : "Live passive scan is OFF — only manual runs produce findings. Click to enable."
          }
          style={{
            background: liveScan ? "rgba(63, 180, 100, 0.18)" : undefined,
            border: liveScan ? "1px solid rgba(63, 180, 100, 0.55)" : undefined,
          }}
        >
          <span
            style={{
              display: "inline-block",
              width: 8,
              height: 8,
              borderRadius: 999,
              marginRight: 6,
              background: liveScan ? "#3fb464" : "#777",
              verticalAlign: "middle",
            }}
          />
          Live scan: {liveScan ? "ON" : "OFF"}
        </button>
        {/* ------------------------------------------------------- */}
        {/* Group-by-host toggle. Mirror of Burp's Scanner tree view */}
        {/* that groups issues under their host for a per-target     */}
        {/* summary ("example.com — 3 critical / 7 high / 12 med").  */}
        {/* The flat table is still the default (fast, scannable);  */}
        {/* flipping modes here switches the center pane to          */}
        {/* collapsible sections keyed on host or detector. R200     */}
        {/* replaced the R116 boolean toggle with a 3-way <select>.  */}
        {/* R252: Group count after the mode in the active label  */}
        {/* so operators see "Group: by host · 7 groups" without   */}
        {/* needing to count the <tr> headers below. "off" stays   */}
        {/* clean (no suffix). The <option> labels in the dropdown */}
        {/* list stay stable — only the current-value render       */}
        {/* varies via a controlled label trick: we actually wrap  */}
        {/* a span with the live count outside the select since    */}
        {/* <select> ignores JSX children on its options.           */}
        <select
          value={groupMode}
          onChange={(e) => setGroupMode(e.target.value as GroupMode)}
          className={groupMode !== "none" ? "primary" : ""}
          title={
            groupMode === "none"
              ? "Flat issue table. Switch to Group by host / detector for a tree-style summary with sev-count badges + per-group collapse."
              : groupMode === "host"
                ? `Grouping findings under their host — ${groupedFindings.length} group${groupedFindings.length === 1 ? "" : "s"}. Each shows severity-count badges + can be collapsed independently. Switch to Group: detector for an alternate pivot, or Group: off for the flat table.`
                : `Grouping findings under their detector id — ${groupedFindings.length} group${groupedFindings.length === 1 ? "" : "s"}. Each shows severity-count badges + can be collapsed independently. Switch to Group: host for an alternate pivot, or Group: off for the flat table.`
          }
          style={{ padding: "2px 6px", fontSize: 12 }}
        >
          <option value="none">Group: off</option>
          <option value="host">Group: by host</option>
          <option value="detector">Group: by detector</option>
        </select>
        {groupMode !== "none" && groupedFindings.length > 0 && (
          <span
            style={{
              fontSize: 10.5,
              color: "var(--text-dim)",
              marginLeft: 4,
              alignSelf: "center",
            }}
            title={`${groupedFindings.length} group${groupedFindings.length === 1 ? "" : "s"} currently rendered (post-chip filters)`}
          >
            · {groupedFindings.length} group{groupedFindings.length === 1 ? "" : "s"}
          </span>
        )}
        {/* R147: Expand / Collapse all groups. Only renders when   */}
        {/* a grouping mode is active since the buttons mean         */}
        {/* nothing in flat view. Collapse all = write every group   */}
        {/* key into collapsedGroups; expand all = clear the Set.   */}
        {groupMode !== "none" && groupedFindings.length > 0 && (
          <>
            <button
              className="ghost"
              disabled={collapsedGroups.size === 0}
              onClick={() => setCollapsedGroups(new Set())}
              title={
                collapsedGroups.size === 0
                  ? "No groups collapsed"
                  : `Expand all ${collapsedGroups.size} collapsed group${collapsedGroups.size === 1 ? "" : "s"}`
              }
              style={{ padding: "2px 6px", fontSize: 11 }}
            >
              ⇲ all
            </button>
            <button
              className="ghost"
              disabled={collapsedGroups.size === groupedFindings.length}
              onClick={() =>
                setCollapsedGroups(new Set(groupedFindings.map((g) => g.key)))
              }
              title={
                collapsedGroups.size === groupedFindings.length
                  ? "All groups already collapsed"
                  : `Collapse all ${groupedFindings.length} group${groupedFindings.length === 1 ? "" : "s"}`
              }
              style={{ padding: "2px 6px", fontSize: 11 }}
            >
              ⇱ all
            </button>
          </>
        )}
        <span className="spacer" style={{ flex: 1 }} />
        {/* ------------------------------------------------------- */}
        {/* R123: Manual issue. Mirror of Burp's "Add manual issue" */}
        {/* — pentesters add findings for things detectors won't    */}
        {/* catch (business-logic abuse, chained exploits, in-      */}
        {/* browser-only XSS). The composer opens a modal with      */}
        {/* title + severity + description + evidence + remediation */}
        {/* + optional tx-id + tags; backend sets confidence=firm,  */}
        {/* verification=verified, status=new, observation_count=1. */}
        <button
          onClick={() => setManualIssueOpen(true)}
          title="Add an operator-authored finding (business logic / chained exploits / things detectors miss)"
        >
          + Manual issue
        </button>
        {/* R130: Prune false positives — companion to R129 */}
        {/* HTTP-history prune. Operators who triage a scan + */}
        {/* dismiss noise as false_positive accumulate a long */}
        {/* tail of dismissed rows; this button zaps them in  */}
        {/* one click without touching anything still open.    */}
        <button
          className="ghost"
          onClick={() => void pruneFalsePositives()}
          title="Delete every finding whose status is `false_positive`. Rows marked new / triaging / confirmed / fixed / wontfix stay untouched. Cannot be undone."
        >
          ⚠ Prune FP
        </button>
        <button
          className="ghost"
          onClick={() => void pruneInfoFindings()}
          title="Delete every info-severity finding. Low / medium / high / critical stay untouched. Cannot be undone."
        >
          ⚪ Prune info
        </button>
        {/* R277: Copy counts — companion to R206 Summary. Where R206 */}
        {/* writes a one-line headline (`N total: X critical, …`), R277*/}
        {/* ships the full two-dimensional count matrix (severity ×   */}
        {/* status) so operators can paste a snapshot into a stand-up */}
        {/* / status report / ticket update and show how triage work  */}
        {/* is progressing. Markdown-friendly tabular layout fits in a*/}
        {/* code block or a mono-font Slack message. Zero recompute   */}
        {/* cost — reads sevCounts + statusCounts which are already   */}
        {/* memo-ised on findings change.                              */}
        <button
          onClick={async () => {
            const sevOrder: SevKey[] = ["critical", "high", "medium", "low", "info"];
            const statuses = ["new", "triaging", "confirmed", "false_positive", "fixed", "wontfix"];
            const sevLine = sevOrder
              .filter((k) => sevCounts[k] > 0)
              .map((k) => `${sevCounts[k]} ${k}`);
            const statusLine = statuses
              .filter((s) => (statusCounts[s] ?? 0) > 0)
              .map((s) => `${statusCounts[s]} ${s}`);
            const total = findings.length;
            const stamp = new Date().toISOString().replace(/\.\d+Z$/, "Z");
            const snippet =
              `BurpFree scan counts — ${stamp}\n` +
              `Total: ${total} finding${total === 1 ? "" : "s"}\n` +
              `  by severity: ${sevLine.length ? sevLine.join(", ") : "(none)"}\n` +
              `  by status:   ${statusLine.length ? statusLine.join(", ") : "(none)"}`;
            try {
              await navigator.clipboard.writeText(snippet);
            } catch (e) {
              alert(`Copy failed: ${e}`);
            }
          }}
          disabled={findings.length === 0}
          title={
            findings.length === 0
              ? "No findings yet — counts snapshot would be empty"
              : "Copy a sev × status count snapshot (Markdown-friendly tabular text) to the clipboard for status reports / stand-ups / tickets"
          }
        >
          📊 Counts
        </button>
        {/* R206: Copy summary — a one-shot Markdown snippet of the  */}
        {/* current sev-count breakdown that operators can paste    */}
        {/* into Slack / ticket updates / status reports mid-triage.*/}
        {/* Independent from R178 (per-finding Markdown) + R122     */}
        {/* (full HTML/JSON/SARIF/Markdown report); this is just    */}
        {/* the headline sentence. Reads sevCounts (already memo-   */}
        {/* ised on findings change) — zero recompute cost.         */}
        <button
          className="ghost"
          disabled={findings.length === 0}
          onClick={async () => {
            if (findings.length === 0) return;
            const order: SevKey[] = [
              "critical",
              "high",
              "medium",
              "low",
              "info",
            ];
            const parts = order
              .filter((k) => sevCounts[k] > 0)
              .map((k) => `${sevCounts[k]} ${k}`);
            const total = findings.length;
            const stamp = new Date().toISOString().replace(/\.\d+Z$/, "Z");
            const text =
              parts.length === 0
                ? `Scanner summary (${stamp}): 0 findings`
                : `Scanner summary (${stamp}): ${parts.join(" · ")} — total ${total}`;
            try {
              await navigator.clipboard.writeText(text);
            } catch (e) {
              alert(`Copy failed: ${e}`);
            }
          }}
          title={
            findings.length === 0
              ? "No findings yet — run a scan first"
              : `Copy a one-line Markdown summary of the sev-count breakdown (${findings.length} finding${findings.length === 1 ? "" : "s"} total) to clipboard`
          }
        >
          📋 Summary
        </button>
        <div style={{ position: "relative", display: "inline-block" }}>
          <button
            data-scanner-report-btn
            onClick={() => setReportMenuOpen((v) => !v)}
            disabled={reportBusy || findings.length === 0}
            title={
              findings.length === 0
                ? "No findings to report — run a scan first"
                : selectedIds.size > 0
                  ? `Report the ${selectedIds.size} selected finding${selectedIds.size === 1 ? "" : "s"} as HTML / JSON / SARIF / Markdown`
                  : `Report every finding (${findings.length}) as HTML / JSON / SARIF / Markdown`
            }
          >
            {reportBusy ? "Writing…" : "Export report"}
            {selectedIds.size > 0 ? ` (${selectedIds.size})` : ""} ▾
          </button>
          {reportMenuOpen && (
            <div
              data-scanner-report-popover
              style={{
                position: "absolute",
                top: "calc(100% + 2px)",
                right: 0,
                minWidth: 200,
                padding: 4,
                background: "var(--bg-raised)",
                border: "1px solid var(--border)",
                borderRadius: 4,
                boxShadow: "0 4px 10px rgba(0,0,0,0.25)",
                zIndex: 100,
              }}
            >
              {([
                {
                  format: "html" as const,
                  label: "HTML",
                  hint: "Self-contained single-file report, client-ready",
                },
                {
                  format: "json" as const,
                  label: "JSON",
                  hint: "Machine-readable finding list",
                },
                {
                  format: "sarif" as const,
                  label: "SARIF 2.1.0",
                  hint: "CI (GitHub / GitLab / Azure) code-scanning ingest",
                },
                {
                  format: "markdown" as const,
                  label: "Markdown",
                  hint: "GitHub-flavoured, drop-in for issues / Slack / wiki",
                },
                {
                  format: "csv" as const,
                  label: "CSV",
                  hint: "RFC 4180 spreadsheet row-per-finding (Excel / Sheets)",
                },
              ]).map((opt) => (
                <button
                  key={opt.format}
                  onClick={() => void exportReport(opt.format)}
                  style={{
                    width: "100%",
                    textAlign: "left",
                    padding: "6px 8px",
                    background: "transparent",
                    border: "none",
                    borderRadius: 3,
                    cursor: "pointer",
                    display: "flex",
                    flexDirection: "column",
                    gap: 1,
                  }}
                  onMouseEnter={(e) =>
                    (e.currentTarget.style.background =
                      "var(--bg-hover, rgba(255,255,255,0.05))")
                  }
                  onMouseLeave={(e) =>
                    (e.currentTarget.style.background = "transparent")
                  }
                >
                  <span style={{ fontSize: 12, fontWeight: 600 }}>
                    {opt.label}
                  </span>
                  <span style={{ fontSize: 10, color: "var(--text-dim)" }}>
                    {opt.hint}
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>
        {/* R234: Promote the toolbar count badge to show the      */}
        {/* filtered-vs-total ratio when any chip filter is active. */}
        {/* Operators pivoting between filter sets can see at a    */}
        {/* glance "I'm hiding 23 of 50 findings" without hunting  */}
        {/* for the chip-strip's N/M text. Falls back to the plain  */}
        {/* count when no filter is active so the badge stays       */}
        {/* minimal on fresh scans.                                 */}
        <span
          className="badge"
          title={
            anyChipActive
              ? `${filteredFindings.length} shown out of ${findings.length} total (chip filters active)`
              : `${findings.length} findings in this project`
          }
        >
          {anyChipActive
            ? `${filteredFindings.length} / ${findings.length}`
            : `${findings.length}`}
          {" "}finding{findings.length === 1 ? "" : "s"}
        </span>
      </div>
      <div style={{ padding: "4px 10px", color: "var(--text-dim)", fontSize: 11 }}>
        {liveScan
          ? "Live scan is on — every new in-scope transaction is passed through the passive detectors automatically."
          : "Live scan is off — only the manual \u201CRun passive scan\u201D buttons produce findings. New traffic is not scanned."}
      </div>
      {detectors.length > 0 && (
        <div
          style={{
            padding: "4px 10px 6px",
            borderBottom: "1px solid var(--border)",
            background: "var(--bg-raised)",
          }}
        >
          <button
            className="ghost"
            onClick={() => setDetectorsOpen((o) => !o)}
            title={
              detectorsOpen
                ? "Hide the per-detector enable grid"
                : "Show the per-detector enable grid"
            }
            style={{ fontSize: 11, padding: "2px 8px" }}
          >
            {detectorsOpen ? "▾" : "▸"} Passive detectors (
            {detectors.filter((d) => d.enabled).length}/{detectors.length} enabled)
          </button>
          {/* R256: Bulk enable / disable detectors. Operators    */}
          {/* flipping between engagements want a one-click way   */}
          {/* to disable every passive detector (so legacy auth   */}
          {/* findings don't contaminate a new target) + flip     */}
          {/* back on when the project is ready. Mirror of R156   */}
          {/* (session rules) + R160 (match-and-replace). Fires   */}
          {/* per-detector toggles via Promise.allSettled so one  */}
          {/* bad write doesn't strand the rest. Only renders     */}
          {/* when the grid is expanded.                          */}
          {detectorsOpen && detectors.length > 0 && (
            <>
              <button
                className="ghost"
                disabled={detectors.every((d) => d.enabled)}
                onClick={async () => {
                  const victims = detectors.filter((d) => !d.enabled);
                  if (victims.length === 0) return;
                  try {
                    await Promise.allSettled(
                      victims.map((d) => toggleDetector(d.id, true)),
                    );
                    await refreshDetectors();
                  } catch (e) {
                    alert(`Enable all failed: ${e}`);
                  }
                }}
                title={
                  detectors.every((d) => d.enabled)
                    ? "All detectors already enabled"
                    : `Enable ${detectors.filter((d) => !d.enabled).length} disabled detector(s)`
                }
                style={{ fontSize: 11, padding: "2px 8px", marginLeft: 6 }}
              >
                ✓ enable all
              </button>
              <button
                className="ghost"
                disabled={detectors.every((d) => !d.enabled)}
                onClick={async () => {
                  const victims = detectors.filter((d) => d.enabled);
                  if (victims.length === 0) return;
                  if (
                    !confirm(
                      `Disable ${victims.length} active detector${victims.length === 1 ? "" : "s"}? No new in-scope traffic will be probed by any passive detector until re-enabled.`,
                    )
                  )
                    return;
                  try {
                    await Promise.allSettled(
                      victims.map((d) => toggleDetector(d.id, false)),
                    );
                    await refreshDetectors();
                  } catch (e) {
                    alert(`Disable all failed: ${e}`);
                  }
                }}
                title={
                  detectors.every((d) => !d.enabled)
                    ? "All detectors already disabled"
                    : `Disable ${detectors.filter((d) => d.enabled).length} enabled detector(s)`
                }
                style={{ fontSize: 11, padding: "2px 8px", marginLeft: 4 }}
              >
                ∅ disable all
              </button>
            </>
          )}
          {detectorsOpen && (
            <div
              style={{
                marginTop: 6,
                display: "grid",
                gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))",
                gap: "4px 10px",
                fontSize: 11,
              }}
            >
              {detectors.map((d) => (
                <label
                  key={d.id}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 6,
                    cursor: "pointer",
                    opacity: d.enabled ? 1 : 0.55,
                  }}
                  title={
                    d.enabled
                      ? `Click to disable — new in-scope traffic will stop being probed by ${d.id}.`
                      : `Click to re-enable — ${d.id} resumes probing new traffic immediately.`
                  }
                >
                  <input
                    type="checkbox"
                    checked={d.enabled}
                    onChange={(e) => void toggleDetector(d.id, e.target.checked)}
                  />
                  <span className="mono">{d.id}</span>
                </label>
              ))}
            </div>
          )}
          {detectorsOpen && (
            <div
              style={{
                marginTop: 6,
                color: "var(--text-dim)",
                fontSize: 10,
              }}
            >
              Flipping a checkbox takes effect on the next recorded transaction — no scanner restart. Disabled detector ids persist to project config.
            </div>
          )}
        </div>
      )}
      {probes.length > 0 && (
        <div
          style={{
            padding: "4px 10px 6px",
            borderBottom: "1px solid var(--border)",
            background: "var(--bg-raised)",
          }}
        >
          <button
            className="ghost"
            onClick={() => setProbesOpen((o) => !o)}
            title={
              probesOpen
                ? "Hide the per-active-probe enable grid"
                : "Show the per-active-probe enable grid"
            }
            style={{ fontSize: 11, padding: "2px 8px" }}
          >
            {probesOpen ? "▾" : "▸"} Active probes (
            {probes.filter((p) => p.enabled).length}/{probes.length} enabled)
          </button>
          {/* R257: Bulk enable / disable active probes. Mirror of  */}
          {/* R256 (passive detectors). Active probes default-off   */}
          {/* for a reason (noise + traffic cost) so operators need */}
          {/* a one-click way to arm/disarm the whole grid when     */}
          {/* starting / stopping an active-scan engagement.        */}
          {probesOpen && probes.length > 0 && (
            <>
              <button
                className="ghost"
                disabled={probes.every((p) => p.enabled)}
                onClick={async () => {
                  const victims = probes.filter((p) => !p.enabled);
                  if (victims.length === 0) return;
                  if (
                    !confirm(
                      `Enable ${victims.length} active probe${victims.length === 1 ? "" : "s"}? Active probes fire extra requests at targets — expect a traffic + noise bump on the next recorded transaction.`,
                    )
                  )
                    return;
                  try {
                    await Promise.allSettled(
                      victims.map((p) => toggleProbe(p.id, true)),
                    );
                    await refreshProbes();
                  } catch (e) {
                    alert(`Enable all failed: ${e}`);
                  }
                }}
                title={
                  probes.every((p) => p.enabled)
                    ? "All active probes already enabled"
                    : `Enable ${probes.filter((p) => !p.enabled).length} disabled probe(s) — confirms first (traffic bump)`
                }
                style={{ fontSize: 11, padding: "2px 8px", marginLeft: 6 }}
              >
                ✓ enable all
              </button>
              <button
                className="ghost"
                disabled={probes.every((p) => !p.enabled)}
                onClick={async () => {
                  const victims = probes.filter((p) => p.enabled);
                  if (victims.length === 0) return;
                  try {
                    await Promise.allSettled(
                      victims.map((p) => toggleProbe(p.id, false)),
                    );
                    await refreshProbes();
                  } catch (e) {
                    alert(`Disable all failed: ${e}`);
                  }
                }}
                title={
                  probes.every((p) => !p.enabled)
                    ? "All active probes already disabled"
                    : `Disable ${probes.filter((p) => p.enabled).length} enabled probe(s) — stops the extra traffic`
                }
                style={{ fontSize: 11, padding: "2px 8px", marginLeft: 4 }}
              >
                ∅ disable all
              </button>
            </>
          )}
          {probesOpen && (
            <div
              style={{
                marginTop: 6,
                display: "grid",
                gridTemplateColumns: "repeat(auto-fill, minmax(240px, 1fr))",
                gap: "4px 10px",
                fontSize: 11,
              }}
            >
              {probes.map((p) => (
                <label
                  key={p.id}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 6,
                    cursor: "pointer",
                    opacity: p.enabled ? 1 : 0.55,
                  }}
                  title={
                    p.default_disabled
                      ? `${p.id} ships default-disabled — opt-in because it carries extra cost (e.g. BlindSqlTime adds ~2 s per probed parameter). ${p.enabled ? "Click to disable." : "Click to opt in."}`
                      : p.enabled
                        ? `Click to disable ${p.id} — the active-scan dispatcher will stop firing it against in-scope targets.`
                        : `Click to re-enable ${p.id}.`
                  }
                >
                  <input
                    type="checkbox"
                    checked={p.enabled}
                    onChange={(e) => void toggleProbe(p.id, e.target.checked)}
                  />
                  <span className="mono">{p.id}</span>
                  {p.default_disabled && (
                    <span
                      style={{
                        fontSize: 9,
                        color: "var(--accent, #e07c50)",
                        border: "1px solid var(--accent, #e07c50)",
                        borderRadius: 3,
                        padding: "0 4px",
                        marginLeft: "auto",
                        letterSpacing: "0.5px",
                      }}
                      title="This probe ships default-disabled because it has a measurable wall-clock cost. Enable at your own pace."
                    >
                      opt-in
                    </span>
                  )}
                </label>
              ))}
            </div>
          )}
          {probesOpen && (
            <div
              style={{
                marginTop: 6,
                color: "var(--text-dim)",
                fontSize: 10,
              }}
            >
              Toggles persist to project config. Opt-in probes stay off until explicitly checked. Dispatcher wiring arrives in a follow-up round.
            </div>
          )}
        </div>
      )}
      {/* ---------------------------------------------------------- */}
      {/* Burp-style chip filter strip — severity + status with per-   */}
      {/* chip count badges. Reuses the R81 .issue-filter-strip CSS.   */}
      {/* Rendered unconditionally so an empty scan still shows the    */}
      {/* chip slots (counts read 0) rather than popping in later —    */}
      {/* avoids layout shift when the first finding lands.            */}
      {findings.length > 0 && (
        <div className="issue-filter-strip">
          <div className="issue-filter-row">
            <span className="issue-filter-label">severity</span>
            {([
              { key: "critical" as const, label: "critical" },
              { key: "high" as const, label: "high" },
              { key: "medium" as const, label: "medium" },
              { key: "low" as const, label: "low" },
              { key: "info" as const, label: "info" },
            ]).map(({ key, label }) => {
              const active = sevFilter.has(key);
              const count = sevCounts[key];
              return (
                <button
                  key={key}
                  type="button"
                  className={`issue-sev-chip severity-${key} ${active ? "on" : "off"}`}
                  onClick={() => toggleSev(key)}
                  disabled={count === 0 && !active}
                  title={
                    active
                      ? `Showing ${label} — click to hide`
                      : count === 0
                        ? `No ${label} findings`
                        : `Click to filter to ${label}`
                  }
                >
                  <span className="chip-label">{label}</span>
                  <span className="chip-count">{count}</span>
                </button>
              );
            })}
            {/* R167: "Actionable" quick preset — flips the sev chip   */}
            {/* set to {critical, high, medium} in one click so triage  */}
            {/* operators can mute info/low noise with a single press.  */}
            {/* Clicking again (when all three are already on and no    */}
            {/* low/info is on) clears back to show-all. Mirrors the    */}
            {/* way Burp Pro's severity dropdown has an "Important+"    */}
            {/* preset. Button renders only when the chip strip is      */}
            {/* visible (findings.length > 0 — same gate as the strip).  */}
            {(() => {
              const actionable: SevKey[] = ["critical", "high", "medium"];
              const allOn = actionable.every((s) => sevFilter.has(s));
              const nothingElse = !sevFilter.has("low") && !sevFilter.has("info");
              const alreadyActionable = allOn && nothingElse;
              return (
                <button
                  type="button"
                  className={`issue-sev-chip ${alreadyActionable ? "on" : "off"}`}
                  onClick={() => {
                    setSevFilter(
                      alreadyActionable ? new Set() : new Set(actionable),
                    );
                  }}
                  title={
                    alreadyActionable
                      ? "Click to clear — show every severity again"
                      : "Preset: show only critical + high + medium (hide low + info noise)"
                  }
                  style={{ marginLeft: 6 }}
                >
                  <span className="chip-label">⚠ actionable</span>
                  <span className="chip-count">
                    {sevCounts.critical + sevCounts.high + sevCounts.medium}
                  </span>
                </button>
              );
            })()}
            <span className="dim" style={{ fontSize: 10.5, marginLeft: 8 }}>
              {filteredFindings.length} / {findings.length} shown
            </span>
          </div>
          <div className="issue-filter-row">
            <span className="issue-filter-label">status</span>
            {([
              { value: "new", label: "new" },
              { value: "triaging", label: "triaging" },
              { value: "confirmed", label: "confirmed" },
              { value: "false_positive", label: "false positive" },
              { value: "fixed", label: "fixed" },
              { value: "wontfix", label: "wontfix" },
            ]).map(({ value, label }) => {
              const active = issueStatusFilter.has(value);
              const count = statusCounts[value] ?? 0;
              return (
                <button
                  key={value}
                  type="button"
                  className={`issue-status-chip ${active ? "on" : "off"}`}
                  onClick={() => toggleIssueStatus(value)}
                  disabled={count === 0 && !active}
                  title={
                    active
                      ? `Showing ${label} — click to hide`
                      : count === 0
                        ? `No ${label} findings`
                        : `Click to filter to ${label}`
                  }
                >
                  <span className="chip-label">{label}</span>
                  <span className="chip-count">{count}</span>
                </button>
              );
            })}
            {/* R196: "Untriaged" quick preset — flips the status chip  */}
            {/* set to {new, triaging} in one click so triage operators */}
            {/* can zero in on findings that still need review and      */}
            {/* hide confirmed / false-positive / fixed / wontfix       */}
            {/* chatter. Mirror of R167's "actionable" sev preset. One  */}
            {/* click arms it, second click clears it (toggle).         */}
            {(() => {
              const untriaged = ["new", "triaging"];
              const allOn = untriaged.every((s) => issueStatusFilter.has(s));
              const nothingElse =
                !issueStatusFilter.has("confirmed") &&
                !issueStatusFilter.has("false_positive") &&
                !issueStatusFilter.has("fixed") &&
                !issueStatusFilter.has("wontfix");
              const alreadyUntriaged = allOn && nothingElse;
              return (
                <button
                  type="button"
                  className={`issue-status-chip ${alreadyUntriaged ? "on" : "off"}`}
                  onClick={() => {
                    setIssueStatusFilter(
                      alreadyUntriaged ? new Set() : new Set(untriaged),
                    );
                  }}
                  title={
                    alreadyUntriaged
                      ? "Click to clear — show every status again"
                      : "Preset: show only new + triaging (hide confirmed / false_positive / fixed / wontfix)"
                  }
                  style={{ marginLeft: 6 }}
                >
                  <span className="chip-label">🔎 untriaged</span>
                  <span className="chip-count">
                    {(statusCounts.new ?? 0) + (statusCounts.triaging ?? 0)}
                  </span>
                </button>
              );
            })()}
            {/* R265: Bulk "Mark N as triaging" — one-click way to  */}
            {/* promote every "new" finding in the filtered view to  */}
            {/* "triaging" status without having to select-all. Only */}
            {/* renders when there are "new" findings in the current */}
            {/* filtered view (so the button disappears once every   */}
            {/* row has been triaged + a repeat press is impossible).*/}
            {/* Chip-filter-aware so operators can promote just the  */}
            {/* slice they're staring at (e.g. "mark every high-sev   */}
            {/* new finding as triaging"). Lives next to the clear-  */}
            {/* filters button so triage-oriented actions cluster.   */}
            {(() => {
              const newCount = filteredFindings.filter(
                (f) => (f.status || "new").toLowerCase() === "new",
              ).length;
              if (newCount === 0) return null;
              return (
                <button
                  type="button"
                  className="ghost"
                  disabled={markingTriaging}
                  onClick={() => void markFilteredAsTriaging()}
                  title={`Promote every "new" finding in the current filtered view (${newCount}) to "triaging" — a one-click "I've seen all of these" bulk op. Rows already at other statuses stay untouched.`}
                  style={{ fontSize: 11, padding: "2px 8px", marginLeft: 6 }}
                >
                  {markingTriaging
                    ? "Marking…"
                    : `✎ mark ${newCount} as triaging`}
                </button>
              );
            })()}
            {/* R287: Second step in the triage pipeline — promote */}
            {/* every "triaging" finding in the current filtered   */}
            {/* view to "confirmed". Only renders when there's at  */}
            {/* least one triaging row in view so the button auto- */}
            {/* hides as operators work through the list.          */}
            {(() => {
              const triagingCount = filteredFindings.filter(
                (f) => (f.status || "new").toLowerCase() === "triaging",
              ).length;
              if (triagingCount === 0) return null;
              return (
                <button
                  type="button"
                  className="ghost"
                  disabled={confirmingTriaging}
                  onClick={() => void confirmFilteredTriaging()}
                  title={`Promote every "triaging" finding in the current filtered view (${triagingCount}) to "confirmed" — a one-click "I've verified all of these" bulk op. Rows at other statuses stay untouched.`}
                  style={{ fontSize: 11, padding: "2px 8px", marginLeft: 6 }}
                >
                  {confirmingTriaging
                    ? "Confirming…"
                    : `✓ confirm ${triagingCount} triaging`}
                </button>
              );
            })()}
            {/* R238: Include the active-filter count so operators */}
            {/* know what will be reset at a glance. Sum of the     */}
            {/* three Set sizes — matches the chip strip's visual   */}
            {/* count of coloured chips.                            */}
            {anyChipActive &&
              (() => {
                const activeCount =
                  sevFilter.size + issueStatusFilter.size + tagFilter.size;
                return (
                  <button
                    type="button"
                    className="issue-filter-clear"
                    onClick={clearChipFilters}
                    title={`Clear all ${activeCount} chip filter${activeCount === 1 ? "" : "s"} (Esc also works)`}
                  >
                    clear {activeCount} filter{activeCount === 1 ? "" : "s"}
                  </button>
                );
              })()}
          </div>
          {/* --------------------------------------------------- */}
          {/* Tag filter row — only renders when at least one      */}
          {/* finding on the current page carries a tag. Reuses    */}
          {/* R91's .finding-tag chip visual but promotes to a     */}
          {/* clickable button with on/off states. Multi-select,   */}
          {/* OR-match semantics (any-tag-matches). "N" badge      */}
          {/* shows the per-tag count baseline (whole list, not    */}
          {/* post-chip, matching R81 count semantics).            */}
          {tagInventory.length > 0 && (
            <div className="issue-filter-row">
              <span className="issue-filter-label">tags</span>
              {tagInventory.map(({ tag, count }) => {
                const active = tagFilter.has(tag);
                return (
                  <button
                    key={tag}
                    type="button"
                    className={`issue-tag-chip ${active ? "on" : "off"}`}
                    onClick={() => toggleTagFilter(tag)}
                    title={
                      active
                        ? `Showing findings tagged "${tag}" — click to hide`
                        : `Click to filter to findings tagged "${tag}"`
                    }
                  >
                    <span className="chip-label">{tag}</span>
                    <span className="chip-count">{count}</span>
                  </button>
                );
              })}
            </div>
          )}
        </div>
      )}
      {bulkRows.length > 0 && (
        <div
          style={{
            padding: "6px 10px",
            borderBottom: "1px solid var(--border)",
            background: "var(--bg-raised)",
            display: "flex",
            gap: 8,
            alignItems: "center",
            flexWrap: "wrap",
            fontSize: 12,
          }}
        >
          <strong>{bulkRows.length} finding{bulkRows.length === 1 ? "" : "s"} selected</strong>
          <span className="sep" />
          <button onClick={() => void bulkSetStatus("triaging")}>Mark triaging</button>
          <button onClick={() => void bulkSetStatus("confirmed")}>Mark confirmed</button>
          <button onClick={() => void bulkSetStatus("false_positive")}>
            Mark false positive
          </button>
          {/* R361: Mark fixed + Mark wontfix complete the bulk-     */}
          {/* status button sextet. Operators auditing a post-fix    */}
          {/* review often need to promote verified → fixed in bulk  */}
          {/* once a dev deploys the patch; "wontfix" for cases     */}
          {/* like inherited third-party CVEs that aren't getting   */}
          {/* patched. Mirrors the existing triaging / confirmed /  */}
          {/* false-positive bulk buttons.                           */}
          <button onClick={() => void bulkSetStatus("fixed")}>Mark fixed</button>
          <button onClick={() => void bulkSetStatus("wontfix")}>Mark wontfix</button>
          <span className="sep" />
          <button onClick={() => void bulkSetVerification("verified")}>Verify</button>
          <button onClick={() => void bulkSetVerification("unverified")}>Unverify</button>
          {/* R383: Third verification state — bulk-mark as "false  */}
          {/* positive" at the verification axis. Distinct from the */}
          {/* status=false_positive button above: verification is   */}
          {/* a per-finding assertion about reproducibility ("I     */}
          {/* tried, couldn't trigger it") whereas status is the    */}
          {/* workflow label ("deprioritised in triage"). The       */}
          {/* ISSUE_VERIFICATIONS enum has three values —           */}
          {/* unverified / verified / false_positive — but only    */}
          {/* two had bulk buttons until now, forcing operators     */}
          {/* through the row-right-click submenu for every row     */}
          {/* they wanted to flip. Closes the bulk verification    */}
          {/* trio.                                                   */}
          <button
            onClick={() => void bulkSetVerification("false_positive")}
            title={`Set verification=false_positive on ${bulkRows.length} selected finding${bulkRows.length === 1 ? "" : "s"}. Distinct from status=false_positive — verification tracks "I tried, couldn't trigger it", status tracks workflow label.`}
          >
            FP (verif.)
          </button>
          {/* R374: Bulk severity override — operators auditing a    */}
          {/* detector that mis-classifies (e.g. a passive rule     */}
          {/* that flags everything as "high") want to batch-fix    */}
          {/* the severity without walking the row-right-click      */}
          {/* severity submenu on each row. Dropdown so operators   */}
          {/* don't need five separate buttons.                      */}
          <select
            value=""
            onChange={async (e) => {
              const sev = e.target.value;
              e.target.value = "";
              if (!sev) return;
              if (
                !confirm(
                  `Override severity to "${sev}" on ${bulkRows.length} selected finding${bulkRows.length === 1 ? "" : "s"}?`,
                )
              )
                return;
              try {
                await Promise.all(
                  bulkRows.map((f) => api.findingSetSeverity(f.id, sev)),
                );
                await refresh();
              } catch (err) {
                alert(`${err}`);
              }
            }}
            title={`Override severity for ${bulkRows.length} selected finding${bulkRows.length === 1 ? "" : "s"}. Confirms pre-fire.`}
            style={{ fontSize: 11, padding: "2px 4px" }}
          >
            <option value="">Severity ▾</option>
            <option value="critical">critical</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
            <option value="info">info</option>
          </select>
          <span className="sep" />
          <button onClick={bulkExportCsv}>Export CSV</button>
          {/* R601: Clipboard-only CSV counterpart to Export CSV on
              Scanner. Mirror of R600 HistoryPanel. Operators pasting
              into Excel / Sheets want the finding table on the
              clipboard directly without the file-save + open
              roundtrip. Byte-identical column shape to Export CSV. */}
          <button
            onClick={bulkCopyCsv}
            disabled={bulkRows.length === 0}
            title={
              bulkRows.length === 0
                ? "No findings selected"
                : `Copy ${bulkRows.length} selected finding${bulkRows.length === 1 ? "" : "s"} as a CSV table to clipboard (9 columns: id, severity, confidence, detector, title, status, verification, evidence, transaction_id). Paste into Excel / Sheets / Google Docs without the file-save roundtrip. Byte-identical column shape to Export CSV. Mirror of HistoryPanel R600.`
            }
          >
            📋 Copy as CSV
          </button>
          <button
            onClick={bulkExportJsonl}
            title="Export the selected findings as JSONL (one JSON object per line). Preserves every StoredFinding field (tags, references, insertion_point, remediation, description, note, assignee) that CSV flattens away. Pipe into jq / Jira import / Linear API without column loss."
          >
            Export JSONL
          </button>
          {/* R606: Clipboard-only JSON array counterpart to Export
              JSONL on Scanner. Second entry in the cross-panel
              "Copy as JSON" family after HistoryPanel R605.
              Operators dropping finding records into test fixtures
              / detector-tuning datasets / jq pipelines want a
              top-level JSON array (not JSONL) on the clipboard
              directly. Pretty-printed 2-space indent. */}
          <button
            onClick={bulkCopyJson}
            disabled={bulkRows.length === 0}
            title={
              bulkRows.length === 0
                ? "No findings selected"
                : `Copy ${bulkRows.length} selected finding${bulkRows.length === 1 ? "" : "s"} as a JSON array to clipboard (2-space indent, pretty-printed, preserves every StoredFinding field: tags, references, insertion_point, remediation, description, note, assignee). Great for test fixtures, detector-tuning datasets, jq pipelines. Mirror of HistoryPanel R605.`
            }
          >
            📋 Copy as JSON
          </button>
          {/* R634: Scanner bulk "📋 Copy as cURL" — operators
              building a bash replay script from a finding cluster
              want cURL commands directly on the clipboard, not a
              per-row right-click dance. Mirror of R407 History
              bulk cURL. Fan-out via historyShow per unique
              transaction_id (dedupes passive-only findings that
              share a parent tx). Partial-failure UX: alerts count
              of successful + skipped. Separator `\n\n` so each
              command lands on its own shell line. */}
          <button
            onClick={async () => {
              if (bulkRows.length === 0) return;
              const uniqTxIds = Array.from(
                new Set(
                  bulkRows
                    .map((f) => f.transaction_id)
                    .filter((id): id is number => id != null),
                ),
              );
              if (uniqTxIds.length === 0) {
                alert("No parent transactions in the selection — passive-only findings can't produce cURL commands.");
                return;
              }
              const cmds: string[] = [];
              const skipped: number[] = [];
              for (const txId of uniqTxIds) {
                try {
                  const view = await api.historyShow(txId);
                  if (!view?.request_raw) {
                    skipped.push(txId);
                    continue;
                  }
                  const req = fromSummaryAndRaw(view.summary, view.request_raw);
                  cmds.push(buildCurl(req));
                } catch {
                  skipped.push(txId);
                }
              }
              if (cmds.length === 0) {
                alert("No cURL commands produced — every parent transaction was missing request_raw.");
                return;
              }
              await copyToClipboard(cmds.join("\n\n"));
              if (skipped.length > 0) {
                alert(
                  `Copied ${cmds.length} cURL command${cmds.length === 1 ? "" : "s"} to clipboard. ${skipped.length} parent tx${skipped.length === 1 ? "" : "s"} skipped (missing request_raw).`,
                );
              }
            }}
            disabled={bulkRows.length === 0}
            title={
              bulkRows.length === 0
                ? "No findings selected"
                : `Copy cURL commands for every unique parent transaction across ${bulkRows.length} selected finding${bulkRows.length === 1 ? "" : "s"} (one command per unique tx, separated by blank lines). Great for bash replay scripts, CI smoke-tests, teammate paste. Mirror of HistoryPanel R407.`
            }
          >
            📋 Copy as cURL
          </button>
          {/* R635: Scanner bulk "📋 Copy as PowerShell" — Windows-
              native sibling of R634 bulk cURL. Operators on
              Windows building a PowerShell replay script prefer
              Invoke-WebRequest. Same fan-out + partial-failure UX
              as R634, swapping buildCurl for buildPowerShell.
              Mirror of HistoryPanel R432. */}
          <button
            onClick={async () => {
              if (bulkRows.length === 0) return;
              const uniqTxIds = Array.from(
                new Set(
                  bulkRows
                    .map((f) => f.transaction_id)
                    .filter((id): id is number => id != null),
                ),
              );
              if (uniqTxIds.length === 0) {
                alert("No parent transactions in the selection — passive-only findings can't produce PowerShell commands.");
                return;
              }
              const cmds: string[] = [];
              const skipped: number[] = [];
              for (const txId of uniqTxIds) {
                try {
                  const view = await api.historyShow(txId);
                  if (!view?.request_raw) {
                    skipped.push(txId);
                    continue;
                  }
                  const req = fromSummaryAndRaw(view.summary, view.request_raw);
                  cmds.push(buildPowerShell(req));
                } catch {
                  skipped.push(txId);
                }
              }
              if (cmds.length === 0) {
                alert("No PowerShell commands produced — every parent transaction was missing request_raw.");
                return;
              }
              await copyToClipboard(cmds.join("\n\n"));
              if (skipped.length > 0) {
                alert(
                  `Copied ${cmds.length} PowerShell command${cmds.length === 1 ? "" : "s"} to clipboard. ${skipped.length} parent tx${skipped.length === 1 ? "" : "s"} skipped (missing request_raw).`,
                );
              }
            }}
            disabled={bulkRows.length === 0}
            title={
              bulkRows.length === 0
                ? "No findings selected"
                : `Copy Invoke-WebRequest commands for every unique parent transaction across ${bulkRows.length} selected finding${bulkRows.length === 1 ? "" : "s"}. Great for Windows CI smoke-tests or scheduled task sets. Mirror of HistoryPanel R432.`
            }
          >
            📋 Copy as PowerShell
          </button>
          {/* R636: Scanner bulk "📋 Copy as Python" — Python
              requests library replay for pytest harnesses /
              custom extractor scripts / sqlmap wrappers. Same
              fan-out + partial-failure UX as R634/R635, swapping
              builder for buildPython. Mirror of HistoryPanel
              R433. */}
          <button
            onClick={async () => {
              if (bulkRows.length === 0) return;
              const uniqTxIds = Array.from(
                new Set(
                  bulkRows
                    .map((f) => f.transaction_id)
                    .filter((id): id is number => id != null),
                ),
              );
              if (uniqTxIds.length === 0) {
                alert("No parent transactions in the selection — passive-only findings can't produce Python commands.");
                return;
              }
              const cmds: string[] = [];
              const skipped: number[] = [];
              for (const txId of uniqTxIds) {
                try {
                  const view = await api.historyShow(txId);
                  if (!view?.request_raw) {
                    skipped.push(txId);
                    continue;
                  }
                  const req = fromSummaryAndRaw(view.summary, view.request_raw);
                  cmds.push(buildPython(req));
                } catch {
                  skipped.push(txId);
                }
              }
              if (cmds.length === 0) {
                alert("No Python snippets produced — every parent transaction was missing request_raw.");
                return;
              }
              await copyToClipboard(cmds.join("\n\n"));
              if (skipped.length > 0) {
                alert(
                  `Copied ${cmds.length} Python snippet${cmds.length === 1 ? "" : "s"} to clipboard. ${skipped.length} parent tx${skipped.length === 1 ? "" : "s"} skipped (missing request_raw).`,
                );
              }
            }}
            disabled={bulkRows.length === 0}
            title={
              bulkRows.length === 0
                ? "No findings selected"
                : `Copy Python requests snippets for every unique parent transaction across ${bulkRows.length} selected finding${bulkRows.length === 1 ? "" : "s"}. Great for pytest harnesses / custom extractor scripts. Mirror of HistoryPanel R433.`
            }
          >
            📋 Copy as Python
          </button>
          {/* R637: Scanner bulk "📋 Copy as fetch()" — completes
              the Scanner bulk shell-replay quartet alongside
              R634 cURL + R635 PowerShell + R636 Python. DevTools-
              ready fetch() snippets. Mirror of HistoryPanel R434. */}
          <button
            onClick={async () => {
              if (bulkRows.length === 0) return;
              const uniqTxIds = Array.from(
                new Set(
                  bulkRows
                    .map((f) => f.transaction_id)
                    .filter((id): id is number => id != null),
                ),
              );
              if (uniqTxIds.length === 0) {
                alert("No parent transactions in the selection — passive-only findings can't produce fetch() snippets.");
                return;
              }
              const cmds: string[] = [];
              const skipped: number[] = [];
              for (const txId of uniqTxIds) {
                try {
                  const view = await api.historyShow(txId);
                  if (!view?.request_raw) {
                    skipped.push(txId);
                    continue;
                  }
                  const req = fromSummaryAndRaw(view.summary, view.request_raw);
                  cmds.push(buildFetch(req));
                } catch {
                  skipped.push(txId);
                }
              }
              if (cmds.length === 0) {
                alert("No fetch() snippets produced — every parent transaction was missing request_raw.");
                return;
              }
              await copyToClipboard(cmds.join("\n\n"));
              if (skipped.length > 0) {
                alert(
                  `Copied ${cmds.length} fetch() snippet${cmds.length === 1 ? "" : "s"} to clipboard. ${skipped.length} parent tx${skipped.length === 1 ? "" : "s"} skipped (missing request_raw).`,
                );
              }
            }}
            disabled={bulkRows.length === 0}
            title={
              bulkRows.length === 0
                ? "No findings selected"
                : `Copy fetch() snippets for every unique parent transaction across ${bulkRows.length} selected finding${bulkRows.length === 1 ? "" : "s"}. Great for DevTools console replay. Mirror of HistoryPanel R434. Scanner bulk shell-replay quartet complete.`
            }
          >
            📋 Copy as fetch()
          </button>
          {/* R615: Clipboard-only JSONL counterpart to Export JSONL
              on Scanner. Second entry in cross-panel "Copy as
              JSONL" family after HistoryPanel R614. Dense format
              for jq / ELK streaming consumers. */}
          <button
            onClick={bulkCopyJsonl}
            disabled={bulkRows.length === 0}
            title={
              bulkRows.length === 0
                ? "No findings selected"
                : `Copy ${bulkRows.length} selected finding${bulkRows.length === 1 ? "" : "s"} as JSONL to clipboard (one JSON object per line, no indent — byte-identical to Export JSONL). Great for jq / grep / ELK / Jira import pipelines. Second entry in cross-panel Copy-as-JSONL family.`
            }
          >
            📋 Copy as JSONL
          </button>
          {/* R626: Scanner "Copy as Markdown table" — third entry
              in the cross-panel "Copy as Markdown" family (History
              R624 + Target Issues R625 + Scanner R626). Distinct
              from the existing R369 Copy Markdown (which emits
              per-finding H3 blocks with evidence + remediation +
              references) — R626 emits a one-line-per-finding
              table that's reader-friendly for Jira / Slack. */}
          <button
            onClick={() => {
              if (bulkRows.length === 0) return;
              const headers = ["id", "sev", "title", "status", "verification", "detector"];
              const esc = (v: unknown) =>
                String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
              const sep = headers.map(() => "---").join(" | ");
              const body = bulkRows
                .map((f) =>
                  [f.id, f.severity, f.title, f.status, f.verification, f.detector]
                    .map(esc)
                    .join(" | "),
                )
                .join("\n");
              const md = `| ${headers.join(" | ")} |\n| ${sep} |\n${body
                .split("\n")
                .map((line) => `| ${line} |`)
                .join("\n")}`;
              void navigator.clipboard.writeText(md);
            }}
            disabled={bulkRows.length === 0}
            title={
              bulkRows.length === 0
                ? "No findings selected"
                : `Copy ${bulkRows.length} selected finding${bulkRows.length === 1 ? "" : "s"} as a GitHub-flavored Markdown table (6 cols: id, sev, title, status, verification, detector). Great for Jira / PR description / Slack. Distinct from "Copy Markdown" (which emits per-finding H3 blocks); this one is one-line-per-finding. Third entry in cross-panel Copy-as-Markdown family.`
            }
          >
            📋 Copy as table
          </button>
          {/* R356: Bulk "📋 Copy URLs" — Scanner equivalent of R353 */}
          {/* History 📋 Copy URLs. Uses `issueTx` lookup where      */}
          {/* available (only loads for the currently-selected       */}
          {/* finding; others fall through to the fingerprint-level */}
          {/* URL in `tx[f.transaction_id]`-style lookups that      */}
          {/* ScannerPanel already does for row rendering). But     */}
          {/* here we need URLs for every bulk-selected finding — a */}
          {/* synchronous lookup against a frontend tx cache. If     */}
          {/* the cache doesn't carry it, operators get a `?` entry */}
          {/* in the list rather than a backend fan-out that could  */}
          {/* stall the clipboard write.                             */}
          {/* **Simplification** rather than threading a full tx    */}
          {/* cache, use the finding's embedded `insertion_point`   */}
          {/* field when available OR skip. Operators who want full */}
          {/* parent URLs can use R288 bulk JSONL (which triggers   */}
          {/* a backend lookup inside the handler).                 */}
          {/* **Scope** `bulkRows`. Dedupe + sort alpha. */}
          <button
            onClick={async () => {
              if (bulkRows.length === 0) return;
              try {
                // Use `insertion_point` as a URL proxy — it often
                // carries a path hint ("GET /search?q=…") that
                // operators can grep against. Falls back to the
                // finding title when absent so no row produces an
                // empty string.
                const uniq = Array.from(
                  new Set(
                    bulkRows.map((f) => f.insertion_point || f.title),
                  ),
                ).sort();
                await navigator.clipboard.writeText(uniq.join("\n"));
              } catch (e) {
                alert(`${e}`);
              }
            }}
            title={`Copy ${bulkRows.length} selected finding${bulkRows.length === 1 ? " insertion_point / title" : "s insertion_points / titles"} to clipboard as a newline-joined list (deduped + sorted alpha). Prefers insertion_point (operator-grep friendly) → falls back to title when absent.`}
          >
            📋 Copy locations
          </button>
          {/* R558: Bulk "📋 Copy detectors" — Scanner-only
              complement to R356 Copy URLs / R369 Copy locations.
              Operators auditing which detectors fire across a
              finding cluster ("do these 50 findings come from
              just 3 detectors or 15?") want a quick detector-
              distribution grab. Mirrors HistoryPanel R554 Copy
              methods pattern. Dedupe via Set + sort alpha. */}
          <button
            onClick={async () => {
              if (bulkRows.length === 0) return;
              try {
                const uniq = Array.from(
                  new Set(bulkRows.map((f) => f.detector || "(unknown)")),
                ).sort();
                await navigator.clipboard.writeText(uniq.join("\n"));
              } catch (e) {
                alert(`${e}`);
              }
            }}
            title={`Copy ${bulkRows.length} selected finding${bulkRows.length === 1 ? "'s detector" : "s' unique detectors"} to clipboard as a newline-joined list (deduped + sorted alpha). Operators auditing detector coverage ("which rules fired?") want this breakdown without pivoting to Export JSONL + jq.`}
          >
            📋 Copy detectors
          </button>
          {/* R559: Bulk "📋 Copy severities" — complements R558
              detectors. Operators grouping findings by severity
              want a quick severity-distribution grab. Sorted by
              Burp canonical order (critical > high > medium >
              low > info) rather than alpha so the output reads
              in triage-priority order. Dedupe via Set. */}
          <button
            onClick={async () => {
              if (bulkRows.length === 0) return;
              try {
                const order = ["critical", "high", "medium", "low", "info"];
                const uniq = Array.from(
                  new Set(bulkRows.map((f) => f.severity || "info")),
                );
                uniq.sort((a, b) => {
                  const ai = order.indexOf(a);
                  const bi = order.indexOf(b);
                  return (
                    (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi)
                  );
                });
                await navigator.clipboard.writeText(uniq.join("\n"));
              } catch (e) {
                alert(`${e}`);
              }
            }}
            title={`Copy ${bulkRows.length} selected finding${bulkRows.length === 1 ? "'s severity" : "s' unique severities"} to clipboard as a newline-joined list (deduped + sorted by triage priority: critical > high > medium > low > info). Unknown severities land after "info".`}
          >
            📋 Copy severities
          </button>
          {/* R562: Bulk "📋 Copy statuses" — complements R559
              severities. Operators auditing status-workflow
              coverage ("do I still have un-triaged findings in
              this cluster?") want a quick status-distribution
              grab. Sorted by Burp canonical workflow order
              (new > triaging > confirmed > fixed > wontfix >
              false_positive) rather than alpha so the output
              reads in workflow-progression order. */}
          <button
            onClick={async () => {
              if (bulkRows.length === 0) return;
              try {
                const order = [
                  "new",
                  "triaging",
                  "confirmed",
                  "fixed",
                  "wontfix",
                  "false_positive",
                ];
                const uniq = Array.from(
                  new Set(bulkRows.map((f) => f.status || "new")),
                );
                uniq.sort((a, b) => {
                  const ai = order.indexOf(a);
                  const bi = order.indexOf(b);
                  return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
                });
                await navigator.clipboard.writeText(uniq.join("\n"));
              } catch (e) {
                alert(`${e}`);
              }
            }}
            title={`Copy ${bulkRows.length} selected finding${bulkRows.length === 1 ? "'s status" : "s' unique statuses"} to clipboard as a newline-joined list (deduped + sorted by workflow order: new > triaging > confirmed > fixed > wontfix > false_positive). Rows with missing status default to "new".`}
          >
            📋 Copy statuses
          </button>
          {/* R573: Bulk "📋 Copy tags" — Scanner-only mirror of
              HistoryPanel R561. Operators auditing a tag
              campaign on findings ("which cluster got the
              'auth-attempt' tag? / what's my tag coverage?")
              want the distinct list. Flattens each finding's
              `tags: string[]` into a Set, dedupe + alpha sort.
              Empty-safe alert when the selection has zero
              tagged findings. Complements R312 bulk + Add tag
              (which writes a tag) with the counterpart read-op
              (dumps tag distribution). */}
          <button
            onClick={async () => {
              if (bulkRows.length === 0) return;
              try {
                const seen = new Set<string>();
                for (const f of bulkRows) {
                  for (const t of f.tags ?? []) {
                    if (t) seen.add(t);
                  }
                }
                if (seen.size === 0) {
                  alert("No tags found across the selected findings.");
                  return;
                }
                const uniq = Array.from(seen).sort();
                await navigator.clipboard.writeText(uniq.join("\n"));
              } catch (e) {
                alert(`${e}`);
              }
            }}
            title={`Copy ${bulkRows.length} selected finding${bulkRows.length === 1 ? "'s tags" : "s' unique tags"} to clipboard as a newline-joined list (deduped + alpha-sorted from all findings' tag arrays). Alerts if the selection has no tags at all. Mirror of HistoryPanel R561.`}
          >
            📋 Copy tags
          </button>
          {/* R575: Bulk "📋 Copy verifications" — complements
              R559 severities / R562 statuses with the third
              finding-metadata axis (verification: verified /
              false_positive / none). Operators auditing which
              findings have been verified vs false-positive'd
              vs untouched want this distribution. Fallback
              "(none)" for findings with missing verification
              — matches the "not yet reviewed" semantics the
              toolbar's "Verified" chip uses. Alpha sort since
              verification is a free-form string (no canonical
              workflow order like status). */}
          <button
            onClick={async () => {
              if (bulkRows.length === 0) return;
              try {
                const uniq = Array.from(
                  new Set(
                    bulkRows.map((f) => f.verification || "(none)"),
                  ),
                ).sort();
                await navigator.clipboard.writeText(uniq.join("\n"));
              } catch (e) {
                alert(`${e}`);
              }
            }}
            title={`Copy ${bulkRows.length} selected finding${bulkRows.length === 1 ? "'s verification" : "s' unique verifications"} to clipboard as a newline-joined list (deduped + alpha-sorted). "(none)" means not yet reviewed. Great for triage audit: "how many of these are still unverified?".`}
          >
            📋 Copy verifications
          </button>
          {/* 🎯 R690: Scanner bulk toolbar "📋 Copy stats" —
              finding-focused version of R689 HistoryPanel stats.
              Format: total findings / crit+high count /
              detectors count / verified-vs-unverified / with-
              evidence count. Perfect ticket-ready summary.
              🎯 R690 round-number milestone — 15th this chunk. */}
          <button
            onClick={async () => {
              if (bulkRows.length === 0) return;
              try {
                let critHigh = 0;
                const detectors = new Set<string>();
                let verified = 0;
                let unverified = 0;
                let falsePositive = 0;
                let withEvidence = 0;
                for (const f of bulkRows) {
                  const sev = (f.severity || "info").toLowerCase();
                  if (sev === "critical" || sev === "high") critHigh++;
                  if (f.detector) detectors.add(f.detector);
                  const v = (f.verification || "unverified").toLowerCase();
                  if (v === "verified") verified++;
                  else if (v === "false_positive") falsePositive++;
                  else unverified++;
                  if (f.evidence && f.evidence.length > 0) withEvidence++;
                }
                const lines = [
                  `Findings: ${bulkRows.length}`,
                  `Critical+High: ${critHigh}`,
                  `Unique detectors: ${detectors.size}`,
                  `Verified · Unverified · FP: ${verified} · ${unverified} · ${falsePositive}`,
                  `With evidence: ${withEvidence}`,
                ];
                await navigator.clipboard.writeText(lines.join("\n"));
              } catch (e) {
                alert(`${e}`);
              }
            }}
            title={`Copy one-shot scope-pass summary across ${bulkRows.length} selected finding${bulkRows.length === 1 ? "" : "s"} (total / crit+high / unique detectors / triage split / with-evidence). Great for a ticket-ready scope-pass report. 🎯 R690 round-number milestone.`}
          >
            📋 Copy stats
          </button>
          {/* R697: Scanner bulk toolbar "📋 Copy time range" —
              2nd metadata-summary op on Scanner (companion to
              R690 Copy stats). Mirrors R688 History time range
              as a finding-focused variant: earliest + latest
              finding ts_ms + duration + rows. Operators asked
              "when did this scope-pass's findings actually
              land?" during ticket write-ups. Adaptive duration
              formatter: <60s = s, <1h = m+s, <1d = h+m, else
              d+h. ISO 8601 timestamps. */}
          <button
            onClick={async () => {
              if (bulkRows.length === 0) return;
              try {
                let minTs = Number.POSITIVE_INFINITY;
                let maxTs = Number.NEGATIVE_INFINITY;
                for (const f of bulkRows) {
                  const ts = f.ts_ms ?? 0;
                  if (ts > 0) {
                    if (ts < minTs) minTs = ts;
                    if (ts > maxTs) maxTs = ts;
                  }
                }
                if (!isFinite(minTs) || !isFinite(maxTs)) {
                  alert("No findings in the selection have a timestamp.");
                  return;
                }
                const from = new Date(minTs).toISOString();
                const to = new Date(maxTs).toISOString();
                const dur = maxTs - minTs;
                let durStr: string;
                if (dur < 60_000) durStr = `${(dur / 1000).toFixed(1)}s`;
                else if (dur < 3_600_000)
                  durStr = `${Math.floor(dur / 60_000)}m ${Math.floor((dur % 60_000) / 1000)}s`;
                else if (dur < 86_400_000)
                  durStr = `${Math.floor(dur / 3_600_000)}h ${Math.floor((dur % 3_600_000) / 60_000)}m`;
                else
                  durStr = `${Math.floor(dur / 86_400_000)}d ${Math.floor((dur % 86_400_000) / 3_600_000)}h`;
                const lines = [
                  `From: ${from}`,
                  `To: ${to}`,
                  `Duration: ${durStr}`,
                  `Findings: ${bulkRows.length}`,
                ];
                await navigator.clipboard.writeText(lines.join("\n"));
              } catch (e) {
                alert(`${e}`);
              }
            }}
            title={`Copy time range across ${bulkRows.length} selected finding${bulkRows.length === 1 ? "" : "s"} (earliest → latest ISO 8601 + adaptive duration + row count). Mirrors R688 History time range as a finding-focused variant — great for "when did this scope-pass's findings land?" ticket write-ups.`}
          >
            📋 Copy time range
          </button>
          {/* R685: Scanner bulk toolbar "📋 Copy tag counts" —
              tally variant of R573 Copy tags. Each tag counts
              once per finding that carries it (multi-value field
              — a finding with 3 tags contributes to 3 tally
              rows). Sorted desc by count so most-used tags
              surface first. Format "auth-bypass: 12,
              needs-manual: 8". */}
          <button
            onClick={async () => {
              if (bulkRows.length === 0) return;
              try {
                const counts: Record<string, number> = {};
                for (const f of bulkRows) {
                  for (const t of f.tags ?? []) {
                    if (!t) continue;
                    counts[t] = (counts[t] ?? 0) + 1;
                  }
                }
                if (Object.keys(counts).length === 0) {
                  alert("No tags across the selected findings.");
                  return;
                }
                const sorted = Object.entries(counts).sort(
                  (a, b) => b[1] - a[1],
                );
                const text = sorted.map(([t, n]) => `${t}: ${n}`).join(", ");
                await navigator.clipboard.writeText(text);
              } catch (e) {
                alert(`${e}`);
              }
            }}
            title={`Copy tag counts across ${bulkRows.length} selected finding${bulkRows.length === 1 ? "" : "s"} as a one-line tally. Each tag counts once per finding that carries it (multi-value). Sorted desc by count. Great for "which tag campaign is most active?" audit.`}
          >
            📋 Copy tag counts
          </button>
          {/* R677: Scanner bulk toolbar "📋 Copy detector counts"
              — tally variant of R558 Copy detectors. Sorted desc
              by count so the "chatty" detectors surface first.
              Format "sql-injection: 15, xss-reflected: 8" per
              line (newline since detector names can be long). */}
          <button
            onClick={async () => {
              if (bulkRows.length === 0) return;
              try {
                const counts: Record<string, number> = {};
                for (const f of bulkRows) {
                  const d = f.detector || "(unknown)";
                  counts[d] = (counts[d] ?? 0) + 1;
                }
                const sorted = Object.entries(counts).sort(
                  (a, b) => b[1] - a[1],
                );
                const text = sorted.map(([d, n]) => `${d}: ${n}`).join("\n");
                await navigator.clipboard.writeText(text);
              } catch (e) {
                alert(`${e}`);
              }
            }}
            title={`Copy detector counts across ${bulkRows.length} selected finding${bulkRows.length === 1 ? "" : "s"} as a newline-separated list (sorted desc by count). Great for auditing "which rules dominate my finding set?" — chatty detectors cluster at the top.`}
          >
            📋 Copy detector counts
          </button>
          {/* R676: Scanner bulk toolbar "📋 Copy verification
              counts" — tally variant of R575 Copy verifications.
              Format "verified: 12, false_positive: 3,
              unverified: 25". */}
          <button
            onClick={async () => {
              if (bulkRows.length === 0) return;
              try {
                const order = ["verified", "false_positive", "unverified"];
                const counts: Record<string, number> = {};
                for (const f of bulkRows) {
                  const v = f.verification || "unverified";
                  counts[v] = (counts[v] ?? 0) + 1;
                }
                const sorted = Object.entries(counts).sort((a, b) => {
                  const ai = order.indexOf(a[0]);
                  const bi = order.indexOf(b[0]);
                  return (
                    (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi)
                  );
                });
                const text = sorted.map(([v, n]) => `${v}: ${n}`).join(", ");
                await navigator.clipboard.writeText(text);
              } catch (e) {
                alert(`${e}`);
              }
            }}
            title={`Copy verification counts across ${bulkRows.length} selected finding${bulkRows.length === 1 ? "" : "s"} as a one-line tally (e.g. "verified: 12, false_positive: 3, unverified: 25"). Great for triage progress audit.`}
          >
            📋 Copy verif counts
          </button>
          {/* R675: Scanner bulk toolbar "📋 Copy status counts" —
              tally variant of R562 Copy statuses. Format "new:
              15, triaging: 8, confirmed: 2". Sorted by Burp
              workflow order (new > triaging > confirmed > fixed >
              wontfix > false_positive). */}
          <button
            onClick={async () => {
              if (bulkRows.length === 0) return;
              try {
                const order = [
                  "new",
                  "triaging",
                  "confirmed",
                  "fixed",
                  "wontfix",
                  "false_positive",
                ];
                const counts: Record<string, number> = {};
                for (const f of bulkRows) {
                  const s = f.status || "new";
                  counts[s] = (counts[s] ?? 0) + 1;
                }
                const sorted = Object.entries(counts).sort((a, b) => {
                  const ai = order.indexOf(a[0]);
                  const bi = order.indexOf(b[0]);
                  return (
                    (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi)
                  );
                });
                const text = sorted.map(([s, n]) => `${s}: ${n}`).join(", ");
                await navigator.clipboard.writeText(text);
              } catch (e) {
                alert(`${e}`);
              }
            }}
            title={`Copy status counts across ${bulkRows.length} selected finding${bulkRows.length === 1 ? "" : "s"} as a one-line tally (e.g. "new: 15, triaging: 8, confirmed: 2"). Sorted by Burp workflow order. Great for triage standups.`}
          >
            📋 Copy status counts
          </button>
          {/* R669: Scanner bulk toolbar "📋 Copy sev counts" —
              tally variant of R559 Copy severities. Where R559
              dumps unique severities deduped (useful for building
              a filter list), R669 dumps counts per severity
              ("critical: 3, high: 7, …" — great for a one-line
              report summary in Slack / standup). Sorted by Burp
              canonical priority (critical > high > ... > info). */}
          <button
            onClick={async () => {
              if (bulkRows.length === 0) return;
              try {
                const order = ["critical", "high", "medium", "low", "info"];
                const counts: Record<string, number> = {};
                for (const f of bulkRows) {
                  const sev = f.severity || "info";
                  counts[sev] = (counts[sev] ?? 0) + 1;
                }
                const sorted = Object.entries(counts).sort((a, b) => {
                  const ai = order.indexOf(a[0]);
                  const bi = order.indexOf(b[0]);
                  return (
                    (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi)
                  );
                });
                const text = sorted.map(([s, n]) => `${s}: ${n}`).join(", ");
                await navigator.clipboard.writeText(text);
              } catch (e) {
                alert(`${e}`);
              }
            }}
            title={`Copy severity counts across ${bulkRows.length} selected finding${bulkRows.length === 1 ? "" : "s"} as a one-line tally (e.g. "critical: 3, high: 7, medium: 12"). Great for a Slack / standup / ticket summary. Sorted by Burp canonical priority.`}
          >
            📋 Copy sev counts
          </button>
          {/* R598: Bulk "📋 Copy confidences" — fourth finding-
              metadata axis after R559 severities / R562 statuses /
              R575 verifications. Operators often want a
              confidence-distribution view ("firm vs tentative?")
              before deciding whether to triage or re-run with
              different detectors. Scanner's `confidence` is a
              free-form string (firm/certain/tentative in common
              usage); dedupe via Set and sort by Burp's canonical
              confidence order (certain > firm > tentative) so the
              output reads in strongest-first order. Fallback
              "(none)" for findings with missing confidence. */}
          <button
            onClick={async () => {
              if (bulkRows.length === 0) return;
              try {
                const order = ["certain", "firm", "tentative"];
                const uniq = Array.from(
                  new Set(
                    bulkRows.map((f) =>
                      (f.confidence || "(none)").toLowerCase(),
                    ),
                  ),
                );
                uniq.sort((a, b) => {
                  const ai = order.indexOf(a);
                  const bi = order.indexOf(b);
                  return (
                    (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi)
                  );
                });
                await navigator.clipboard.writeText(uniq.join("\n"));
              } catch (e) {
                alert(`${e}`);
              }
            }}
            title={`Copy ${bulkRows.length} selected finding${bulkRows.length === 1 ? "'s confidence" : "s' unique confidences"} to clipboard as a newline-joined list (deduped + sorted by Burp confidence order: certain > firm > tentative). Rows with missing confidence land as "(none)" after the known values. Operators want this distribution before deciding whether a cluster is worth triaging.`}
          >
            📋 Copy confidences
          </button>
          {/* R369: Bulk "📋 Copy as Markdown" — operators preparing  */}
          {/* a Jira ticket / Confluence page / Slack post for a      */}
          {/* finding cluster want the full Markdown dump for every   */}
          {/* selected row, concatenated with H2 headers between      */}
          {/* findings so the output is ticket-ready. Scales R178     */}
          {/* (per-row Markdown) to a batch workflow. R389 extracted  */}
          {/* the body into `bulkCopyMarkdown()` to share with the    */}
          {/* Alt+Shift+M keyboard shortcut.                           */}
          <button
            onClick={() => void bulkCopyMarkdown()}
            title={`Copy ${bulkRows.length} selected finding${bulkRows.length === 1 ? "" : "s"} as a Markdown document (ticket-ready: H3 title + emoji sev + description + fenced evidence + remediation + references). ---  separators between findings.`}
          >
            📋 Copy Markdown
          </button>
          {/* R355: Bulk "📋 Copy titles" — dump every selected row's */}
          {/* `[sev] title` to clipboard as a newline-joined list.    */}
          {/* Operators preparing a Jira / ticket / Slack summary of */}
          {/* a finding cluster want this often — the R277 📊 Counts */}
          {/* button gives aggregate stats; this one gives the        */}
          {/* actual title list. **Format** `[CRITICAL] SQLi — /api/… */}
          {/* / [HIGH] Reflected XSS — /search` so the output is      */}
          {/* already Jira-shaped. **Dedupe + sort** by sev order      */}
          {/* then alpha so the clipboard output has a predictable    */}
          {/* shape. **Scope** `bulkRows` so operators pivot R328     */}
          {/* Ctrl+A → 📋 Copy titles for a filtered-view dump in     */}
          {/* two keystrokes.                                         */}
          <button
            onClick={async () => {
              if (bulkRows.length === 0) return;
              try {
                const sevOrder = ["critical", "high", "medium", "low", "info"];
                const lines = Array.from(
                  new Set(
                    bulkRows.map(
                      (f) => `[${f.severity.toUpperCase()}] ${f.title}`,
                    ),
                  ),
                ).sort((a, b) => {
                  const sa = sevOrder.findIndex((s) =>
                    a.toLowerCase().startsWith(`[${s}]`),
                  );
                  const sb = sevOrder.findIndex((s) =>
                    b.toLowerCase().startsWith(`[${s}]`),
                  );
                  if (sa !== sb) return sa - sb;
                  return a.localeCompare(b);
                });
                await navigator.clipboard.writeText(lines.join("\n"));
              } catch (e) {
                alert(`${e}`);
              }
            }}
            title={`Copy ${bulkRows.length} selected finding title${bulkRows.length === 1 ? "" : "s"} to clipboard (format: [SEV] title, sorted by sev then alpha, deduped). Great for a Jira / Slack / ticket summary.`}
          >
            📋 Copy titles
          </button>
          {/* R465: Bulk "⬇ Save evidence" — saves every selected   */}
          {/* finding's evidence blob into one combined file.        */}
          {/* Extends the Scanner bulk toolbar's "copy / export"     */}
          {/* family (R369 Copy Markdown / R355 Copy titles /        */}
          {/* R356 Copy locations / R311 Export CSV / R288 Export    */}
          {/* JSONL) with a disk-save for just the evidence blobs,   */}
          {/* which is the format operators attach to tickets +      */}
          {/* PoC bundles. **Scope** `bulkRows` filtered to those    */}
          {/* with evidence (skips title-only passive findings so    */}
          {/* the output doesn't carry blank sections). **Format**   */}
          {/* H2 header per finding (`## [SEV] title (#id)`) +       */}
          {/* two newlines + evidence blob + blank-line separator —  */}
          {/* text file matches R389 Markdown's visual rhythm so a   */}
          {/* mixed workflow (Markdown dump for prose, evidence      */}
          {/* dump for data) reads consistently. **Filename**        */}
          {/* `burpfree-evidence-batch-<timestamp>.txt` so repeat    */}
          {/* saves don't clobber. **Disabled gate** `bulkRows.length */}
          {/* === 0 || evidenceRows.length === 0` so a selection of  */}
          {/* only title-only findings shows the disabled state      */}
          {/* instead of saving an empty file.                       */}
          <button
            onClick={() => {
              if (bulkRows.length === 0) return;
              const evidenceRows = bulkRows.filter((f) => f.evidence);
              if (evidenceRows.length === 0) {
                alert(
                  "None of the selected findings have an evidence blob — passive-only / title-only findings don't carry one. Try selecting rows with the Evidence section populated.",
                );
                return;
              }
              const sevOrder: Record<string, number> = {
                critical: 0, high: 1, medium: 2, low: 3, info: 4,
              };
              const sorted = evidenceRows.slice().sort((a, b) => {
                const sa = sevOrder[a.severity] ?? 99;
                const sb = sevOrder[b.severity] ?? 99;
                if (sa !== sb) return sa - sb;
                return (a.title || "").localeCompare(b.title || "");
              });
              const sections = sorted.map((f) => {
                const sevUpper = (f.severity || "unknown").toUpperCase();
                return `## [${sevUpper}] ${f.title} (#${f.id})\n\n${f.evidence}\n`;
              });
              const body = sections.join("\n");
              const stamp = new Date()
                .toISOString()
                .replace(/[:T]/g, "-")
                .replace(/\..*$/, "");
              const name = `burpfree-evidence-batch-${stamp}.txt`;
              try {
                const blob = new Blob([body], {
                  type: "text/plain;charset=utf-8",
                });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = name;
                document.body.appendChild(a);
                a.click();
                a.remove();
                URL.revokeObjectURL(url);
                const skipped = bulkRows.length - evidenceRows.length;
                if (skipped > 0) {
                  // Non-blocking info — the file saved fine, just
                  // tell the operator a subset was skipped so they
                  // don't wonder why the count differs.
                  console.info(
                    `Saved ${evidenceRows.length} evidence section${evidenceRows.length === 1 ? "" : "s"}; ${skipped} selected finding${skipped === 1 ? "" : "s"} skipped (no evidence blob).`,
                  );
                }
              } catch (err) {
                alert(`${err}`);
              }
            }}
            disabled={bulkRows.length === 0}
            title={
              bulkRows.length === 0
                ? "No rows selected"
                : `Save every selected finding's evidence blob (${bulkRows.filter((f) => f.evidence).length}/${bulkRows.length} rows carry one) into a single combined .txt file. Format: H2 header per finding (## [SEV] title (#id)) + evidence + blank line separator — matches R369 Copy Markdown's layout. Great for PoC bundle attachments or evidence-only archives separated from the full JSON exports.`
            }
          >
            ⬇ Save evidence
          </button>
          {/* R479: Bulk "📋 Copy as HAR" — multi-finding HAR 1.2  */}
          {/* dump covering every selected finding's parent         */}
          {/* transaction. Natural pair with R453 HistoryPanel     */}
          {/* bulk HAR (same JSON shape, same per-row fan-out      */}
          {/* pattern) and R477/R478 Scanner/Target detail-pane     */}
          {/* HAR (same build pipeline, scaled to a batch).        */}
          {/* Operators moving a cluster of findings to a browser- */}
          {/* based reproduction (DevTools / HTTP Toolkit /         */}
          {/* Fiddler) get a single JSON file instead of walking   */}
          {/* each finding individually. **Scope** `bulkRows`      */}
          {/* filtered to those with transaction_id (skips        */}
          {/* passive-only findings silently). **Fan-out**         */}
          {/* Promise.allSettled over `api.historyShow(txId)`      */}
          {/* per selected row — ~20ms per RPC so a 50-finding    */}
          {/* batch runs ~1s on a localhost project. Rows with    */}
          {/* missing request_raw are counted as skipped and      */}
          {/* reported in the alert. **Output** single            */}
          {/* `{log:{version,creator,entries[...]}}` object       */}
          {/* copied as pretty-printed JSON — same shape as       */}
          {/* R453 so a mixed workflow stays consistent.          */}
          <button
            onClick={async () => {
              if (bulkRows.length === 0) return;
              const txRows = bulkRows.filter((f) => f.transaction_id != null);
              if (txRows.length === 0) {
                alert(
                  "None of the selected findings have a parent transaction — passive-only findings can't be HAR-exported. Try selecting rows with a tx link.",
                );
                return;
              }
              const results = await Promise.allSettled(
                txRows.map(async (f) => {
                  const txId = f.transaction_id!;
                  const view = await api.historyShow(txId);
                  if (!view?.request_raw)
                    throw new Error(`tx #${txId}: no request_raw`);
                  const req = fromSummaryAndRaw(
                    view.summary,
                    view.request_raw,
                  );
                  let resp: Parameters<typeof buildHarEntry>[2] = undefined;
                  if (view.response_raw) {
                    const text = view.response_raw.replace(/\r\n/g, "\n");
                    const headerEnd = text.indexOf("\n\n");
                    const headerBlock =
                      headerEnd >= 0 ? text.slice(0, headerEnd) : text;
                    const body =
                      headerEnd >= 0 ? text.slice(headerEnd + 2) : "";
                    const lines = headerBlock.split("\n");
                    const statusLine = (lines.shift() ?? "").trim();
                    const m = statusLine.match(
                      /^(HTTP\/\S+)\s+(\d+)(?:\s+(.*))?$/,
                    );
                    const httpVersion = m?.[1] ?? "HTTP/1.1";
                    const status = m ? parseInt(m[2], 10) : 0;
                    const statusText = m?.[3] ?? "";
                    const headers: Array<[string, string]> = [];
                    let mimeType = "";
                    for (const l of lines) {
                      const colon = l.indexOf(":");
                      if (colon <= 0) continue;
                      const n = l.slice(0, colon).trim();
                      const v = l.slice(colon + 1).trim();
                      if (!n) continue;
                      headers.push([n, v]);
                      if (n.toLowerCase() === "content-type") mimeType = v;
                    }
                    resp = { status, statusText, httpVersion, headers, mimeType, body };
                  }
                  const startedDateTime = new Date(view.summary.ts_ms).toISOString();
                  return buildHarEntry(req, startedDateTime, resp);
                }),
              );
              const entries: object[] = [];
              let failed = 0;
              for (const res of results) {
                if (res.status === "fulfilled") entries.push(res.value);
                else failed += 1;
              }
              if (entries.length === 0) {
                alert(
                  `All ${txRows.length} selected finding${txRows.length === 1 ? "" : "s"} failed to resolve parent tx bytes. Try a smaller selection to narrow down.`,
                );
                return;
              }
              const har = buildHarLog(entries);
              try {
                await navigator.clipboard.writeText(
                  JSON.stringify(har, null, 2),
                );
              } catch (err) {
                alert(`${err}`);
                return;
              }
              const passiveSkipped = bulkRows.length - txRows.length;
              if (failed > 0 || passiveSkipped > 0) {
                const parts: string[] = [`Copied ${entries.length} HAR entr${entries.length === 1 ? "y" : "ies"}`];
                if (failed > 0) parts.push(`${failed} tx fetch failed`);
                if (passiveSkipped > 0) parts.push(`${passiveSkipped} passive-only finding${passiveSkipped === 1 ? "" : "s"} skipped (no parent tx)`);
                alert(parts.join("; ") + ".");
              }
            }}
            disabled={bulkRows.length === 0}
            title={
              bulkRows.length === 0
                ? "No rows selected"
                : `Copy a HAR 1.2 log covering every selected finding's parent transaction (${bulkRows.filter((f) => f.transaction_id != null).length}/${bulkRows.length} rows carry one; passive-only findings skip silently). One historyShow RPC per row — expect ~${Math.max(1, Math.ceil(bulkRows.length * 20))} ms. Container format: single JSON object with entries[]. Paste into Chrome DevTools "Network → Import HAR", Firefox, HTTP Toolkit, Fiddler.`
            }
          >
            📋 Copy as HAR
          </button>
          {/* R504: Scanner bulk "⬇ Save as HAR file" — file-save    */}
          {/* variant of R479 Copy as HAR, mirrors R490 History bulk  */}
          {/* HAR file-save pattern. Same HAR 1.2 content + same      */}
          {/* Promise.allSettled fan-out, writes a .har file to disk   */}
          {/* via Blob + anchor click instead of clipboard. Operators  */}
          {/* attaching Scanner findings' parent HARs to tickets /    */}
          {/* long-term archive need a file — clipboard caps blow     */}
          {/* past 500 KB on some OSes. Filename pattern              */}
          {/* `burpfree-scanner-har-<timestamp>.har` so it doesn't    */}
          {/* collide with HistoryPanel's R490 export + stays         */}
          {/* identifiable in a shared ticket inbox.                   */}
          <button
            onClick={async () => {
              if (bulkRows.length === 0) return;
              const txRows = bulkRows.filter((f) => f.transaction_id != null);
              if (txRows.length === 0) {
                alert(
                  "None of the selected findings have a parent transaction — passive-only findings can't be HAR-exported.",
                );
                return;
              }
              const results = await Promise.allSettled(
                txRows.map(async (f) => {
                  const txId = f.transaction_id!;
                  const view = await api.historyShow(txId);
                  if (!view?.request_raw)
                    throw new Error(`tx #${txId}: no request_raw`);
                  const req = fromSummaryAndRaw(
                    view.summary,
                    view.request_raw,
                  );
                  let resp: Parameters<typeof buildHarEntry>[2] = undefined;
                  if (view.response_raw) {
                    const text = view.response_raw.replace(/\r\n/g, "\n");
                    const headerEnd = text.indexOf("\n\n");
                    const headerBlock =
                      headerEnd >= 0 ? text.slice(0, headerEnd) : text;
                    const body =
                      headerEnd >= 0 ? text.slice(headerEnd + 2) : "";
                    const lines = headerBlock.split("\n");
                    const statusLine = (lines.shift() ?? "").trim();
                    const m = statusLine.match(
                      /^(HTTP\/\S+)\s+(\d+)(?:\s+(.*))?$/,
                    );
                    const httpVersion = m?.[1] ?? "HTTP/1.1";
                    const status = m ? parseInt(m[2], 10) : 0;
                    const statusText = m?.[3] ?? "";
                    const headers: Array<[string, string]> = [];
                    let mimeType = "";
                    for (const l of lines) {
                      const colon = l.indexOf(":");
                      if (colon <= 0) continue;
                      const n = l.slice(0, colon).trim();
                      const v = l.slice(colon + 1).trim();
                      if (!n) continue;
                      headers.push([n, v]);
                      if (n.toLowerCase() === "content-type") mimeType = v;
                    }
                    resp = { status, statusText, httpVersion, headers, mimeType, body };
                  }
                  const startedDateTime = new Date(view.summary.ts_ms).toISOString();
                  return buildHarEntry(req, startedDateTime, resp);
                }),
              );
              const entries: object[] = [];
              let failed = 0;
              for (const res of results) {
                if (res.status === "fulfilled") entries.push(res.value);
                else failed += 1;
              }
              if (entries.length === 0) {
                alert(
                  `All ${txRows.length} selected finding${txRows.length === 1 ? "" : "s"} failed to resolve parent tx bytes.`,
                );
                return;
              }
              const har = buildHarLog(entries);
              const stamp = new Date()
                .toISOString()
                .replace(/[:T]/g, "-")
                .replace(/\..*$/, "");
              const name = `burpfree-scanner-har-${stamp}.har`;
              try {
                const blob = new Blob([JSON.stringify(har, null, 2)], {
                  type: "application/json;charset=utf-8",
                });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = name;
                document.body.appendChild(a);
                a.click();
                a.remove();
                URL.revokeObjectURL(url);
              } catch (err) {
                alert(`${err}`);
                return;
              }
              const passiveSkipped = bulkRows.length - txRows.length;
              if (failed > 0 || passiveSkipped > 0) {
                const parts: string[] = [
                  `Saved ${entries.length} HAR entr${entries.length === 1 ? "y" : "ies"} to ${name}`,
                ];
                if (failed > 0) parts.push(`${failed} tx fetch failed`);
                if (passiveSkipped > 0)
                  parts.push(
                    `${passiveSkipped} passive-only finding${passiveSkipped === 1 ? "" : "s"} skipped`,
                  );
                alert(parts.join("; ") + ".");
              }
            }}
            disabled={bulkRows.length === 0}
            title={
              bulkRows.length === 0
                ? "No rows selected"
                : `Save a HAR 1.2 .har file covering every selected finding's parent transaction. Pattern burpfree-scanner-har-<timestamp>.har. Great for ticket attachments where clipboard-paste doesn't fit.`
            }
          >
            ⬇ Save as HAR file
          </button>
          {/* R348: Bulk "+ Note" — drop one shared note on every   */}
          {/* selected finding. Operators triaging a cluster that    */}
          {/* shares a common context ("all auth-related, blocked    */}
          {/* on 2FA rollout") want one annotation applied across    */}
          {/* the batch so later exports carry the context. Mirrors  */}
          {/* R339 History bulk + Comment: replace semantics,        */}
          {/* confirms when any row already has a note.              */}
          <button
            onClick={() => {
              const existing = bulkRows.filter((f) => f.note && f.note.length > 0).length;
              const next = prompt(
                `Set a note on ${bulkRows.length} selected finding${bulkRows.length === 1 ? "" : "s"}:\n\n` +
                (existing > 0
                  ? `(Replace mode — ${existing} row${existing === 1 ? "" : "s"} already have${existing === 1 ? "s" : ""} a note that will be overwritten.)`
                  : "(Replace mode — no rows currently have a note.)"),
                "",
              );
              if (next === null) return;
              const note = next;
              if (existing > 0 && !confirm(
                `${existing} selected row${existing === 1 ? "" : "s"} already have${existing === 1 ? "s" : ""} a note that will be overwritten.\n\nContinue?`,
              )) {
                return;
              }
              void (async () => {
                let ok = 0;
                let failed = 0;
                for (const f of bulkRows) {
                  try {
                    await api.findingSetNote(f.id, note);
                    ok += 1;
                  } catch {
                    failed += 1;
                  }
                }
                await refresh();
                alert(
                  `Noted ${ok} finding${ok === 1 ? "" : "s"}${failed > 0 ? ` (${failed} failed)` : ""}.`,
                );
              })();
            }}
            title={`Set a shared note on each of the ${bulkRows.length} selected finding${bulkRows.length === 1 ? "" : "s"}. Overwrites — confirms pre-fire when any row already has a note. Empty string clears.`}
          >
            + Note
          </button>
          {/* R312: Bulk "+ Add tag" — operators triaging a cluster  */}
          {/* (same CWE / same host / same campaign) want to stamp    */}
          {/* every row with a shared label for later jq-filter /     */}
          {/* Jira-sync / grep-pipeline work. Reuses the existing     */}
          {/* `findingSetTags(id, tags)` RPC (R154-era) in merge mode: */}
          {/* reads each finding's current tag set, adds the new tag  */}
          {/* if absent (Set dedupe so clicking twice is idempotent), */}
          {/* writes back. Serial per-id because the backend's write  */}
          {/* lock serializes anyway — Promise.all would just stack   */}
          {/* contention. **No side-effects on already-tagged rows**  */}
          {/* a row that already has the tag gets a no-op skip        */}
          {/* (bulkSkipped counter in the final toast) so operators   */}
          {/* re-tagging a mixed cluster see what actually changed.    */}
          <button
            onClick={() => {
              const next = prompt(
                `Add a tag to ${bulkRows.length} selected finding${bulkRows.length === 1 ? "" : "s"}:\n\n(Merge mode — existing tags on each row are preserved. Rows that already have the tag are skipped.)`,
                "",
              );
              if (next === null) return;
              const tag = next.trim();
              if (tag.length === 0) {
                alert("Empty tag — nothing to apply.");
                return;
              }
              void (async () => {
                let ok = 0;
                let skipped = 0;
                let failed = 0;
                for (const f of bulkRows) {
                  const cur = f.tags ?? [];
                  if (cur.includes(tag)) {
                    skipped += 1;
                    continue;
                  }
                  try {
                    const merged = Array.from(new Set([...cur, tag]));
                    await api.findingSetTags(f.id, merged);
                    ok += 1;
                  } catch {
                    failed += 1;
                  }
                }
                await refresh();
                alert(
                  `Tagged ${ok} finding${ok === 1 ? "" : "s"} with "${tag}"${skipped > 0 ? ` (${skipped} already had it)` : ""}${failed > 0 ? ` (${failed} failed)` : ""}.`,
                );
              })();
            }}
            title={`Add a tag to each of the ${bulkRows.length} selected finding${bulkRows.length === 1 ? "" : "s"} (merge semantics — existing tags survive). Rows that already have the tag are skipped. Great for marking a cluster "campaign-X" / "cwe-89-wave-2" / "false-positive-review" for later jq / Jira / grep workflows.`}
          >
            + Add tag
          </button>
          <button
            onClick={() => void bulkRerunActiveScan()}
            disabled={bulkVerifying}
            title="Re-run every enabled active-scan probe against each selected finding's parent transaction. Expect a traffic + noise bump — one active-scan dispatch per selected finding. Passive findings (no transaction_id) are skipped. Existing findings get their observation_count bumped via fingerprint upsert; new findings surface in the list."
          >
            {bulkVerifying ? "Verifying…" : "✓ Verify selected"}
          </button>
          <button className="danger" onClick={() => void bulkDelete()}>
            Delete
          </button>
          <span className="spacer" style={{ flex: 1 }} />
          <button onClick={clearSelection}>Clear selection</button>
        </div>
      )}
      <div style={{ display: "flex", flex: 1, minHeight: 0 }}>
        <div className="table" style={{ flex: 1 }}>
          <table>
            <colgroup>
              <col style={{ width: 90 }} />
              <col style={{ width: 110 }} />
              <col style={{ width: 90 }} />
              <col />
              <col style={{ width: 60 }} />
              <col style={{ width: 110 }} />
            </colgroup>
            {/* R243: Sticky header row — operators scrolling     */}
            {/* through hundreds of grouped findings lose track of  */}
            {/* which column is which. position:sticky inside a     */}
            {/* scrolling table parent pins the thead to the top of */}
            {/* the viewport without changing the layout model.     */}
            {/* Background is required to prevent rows showing     */}
            {/* through as they scroll underneath. The containing  */}
            {/* div (`<tbody>`'s scroll parent) carries the        */}
            {/* overflow — set via the panel's existing CSS.       */}
            <thead
              style={{
                position: "sticky",
                top: 0,
                zIndex: 1,
                background: "var(--bg)",
              }}
            >
              <tr>
                <th>Severity</th>
                <th>Detector</th>
                <th>Confidence</th>
                <th>Title</th>
                <th title="How long ago the finding first landed (hover for ISO timestamp)">Age</th>
                <th>Tx</th>
              </tr>
            </thead>
            <tbody>
              {/* R781: Burp-identical "no findings yet" empty state
                  card. Mirrors Burp Suite 2026.8's Scanner tab which
                  shows a friendly centered card when the project has
                  0 findings — explains that findings land from
                  passive detectors on history traffic + active
                  probes fired explicitly. Replaces the previous
                  silent-empty-tbody render that left operators
                  staring at just column headers after opening the
                  Scanner tab on a fresh project. Separate from the
                  chip-filtered empty state below (which assumes
                  there IS data to filter). Rendered as a <tr> with
                  colspan=6 so it slots into the table layout
                  without breaking the column structure. */}
              {findings.length === 0 && (
                <tr>
                  <td colSpan={6}>
                    <div className="scan-empty-card">
                      <div className="scan-empty-icon">
                        <svg
                          width="56"
                          height="56"
                          viewBox="0 0 24 24"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="1.5"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          aria-hidden="true"
                        >
                          <path d="M12 2l9 4.5v6c0 5-3.5 8.5-9 11-5.5-2.5-9-6-9-11v-6L12 2z" />
                          <path d="M9 12l2 2 4-4" />
                        </svg>
                      </div>
                      <div className="scan-empty-title">
                        No findings yet
                      </div>
                      <div className="scan-empty-sub">
                        Scanner findings land from <b>passive detectors</b>{" "}
                        running over stored HTTP history (click{" "}
                        <b>Run passive scan over history</b> above) or from{" "}
                        <b>active probes</b> fired explicitly against
                        specific transactions (right-click a History row →{" "}
                        <b>Fire active probes</b>, or hit <b>🎯 Scan</b> in
                        Repeater). Live scan can also auto-fire on fresh
                        in-scope traffic — toggle <b>Live scan: ON</b>{" "}
                        above.
                      </div>
                      <div className="scan-empty-hints">
                        Shortcuts: <b>J</b>/<b>K</b> walk rows ·{" "}
                        <b>Ctrl+A</b> select all · <b>Alt+1..5</b> severity
                        chips · <b>Alt+Shift+I</b> invert · <b>Alt+Shift+R</b>{" "}
                        rerun active probes on selected rows · right-click
                        row for Report / Export / tag / confirm
                      </div>
                    </div>
                  </td>
                </tr>
              )}
              {filteredFindings.length === 0 && findings.length > 0 && (
                <tr>
                  <td colSpan={6} className="dim" style={{ padding: 12, textAlign: "center" }}>
                    No findings match the chip filter. <button className="link" onClick={clearChipFilters} style={{ background: "none", border: "none", color: "var(--accent)", cursor: "pointer", padding: 0 }}>Clear filters</button>
                  </td>
                </tr>
              )}
              {/* Grouped render: one `<tr class="group-header">` per */}
              {/* host followed by the group's findings (unless the  */}
              {/* host is collapsed). Preserves the existing row     */}
              {/* click/select/menu wiring so Advisory tab + context */}
              {/* menu + bulk selection all keep working inside      */}
              {/* groups. Each header's rightmost cell shows the     */}
              {/* severity count pills, mirroring the SiteMap host   */}
              {/* badges (R90).                                      */}
              {groupMode !== "none" &&
                filteredFindings.length > 0 &&
                groupedFindings.map((g) => {
                  const collapsed = collapsedGroups.has(g.key);
                  const total = g.findings.length;
                  return (
                    <React.Fragment key={`group-${g.key}`}>
                      <tr
                        onClick={() => toggleGroupCollapsed(g.key)}
                        style={{
                          background: "var(--bg-raised)",
                          cursor: "pointer",
                          userSelect: "none",
                          borderTop: "1px solid var(--border)",
                        }}
                        title={
                          collapsed
                            ? `Click to expand ${g.key} (${total} finding${total === 1 ? "" : "s"})`
                            : `Click to collapse ${g.key}`
                        }
                      >
                        <td
                          colSpan={5}
                          style={{
                            padding: "4px 8px",
                            fontWeight: 600,
                            fontSize: 11.5,
                          }}
                        >
                          <span style={{ fontFamily: "var(--font-mono)", opacity: 0.7, marginRight: 4 }}>
                            {collapsed ? "▶" : "▼"}
                          </span>
                          {g.key}
                          <span
                            style={{
                              color: "var(--text-dim)",
                              fontWeight: 400,
                              marginLeft: 8,
                              fontSize: 10.5,
                            }}
                          >
                            · {total} finding{total === 1 ? "" : "s"}
                          </span>
                        </td>
                        <td style={{ textAlign: "right", padding: "4px 8px" }}>
                          {(["critical", "high", "medium", "low", "info"] as SevKey[]).map(
                            (sev) => {
                              const n = g.sevCounts[sev];
                              if (n === 0) return null;
                              /* R239: Group-header sev-count pill   */
                              /* clickable — sets sev filter to that */
                              /* single key. Click again on an       */
                              /* already-active sev clears it        */
                              /* (toggle semantic matches R81's      */
                              /* chip strip). stopPropagation keeps  */
                              /* the group-collapse click from       */
                              /* firing when the pill is clicked.    */
                              const active =
                                sevFilter.has(sev) && sevFilter.size === 1;
                              return (
                                <button
                                  key={sev}
                                  type="button"
                                  className={`severity-${sev}`}
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    if (active) {
                                      setSevFilter(new Set());
                                    } else {
                                      setSevFilter(new Set<SevKey>([sev]));
                                    }
                                  }}
                                  style={{
                                    marginLeft: 4,
                                    padding: "1px 6px",
                                    borderRadius: 8,
                                    fontSize: 10,
                                    fontWeight: 600,
                                    border: active
                                      ? "1px solid var(--accent)"
                                      : "1px solid transparent",
                                    cursor: "pointer",
                                    background: "transparent",
                                    font: "inherit",
                                  }}
                                  title={
                                    active
                                      ? `Click to clear sev filter — currently showing only ${sev}`
                                      : `${n} ${sev} finding${n === 1 ? "" : "s"} on ${g.key} — click to filter sev=${sev}`
                                  }
                                >
                                  {n}
                                </button>
                              );
                            },
                          )}
                        </td>
                      </tr>
                      {!collapsed &&
                        g.findings.map((f) => {
                          const isBulk = selectedIds.has(f.id);
                          const isActive = selected?.id === f.id;
                          return (
                            <tr
                              key={f.id}
                              className={isActive ? "selected" : ""}
                              onClick={(e) => onRowClick(e, f)}
                              onContextMenu={(e) => {
                                e.preventDefault();
                                setSelected(f);
                                setMenu({ x: e.clientX, y: e.clientY, data: f });
                              }}
                              style={isBulk ? { background: "var(--accent-dim)" } : undefined}
                            >
                              <td className={`mono severity-${f.severity}`}>{f.severity}</td>
                              <td className="mono">{f.detector}</td>
                              <td className="mono">{f.confidence}</td>
                              <td>{f.title}</td>
                              <td
                                className="mono"
                                style={{ fontSize: 10.5, ...ageTintStyle(f.ts_ms) }}
                                title={new Date(f.ts_ms).toISOString()}
                              >
                                {humanizeAge(f.ts_ms)}
                              </td>
                              <td className="mono">{f.transaction_id ?? "—"}</td>
                            </tr>
                          );
                        })}
                    </React.Fragment>
                  );
                })}
              {/* Flat render — keep as the default and the fallback */}
              {/* when groupMode is "none". The grouping branch above*/}
              {/* short-circuits via `groupMode !== "none" &&` so    */}
              {/* this map only runs when the mode is off.           */}
              {groupMode === "none" &&
                filteredFindings.map((f) => {
                  const isBulk = selectedIds.has(f.id);
                  const isActive = selected?.id === f.id;
                  // R299: Severity row tint — fifth entry in the
                  // row-tint family after R294 (Intruder status),
                  // R295 (History status), R297 (Logger kind),
                  // R298 (Target Issues sev). Mirror of R298 but
                  // on the main Scanner panel. Palette matches so
                  // operators get consistent cross-panel colour
                  // semantics between Scanner and Target Issues.
                  // Bulk-select trumps sev tint via the isBulk
                  // branch below so operators always see which
                  // rows a bulk op will act on.
                  const sev = (f.severity || "info").toLowerCase();
                  let sevBg: string | undefined;
                  if (sev === "critical")
                    sevBg = "rgba(224, 68, 68, 0.14)";
                  else if (sev === "high")
                    sevBg = "rgba(240, 140, 60, 0.10)";
                  else if (sev === "medium")
                    sevBg = "rgba(240, 210, 60, 0.08)";
                  else if (sev === "low")
                    sevBg = "rgba(100, 170, 220, 0.07)";
                  // info stays default
                  return (
                    <tr
                      key={f.id}
                      className={isActive ? "selected" : ""}
                      onClick={(e) => onRowClick(e, f)}
                      onContextMenu={(e) => {
                        e.preventDefault();
                        setSelected(f);
                        setMenu({ x: e.clientX, y: e.clientY, data: f });
                      }}
                      style={
                        isBulk
                          ? { background: "var(--accent-dim)" }
                          : sevBg
                            ? { background: sevBg }
                            : undefined
                      }
                    >
                      <td className={`mono severity-${f.severity}`}>{f.severity}</td>
                      <td className="mono">{f.detector}</td>
                      <td className="mono">{f.confidence}</td>
                      <td>{f.title}</td>
                      <td
                        className="mono"
                        style={{ fontSize: 10.5, ...ageTintStyle(f.ts_ms) }}
                        title={new Date(f.ts_ms).toISOString()}
                      >
                        {humanizeAge(f.ts_ms)}
                      </td>
                      <td className="mono">{f.transaction_id ?? "—"}</td>
                    </tr>
                  );
                })}
            </tbody>
          </table>
        </div>
        <div
          style={{
            width: "48%",
            borderLeft: "1px solid var(--border)",
            display: "flex",
            flexDirection: "column",
            minWidth: 0,
          }}
        >
          {!selected && <div className="empty">Select a finding</div>}
          {selected && (
            <>
              {/* Sticky header: title + severity badge row + Advisory/Request/Response tab strip */}
              <div
                style={{
                  padding: "10px 10px 0",
                  borderBottom: "1px solid var(--border)",
                  background: "var(--bg-raised)",
                }}
              >
                <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
                  <h3 style={{ margin: "0 0 4px", fontSize: 14, flex: 1 }}>
                    {selected.title}
                  </h3>
                  {/* R491: Scanner detail-pane "📎 Copy parent URL"    */}
                  {/* button — detail-pane variant of R486 Scanner      */}
                  {/* row-right-click "Copy parent tx URL" entry.       */}
                  {/* Operators looking at the finding detail-pane      */}
                  {/* want the URL without a round-trip back to the row */}
                  {/* menu. Lives next to the title so it's always      */}
                  {/* visible (unlike R477/R401/R304 which hide inside  */}
                  {/* the evidence-block gate). Byte-identical output   */}
                  {/* to R486 — same `historyShow(txId)` lookup +       */}
                  {/* `urlFromSummary(view.summary)`. **Visibility**    */}
                  {/* only renders for findings with transaction_id —   */}
                  {/* passive-only findings skip gracefully.            */}
                  {selected.transaction_id != null && (
                    <button
                      className="ghost"
                      onClick={async () => {
                        const txId = selected.transaction_id;
                        if (txId == null) return;
                        try {
                          const view = await api.historyShow(txId);
                          if (!view?.summary) {
                            alert(
                              `Parent transaction #${txId} could not be resolved.`,
                            );
                            return;
                          }
                          const url = urlFromSummary(view.summary);
                          await navigator.clipboard.writeText(url);
                        } catch (err) {
                          alert(`${err}`);
                        }
                      }}
                      title={`Copy the parent transaction's URL to clipboard — scheme + host + path, no query from the finding. Mirrors R486 row-right-click.`}
                      style={{ fontSize: 10.5, padding: "1px 6px" }}
                    >
                      📎 Copy URL
                    </button>
                  )}
                  {/* R548: Scanner detail-pane "📋 cURL" button —
                      mirror of R546 HistoryPanel + R547 ProxyPanel
                      cURL buttons on their sticky URL headers,
                      applied to Scanner. One-click cURL from the
                      detail pane without a row-right-click pivot.
                      Byte-identical output to R494 row-right-click
                      "Copy as cURL". Visibility same as R491:
                      transaction_id required. */}
                  {selected.transaction_id != null && (
                    <button
                      className="ghost"
                      onClick={async () => {
                        const txId = selected.transaction_id;
                        if (txId == null) return;
                        try {
                          const view = await api.historyShow(txId);
                          if (!view?.summary || !view.request_raw) {
                            alert(
                              `Parent transaction #${txId} has no stored request_raw — cannot build cURL.`,
                            );
                            return;
                          }
                          const req = fromSummaryAndRaw(
                            view.summary,
                            view.request_raw,
                          );
                          await navigator.clipboard.writeText(buildCurl(req));
                        } catch (err) {
                          alert(`${err}`);
                        }
                      }}
                      title={`Copy as cURL (headers + body) from the parent transaction — mirrors R494 row-right-click entry.`}
                      style={{ fontSize: 10.5, padding: "1px 6px" }}
                    >
                      📋 cURL
                    </button>
                  )}
                  {/* R552: Scanner detail-pane "📋 HAR" button —
                      mirror of R550 HistoryPanel + R551 ProxyPanel
                      sticky-header HAR buttons, applied to Scanner.
                      Byte-identical output to R482 row-right-click
                      "Copy as HAR entry" since both call
                      buildHarEntry + buildHarLog with the inline
                      response-parse logic. Visibility same as
                      R491/R548: transaction_id required. */}
                  {selected.transaction_id != null && (
                    <button
                      className="ghost"
                      onClick={async () => {
                        const txId = selected.transaction_id;
                        if (txId == null) return;
                        try {
                          const view = await api.historyShow(txId);
                          if (!view?.summary || !view.request_raw) {
                            alert(
                              `Parent transaction #${txId} has no stored request_raw — cannot build HAR entry.`,
                            );
                            return;
                          }
                          const req = fromSummaryAndRaw(
                            view.summary,
                            view.request_raw,
                          );
                          let resp: Parameters<typeof buildHarEntry>[2] =
                            undefined;
                          if (view.response_raw) {
                            const text = view.response_raw.replace(
                              /\r\n/g,
                              "\n",
                            );
                            const headerEnd = text.indexOf("\n\n");
                            const headerBlock =
                              headerEnd >= 0
                                ? text.slice(0, headerEnd)
                                : text;
                            const body =
                              headerEnd >= 0 ? text.slice(headerEnd + 2) : "";
                            const lines = headerBlock.split("\n");
                            const statusLine = (lines.shift() ?? "").trim();
                            const m = statusLine.match(
                              /^(HTTP\/\S+)\s+(\d+)(?:\s+(.*))?$/,
                            );
                            const httpVersion = m?.[1] ?? "HTTP/1.1";
                            const status = m ? parseInt(m[2], 10) : 0;
                            const statusText = m?.[3] ?? "";
                            const headers: Array<[string, string]> = [];
                            let mimeType = "";
                            for (const l of lines) {
                              const colon = l.indexOf(":");
                              if (colon <= 0) continue;
                              const n = l.slice(0, colon).trim();
                              const v = l.slice(colon + 1).trim();
                              if (!n) continue;
                              headers.push([n, v]);
                              if (n.toLowerCase() === "content-type")
                                mimeType = v;
                            }
                            resp = {
                              status,
                              statusText,
                              httpVersion,
                              headers,
                              mimeType,
                              body,
                            };
                          }
                          const startedDateTime = new Date(
                            view.summary.ts_ms,
                          ).toISOString();
                          const entry = buildHarEntry(
                            req,
                            startedDateTime,
                            resp,
                          );
                          const har = buildHarLog([entry]);
                          await navigator.clipboard.writeText(
                            JSON.stringify(har, null, 2),
                          );
                        } catch (err) {
                          alert(`${err}`);
                        }
                      }}
                      title={`Copy single-entry HAR 1.2 log (request + response) — mirrors R482 row-right-click.`}
                      style={{ fontSize: 10.5, padding: "1px 6px" }}
                    >
                      📋 HAR
                    </button>
                  )}
                  {/* R584: Scanner sticky-header "+ scope" button
                      — mirror of R582 ProxyPanel + R583 History.
                      Operators previewing a finding want to one-
                      click scope-add the parent tx's host without
                      a row-right-click pivot. Needs the parent tx
                      lookup via `historyShow(txId)` since Scanner
                      findings don't carry host directly (same
                      pattern as R579 row-right-click). Backend's
                      unique-rule guard idempotently no-ops on
                      duplicate adds. */}
                  {selected.transaction_id != null && (
                    <button
                      className="ghost"
                      onClick={async () => {
                        const txId = selected.transaction_id;
                        if (txId == null) return;
                        try {
                          const view = await api.historyShow(txId);
                          const host = view?.summary?.host;
                          if (!host) {
                            alert(
                              `Parent transaction #${txId} has no host — cannot add to scope.`,
                            );
                            return;
                          }
                          await api.scopeAddRule(buildHostIncludeRule(host));
                          alert(`Added host "${host}" to scope.`);
                        } catch (e) {
                          alert(`${e}`);
                        }
                      }}
                      title={`Add parent tx's host to scope include rules. Backend dedupes if already in scope.`}
                      style={{ fontSize: 10.5, padding: "1px 6px" }}
                    >
                      + scope
                    </button>
                  )}
                  {/* R586: Scanner sticky-header "+ scope path"
                      button — path-exact variant of R584 at the
                      sticky-header level. Operators previewing a
                      finding often want narrower scope rules
                      ("just this specific endpoint, not the whole
                      host"). Uses `buildPathIncludeRule` which
                      strips the query string. Needs historyShow
                      lookup since Scanner findings don't carry
                      host/path directly. */}
                  {selected.transaction_id != null && (
                    <button
                      className="ghost"
                      onClick={async () => {
                        const txId = selected.transaction_id;
                        if (txId == null) return;
                        try {
                          const view = await api.historyShow(txId);
                          const host = view?.summary?.host;
                          const path = view?.summary?.path;
                          if (!host || !path) {
                            alert(
                              `Parent transaction #${txId} missing host or path — cannot add path-exact rule.`,
                            );
                            return;
                          }
                          await api.scopeAddRule(buildPathIncludeRule(host, path));
                          alert(`Added "${host}${path.split("?")[0] || "/"}" to scope.`);
                        } catch (e) {
                          alert(`${e}`);
                        }
                      }}
                      title={`Add parent tx's host:path to scope include rules — path-exact, narrower than + scope.`}
                      style={{ fontSize: 10.5, padding: "1px 6px" }}
                    >
                      + path
                    </button>
                  )}
                </div>
                <div
                  style={{
                    color: "var(--text-dim)",
                    marginBottom: 8,
                    fontSize: 11,
                    display: "flex",
                    flexWrap: "wrap",
                    gap: 10,
                    alignItems: "center",
                  }}
                >
                  <span className={`severity-${selected.severity}`}>
                    {selected.severity}
                  </span>
                  <span>· {selected.confidence}</span>
                  <span className="mono">· {selected.detector}</span>
                  {selected.transaction_id ? (
                    <span className="mono">· tx #{selected.transaction_id}</span>
                  ) : null}
                  {selected.insertion_point ? (
                    <span className="mono" title={selected.insertion_point}>
                      · ↳ {selected.insertion_point}
                    </span>
                  ) : null}
                  {typeof selected.observation_count === "number" &&
                  selected.observation_count > 1 ? (
                    <span title="Times this fingerprint matched a transaction">
                      · seen × {selected.observation_count}
                    </span>
                  ) : null}
                  <span style={{ flex: 1 }} />
                  <button
                    className="ghost"
                    disabled={!selected.transaction_id || rerunBusy}
                    onClick={() => void rerunActiveScan(selected)}
                    title={
                      !selected.transaction_id
                        ? "No linked transaction — passive findings without a tx can't be re-probed"
                        : "Re-fire every enabled active probe against this finding's parent request. Fingerprint upsert means repeats on the same tx dedupe."
                    }
                    style={{ padding: "2px 8px", fontSize: 11 }}
                  >
                    {rerunBusy ? "Running…" : "↻ Rerun active scan"}
                  </button>
                  {/* R161: "→ History" — jump straight to the        */}
                  {/* HTTP history row that triggered this finding.   */}
                  {/* Reuses the existing `burpfree:history-focus`     */}
                  {/* bridge HistoryPanel listens for (used by R126   */}
                  {/* Slowest responses + others). Fires navigate     */}
                  {/* first so the history panel is mounted when the  */}
                  {/* focus event lands + its handler reloads filters  */}
                  {/* if the row isn't in the current window.          */}
                  <button
                    className="ghost"
                    disabled={!selected.transaction_id}
                    onClick={() => {
                      const txId = selected.transaction_id;
                      if (txId == null) return;
                      window.dispatchEvent(
                        new CustomEvent("burpfree:navigate", {
                          detail: { target: "history" },
                        }),
                      );
                      window.dispatchEvent(
                        new CustomEvent("burpfree:history-focus", {
                          detail: { id: txId },
                        }),
                      );
                    }}
                    title={
                      !selected.transaction_id
                        ? "No linked transaction — passive findings without a tx have no history row to jump to"
                        : "Jump to the HTTP history row that triggered this finding"
                    }
                    style={{ padding: "2px 8px", fontSize: 11, marginLeft: 4 }}
                  >
                    → History
                  </button>
                  {/* R324: Single-finding JSON export — companion   */}
                  {/* to the R288 bulk JSONL. Operators grabbing one */}
                  {/* finding for a Jira ticket attachment / Slack  */}
                  {/* message / shell-script input don't want the   */}
                  {/* bulk JSONL that R288 produces (one row + the  */}
                  {/* `_meta` header is awkward for a single        */}
                  {/* finding). This button writes a pretty-printed */}
                  {/* two-space-indented JSON blob of the selected  */}
                  {/* StoredFinding — every field preserved,         */}
                  {/* human-readable. **Filename** carries the id +  */}
                  {/* severity so operators juggling multiple        */}
                  {/* exported findings don't collide on disk.       */}
                  <button
                    className="ghost"
                    onClick={() => {
                      try {
                        const blob = new Blob(
                          [JSON.stringify(selected, null, 2)],
                          { type: "application/json;charset=utf-8" },
                        );
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement("a");
                        const stamp = new Date()
                          .toISOString()
                          .replace(/[:T]/g, "-")
                          .replace(/\..*$/, "");
                        a.href = url;
                        a.download = `burpfree-finding-${selected.id}-${selected.severity}-${stamp}.json`;
                        document.body.appendChild(a);
                        a.click();
                        a.remove();
                        URL.revokeObjectURL(url);
                      } catch (err) {
                        alert(`${err}`);
                      }
                    }}
                    title="Export this single finding as a pretty-printed JSON file. Great for Jira ticket attachments or sharing a specific finding with a teammate without the bulk JSONL wrapper."
                    style={{ padding: "2px 8px", fontSize: 11, marginLeft: 4 }}
                  >
                    ⬇ JSON
                  </button>
                  {/* R344: Note editor — operators often want to      */}
                  {/* annotate a finding ("need to re-run after deploy */}
                  {/* X" / "waiting on vendor response" / "false       */}
                  {/* positive — see thread Y") without moving it      */}
                  {/* through the triage lifecycle. Pops a prompt       */}
                  {/* seeded with the current note; empty string       */}
                  {/* clears. Uses the new finding_set_note RPC. The  */}
                  {/* button label pivots to "✎ Note" when a note     */}
                  {/* exists so operators see at a glance that        */}
                  {/* annotation is already present on this row.      */}
                  <button
                    className="ghost"
                    onClick={() => {
                      const next = prompt(
                        `Note for finding "${selected.title.length > 50 ? selected.title.slice(0, 47) + "…" : selected.title}":\n\n(Empty string clears the note.)`,
                        selected.note ?? "",
                      );
                      if (next === null) return;
                      void api
                        .findingSetNote(selected.id, next)
                        .then(() => api.findingsList().then(setFindings))
                        .catch((err) => alert(`${err}`));
                    }}
                    title={
                      selected.note
                        ? `Edit this finding's operator note (currently: ${selected.note.slice(0, 80)}${selected.note.length > 80 ? "…" : ""})`
                        : "Add an operator-side note to this finding — stored separately from the status + stays with the finding across exports"
                    }
                    style={{ padding: "2px 8px", fontSize: 11, marginLeft: 4 }}
                  >
                    {selected.note ? "✎ Note" : "+ Note"}
                  </button>
                  {/* R351: Inline + Tag button in the detail-pane     */}
                  {/* toolbar so operators triaging a specific finding */}
                  {/* don't have to right-click + Add tag → re-focus   */}
                  {/* back to the detail pane. Reuses R322 handler    */}
                  {/* exactly — merge-mode, "already has it" short-   */}
                  {/* circuit, empty-string bail. Hint shows current   */}
                  {/* tag list for context before the prompt lands.    */}
                  <button
                    className="ghost"
                    onClick={() => {
                      const next = prompt(
                        `Add a tag to "${selected.title.length > 50 ? selected.title.slice(0, 47) + "…" : selected.title}":\n\n(Merge mode — existing tags survive. No-op if the tag's already here.)`,
                        "",
                      );
                      if (next === null) return;
                      const tag = next.trim();
                      if (tag.length === 0) {
                        alert("Empty tag — nothing to apply.");
                        return;
                      }
                      const cur = selected.tags ?? [];
                      if (cur.includes(tag)) {
                        alert(`Already has tag "${tag}" — no change.`);
                        return;
                      }
                      const merged = Array.from(new Set([...cur, tag]));
                      void api
                        .findingSetTags(selected.id, merged)
                        .then(() => api.findingsList().then(setFindings))
                        .catch((err) => alert(`${err}`));
                    }}
                    title={
                      (selected.tags?.length ?? 0) > 0
                        ? `Add a tag to this finding (currently: ${(selected.tags ?? []).join(", ")})`
                        : "Add a tag to this finding (no tags yet)"
                    }
                    style={{ padding: "2px 8px", fontSize: 11, marginLeft: 4 }}
                  >
                    + Tag
                  </button>
                </div>
                {/* R370: Tag chips row — operators tagging findings  */}
                {/* via R312 bulk / R322 right-click / R351 inline    */}
                {/* had no visual indicator of the current tag set    */}
                {/* in the detail pane. This row renders each tag as */}
                {/* a chip with a one-click ⨯ remove so operators     */}
                {/* can prune a mis-applied tag without re-reading   */}
                {/* the whole set. Only renders when tags.length > 0 */}
                {/* so idle findings don't carry an empty strip.     */}
                {selected.tags && selected.tags.length > 0 && (
                  <div
                    style={{
                      display: "flex",
                      flexWrap: "wrap",
                      gap: 6,
                      padding: "0 10px 6px",
                      fontSize: 11,
                    }}
                  >
                    <span className="dim" style={{ alignSelf: "center" }}>
                      tags:
                    </span>
                    {selected.tags.map((t) => (
                      <span
                        key={t}
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          gap: 4,
                          padding: "1px 6px",
                          borderRadius: 10,
                          background: "rgba(100,150,255,0.14)",
                          border: "1px solid rgba(100,150,255,0.4)",
                        }}
                      >
                        {t}
                        <button
                          onClick={() => {
                            const next = (selected.tags ?? []).filter(
                              (x) => x !== t,
                            );
                            void api
                              .findingSetTags(selected.id, next)
                              .then(() => api.findingsList().then(setFindings))
                              .catch((err) => alert(`${err}`));
                          }}
                          title={`Remove tag "${t}"`}
                          style={{
                            background: "transparent",
                            border: "none",
                            padding: 0,
                            cursor: "pointer",
                            color: "var(--text-dim)",
                            fontSize: 12,
                            lineHeight: 1,
                          }}
                        >
                          ⨯
                        </button>
                      </span>
                    ))}
                  </div>
                )}
                <div className="rep-tabs" style={{ borderBottom: "none" }}>
                  <div
                    className={`rep-tab ${issueTab === "advisory" ? "active" : ""}`}
                    onClick={() => setIssueTab("advisory")}
                    style={{ cursor: "pointer" }}
                  >
                    <span className="rep-tab-label">Advisory</span>
                  </div>
                  <div
                    className={`rep-tab ${issueTab === "request" ? "active" : ""}`}
                    onClick={() => {
                      if (selected.transaction_id) setIssueTab("request");
                    }}
                    style={{
                      cursor: selected.transaction_id ? "pointer" : "not-allowed",
                      opacity: selected.transaction_id ? 1 : 0.4,
                    }}
                    title={
                      selected.transaction_id
                        ? "View the request bytes that produced this finding"
                        : "No linked transaction — this finding wasn't tied to a specific request"
                    }
                  >
                    <span className="rep-tab-label">Request</span>
                  </div>
                  <div
                    className={`rep-tab ${issueTab === "response" ? "active" : ""}`}
                    onClick={() => {
                      if (selected.transaction_id) setIssueTab("response");
                    }}
                    style={{
                      cursor: selected.transaction_id ? "pointer" : "not-allowed",
                      opacity: selected.transaction_id ? 1 : 0.4,
                    }}
                    title={
                      selected.transaction_id
                        ? "View the response bytes that produced this finding"
                        : "No linked transaction"
                    }
                  >
                    <span className="rep-tab-label">Response</span>
                  </div>
                </div>
              </div>
              {/* Tab content */}
              <div style={{ flex: 1, overflow: "auto", minHeight: 0 }}>
                {issueTab === "advisory" && (
                  <div style={{ padding: 10 }}>
                    <h4 style={{ marginTop: 0 }}>Description</h4>
                    <div>
                      {selected.description || <em>No description</em>}
                    </div>
                    <div
                      style={{
                        display: "flex",
                        alignItems: "baseline",
                        gap: 8,
                        marginBottom: 2,
                      }}
                    >
                      <h4 style={{ margin: 0 }}>Evidence</h4>
                      {/* R304: One-click copy of evidence string.   */}
                      {/* Operators pasting into tickets / Jira /    */}
                      {/* Slack want a direct button rather than     */}
                      {/* right-click → Copy evidence (which exists  */}
                      {/* via R91 context menu).                     */}
                      {selected.evidence && (
                        <>
                          <button
                            className="ghost"
                            onClick={async () => {
                              try {
                                await navigator.clipboard.writeText(
                                  selected.evidence,
                                );
                              } catch (e) {
                                alert(`Copy failed: ${e}`);
                              }
                            }}
                            title="Copy the evidence string to clipboard — same as the right-click Copy evidence action but inline next to the heading"
                            style={{ fontSize: 10.5, padding: "1px 6px" }}
                          >
                            📋 Copy
                          </button>
                          {/* R401: Save evidence to a .txt file —    */}
                          {/* companion to R304's inline Copy button.  */}
                          {/* Evidence blobs can run large (full raw   */}
                          {/* response bodies for XSS reflections / */}
                          {/* SSRF response bodies / stack-trace       */}
                          {/* dumps) — a clipboard round-trip truncates*/}
                          {/* for anything over ~1 MB on some          */}
                          {/* OS clipboards. File-save sidesteps the   */}
                          {/* limit and gives operators a persistent   */}
                          {/* on-disk artefact for a PoC bundle /      */}
                          {/* ticket attachment. Filename pattern:     */}
                          {/* `evidence-<finding-id>-<slug>.txt` so    */}
                          {/* multiple findings don't clobber each     */}
                          {/* other and the slug makes the file self-  */}
                          {/* describing when found again later.       */}
                          <button
                            className="ghost"
                            onClick={() => {
                              const slug =
                                (selected.title || "evidence")
                                  .toLowerCase()
                                  .replace(/[^a-z0-9]+/g, "-")
                                  .replace(/^-|-$/g, "")
                                  .slice(0, 40) || "evidence";
                              const name = `evidence-${selected.id}-${slug}.txt`;
                              const blob = new Blob([selected.evidence ?? ""], {
                                type: "text/plain;charset=utf-8",
                              });
                              const url = URL.createObjectURL(blob);
                              const a = document.createElement("a");
                              a.href = url;
                              a.download = name;
                              a.click();
                              URL.revokeObjectURL(url);
                            }}
                            title={`Save the evidence string as "${(selected.title || "evidence")
                              .toLowerCase()
                              .replace(/[^a-z0-9]+/g, "-")
                              .replace(/^-|-$/g, "")
                              .slice(0, 40) || "evidence"}.txt" — great for PoC bundles / ticket attachments / large evidence blobs that exceed clipboard limits.`}
                            style={{ fontSize: 10.5, padding: "1px 6px" }}
                          >
                            ⬇ Save
                          </button>
                          {/* R477: Copy as HAR entry — complement to    */}
                          {/* R470's HistoryPanel per-row HAR + R453's   */}
                          {/* bulk HAR button, applied to the Scanner    */}
                          {/* detail pane. For a selected finding with   */}
                          {/* a transaction_id, pulls the parent tx's   */}
                          {/* request_raw + response_raw via             */}
                          {/* historyShow() and emits a single-entry    */}
                          {/* HAR 1.2 log to the clipboard. Byte-        */}
                          {/* identical output to R470 for the same     */}
                          {/* row, so operators mixing per-finding +    */}
                          {/* per-history-row workflows get consistent  */}
                          {/* artifacts. Disabled when transaction_id   */}
                          {/* is null — passive-only findings have no    */}
                          {/* parent tx to export (same gate as R420     */}
                          {/* Alt+Shift+H history pivot).                 */}
                          {selected.transaction_id != null && (
                            <button
                              className="ghost"
                              onClick={async () => {
                                const txId = selected.transaction_id;
                                if (txId == null) return;
                                try {
                                  const view = await api.historyShow(txId);
                                  if (!view?.request_raw) {
                                    alert(
                                      `Parent transaction #${txId} has no stored request_raw — cannot build a HAR entry.`,
                                    );
                                    return;
                                  }
                                  const req = fromSummaryAndRaw(
                                    view.summary,
                                    view.request_raw,
                                  );
                                  let resp: Parameters<typeof buildHarEntry>[2] =
                                    undefined;
                                  if (view.response_raw) {
                                    const text = view.response_raw.replace(
                                      /\r\n/g,
                                      "\n",
                                    );
                                    const headerEnd = text.indexOf("\n\n");
                                    const headerBlock =
                                      headerEnd >= 0
                                        ? text.slice(0, headerEnd)
                                        : text;
                                    const body =
                                      headerEnd >= 0
                                        ? text.slice(headerEnd + 2)
                                        : "";
                                    const lines = headerBlock.split("\n");
                                    const statusLine = (
                                      lines.shift() ?? ""
                                    ).trim();
                                    const m = statusLine.match(
                                      /^(HTTP\/\S+)\s+(\d+)(?:\s+(.*))?$/,
                                    );
                                    const httpVersion = m?.[1] ?? "HTTP/1.1";
                                    const status = m
                                      ? parseInt(m[2], 10)
                                      : 0;
                                    const statusText = m?.[3] ?? "";
                                    const headers: Array<[string, string]> = [];
                                    let mimeType = "";
                                    for (const l of lines) {
                                      const colon = l.indexOf(":");
                                      if (colon <= 0) continue;
                                      const n = l.slice(0, colon).trim();
                                      const v = l.slice(colon + 1).trim();
                                      if (!n) continue;
                                      headers.push([n, v]);
                                      if (n.toLowerCase() === "content-type")
                                        mimeType = v;
                                    }
                                    resp = {
                                      status,
                                      statusText,
                                      httpVersion,
                                      headers,
                                      mimeType,
                                      body,
                                    };
                                  }
                                  const startedDateTime = new Date(
                                    view.summary.ts_ms,
                                  ).toISOString();
                                  const entry = buildHarEntry(
                                    req,
                                    startedDateTime,
                                    resp,
                                  );
                                  const har = buildHarLog([entry]);
                                  await navigator.clipboard.writeText(
                                    JSON.stringify(har, null, 2),
                                  );
                                } catch (err) {
                                  alert(`${err}`);
                                }
                              }}
                              title={`Copy the parent transaction (tx #${selected.transaction_id}) as a single-entry HAR 1.2 log — paste into Chrome DevTools "Network → Import HAR", Firefox, HTTP Toolkit, Fiddler. Operators moving a Scanner finding to a browser-based reproduction get a universal replay format.`}
                              style={{ fontSize: 10.5, padding: "1px 6px" }}
                            >
                              📋 Copy as HAR
                            </button>
                          )}
                        </>
                      )}
                    </div>
                    <pre
                      className="mono"
                      style={{
                        maxHeight: 220,
                        overflow: "auto",
                        background: "var(--bg-raised)",
                        padding: 8,
                        borderRadius: 3,
                        fontSize: 11,
                      }}
                    >
                      {selected.evidence || "(none)"}
                    </pre>
                    <h4>Remediation</h4>
                    <div>{selected.remediation || "(not specified)"}</div>
                    <h4>Tags</h4>
                    <TagsEditor
                      finding={selected}
                      onChange={async (next) => {
                        try {
                          await api.findingSetTags(selected.id, next);
                          await refresh();
                        } catch (e) {
                          alert(`Could not save tags: ${e}`);
                        }
                      }}
                    />
                    {selected.references && selected.references.length > 0 && (
                      <>
                        <h4>References</h4>
                        <ul
                          style={{
                            margin: "0 0 10px 20px",
                            padding: 0,
                            fontSize: 12,
                            lineHeight: 1.6,
                          }}
                        >
                          {selected.references.map((r, i) => (
                            <li key={i}>
                              {/^https?:\/\//i.test(r) ? (
                                <a
                                  href={r}
                                  target="_blank"
                                  rel="noreferrer"
                                  style={{
                                    color: "var(--accent)",
                                    textDecoration: "none",
                                  }}
                                  onMouseEnter={(e) =>
                                    (e.currentTarget.style.textDecoration =
                                      "underline")
                                  }
                                  onMouseLeave={(e) =>
                                    (e.currentTarget.style.textDecoration = "none")
                                  }
                                >
                                  {r}
                                </a>
                              ) : (
                                <span className="mono">{r}</span>
                              )}
                            </li>
                          ))}
                        </ul>
                      </>
                    )}
                  </div>
                )}
                {issueTab === "request" && (
                  <>
                    {issueTxBusy && (
                      <div className="empty">Loading request…</div>
                    )}
                    {!issueTxBusy && !issueTx && (
                      <div className="empty">
                        No linked transaction or fetch failed.
                      </div>
                    )}
                    {issueTx && (
                      <MessageEditor
                        label="Request"
                        value={issueTx.request_raw ?? ""}
                        onChange={() => {}}
                        direction="request"
                        readOnly
                      />
                    )}
                  </>
                )}
                {issueTab === "response" && (
                  <>
                    {issueTxBusy && (
                      <div className="empty">Loading response…</div>
                    )}
                    {!issueTxBusy && !issueTx && (
                      <div className="empty">
                        No linked transaction or fetch failed.
                      </div>
                    )}
                    {issueTx && (
                      <MessageEditor
                        label="Response"
                        value={issueTx.response_raw ?? ""}
                        onChange={() => {}}
                        direction="response"
                        readOnly
                      />
                    )}
                  </>
                )}
              </div>
            </>
          )}
        </div>
      </div>
      <FloatingMenu
        state={menu}
        onClose={() => setMenu(null)}
        items={
          menu?.data
            ? [
                {
                  label: "Mark as triaging",
                  onClick: () => {
                    void api
                      .findingSetStatus(menu.data!.id, "triaging")
                      .then(() => api.findingsList().then(setFindings));
                  },
                },
                {
                  label: "Mark as confirmed",
                  onClick: () => {
                    void api
                      .findingSetStatus(menu.data!.id, "confirmed")
                      .then(() => api.findingsList().then(setFindings));
                  },
                },
                {
                  label: "Mark as false positive",
                  onClick: () => {
                    void api
                      .findingSetStatus(menu.data!.id, "false_positive")
                      .then(() => api.findingsList().then(setFindings));
                  },
                },
                { separator: true },
                {
                  label: "Verify",
                  onClick: () => {
                    void api
                      .findingSetVerification(menu.data!.id, "verified")
                      .then(() => api.findingsList().then(setFindings));
                  },
                  hint: "mark as verified",
                },
                /* R164: Operator-driven severity override. Burp Pro's */
                /* Issue → Set severity submenu lets triagers bump or   */
                /* demote the detector's auto-assigned severity when    */
                /* their context (production reach, auth state, data    */
                /* sensitivity) differs from the detector's heuristic.  */
                /* Only shows items that would actually change the row  */
                /* so a critical finding doesn't offer a redundant      */
                /* "Severity: critical" entry.                            */
                ...(
                  ["critical", "high", "medium", "low", "info"]
                    .filter((s) => s !== menu.data!.severity)
                    .map((sev) => ({
                      label: `Severity: ${sev}`,
                      hint:
                        sev === "critical" || sev === "high"
                          ? "bump up"
                          : "bump down",
                      onClick: () => {
                        void api
                          .findingSetSeverity(menu.data!.id, sev)
                          .then(() => api.findingsList().then(setFindings))
                          .catch((e) => alert(`${e}`));
                      },
                    }))
                ),
                {
                  label: "Rerun active scan",
                  onClick: () => void rerunActiveScan(menu.data!),
                  disabled: !menu.data!.transaction_id || rerunBusy,
                  hint: !menu.data!.transaction_id
                    ? "no linked transaction"
                    : "fires every enabled probe against the parent request",
                },
                // R316: Send parent request to Repeater — Burp Pro
                // canonical issue-right-click action. Operators
                // triaging a finding want to iterate on the request
                // in Repeater (tweak header / change payload / replay
                // without the probe). Mirrors R131-era TargetPanel
                // sendIssueToRepeater. Disabled for passive-only
                // findings where transaction_id is null (no parent
                // request to send).
                {
                  label: "Send request to Repeater",
                  onClick: () => {
                    const f = menu.data!;
                    const txId = f.transaction_id;
                    if (!txId) {
                      alert("Finding has no parent transaction to send.");
                      return;
                    }
                    void (async () => {
                      try {
                        await api.repeaterAddFromHistory(txId, f.title);
                        window.dispatchEvent(
                          new CustomEvent("burpfree:navigate", {
                            detail: { target: "repeater" },
                          }),
                        );
                      } catch (e) {
                        alert(`Send to Repeater failed: ${e}`);
                      }
                    })();
                  },
                  disabled: !menu.data!.transaction_id,
                  hint: !menu.data!.transaction_id
                    ? "no linked transaction"
                    : "clones the parent request into a new Repeater tab + jumps the UI",
                },
                /* R419: "→ History (parent tx)" row-context entry —  */
                /* row-right-click counterpart to R161's detail-pane  */
                /* "→ History" button. Jumps to HTTP history and     */
                /* highlights the specific row that produced this    */
                /* finding. Operators triaging in Scanner often want */
                /* to pivot into History to see the full tx context  */
                /* (headers / cookies / referrer) without opening    */
                /* the detail pane first. Reuses the existing        */
                /* `burpfree:history-focus` CustomEvent bridge +     */
                /* `burpfree:navigate` jump. **Mechanism** mirrors   */
                /* R161 exactly: dispatch both events in order so    */
                /* HistoryPanel both switches tabs AND scrolls the   */
                /* targeted row into view. **Guards** disabled when  */
                /* no transaction_id (passive findings).              */
                {
                  label: "→ History (parent tx)",
                  hint: "jump to the HTTP history row",
                  onClick: () => {
                    const f = menu.data!;
                    const txId = f.transaction_id;
                    if (!txId) return;
                    window.dispatchEvent(
                      new CustomEvent("burpfree:history-focus", {
                        detail: { id: txId },
                      }),
                    );
                    window.dispatchEvent(
                      new CustomEvent("burpfree:navigate", {
                        detail: { target: "history" },
                      }),
                    );
                  },
                  disabled: !menu.data!.transaction_id,
                },
                // R317: Send parent request to Intruder — completes the
                // Burp-Pro triage-pivot triad with R316 (Repeater) +
                // Rerun active scan. Operators triaging a finding
                // (e.g. "potential SQLi") want to fuzz the request's
                // parameters with a wordlist; this hands the request
                // url + method + tx id to the Intruder panel via the
                // same CustomEvent payload TargetPanel's R131-era
                // sendIssueToIntruder uses. Mechanism needs one
                // round-trip to `historyShow(txId)` to grab the
                // scheme + host + port + path (StoredFinding carries
                // transaction_id but not the full URL — that lives
                // on the StoredSummary inside TransactionView).
                {
                  label: "Send request to Intruder",
                  onClick: () => {
                    const f = menu.data!;
                    const txId = f.transaction_id;
                    if (!txId) {
                      alert("Finding has no parent transaction to send.");
                      return;
                    }
                    void (async () => {
                      try {
                        const view = await api.historyShow(txId);
                        const url = urlFromSummary(view.summary);
                        window.dispatchEvent(
                          new CustomEvent("burpfree:intruder-load", {
                            detail: {
                              url,
                              method: view.summary.method,
                              transactionId: txId,
                            },
                          }),
                        );
                        window.dispatchEvent(
                          new CustomEvent("burpfree:navigate", {
                            detail: { target: "intruder" },
                          }),
                        );
                      } catch (e) {
                        alert(`Send to Intruder failed: ${e}`);
                      }
                    })();
                  },
                  disabled: !menu.data!.transaction_id,
                  hint: !menu.data!.transaction_id
                    ? "no linked transaction"
                    : "seeds the Intruder composer with url / method / tx id + jumps the UI",
                },
                // R318: Send parent request to Comparer (left/right)
                // — completes the Scanner row's triage-pivot quartet
                // (Rerun + Repeater + Intruder + Comparer). Operators
                // triaging a finding regularly want to diff the
                // parent request against a known-good baseline or a
                // sibling attack-variant. Follows the correct R208
                // HistoryPanel pattern: `{left, right, label}` where
                // only the slot that matches is filled and the
                // other side stays empty. **Payload shape** matches
                // `ComparerLoadDetail` exactly — TargetPanel's older
                // sendIssueToComparer uses `{slot, text, label}`
                // which is a shape mismatch vs what ComparerPanel
                // listens for (noted — out of scope here). **Round-
                // trip** one `historyShow(txId)` call to grab the
                // raw request bytes.
                {
                  label: "Send request to Comparer (left)",
                  onClick: () => {
                    const f = menu.data!;
                    const txId = f.transaction_id;
                    if (!txId) {
                      alert("Finding has no parent transaction to send.");
                      return;
                    }
                    void (async () => {
                      try {
                        const view = await api.historyShow(txId);
                        window.dispatchEvent(
                          new CustomEvent("burpfree:comparer-load", {
                            detail: {
                              left: view.request_raw ?? "",
                              right: "",
                              label: `finding ${f.id}: ${f.title}`,
                            },
                          }),
                        );
                        window.dispatchEvent(
                          new CustomEvent("burpfree:navigate", {
                            detail: { target: "comparer" },
                          }),
                        );
                      } catch (e) {
                        alert(`Send to Comparer failed: ${e}`);
                      }
                    })();
                  },
                  disabled: !menu.data!.transaction_id,
                  hint: !menu.data!.transaction_id
                    ? "no linked transaction"
                    : "loads the request bytes into the LEFT Comparer slot + jumps the UI",
                },
                {
                  label: "Send request to Comparer (right)",
                  onClick: () => {
                    const f = menu.data!;
                    const txId = f.transaction_id;
                    if (!txId) {
                      alert("Finding has no parent transaction to send.");
                      return;
                    }
                    void (async () => {
                      try {
                        const view = await api.historyShow(txId);
                        window.dispatchEvent(
                          new CustomEvent("burpfree:comparer-load", {
                            detail: {
                              left: "",
                              right: view.request_raw ?? "",
                              label: `finding ${f.id}: ${f.title}`,
                            },
                          }),
                        );
                        window.dispatchEvent(
                          new CustomEvent("burpfree:navigate", {
                            detail: { target: "comparer" },
                          }),
                        );
                      } catch (e) {
                        alert(`Send to Comparer failed: ${e}`);
                      }
                    })();
                  },
                  disabled: !menu.data!.transaction_id,
                  hint: !menu.data!.transaction_id
                    ? "no linked transaction"
                    : "loads the request bytes into the RIGHT Comparer slot + jumps the UI",
                },
                { separator: true },
                {
                  label: "Copy title",
                  onClick: () => void navigator.clipboard.writeText(menu.data!.title),
                },
                {
                  label: "Copy evidence",
                  onClick: () => void navigator.clipboard.writeText(menu.data!.evidence),
                  disabled: !menu.data.evidence,
                },
                // R652: Scanner row-right-click "Copy as JSON" —
                // single-row counterpart to R606 bulk Copy as JSON.
                // Operators scripting a finding into a test case /
                // regression seed / jq pipeline want the full
                // StoredFinding record (tags, references,
                // insertion_point, remediation, description, note,
                // assignee) on the clipboard pretty-printed.
                {
                  label: "Copy as JSON",
                  hint: "full StoredFinding record · pretty-printed",
                  onClick: () =>
                    void navigator.clipboard.writeText(
                      JSON.stringify(menu.data!, null, 2),
                    ),
                },
                // R709: Scanner row "Copy JSONL line" — 2nd
                // panel in the cross-panel row-level JSONL-line
                // family (HistoryPanel R708 + Scanner R709).
                // Single-line NDJSON (one object, one line, no
                // array wrap, no pretty-print) — for operators
                // building a scratch jq input one finding at a
                // time or appending to an existing .jsonl log.
                // Trailing newline so repeated clicks concat
                // cleanly. Byte-identical to R615 bulk Copy-as-
                // JSONL per-line output on Scanner.
                {
                  label: "Copy JSONL line",
                  hint: "one object, one line + newline",
                  onClick: () =>
                    void navigator.clipboard.writeText(
                      JSON.stringify(menu.data!) + "\n",
                    ),
                },
                // R728: Scanner row "Copy triage line" — compact
                // single-line finding summary. Mirrors R717
                // HistoryPanel pattern adapted for finding shape:
                // "SEV detector · 'title' · verification · tx:#N
                // · 📎evidence". Perfect for Slack / ticket /
                // commit-message annotation where neither JSON
                // nor Markdown fits. Conditional bits: verification
                // only renders when not "unverified" (default),
                // tx:#N only when transaction_id is set, evidence
                // emoji only when evidence is non-empty.
                {
                  label: "Copy triage line",
                  hint: "compact SEV detector title · tx · evidence",
                  onClick: () => {
                    const f = menu.data!;
                    const sev = (f.severity || "info").toUpperCase();
                    const parts: string[] = [`${sev} ${f.detector || "(unknown)"}`];
                    if (f.title) parts.push(`'${f.title}'`);
                    const v = (f.verification || "").toLowerCase();
                    if (v && v !== "unverified") parts.push(v);
                    if (typeof f.transaction_id === "number")
                      parts.push(`tx:#${f.transaction_id}`);
                    if (f.evidence && f.evidence.length > 0)
                      parts.push("📎evidence");
                    void navigator.clipboard.writeText(parts.join(" · "));
                  },
                },
                // R664: Scanner row-right-click "Copy table row"
                // — single-row Markdown table variant of R626 bulk
                // Copy as table on Scanner. Just the row-content
                // Markdown line matching R626's 6-column shape so
                // operators can mix row-right-click + bulk outputs
                // in the same table. Mirror of R663 HistoryPanel
                // pattern.
                {
                  label: "Copy table row",
                  hint: "Markdown table body line · no header",
                  onClick: () => {
                    const f = menu.data!;
                    const esc = (v: unknown) =>
                      String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
                    const cells = [
                      f.id,
                      f.severity,
                      f.title,
                      f.status,
                      f.verification,
                      f.detector,
                    ]
                      .map(esc)
                      .join(" | ");
                    void navigator.clipboard.writeText(`| ${cells} |`);
                  },
                },
                // 🎯 R660: Scanner row-right-click "Copy as
                // Markdown" — completes the 4-panel row-right-
                // click Markdown family (HistoryPanel R640 /
                // Target Issues R625 / ProxyPanel R659 / Scanner
                // R660). Scanner uses the finding-focused 6-field
                // shape (sev + title + status + verification +
                // detector + optional evidence) rather than the
                // tx-focused shape of History/Proxy. 🎯 R660
                // round-number milestone.
                {
                  label: "Copy as Markdown",
                  hint: "H3 section · severity+evidence",
                  onClick: () => {
                    const f = menu.data!;
                    const sevIcon =
                      f.severity === "critical"
                        ? "🔴"
                        : f.severity === "high"
                          ? "🟠"
                          : f.severity === "medium"
                            ? "🟡"
                            : f.severity === "low"
                              ? "🔵"
                              : "⚪";
                    const lines = [
                      `### ${sevIcon} [${(f.severity || "info").toUpperCase()}] ${f.title}`,
                      "",
                      `- **Status**: ${f.status || "new"}`,
                      `- **Verification**: ${f.verification || "unverified"}`,
                      `- **Detector**: ${f.detector || "—"}`,
                      `- **Confidence**: ${f.confidence || "—"}`,
                    ];
                    if (f.evidence) {
                      lines.push("", "**Evidence**", "```", f.evidence, "```");
                    }
                    if (f.tags && f.tags.length > 0)
                      lines.push("", `- **Tags**: ${f.tags.join(", ")}`);
                    void navigator.clipboard.writeText(lines.join("\n"));
                  },
                },
                // R486: Row-scope "Copy parent tx URL" — one-click
                // URL copy for the parent transaction, matching the
                // "Copy URL" entry on HistoryPanel row-right-click +
                // TargetPanel node-menu. Operators pivoting a
                // finding into a sibling tool (sqlmap / nikto /
                // ffuf / zap import) want just the URL — not the
                // full cURL command (which includes headers +
                // method) or the HAR entry (which includes
                // response). **Mechanism** calls `api.historyShow`
                // for the parent tx + extracts the URL via
                // `urlFromSummary`. One RPC per click. Alerts on
                // missing tx. **Disabled gate** `transaction_id ==
                // null` — passive-only findings have no parent tx,
                // same gate as R420 Alt+Shift+H history pivot +
                // R482 Copy as HAR entry.
                {
                  label: "Copy parent tx URL",
                  hint: "clipboard · scheme + host + path",
                  disabled: menu.data!.transaction_id == null,
                  onClick: async () => {
                    const txId = menu.data!.transaction_id;
                    if (txId == null) return;
                    try {
                      const view = await api.historyShow(txId);
                      if (!view?.summary) {
                        alert(
                          `Parent transaction #${txId} could not be resolved.`,
                        );
                        return;
                      }
                      const url = urlFromSummary(view.summary);
                      await navigator.clipboard.writeText(url);
                    } catch (err) {
                      alert(`${err}`);
                    }
                  },
                },
                // R326: Row-scope "⬇ Export JSON" — right-click
                // equivalent of R324 Scanner detail-pane JSON export.
                // Operators sometimes want to grab a finding JSON
                // without having to first select it into the detail
                // pane (which replaces the current detail view).
                // Pretty-printed two-space-indented JSON matches
                // R324 so the filename pattern (and output format)
                // round-trips byte-for-byte between the two paths.
                {
                  label: "⬇ Export JSON",
                  hint: "pretty-printed, single-finding",
                  onClick: () => {
                    const f = menu.data!;
                    try {
                      const blob = new Blob(
                        [JSON.stringify(f, null, 2)],
                        { type: "application/json;charset=utf-8" },
                      );
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement("a");
                      const stamp = new Date()
                        .toISOString()
                        .replace(/[:T]/g, "-")
                        .replace(/\..*$/, "");
                      a.href = url;
                      a.download = `burpfree-finding-${f.id}-${f.severity}-${stamp}.json`;
                      document.body.appendChild(a);
                      a.click();
                      a.remove();
                      URL.revokeObjectURL(url);
                    } catch (err) {
                      alert(`${err}`);
                    }
                  },
                },
                // R494: Row-scope "Copy as cURL" — pulls parent tx
                // request_raw via historyShow() + builds a cURL
                // command via buildCurl(fromSummaryAndRaw()).
                // Operators moving a Scanner finding to a shell
                // replay (sqlmap target / nikto scan / smoke test
                // loop) want the cURL immediately — currently they
                // pivot to HistoryPanel + row-right-click "Copy as
                // cURL". R494 closes that gap: Scanner row-right-
                // click now mirrors HistoryPanel's shape for the
                // common cURL / URL / HAR trio (R486 URL / R494
                // cURL / R482 HAR). **Disabled gate**
                // `transaction_id == null` — passive-only skips.
                {
                  label: "Copy as cURL",
                  hint: "parent tx · full headers + body",
                  disabled: menu.data!.transaction_id == null,
                  onClick: async () => {
                    const txId = menu.data!.transaction_id;
                    if (txId == null) return;
                    try {
                      const view = await api.historyShow(txId);
                      if (!view?.request_raw) {
                        alert(
                          `Parent transaction #${txId} has no stored request_raw.`,
                        );
                        return;
                      }
                      const req = fromSummaryAndRaw(
                        view.summary,
                        view.request_raw,
                      );
                      await copyToClipboard(buildCurl(req));
                    } catch (err) {
                      alert(`${err}`);
                    }
                  },
                },
                // R497: Row-scope "Copy as PowerShell" — Windows-
                // native variant of R494 cURL. Operators on Windows
                // workstations without curl / WSL want PowerShell
                // (Invoke-WebRequest) as the primary replay format
                // — curl on Windows requires git-bash, WSL, or a
                // modern curl.exe install, while PowerShell is
                // always present. Same mechanism as R494, just swap
                // `buildCurl` for `buildPowerShell`.
                {
                  label: "Copy as PowerShell",
                  hint: "parent tx · Invoke-WebRequest",
                  disabled: menu.data!.transaction_id == null,
                  onClick: async () => {
                    const txId = menu.data!.transaction_id;
                    if (txId == null) return;
                    try {
                      const view = await api.historyShow(txId);
                      if (!view?.request_raw) {
                        alert(
                          `Parent transaction #${txId} has no stored request_raw.`,
                        );
                        return;
                      }
                      const req = fromSummaryAndRaw(
                        view.summary,
                        view.request_raw,
                      );
                      await copyToClipboard(buildPowerShell(req));
                    } catch (err) {
                      alert(`${err}`);
                    }
                  },
                },
                // R500: 🎯 Round-number milestone. Scanner row-scope
                // "Copy as Python (requests)" — completes the shell-
                // replay triad on Scanner alongside R494 cURL + R497
                // PowerShell. Operators scripting a Python-based
                // follow-up probe (pytest harness, custom extractor,
                // sqlmap wrapper) get the ready-to-run requests
                // library snippet directly. Same mechanism as R494/
                // R497: historyShow → fromSummaryAndRaw → buildPython.
                // HistoryPanel has had Copy as Python since R433-era
                // bulk + per-row via copyAs("python"); Scanner is now
                // caught up. Scanner row-right-click menu now carries
                // nine single-row ops: Copy title / Copy evidence /
                // Copy parent tx URL / Copy as cURL / Copy as
                // PowerShell / Copy as Python / Copy as HAR entry /
                // Export JSON / Save evidence — Linux shell / Windows
                // shell / Python / browser format / identifier /
                // record / artifact / data / text.
                {
                  label: "Copy as Python (requests)",
                  hint: "parent tx · import requests",
                  disabled: menu.data!.transaction_id == null,
                  onClick: async () => {
                    const txId = menu.data!.transaction_id;
                    if (txId == null) return;
                    try {
                      const view = await api.historyShow(txId);
                      if (!view?.request_raw) {
                        alert(
                          `Parent transaction #${txId} has no stored request_raw.`,
                        );
                        return;
                      }
                      const req = fromSummaryAndRaw(
                        view.summary,
                        view.request_raw,
                      );
                      await copyToClipboard(buildPython(req));
                    } catch (err) {
                      alert(`${err}`);
                    }
                  },
                },
                // R632: Scanner row-right-click "Copy as fetch()" —
                // completes the shell-replay quartet alongside
                // R494 cURL + R497 PowerShell + R500 Python. DevTools-
                // ready fetch() snippet for in-browser replay. Same
                // mechanism as R494/R497/R500: historyShow →
                // fromSummaryAndRaw → buildFetch. HistoryPanel has had
                // "Copy as fetch()" since R434-era bulk + R-era row-
                // right-click; Scanner is now caught up.
                {
                  label: "Copy as fetch()",
                  hint: "parent tx · DevTools console paste",
                  disabled: menu.data!.transaction_id == null,
                  onClick: async () => {
                    const txId = menu.data!.transaction_id;
                    if (txId == null) return;
                    try {
                      const view = await api.historyShow(txId);
                      if (!view?.request_raw) {
                        alert(
                          `Parent transaction #${txId} has no stored request_raw.`,
                        );
                        return;
                      }
                      const req = fromSummaryAndRaw(
                        view.summary,
                        view.request_raw,
                      );
                      await copyToClipboard(buildFetch(req));
                    } catch (err) {
                      alert(`${err}`);
                    }
                  },
                },
                // R579: Scanner row-right-click "+ Add host to
                // scope" — cross-panel mirror of R578 Target
                // row entry. Operators discovering a new target
                // host via a Scanner finding want to one-click
                // add it to scope. Unlike Target (R578) which
                // has an in-memory tx map, Scanner must fetch
                // the parent summary via `historyShow(txId)` to
                // resolve the host. Reuses `scopeAddRule` +
                // `buildHostIncludeRule`. Backend's unique-rule
                // guard idempotently no-ops on duplicate adds.
                {
                  label: "+ Add host to scope",
                  hint: menu.data!.transaction_id
                    ? "resolve host via parent tx"
                    : "passive-only — no parent tx",
                  disabled: menu.data!.transaction_id == null,
                  onClick: async () => {
                    const txId = menu.data!.transaction_id;
                    if (txId == null) return;
                    try {
                      const view = await api.historyShow(txId);
                      const host = view?.summary?.host;
                      if (!host) {
                        alert(
                          `Parent transaction #${txId} has no host — cannot add to scope.`,
                        );
                        return;
                      }
                      await api.scopeAddRule(buildHostIncludeRule(host));
                      alert(`Added host "${host}" to scope.`);
                    } catch (e) {
                      alert(`${e}`);
                    }
                  },
                },
                // R581: Scanner row-right-click "+ Add host:path
                // to scope" — path-exact mirror of R580 Target.
                // Operators doing precision scope ("include only
                // this exact finding's endpoint") want path-level
                // rules. Uses `buildPathIncludeRule` which strips
                // the query string. Needs `historyShow(txId)` to
                // resolve both host + path from the parent tx
                // (Scanner's StoredFinding doesn't carry them
                // directly). Backend idempotency keeps double-
                // adds safe.
                {
                  label: "+ Add host:path to scope",
                  hint: menu.data!.transaction_id
                    ? "path-exact, narrower than + Add host"
                    : "passive-only — no parent tx",
                  disabled: menu.data!.transaction_id == null,
                  onClick: async () => {
                    const txId = menu.data!.transaction_id;
                    if (txId == null) return;
                    try {
                      const view = await api.historyShow(txId);
                      const host = view?.summary?.host;
                      const path = view?.summary?.path;
                      if (!host || !path) {
                        alert(
                          `Parent transaction #${txId} has no host or path — cannot add to scope.`,
                        );
                        return;
                      }
                      await api.scopeAddRule(buildPathIncludeRule(host, path));
                      alert(
                        `Added "${host}${path.split("?")[0] || "/"}" to scope.`,
                      );
                    } catch (e) {
                      alert(`${e}`);
                    }
                  },
                },
                // R594: Scanner row-right-click "− Exclude host" — mirror
                // of R590 HistoryPanel + R592 Target Issues on Scanner.
                // Operators triaging findings often want to actively
                // suppress a noisy host (CDN, analytics, third-party
                // widget) without hiding every finding on included
                // hosts. Builds inline exclude rule (`match_kind:
                // "exclude"`, path "*") — same shape as R590/R592.
                // Needs `historyShow(txId)` since Scanner findings
                // don't carry host directly. Passive-only findings
                // disable the entry. Backend's unique-rule guard
                // idempotently no-ops. Danger-styled.
                {
                  label: "− Exclude host from scope",
                  hint: menu.data!.transaction_id
                    ? "add scope EXCLUDE rule via parent tx"
                    : "passive-only — no parent tx",
                  disabled: menu.data!.transaction_id == null,
                  danger: menu.data!.transaction_id != null,
                  onClick: async () => {
                    const txId = menu.data!.transaction_id;
                    if (txId == null) return;
                    try {
                      const view = await api.historyShow(txId);
                      const host = view?.summary?.host;
                      if (!host) {
                        alert(
                          `Parent transaction #${txId} has no host — cannot exclude from scope.`,
                        );
                        return;
                      }
                      await api.scopeAddRule({
                        match_kind: "exclude",
                        protocol: "any",
                        host: host.trim(),
                        port: null as unknown as undefined,
                        path: "*",
                        regex: false,
                        enabled: true,
                      });
                      alert(`Excluded host "${host}" from scope.`);
                    } catch (e) {
                      alert(`${e}`);
                    }
                  },
                },
                // R595: Scanner row-right-click "− Exclude host:path" —
                // path-exact variant of R594. Operators often want
                // narrower exclude rules ("just this endpoint, not the
                // whole host") to suppress noise from a single noisy
                // URL without hiding other findings on the same host.
                // Same inline exclude-rule shape as R594 but path-exact
                // (`path: path` with query string stripped via
                // split("?")[0]). Needs `historyShow(txId)` for both
                // host + path. Passive-only findings disable the entry.
                // Backend's unique-rule guard idempotently no-ops.
                // Danger-styled.
                {
                  label: "− Exclude host:path from scope",
                  hint: menu.data!.transaction_id
                    ? "path-exact, narrower than R594"
                    : "passive-only — no parent tx",
                  disabled: menu.data!.transaction_id == null,
                  danger: menu.data!.transaction_id != null,
                  onClick: async () => {
                    const txId = menu.data!.transaction_id;
                    if (txId == null) return;
                    try {
                      const view = await api.historyShow(txId);
                      const host = view?.summary?.host;
                      const rawPath = view?.summary?.path;
                      if (!host || !rawPath) {
                        alert(
                          `Parent transaction #${txId} has no host or path — cannot exclude from scope.`,
                        );
                        return;
                      }
                      const path = rawPath.split("?")[0] || "/";
                      await api.scopeAddRule({
                        match_kind: "exclude",
                        protocol: "any",
                        host: host.trim(),
                        port: null as unknown as undefined,
                        path,
                        regex: false,
                        enabled: true,
                      });
                      alert(`Excluded "${host}${path}" from scope.`);
                    } catch (e) {
                      alert(`${e}`);
                    }
                  },
                },
                // R628: Scanner row-right-click "Request in browser" —
                // mirror of HistoryPanel's R79-era "Request in browser"
                // on Scanner. Fires the parent tx's URL at the OS
                // default browser via `api.shellOpenUrl`. Operators
                // triaging a finding often want to inspect the live
                // endpoint in their browser's devtools (CORS behaviour
                // / cookie set / page render) without re-building the
                // URL manually. Needs `historyShow(txId)` to resolve
                // the parent tx (Scanner findings don't carry URL
                // directly). Passive-only findings (no transaction_id)
                // disable the entry.
                {
                  label: "Request in browser",
                  hint: menu.data!.transaction_id
                    ? "fire URL at the OS default browser"
                    : "passive-only — no parent tx",
                  disabled: menu.data!.transaction_id == null,
                  onClick: async () => {
                    const txId = menu.data!.transaction_id;
                    if (txId == null) return;
                    try {
                      const view = await api.historyShow(txId);
                      const sum = view?.summary;
                      if (!sum) {
                        alert(`Parent transaction #${txId} not found.`);
                        return;
                      }
                      const url = `${sum.scheme}://${sum.host}${sum.port && sum.port !== (sum.scheme === "https" ? 443 : 80) ? `:${sum.port}` : ""}${sum.path}`;
                      await api.shellOpenUrl(url);
                    } catch (err) {
                      alert(`Could not open URL in browser: ${err}`);
                    }
                  },
                },
                // 🎯 R630: Scanner row-right-click "Open response in
                // browser" — complement to R628 "Request in browser".
                // Where R628 re-fires the URL fresh at the OS browser
                // (round-trips through DNS/network), R630 renders the
                // *stored* response body — the exact bytes that were
                // captured — into a temp file + OS default handler
                // open. Operators triaging an XSS or template-
                // injection finding want to see the response that
                // *was* served, not a potentially-mutated re-fire.
                // Mirrors R79 History row-right-click behaviour. Uses
                // historyShow to pull response_raw; parses Content-
                // Type from the stored head so .html renders in a
                // browser, .json gets a JSON viewer, binary types
                // get the OS default. 🎯 R630 round-number milestone.
                {
                  label: "Open response in browser",
                  hint: menu.data!.transaction_id
                    ? "render stored body via OS default handler"
                    : "passive-only — no parent tx",
                  disabled: menu.data!.transaction_id == null,
                  onClick: async () => {
                    const txId = menu.data!.transaction_id;
                    if (txId == null) return;
                    try {
                      const view = await api.historyShow(txId);
                      const raw = view?.response_raw ?? "";
                      if (!raw.trim()) {
                        alert(`Parent transaction #${txId} has no stored response body — nothing to open.`);
                        return;
                      }
                      const idx = raw.search(/\r?\n\r?\n/);
                      const head = idx >= 0 ? raw.slice(0, idx) : raw;
                      const body =
                        idx >= 0 ? raw.slice(idx).replace(/^\r?\n\r?\n/, "") : "";
                      const ctLine = head
                        .split(/\r?\n/)
                        .find((l) => /^content-type\s*:/i.test(l));
                      const contentType = ctLine
                        ? ctLine.replace(/^content-type\s*:\s*/i, "").trim()
                        : "text/html";
                      const label = view?.summary
                        ? `${view.summary.host}${view.summary.path}`
                        : `tx-${txId}`;
                      await api.responseOpenInBrowser({
                        content: body || raw,
                        contentType,
                        label,
                      });
                    } catch (err) {
                      alert(`Could not open response in browser: ${err}`);
                    }
                  },
                },
                // R482: Row-scope "Copy as HAR entry" — per-row
                // mirror of R470 HistoryPanel row-right-click HAR,
                // applied to Scanner findings. For a finding with
                // transaction_id, pulls parent tx request_raw +
                // response_raw via historyShow(), builds a single-
                // entry HAR 1.2 log, copies pretty-printed JSON to
                // clipboard. Byte-identical output to R477 detail-
                // pane button + R479 bulk HAR + R470 History row.
                // Lives next to "Copy evidence" so the right-click
                // menu stacks all copy-ops in one visible group.
                // Disabled when transaction_id is null — passive-
                // only findings skip gracefully, same gate as the
                // R477 button + R420 Alt+Shift+H history pivot.
                {
                  label: "Copy as HAR entry",
                  hint: "single-entry HAR 1.2 log · parent tx",
                  disabled: menu.data!.transaction_id == null,
                  onClick: async () => {
                    const txId = menu.data!.transaction_id;
                    if (txId == null) return;
                    try {
                      const view = await api.historyShow(txId);
                      if (!view?.request_raw) {
                        alert(
                          `Parent transaction #${txId} has no stored request_raw — cannot build a HAR entry.`,
                        );
                        return;
                      }
                      const req = fromSummaryAndRaw(
                        view.summary,
                        view.request_raw,
                      );
                      let resp: Parameters<typeof buildHarEntry>[2] =
                        undefined;
                      if (view.response_raw) {
                        const text = view.response_raw.replace(/\r\n/g, "\n");
                        const headerEnd = text.indexOf("\n\n");
                        const headerBlock =
                          headerEnd >= 0
                            ? text.slice(0, headerEnd)
                            : text;
                        const body =
                          headerEnd >= 0 ? text.slice(headerEnd + 2) : "";
                        const lines = headerBlock.split("\n");
                        const statusLine = (lines.shift() ?? "").trim();
                        const m = statusLine.match(
                          /^(HTTP\/\S+)\s+(\d+)(?:\s+(.*))?$/,
                        );
                        const httpVersion = m?.[1] ?? "HTTP/1.1";
                        const status = m ? parseInt(m[2], 10) : 0;
                        const statusText = m?.[3] ?? "";
                        const headers: Array<[string, string]> = [];
                        let mimeType = "";
                        for (const l of lines) {
                          const colon = l.indexOf(":");
                          if (colon <= 0) continue;
                          const n = l.slice(0, colon).trim();
                          const v = l.slice(colon + 1).trim();
                          if (!n) continue;
                          headers.push([n, v]);
                          if (n.toLowerCase() === "content-type")
                            mimeType = v;
                        }
                        resp = {
                          status,
                          statusText,
                          httpVersion,
                          headers,
                          mimeType,
                          body,
                        };
                      }
                      const startedDateTime = new Date(
                        view.summary.ts_ms,
                      ).toISOString();
                      const entry = buildHarEntry(
                        req,
                        startedDateTime,
                        resp,
                      );
                      const har = buildHarLog([entry]);
                      await navigator.clipboard.writeText(
                        JSON.stringify(har, null, 2),
                      );
                    } catch (err) {
                      alert(`${err}`);
                    }
                  },
                },
                // R507: Row-scope "⬇ Save as HAR file" — file-save
                // variant of R482's clipboard "Copy as HAR entry",
                // completing Scanner's HAR surface to clipboard+file
                // at both row and bulk levels (R479 clipboard + R482
                // row clipboard + R504 bulk file + R507 row file).
                // Scanner's row-right-click menu now ships both an
                // in-tab copy (R482 → paste into a HAR viewer / jq)
                // and an on-disk save (R507 → attach to a ticket /
                // archive on the engagement share). Mechanism matches
                // R482 exactly for the HAR 1.2 content (historyShow
                // + fromSummaryAndRaw + inline response-parse +
                // buildHarEntry + buildHarLog) but writes a .har
                // file to disk instead of copying. **Filename
                // pattern** `scanner-har-<fid>-<slug>.har` where
                // `<slug>` is the sanitized finding title — so when
                // operators save several Scanner HARs during one
                // triage session, the files stay identifiable by
                // finding rather than by timestamp alone. Disabled
                // gate same as R482: `transaction_id == null` skips
                // passive-only findings gracefully. HAR surface now
                // spans 13 input paths across 5 panels.
                {
                  label: "⬇ Save as HAR file",
                  hint: "single-entry HAR 1.2 log · parent tx · to disk",
                  disabled: menu.data!.transaction_id == null,
                  onClick: async () => {
                    const f = menu.data!;
                    const txId = f.transaction_id;
                    if (txId == null) return;
                    try {
                      const view = await api.historyShow(txId);
                      if (!view?.request_raw) {
                        alert(
                          `Parent transaction #${txId} has no stored request_raw — cannot build a HAR entry.`,
                        );
                        return;
                      }
                      const req = fromSummaryAndRaw(
                        view.summary,
                        view.request_raw,
                      );
                      let resp: Parameters<typeof buildHarEntry>[2] =
                        undefined;
                      if (view.response_raw) {
                        const text = view.response_raw.replace(/\r\n/g, "\n");
                        const headerEnd = text.indexOf("\n\n");
                        const headerBlock =
                          headerEnd >= 0 ? text.slice(0, headerEnd) : text;
                        const body =
                          headerEnd >= 0 ? text.slice(headerEnd + 2) : "";
                        const lines = headerBlock.split("\n");
                        const statusLine = (lines.shift() ?? "").trim();
                        const m = statusLine.match(
                          /^(HTTP\/\S+)\s+(\d+)(?:\s+(.*))?$/,
                        );
                        const httpVersion = m?.[1] ?? "HTTP/1.1";
                        const status = m ? parseInt(m[2], 10) : 0;
                        const statusText = m?.[3] ?? "";
                        const headers: Array<[string, string]> = [];
                        let mimeType = "";
                        for (const l of lines) {
                          const colon = l.indexOf(":");
                          if (colon <= 0) continue;
                          const n = l.slice(0, colon).trim();
                          const v = l.slice(colon + 1).trim();
                          if (!n) continue;
                          headers.push([n, v]);
                          if (n.toLowerCase() === "content-type")
                            mimeType = v;
                        }
                        resp = {
                          status,
                          statusText,
                          httpVersion,
                          headers,
                          mimeType,
                          body,
                        };
                      }
                      const startedDateTime = new Date(
                        view.summary.ts_ms,
                      ).toISOString();
                      const entry = buildHarEntry(
                        req,
                        startedDateTime,
                        resp,
                      );
                      const har = buildHarLog([entry]);
                      const slug =
                        (f.title || "")
                          .toLowerCase()
                          .replace(/[^a-z0-9]+/g, "-")
                          .replace(/^-|-$/g, "")
                          .slice(0, 40) || "finding";
                      const name = `scanner-har-${f.id}-${slug}.har`;
                      const blob = new Blob(
                        [JSON.stringify(har, null, 2)],
                        { type: "application/json;charset=utf-8" },
                      );
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement("a");
                      a.href = url;
                      a.download = name;
                      document.body.appendChild(a);
                      a.click();
                      a.remove();
                      URL.revokeObjectURL(url);
                    } catch (err) {
                      alert(`${err}`);
                    }
                  },
                },
                // R464: Row-scope "⬇ Save evidence" — visible mirror
                // of R456 Alt+Shift+E keyboard shortcut, cross-panel
                // parallel of R463 Target Issues row-right-click.
                // Right-click → "⬇ Save evidence" produces the exact
                // same `evidence-<id>-<slug>.txt` file as the keyboard
                // path, R401 detail-pane "⬇ Save" button, and R463
                // Target row-right-click — four input paths now share
                // one byte-identical save flow. Lives right after
                // "⬇ Export JSON" so the two save-to-disk entries sit
                // visually paired: JSON for programmatic re-ingest /
                // jq pipelines, Evidence TXT for ticket attachments /
                // PoC bundles. Hint spells out the difference between
                // the two formats. **Disabled gate** `!f.evidence`
                // so title-only passive findings skip gracefully
                // without firing a no-op save on an empty string.
                // Scanner now matches Target Issues' 3-path save-
                // evidence surface (button + keyboard + right-click).
                {
                  label: "⬇ Save evidence",
                  hint: "the evidence blob only — complements Export JSON above (whole record)",
                  disabled: !menu.data!.evidence,
                  onClick: () => {
                    const f = menu.data!;
                    if (!f.evidence) return;
                    const slug =
                      (f.title || "")
                        .toLowerCase()
                        .replace(/[^a-z0-9]+/g, "-")
                        .replace(/^-|-$/g, "")
                        .slice(0, 40) || "evidence";
                    const name = `evidence-${f.id}-${slug}.txt`;
                    try {
                      const blob = new Blob([f.evidence], {
                        type: "text/plain;charset=utf-8",
                      });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement("a");
                      a.href = url;
                      a.download = name;
                      document.body.appendChild(a);
                      a.click();
                      a.remove();
                      URL.revokeObjectURL(url);
                    } catch (err) {
                      alert(`${err}`);
                    }
                  },
                },
                // R322: Row-scope "Add tag…" — companion to R312
                // bulk tagging + R321 History row-level add. Lets
                // operators tag just the right-clicked finding
                // without having to Ctrl+click into a bulk
                // selection first. Reuses `findingSetTags` + the
                // same merge-mode logic (union with existing).
                // Fast-path short-circuit when the tag is already
                // present so operators see "already has it" instead
                // of a no-op backend round-trip + confusing toast.
                {
                  label: "Add tag…",
                  hint:
                    (menu.data.tags?.length ?? 0) > 0
                      ? `currently: ${(menu.data.tags ?? []).join(", ")}`
                      : "no tags yet",
                  onClick: () => {
                    const f = menu.data!;
                    const next = prompt(
                      `Add a tag to this finding ([${f.severity}] ${f.title.length > 50 ? f.title.slice(0, 47) + "…" : f.title}):\n\n(Merge mode — existing tags survive. No-op if the tag's already here.)`,
                      "",
                    );
                    if (next === null) return;
                    const tag = next.trim();
                    if (tag.length === 0) {
                      alert("Empty tag — nothing to apply.");
                      return;
                    }
                    void (async () => {
                      const cur = f.tags ?? [];
                      if (cur.includes(tag)) {
                        alert(`Already has tag "${tag}" — no change.`);
                        return;
                      }
                      try {
                        const merged = Array.from(new Set([...cur, tag]));
                        await api.findingSetTags(f.id, merged);
                        await refresh();
                      } catch (e) {
                        alert(`${e}`);
                      }
                    })();
                  },
                },
                /* R178: Ticket-friendly Markdown dump of the finding — */
                /* parallels R122's full-report Markdown export but    */
                /* scoped to a single issue so operators can paste    */
                /* into GitHub / Jira / Slack without opening the     */
                /* full report. Shape mirrors the markdown report's   */
                /* per-finding block: severity emoji + title header,  */
                /* severity / confidence / status badges, description, */
                /* evidence (fenced), remediation, references list.   */
                {
                  label: "Copy as Markdown",
                  hint: "ticket paste",
                  onClick: () => {
                    const f = menu.data!;
                    const sevEmoji =
                      f.severity === "critical" ? "🔴"
                      : f.severity === "high"     ? "🟠"
                      : f.severity === "medium"   ? "🟡"
                      : f.severity === "low"      ? "🟢"
                      : "⚪";
                    const parts: string[] = [];
                    parts.push(`### ${sevEmoji} ${f.title}`);
                    parts.push("");
                    parts.push(`- **Severity**: ${sevEmoji} ${f.severity}`);
                    parts.push(`- **Confidence**: ${f.confidence}`);
                    parts.push(`- **Status**: ${f.status}`);
                    if (f.verification && f.verification !== "unverified") {
                      parts.push(`- **Verification**: ${f.verification}`);
                    }
                    if (f.detector) {
                      parts.push(`- **Detector**: \`${f.detector}\``);
                    }
                    if (f.transaction_id) {
                      parts.push(`- **Transaction**: #${f.transaction_id}`);
                    }
                    parts.push("");
                    if (f.description) {
                      parts.push("**Description**");
                      parts.push("");
                      parts.push(f.description);
                      parts.push("");
                    }
                    if (f.evidence) {
                      parts.push("**Evidence**");
                      parts.push("");
                      parts.push("```");
                      parts.push(f.evidence.replace(/```/g, "'''"));
                      parts.push("```");
                      parts.push("");
                    }
                    if (f.remediation) {
                      parts.push("**Remediation**");
                      parts.push("");
                      parts.push(f.remediation);
                      parts.push("");
                    }
                    if (f.references && f.references.length > 0) {
                      parts.push("**References**");
                      parts.push("");
                      for (const r of f.references) parts.push(`- <${r}>`);
                      parts.push("");
                    }
                    void navigator.clipboard.writeText(parts.join("\n"));
                  },
                },
                { separator: true },
                {
                  label: "Delete finding",
                  danger: true,
                  onClick: () => {
                    void api
                      .findingDelete(menu.data!.id)
                      .then(() => api.findingsList().then(setFindings));
                    setSelected(null);
                  },
                },
              ]
            : []
        }
      />
      {/* R123: Manual-issue composer modal. Rendered inline so it  */}
      {/* stays scoped to the Scanner panel (closing / reopening    */}
      {/* keeps the draft until Save succeeds). Backdrop click + Esc */}
      {/* dismiss. Save disabled while a request is in flight so a  */}
      {/* double-click can't fire two upserts.                       */}
      {manualIssueOpen && (
        <div
          onClick={(e) => {
            if (e.target === e.currentTarget) setManualIssueOpen(false);
          }}
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,0.45)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 500,
          }}
        >
          <div
            style={{
              background: "var(--bg-raised)",
              border: "1px solid var(--border)",
              borderRadius: 6,
              padding: 16,
              width: 520,
              maxHeight: "90vh",
              overflow: "auto",
              boxShadow: "0 10px 40px rgba(0,0,0,0.4)",
            }}
            onKeyDown={(e) => {
              if (e.key === "Escape") setManualIssueOpen(false);
            }}
          >
            <h3 style={{ margin: "0 0 10px", fontSize: 14 }}>
              Add manual issue
            </h3>
            <div style={{ display: "flex", flexDirection: "column", gap: 8, fontSize: 12 }}>
              <label style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                <span style={{ color: "var(--text-dim)" }}>Title *</span>
                <input
                  value={manualTitle}
                  onChange={(e) => setManualTitle(e.target.value)}
                  placeholder="Business logic: forgot password enumerates emails"
                  autoFocus
                  style={{ fontSize: 12 }}
                />
              </label>
              <label style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                <span style={{ color: "var(--text-dim)" }}>Severity</span>
                <select
                  value={manualSeverity}
                  onChange={(e) =>
                    setManualSeverity(
                      e.target.value as
                        | "critical"
                        | "high"
                        | "medium"
                        | "low"
                        | "info",
                    )
                  }
                  style={{ fontSize: 12 }}
                >
                  <option value="critical">critical</option>
                  <option value="high">high</option>
                  <option value="medium">medium</option>
                  <option value="low">low</option>
                  <option value="info">info</option>
                </select>
              </label>
              <div style={{ display: "flex", gap: 8 }}>
                <label style={{ display: "flex", flexDirection: "column", gap: 2, flex: 1 }}>
                  <span style={{ color: "var(--text-dim)" }}>Detector</span>
                  <input
                    value={manualDetector}
                    onChange={(e) => setManualDetector(e.target.value)}
                    placeholder="manual"
                    style={{ fontSize: 12 }}
                  />
                </label>
                <label style={{ display: "flex", flexDirection: "column", gap: 2, flex: 1 }}>
                  <span style={{ color: "var(--text-dim)" }}>Transaction id (optional)</span>
                  <input
                    value={manualTxId}
                    onChange={(e) => setManualTxId(e.target.value)}
                    placeholder="e.g. 42"
                    style={{ fontSize: 12 }}
                  />
                </label>
              </div>
              <label style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                <span style={{ color: "var(--text-dim)" }}>Description</span>
                <textarea
                  value={manualDescription}
                  onChange={(e) => setManualDescription(e.target.value)}
                  rows={3}
                  style={{ fontSize: 12, resize: "vertical" }}
                />
              </label>
              <label style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                <span style={{ color: "var(--text-dim)" }}>Evidence</span>
                <textarea
                  value={manualEvidence}
                  onChange={(e) => setManualEvidence(e.target.value)}
                  rows={4}
                  placeholder="Raw request fragment, response excerpt, screenshot path…"
                  style={{ fontSize: 12, resize: "vertical", fontFamily: "var(--font-mono)" }}
                />
              </label>
              <label style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                <span style={{ color: "var(--text-dim)" }}>Remediation</span>
                <textarea
                  value={manualRemediation}
                  onChange={(e) => setManualRemediation(e.target.value)}
                  rows={2}
                  style={{ fontSize: 12, resize: "vertical" }}
                />
              </label>
              <label style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                <span style={{ color: "var(--text-dim)" }}>Tags (comma-separated)</span>
                <input
                  value={manualTags}
                  onChange={(e) => setManualTags(e.target.value)}
                  placeholder="auth, enumeration, forgot-pwd"
                  style={{ fontSize: 12 }}
                />
              </label>
            </div>
            <div
              style={{
                display: "flex",
                justifyContent: "flex-end",
                gap: 8,
                marginTop: 12,
              }}
            >
              <button
                onClick={() => {
                  setManualIssueOpen(false);
                  resetManualIssue();
                }}
                disabled={manualBusy}
              >
                Cancel
              </button>
              <button
                className="primary"
                disabled={manualBusy || manualTitle.trim().length === 0}
                onClick={() => void saveManualIssue()}
              >
                {manualBusy ? "Saving…" : "Add issue"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/** Inline tag editor for a Scanner finding. Burp lets operators
 *  attach free-form tags to findings for cross-cutting triage —
 *  "exploitable", "awaiting-triage", "post-auth", "report-ready"
 *  are common patterns. The backend persisted the field + the API
 *  binding was already wired (R?); R91 lands the UI.
 *
 *  Design: existing tags render as removable chips, a trailing
 *  input lets the operator add one more. Enter / blur commit; Esc
 *  resets. Blank / dup entries are silently dropped. All writes
 *  go through the `onChange` callback (parent calls
 *  `api.findingSetTags`) so dirty-state is managed at the panel
 *  level and the editor stays stateless on the id-change pivot.
 *  Local draft is re-seeded on `finding.id` so switching rows
 *  shows the right chip list without leaking the previous one. */
function TagsEditor({
  finding,
  onChange,
}: {
  finding: StoredFinding;
  onChange: (next: string[]) => void | Promise<void>;
}) {
  const [draft, setDraft] = useState<string[]>(finding.tags ?? []);
  const [input, setInput] = useState("");

  // Resync when the selected finding changes.
  useEffect(() => {
    setDraft(finding.tags ?? []);
    setInput("");
  }, [finding.id]);

  function commitAdd() {
    const trimmed = input.trim();
    if (!trimmed) {
      setInput("");
      return;
    }
    // Normalise to lower-case + strip repeated whitespace so
    // "Report ready" and "report-ready" don't duplicate the "report-ready"
    // tag already on the list.
    const normalised = trimmed.toLowerCase().replace(/\s+/g, "-");
    if (draft.includes(normalised)) {
      setInput("");
      return;
    }
    const next = [...draft, normalised];
    setDraft(next);
    setInput("");
    void onChange(next);
  }

  function remove(tag: string) {
    const next = draft.filter((t) => t !== tag);
    setDraft(next);
    void onChange(next);
  }

  return (
    <div
      className="finding-tags"
      style={{
        display: "flex",
        flexWrap: "wrap",
        gap: 4,
        alignItems: "center",
        marginBottom: 10,
      }}
    >
      {draft.length === 0 && (
        <span className="dim" style={{ fontSize: 11, marginRight: 6 }}>
          (none — add one to tag this finding for cross-cutting triage)
        </span>
      )}
      {draft.map((tag) => (
        <span key={tag} className="finding-tag">
          <span className="finding-tag-label">{tag}</span>
          <button
            type="button"
            className="finding-tag-remove"
            onClick={() => remove(tag)}
            title={`Remove tag "${tag}"`}
          >
            ×
          </button>
        </span>
      ))}
      <input
        className="finding-tag-input"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            e.preventDefault();
            commitAdd();
          } else if (e.key === "Escape") {
            e.preventDefault();
            setInput("");
          } else if (e.key === "Backspace" && input === "" && draft.length > 0) {
            // Backspace on empty input nukes the last tag — Burp-style
            // tag-list editor behaviour.
            remove(draft[draft.length - 1]);
          }
        }}
        onBlur={commitAdd}
        placeholder={draft.length === 0 ? "add tag…" : "+"}
        spellCheck={false}
      />
    </div>
  );
}
