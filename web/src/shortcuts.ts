/**
 * Single source of truth for every keyboard shortcut the app surfaces
 * to users. The cheatsheet modal (Ctrl+?) renders this list; add a new
 * entry here when you wire a new shortcut and the help panel picks it
 * up automatically.
 *
 * Scopes are coarse by design — users think about shortcuts in terms
 * of "global vs panel-specific", not per-component.
 */

export type ShortcutScope =
  | "global"
  | "palette"
  | "repeater"
  | "scanner"
  | "intruder"
  | "organizer"
  | "target"
  | "history"
  | "editor"
  | "logger"
  | "collaborator"
  | "decoder"
  | "comparer"
  | "bchecks"
  | "sequencer"
  | "cookiejar"
  | "modal"
  | "context-menu";

export interface ShortcutEntry {
  /** One or more key combinations that trigger this action. */
  keys: string[];
  /** Which part of the app the shortcut is active in. */
  scope: ShortcutScope;
  /** Human-readable description shown in the cheatsheet. */
  description: string;
}

const G = (keys: string | string[], description: string): ShortcutEntry => ({
  keys: typeof keys === "string" ? [keys] : keys,
  scope: "global",
  description,
});
const P = (keys: string | string[], description: string): ShortcutEntry => ({
  keys: typeof keys === "string" ? [keys] : keys,
  scope: "palette",
  description,
});
const scoped = (scope: ShortcutScope) =>
  (keys: string | string[], description: string): ShortcutEntry => ({
    keys: typeof keys === "string" ? [keys] : keys,
    scope,
    description,
  });

export const SHORTCUT_REGISTRY: ShortcutEntry[] = [
  // ----- Global ------------------------------------------------------
  G("Ctrl+K", "Open the command palette"),
  G("Ctrl+?", "Show this shortcut cheatsheet"),
  G("Ctrl+/", "Show this shortcut cheatsheet (alias)"),
  G("Ctrl+1 — Ctrl+9", "Jump directly to the first nine top-level tabs"),
  G("Ctrl+O", "Send the current selection to the Organizer"),
  G("Ctrl+R", "Send the current selection to Repeater"),
  G("Ctrl+I", "Send the current selection to Intruder"),
  G("Ctrl+T", "Toggle proxy interception (requests + responses)"),
  G("Ctrl+F", "Forward the currently intercepted proxy message — R926"),
  G("Ctrl+Shift+G", "Open Burp Agentic Testing (navigates to Dashboard) — R926"),
  G("Ctrl+B", "Open the embedded browser — R926"),
  G("Ctrl+E", "Open the Burp AI drawer in Repeater — mirrors Burp Suite 2026.8's \"Explain this\" global shortcut — R851"),
  G("Alt+L", "Jump to the Learn tab (position 13 in the top-nav, beyond Ctrl+1..9 range) — R459"),
  G("F12 / Ctrl+Shift+I", "Disabled — developer tools are blocked by the chrome guard"),
  G("F5", "Disabled — page reload is blocked"),

  // ----- Command palette --------------------------------------------
  P("↑ / ↓", "Move the cursor between palette entries"),
  P("Enter", "Run the highlighted command"),
  P("Esc", "Dismiss the palette"),

  // ----- Repeater ---------------------------------------------------
  scoped("repeater")("Ctrl+Enter", "Send the current request (from inside the request editor)"),
  scoped("repeater")("Ctrl+Backspace", "Cancel the in-flight send on the active tab"),
  scoped("repeater")("Ctrl+Shift+Backspace", "Cancel every in-flight send across every tab (panic button)"),
  scoped("repeater")("Ctrl+Shift+Left", "View the previous send in this tab's request history"),
  scoped("repeater")("Ctrl+Shift+Right", "View the next send in this tab's request history"),
  scoped("repeater")("Alt+Left", "Switch to the previous Repeater tab"),
  scoped("repeater")("Alt+Right", "Switch to the next Repeater tab"),
  scoped("repeater")("Alt+1 — Alt+9", "Jump directly to tab 1..9 by index"),
  scoped("repeater")("Alt+W", "Close the active tab (pinned tabs stay — unpin first)"),
  scoped("repeater")("Alt+Shift+W", "Close every unpinned tab in one stroke (pinned tabs stay) — asks before firing — R274"),
  scoped("repeater")("Alt+N", "Open the new-tab prompt (URL + name) — same as clicking the + button in the tab bar"),
  scoped("repeater")("Alt+Shift+N", "Open a new tab seeded from the clipboard URL (falls back to Alt+N when the clipboard isn't a URL) — R346"),
  scoped("repeater")("Alt+Shift+D", "Diff the two most recent sends on the active tab — keyboard version of R340's \"Diff last 2\" HistoryStrip button; no-op when the tab has fewer than 2 sends — R381"),
  scoped("repeater")("Alt+Shift+P", "Copy every pinned tab's URL to clipboard (deduped + sorted) — keyboard version of R357's \"📋 Copy pinned\" button; pairs with Alt+P (toggle pin on this tab) — R385"),
  scoped("repeater")("Alt+Shift+U", "Copy every tab's URL to clipboard (deduped + sorted) — keyboard version of R373's \"📋 Copy all URLs\" button; broader-scope sibling of Alt+Shift+P — R386"),
  scoped("repeater")("Alt+Shift+F", "Fire every pinned tab in parallel (Promise.allSettled) — keyboard version of R94's \"⚲ Fire pinned\" button; natural pairing with Alt+Shift+P so \"copy pinned → fire pinned\" lives on two adjacent keys — R396"),
  scoped("repeater")("Alt+Shift+S", "Save the currently-selected send's raw response to a file — keyboard version of R406's \"💾 Save\" HistoryStrip button; filename pattern `response-send<idx>-<status>.txt`; extends the Alt+Shift+S save-visible-artifact family across panels (R401 Scanner evidence button / R438 Decoder save / R454 Repeater save) — R454"),
  scoped("repeater")("Alt+Shift+A", "Sort the tab bar alphabetically by name (case-insensitive localeCompare) — keyboard version of R564's \"🔤 Sort A→Z\" toolbar button; groups preserved, intra-group alpha sort; no-op when fewer than 2 tabs — R566"),
  scoped("repeater")("Alt+Shift+B", "Sort the tab bar by send count desc (busiest first) — keyboard version of R565's \"🔁 Sort by sends\" toolbar button; groups preserved, name tie-breaker; no-op when no tab has history — R567"),
  scoped("repeater")("Ctrl+B", "Jump the caret to the request body — finds the first blank-line header/body separator and places the caret right after it; useful when a request has 10+ headers and you want to go straight to the payload area without manual scroll + click — R833"),
  scoped("repeater")("Ctrl+Shift+PageUp", "Move the active tab one position left within its section (ungrouped tabs stay ungrouped, group members stay in their group) — mirrors Chrome's / Firefox's tab-reorder convention — R834"),
  scoped("repeater")("Ctrl+Shift+PageDown", "Move the active tab one position right within its section — companion to Ctrl+Shift+PageUp — R834"),
  scoped("repeater")("Ctrl+D", "Duplicate the active tab (clone template + colour + follow-redirects + comment; history is dropped so the clone starts clean)"),
  scoped("repeater")("F2", "Rename the active tab (same as double-clicking its label)"),
  scoped("repeater")("Middle-click on a tab", "Close the tab — Burp Suite 2026.8 and every modern browser bind this. Pinned tabs are guarded (confirm before close) per R27. — R856"),
  scoped("repeater")("Ctrl+Shift+T", "Reopen the most-recently-closed tab — Chrome's canonical binding. Restores the tab's name + template + comment + group + color from the session-only ring buffer (last 10 closed tabs). Also surfaced as \"Reopen closed tab\" in the + button right-click menu. — R889 / R892"),
  scoped("repeater")("Alt+Home", "Jump to the first Repeater tab — R333"),
  scoped("repeater")("Alt+End", "Jump to the last Repeater tab — R333"),
  scoped("repeater")("Alt+P", "Toggle pin on the active tab (keyboard version of the Pin / Unpin right-click entry) — R336"),
  scoped("repeater")("Right-click on a tab", "Send / duplicate / copy request / copy response / close tab"),

  // ----- HTTP history -----------------------------------------------
  scoped("history")("↑ / ↓", "Move the row selection up / down"),
  scoped("history")("Home", "Jump to the first row"),
  scoped("history")("End", "Jump to the last row"),
  scoped("history")("Delete", "Delete the current bulk selection (asks before firing)"),
  scoped("history")("Ctrl+F", "Focus the Search box (works even from outside the panel while on the History tab)"),
  scoped("history")("Esc", "Clear the Search box when it has focus (no-op when empty)"),
  scoped("history")(
    "J / K",
    "Vim-style navigation: J moves to the next row, K to the previous (aliases for ↓ / ↑ — clamps at list ends)",
  ),
  scoped("history")(
    "Alt+1 … Alt+7",
    "Quick-highlight the active row (or bulk selection) with colour N — 1=red / 2=orange / 3=yellow / 4=green / 5=cyan / 6=blue / 7=purple",
  ),
  scoped("history")(
    "Alt+0",
    "Clear the highlight on the active row (or bulk selection)",
  ),
  scoped("history")(
    "Alt+Shift+1 … Alt+Shift+5",
    "Toggle the status-class filter chip: 1=1xx / 2=2xx / 3=3xx / 4=4xx / 5=5xx — R262",
  ),
  scoped("history")(
    "Alt+Shift+0",
    "Clear every status-class filter chip (show all response classes) — R262",
  ),
  scoped("history")("Ctrl+A", "Select every row in the current filtered view — chains cleanly into any bulk op (+Add tag, +Comment, Export CSV / JSONL / HAR, → Repeater, Delete) — R329"),
  scoped("history")("Alt+C", "Clear every active filter in one keystroke (keyboard version of the ⨯ clear-filters ghost button; no-op when no filter is active) — R349"),
  scoped("history")("Alt+Shift+H", "Toggle the \"highlighted-only\" filter — zoom into just the rows marked with Alt+1..7 — R354"),
  scoped("history")("Alt+Shift+F", "Toggle the \"commented-only\" filter — zoom into just the annotated rows (R169 single-row + R339 bulk) — R365"),
  scoped("history")("Alt+Shift+U", "Copy every bulk-selected row's URL to clipboard (deduped + sorted) — keyboard version of R353's \"📋 Copy URLs\" bulk button; pairs with Ctrl+A → Alt+Shift+U → paste — R387"),
  scoped("history")("Alt+Shift+P", "Copy every bulk-selected row as \"METHOD /path\" to clipboard (deduped + sorted) — keyboard version of R377's \"📋 Copy method+path\" bulk button; Burp-list-friendly for authz-tester / method-aware wordlist / Intruder input — R394"),
  scoped("history")("Alt+Shift+I", "Invert the bulk selection across the current filtered + sorted view — rows outside the filter stay untouched; cross-panel mirror of R415 Scanner Alt+Shift+I — R437"),
  scoped("history")("Right-click on a row", "Send to Repeater / Intruder / Comparer, replay, highlight, scope, add tag, add comment"),

  // ----- Target / site map ------------------------------------------
  scoped("target")(
    "Right-click on a site-map node",
    "Toggle in-scope, open Discover content, expand / collapse, copy segment",
  ),
  scoped("target")(
    "Esc (Issues search)",
    "Clear the Target → Issues search box when it has focus (no-op when empty)",
  ),
  scoped("target")(
    "Esc (sitemap search)",
    "Clear the sitemap host-filter box when it has focus (no-op when empty)",
  ),
  scoped("target")(
    "J / K (Issues)",
    "Vim-style navigation across the Target → Issues filtered list: J moves to the next finding, K to the previous",
  ),
  scoped("target")(
    "Alt+1 … Alt+5 (Issues)",
    "Toggle the Issues sub-tab severity chip filter (1=critical / 2=high / 3=medium / 4=low / 5=info)",
  ),
  scoped("target")(
    "Alt+Shift+1 … Alt+Shift+6 (Issues)",
    "Toggle the Issues sub-tab status chip filter: 1=new / 2=triaging / 3=confirmed / 4=false_positive / 5=fixed / 6=wontfix — R271",
  ),
  scoped("target")(
    "Alt+Shift+0 (Issues)",
    "Clear every status chip filter in one key — R271",
  ),
  scoped("target")(
    "Alt+C (Issues)",
    "Clear every active filter (sev chips + status chips + host dropdown + search box) in one keystroke — closes the cross-panel Alt+C clear-filters family (R349 History / R392 Decoder / R409 Collaborator / R410 Logger / R412 Target Issues) — R412",
  ),
  scoped("target")(
    "Alt+Shift+H (Issues)",
    "Pivot the selected issue's parent tx to HTTP history (focus the row + navigate) — cross-panel mirror of R420 Scanner Alt+Shift+H — R421",
  ),
  scoped("target")(
    "Alt+W (Issues)",
    "Mark the selected issue as wontfix — cross-panel mirror of R423 Scanner Alt+W — R424",
  ),
  scoped("target")(
    "Alt+Shift+Y (Issues)",
    "Mark the selected issue's verification axis back to \"unverified\" — cross-panel mirror of R426 Scanner Alt+Shift+Y — R427",
  ),
  scoped("target")(
    "Alt+V (Issues)",
    "Mark the selected issue as verified — cross-panel mirror of R337 Scanner Alt+V — R428",
  ),
  scoped("target")(
    "Alt+T (Issues)",
    "Mark the selected issue as triaging — cross-panel mirror of R338 Scanner Alt+T — R429",
  ),
  scoped("target")(
    "Alt+F (Issues)",
    "Mark the selected issue's status as false_positive — cross-panel mirror of R342 Scanner Alt+F (status axis, not verification axis) — R430",
  ),
  scoped("target")(
    "Alt+Shift+E (Issues)",
    "Save the selected issue's evidence blob to `evidence-<id>-<slug>.txt` — cross-panel mirror of R456 Scanner Alt+Shift+E; extends the Scanner↔Target Issues parity set to a 7th shortcut (Alt+V/T/F/W status + Alt+Shift+Y undo-verify + Alt+Shift+H history pivot + Alt+Shift+E save evidence) — R457",
  ),

  // ----- Logger ------------------------------------------------------
  scoped("logger")(
    "Esc (search)",
    "Clear the Logger search box when it has focus (no-op when empty) — R224",
  ),
  scoped("logger")(
    "Alt+1 … Alt+6",
    "Switch kind filter: 1=all / 2=transaction / 3=intercept / 4=finding / 5=ws / 6=log — R235",
  ),
  scoped("logger")(
    "J / K / ↓ / ↑ / Home / End",
    "Row cursor: J or ↓ to next event, K or ↑ to prev, Home / End to jump; replaces the multi-selection with the row the cursor lands on — R258",
  ),
  scoped("logger")(
    "Alt+C",
    "Clear every active filter (kind / search / bambda) in one keystroke — keyboard version of the \"Clear filters\" ghost button; no-op when all defaults — R410",
  ),
  scoped("logger")(
    "Alt+Shift+C",
    "Clear the stored event log (keyboard version of the \"Clear\" toolbar button) — fires api.loggerClear() + resets the drain cursor + empties the local events array; extends the Alt+Shift+C clear-results family (R418 Intruder / R435 Sequencer / R446 Logger) — R446",
  ),

  // ----- Collaborator ------------------------------------------------
  scoped("collaborator")(
    "Esc (search)",
    "Clear the Collaborator search box when it has focus (no-op when empty) — R227",
  ),
  scoped("collaborator")(
    "Alt+1 … Alt+3",
    "Switch kind filter: 1=all / 2=http / 3=dns — R233",
  ),
  scoped("collaborator")(
    "J / K / ↓ / ↑ / Home / End",
    "Row cursor: J or ↓ to the next interaction, K or ↑ to the previous, Home / End to jump; replaces the single selection with the row the cursor lands on — R266",
  ),
  scoped("collaborator")(
    "Alt+C",
    "Clear every active filter (kind / cid / search) in one keystroke — keyboard version of the \"clear N filter(s)\" ghost button; no-op when all defaults — R409",
  ),
  scoped("collaborator")(
    "Alt+Shift+C",
    "Wipe every stored OOB interaction (keyboard version of the \"⚠ Clear\" danger button) — fires api.oobInteractionsClear() behind the same confirm dialog as the button; extends the Alt+Shift+C clear-results family to a fourth panel — R447",
  ),

  // ----- Decoder -----------------------------------------------------
  scoped("decoder")(
    "📋 Paste button",
    "Load input from clipboard; shows a confirm when the current input is non-empty — R213",
  ),
  scoped("decoder")(
    "Alt+C",
    "Clear both input and transform chain in one keystroke (keyboard version of \"⌫ Clear input\"); confirms when combined state > 50 chars — R392",
  ),
  scoped("decoder")(
    "Alt+Shift+S",
    "Save the final chain step's output to file — keyboard version of R150's \"⬇ Save output\" button — R438",
  ),

  // ----- Comparer ----------------------------------------------------
  scoped("comparer")(
    "Esc (Items search)",
    "Clear the Items collection search filter when the search box has focus — R260",
  ),
  scoped("comparer")(
    "Alt+S",
    "Swap the left and right slots (keyboard version of the \"⇄ Swap\" button); operators coming via Send-to-Comparer who got the wrong side can swap in one key — R391",
  ),
  scoped("comparer")(
    "Alt+Shift+C",
    "Clear both slots + stashed Items collection + label in one keystroke (comprehensive workspace reset); items-clear path keeps its confirm dialog, slot wipe fires unconditionally after; extends the Alt+Shift+C clear-results family to a 7th panel — R474",
  ),

  // ----- BChecks -----------------------------------------------------
  scoped("bchecks")(
    "J / K / ↓ / ↑ / Home / End",
    "Row cursor: J or ↓ to the next BCheck rule, K or ↑ to the previous, Home / End to jump; replaces the single selection with the row the cursor lands on — R272",
  ),
  scoped("bchecks")(
    "Esc (search)",
    "Clear the rules search filter when the box has focus (no-op when empty) — R282",
  ),
  scoped("bchecks")(
    "Ctrl+Enter",
    "Run all valid BChecks against observed HTTP history — keyboard version of the primary toolbar button; no-op when nothing to run or already running — R397",
  ),
  scoped("bchecks")(
    "Alt+C",
    "Clear the rules search filter in one keystroke — joins the cross-panel Alt+C clear-filter family (7 panels) — R441",
  ),
  scoped("bchecks")(
    "Alt+Shift+C",
    "Drop the last run's artifacts — lastReport (per-rule hits + timing), runError (failed-run banner), selectedPath (right-pane detail selection); findings stay persisted on-disk via the Scanner's finding store, this only drops the local scratch view; extends the Alt+Shift+C clear-results family to a fifth panel — R448",
  ),
  scoped("bchecks")(
    "Alt+Shift+E",
    "Save the last run's report (rules_ok / rules_loaded / targets / findings / elapsed_ms / load_errors) to `bchecks-report-<timestamp>.json` — diff-friendly pretty-printed JSON for engagement archives + ticket attachments + jq-pipelines; extends the Alt+Shift+E save-visible-artifact family to a third keyboard panel (R456 Scanner / R457 Target Issues / R460 BChecks) — R460",
  ),

  // ----- Sequencer ---------------------------------------------------
  scoped("sequencer")(
    "Ctrl+Enter",
    "Analyze the current token list — keyboard version of the Analyze button; fires from inside the textarea (unlike other panels where text-input focus is skipped) — R399",
  ),
  scoped("sequencer")(
    "Alt+Shift+C",
    "Clear tokens + report (with confirm if >50 chars) — fast workspace reset between token sets — R435",
  ),

  // ----- Cookie jar --------------------------------------------------
  scoped("cookiejar")(
    "Alt+C",
    "Clear the search filter in one keystroke — joins the cross-panel Alt+C clear-filter family (7 panels) — R436",
  ),
  scoped("cookiejar")(
    "Alt+Shift+C",
    "Wipe every cookie from the jar (keyboard version of the \"Clear jar\" destructive button) — fires api.cookieJarClear() behind the same confirm dialog as the button; Set-Cookie headers stored in HTTP history keep their copies, only the shared jar is wiped; extends the Alt+Shift+C clear-results family to a sixth panel — R450",
  ),

  // ----- Editor (shared Repeater / Proxy / Intercept panes) ---------
  // These bindings live on the MessageEditor textarea so they fire
  // only when the operator is actually inside a wire-view editor.
  scoped("editor")(
    "Ctrl+F",
    "Open the Find bar for the current message (textarea-scoped — doesn't collide with the browser's native find on other panels)",
  ),
  scoped("editor")(
    "F3 / Shift+F3",
    "Jump to next / previous Find match; opens the Find bar if closed",
  ),
  scoped("editor")(
    "Ctrl+G",
    "Jump to line N — prompts for a line number and places the cursor at that line (auto-scrolls into view)",
  ),

  // ----- Scanner ----------------------------------------------------
  scoped("scanner")("Delete", "Delete the current bulk selection (asks before firing)"),
  scoped("scanner")(
    "J / K",
    "Vim-style navigation: J moves to the next finding, K to the previous (clamps at list ends — no wrap)",
  ),
  scoped("scanner")(
    "Esc",
    "Clear every active chip filter (severity + status + tag) in one key — no-op when nothing is filtered",
  ),
  scoped("scanner")(
    "Alt+1 … Alt+5",
    "Toggle the severity chip filter (1=critical / 2=high / 3=medium / 4=low / 5=info)",
  ),
  scoped("scanner")(
    "Alt+6",
    "Toggle the R167 \"actionable\" sev preset (sev chips = {critical, high, medium}; second press clears) — R290",
  ),
  scoped("scanner")(
    "Alt+Shift+1 … Alt+Shift+6",
    "Toggle the status chip filter: 1=new / 2=triaging / 3=confirmed / 4=false_positive / 5=fixed / 6=wontfix — R270",
  ),
  scoped("scanner")(
    "Alt+Shift+0",
    "Clear every status chip filter in one key — R270",
  ),
  scoped("scanner")(
    "Alt+Shift+8",
    "Toggle the R196 \"untriaged\" preset (status = {new, triaging}; second press clears) — R289",
  ),
  scoped("scanner")(
    "Alt+Shift+9",
    "Toggle the \"closed\" status preset (confirmed + false_positive + fixed + wontfix; audit the already-handled bucket) — R335",
  ),
  scoped("scanner")(
    "Alt+9",
    "Toggle the \"info-only\" sev preset (sev chip = {info}; audit noisy detectors) — R334",
  ),
  scoped("scanner")(
    "Ctrl+A",
    "Select every row in the current filtered view — chains cleanly into any bulk op (mark triaging, verify, +Add tag, bulk JSONL, delete) — R328",
  ),
  scoped("scanner")(
    "Alt+T",
    "Mark the currently-selected finding as triaging (keyboard version of the row-right-click Mark-as-triaging entry) — R338",
  ),
  scoped("scanner")(
    "Alt+V",
    "Mark the currently-selected finding as verified (keyboard version of the row-right-click Verify entry) — R337",
  ),
  scoped("scanner")(
    "Alt+F",
    "Mark the currently-selected finding as false positive — completes the keyboard status trio with Alt+T / Alt+V — R342",
  ),
  scoped("scanner")(
    "Alt+Shift+V",
    "Mark every bulk-selected finding as verified — keyboard version of the bulk Verify button; pairs with Alt+V (single-row) — R358",
  ),
  scoped("scanner")(
    "Alt+Shift+T",
    "Mark every bulk-selected finding as triaging — pairs with Alt+T (single-row) — R364",
  ),
  scoped("scanner")(
    "Alt+Shift+F",
    "Mark every bulk-selected finding as false positive — closes the bulk-status keyboard trio with Alt+Shift+T/V — R366",
  ),
  scoped("scanner")(
    "Alt+Shift+K",
    "Mark every bulk-selected finding as wontfix — closes the bulk-status keyboard quartet with Alt+Shift+T/V/F; sits next to J (vim down) for the walk → Ctrl+A → Alt+Shift+K dismissal pipeline — R379",
  ),
  scoped("scanner")(
    "Alt+Shift+M",
    "Copy the bulk-selected findings as a Markdown document (H3 title + emoji sev + description + fenced evidence + remediation + references, --- separators) — keyboard version of R369's \"📋 Copy Markdown\" button; one-key path for Ctrl+A → Alt+Shift+M → paste into Jira / Confluence / Slack — R389",
  ),
  scoped("scanner")(
    "Alt+Shift+L",
    "Copy the bulk-selected findings' locations to clipboard (insertion_point|title, deduped + sorted) — keyboard version of R356's \"📋 Copy locations\" button; pairs with Alt+Shift+M in the \"copy formats\" subset of the Scanner Alt+Shift family — R398",
  ),
  scoped("scanner")(
    "Alt+Shift+R",
    "Rerun active-scan probes on the currently-selected finding — keyboard version of R293's detail-pane button; no-op when selection lacks a parent transaction — R413",
  ),
  scoped("scanner")(
    "Alt+Shift+I",
    "Invert the bulk selection across the current filtered view — natural extension of Ctrl+A (select-all) and Alt+Shift+C (clear); operates on `filteredFindings` so chip-hidden rows stay untouched — R415",
  ),
  scoped("scanner")(
    "Alt+Shift+S",
    "Send the selected finding's parent request to a new Repeater tab + navigate; keyboard version of R316's row-right-click entry — R416",
  ),
  scoped("scanner")(
    "Alt+Shift+H",
    "Pivot the selected finding's parent tx to HTTP history (focus the row + navigate) — completes the Scanner triage pivot trio R413+R416+R420 (R=Rerun / S=Send→Repeater / H=History) — R420",
  ),
  scoped("scanner")(
    "Alt+W",
    "Mark the selected finding as wontfix — single-row companion to R379 Alt+Shift+K bulk; closes the single-row status quartet with Alt+V/T/F — R423",
  ),
  scoped("scanner")(
    "Alt+Shift+Y",
    "Mark the selected finding's verification axis back to \"unverified\" — undo-ish companion to Alt+V; Y = Yank — R426",
  ),
  scoped("scanner")(
    "Alt+Shift+C",
    "Clear bulk selection — mirror of R328 Ctrl+A select-all-filtered; natural pipeline Ctrl+A → bulk op → Alt+Shift+C → next filter — R375",
  ),
  scoped("scanner")(
    "Alt+Shift+E",
    "Save the selected finding's evidence blob to `evidence-<id>-<slug>.txt` — keyboard version of R401's \"⬇ Save\" detail-pane button; letter E (not S) avoids collision with R416 Alt+Shift+S (send to Repeater); extends the save-visible-artifact family across Scanner / Decoder / Repeater / Target Issues (R401 / R438 / R454 / R456 / R457) — R456",
  ),
  scoped("scanner")(
    "Right-click on a finding",
    "Mark triaging / confirmed / false-positive, verify, add tag, send to Repeater / Intruder / Comparer, copy title / evidence, export JSON, delete",
  ),

  // ----- Intruder ---------------------------------------------------
  scoped("intruder")(
    "Ctrl+Enter",
    "Toggle Start / Stop attack — starts when idle, cancels when a job is running — R331",
  ),
  scoped("intruder")(
    "Ctrl+Space",
    "Toggle pause / resume on the running attack (in-flight requests still complete; pause only freezes new dispatches)",
  ),
  scoped("intruder")(
    "Esc",
    "Clear every payload marker from the URL (no-op when the URL has none; skipped while editing an input)",
  ),
  scoped("intruder")(
    "Alt+1 … Alt+4",
    "Switch attack mode without the mouse: 1=sniper / 2=battering_ram / 3=pitchfork / 4=cluster_bomb",
  ),
  scoped("intruder")(
    "Alt+Shift+U",
    "Copy every filtered results row's URL to clipboard (deduped + sorted) — keyboard version of R384's \"📋 Copy URLs\" button; honours both text + chip filters — R388",
  ),
  scoped("intruder")(
    "Alt+Shift+P",
    "Copy every filtered results row's payload text to clipboard (deduped + sorted) — keyboard version of R380's \"📋 Copy payloads\" button; multi-position attacks join positions with \" · \" per line — R393",
  ),
  scoped("intruder")(
    "Alt+Shift+C",
    "Clear every results-table row (with confirm) + reset baseline + wipe filter — keyboard version of the \"Clear results\" toolbar button — R418",
  ),

  // ----- Organizer --------------------------------------------------
  scoped("organizer")(
    "Right-click on an item",
    "Mark reviewed / triaging, move to collection, copy title, delete",
  ),
  scoped("organizer")(
    "J / K",
    "Vim-style navigation across the shown items — J moves to the next, K to the previous (respects the current search filter)",
  ),
  scoped("organizer")(
    "Alt+0 / Alt+1 … Alt+9",
    "Switch the sidebar selection: Alt+0 jumps to Inbox, Alt+1..9 picks the Nth collection in sidebar order — R275",
  ),
  scoped("organizer")(
    "Right-click on a collection",
    "Rename, change colour, delete (via the Round-5 collection menu)",
  ),

  // ----- Any open modal ---------------------------------------------
  scoped("modal")("Esc", "Close the current modal (Discovery, JWT editor, PoC, cheatsheet, …)"),

  // ----- Context menus (common pattern) -----------------------------
  scoped("context-menu")("↑ / ↓", "Move between menu entries"),
  scoped("context-menu")("Enter", "Activate the highlighted entry"),
  scoped("context-menu")("Esc / click outside", "Dismiss the menu"),
];

/** Grouped-by-scope view, in the display order the cheatsheet uses. */
export const SHORTCUT_GROUPS: Array<{ scope: ShortcutScope; label: string; entries: ShortcutEntry[] }> = (
  [
    { scope: "global", label: "Global" },
    { scope: "palette", label: "Command palette (Ctrl+K)" },
    { scope: "repeater", label: "Repeater" },
    { scope: "history", label: "HTTP history" },
    { scope: "target", label: "Target / site map" },
    { scope: "scanner", label: "Scanner" },
    { scope: "intruder", label: "Intruder" },
    { scope: "organizer", label: "Organizer" },
    { scope: "collaborator", label: "Collaborator" },
    { scope: "logger", label: "Logger" },
    { scope: "decoder", label: "Decoder" },
    { scope: "comparer", label: "Comparer" },
    { scope: "bchecks", label: "BChecks" },
    { scope: "editor", label: "Message editor (Repeater / Proxy / Intercept)" },
    { scope: "context-menu", label: "Any context menu" },
    { scope: "modal", label: "Any modal" },
  ] as const
).map((g) => ({
  scope: g.scope,
  label: g.label,
  entries: SHORTCUT_REGISTRY.filter((e) => e.scope === g.scope),
}));
