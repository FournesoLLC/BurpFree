// chrome.ts
//
// WebView chrome guards. BurpFree runs inside a Tauri WebView2 (Windows)
// or WebKit (macOS/Linux) and both webviews ship a default right-click
// menu plus devtools shortcuts. Those are great during development but
// jarring for an end user — they expose "Reload", "Inspect element",
// "View source", etc. which don't belong in a shipped app.
//
// `installChromeGuards()` suppresses:
//   • The native context menu — our React `onContextMenu` handlers
//     already call `preventDefault()` on their own events; this global
//     listener catches every other right-click and swallows it too so
//     no surface shows the browser menu by accident.
//   • Devtools shortcuts — F12, Ctrl+Shift+I, Ctrl+Shift+J,
//     Ctrl+Shift+C. (Release Tauri builds don't ship with the
//     `devtools` feature flag, but intercepting the keystroke keeps
//     dev builds consistent with production.)
//   • Accidental reload — F5, Ctrl+R, Ctrl+Shift+R. Reloading inside
//     the shell throws away in-flight panel state (Repeater drafts,
//     Discovery wordlist edits, …); the user can always close+reopen
//     if they really need a fresh load.
//
// We deliberately do NOT suppress Ctrl+F (browser's find bar) — some
// panels still rely on it for raw-text search inside large request
// bodies, and `preventDefault()` here would break that.

export function installChromeGuards(): () => void {
    const onContextMenu = (e: MouseEvent) => {
        // A React `onContextMenu` handler that intends to open our own
        // menu will have already called e.preventDefault() by the time
        // this bubble-phase listener fires. Calling it again is a
        // no-op; the net effect is "no native menu, ever."
        e.preventDefault();
    };

    const onKeyDown = (e: KeyboardEvent) => {
        // F12 — open devtools.
        if (e.key === "F12") {
            e.preventDefault();
            return;
        }
        // F5 — reload.
        if (e.key === "F5") {
            e.preventDefault();
            return;
        }
        const mod = e.ctrlKey || e.metaKey;
        if (!mod) return;
        const key = e.key.toLowerCase();
        // Note: Ctrl+R used to be blocked here to prevent page reload.
        // Round 13 reclaims Ctrl+R as "Send to Repeater" — the App.tsx
        // bubble-phase listener now calls `preventDefault()` on its own
        // handler, which still stops the webview reload. Ctrl+Shift+R
        // (which Ctrl+R aliased for hard-reload) is left to the native
        // webview; the chrome guard doesn't need to care about it.
        // Ctrl+Shift+I — devtools (inspector).
        // Ctrl+Shift+J — devtools (console).
        // Ctrl+Shift+C — devtools (element picker).
        if (e.shiftKey && (key === "i" || key === "j" || key === "c")) {
            e.preventDefault();
            return;
        }
    };

    // Capture-phase listeners so we intercept before any downstream
    // webview default; `preventDefault()` on either phase stops the
    // native menu / shortcut from firing.
    window.addEventListener("contextmenu", onContextMenu, { capture: true });
    window.addEventListener("keydown", onKeyDown, { capture: true });

    return () => {
        window.removeEventListener("contextmenu", onContextMenu, { capture: true } as EventListenerOptions);
        window.removeEventListener("keydown", onKeyDown, { capture: true } as EventListenerOptions);
    };
}
