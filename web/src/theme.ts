// theme.ts
//
// Minimal theme switcher. Three modes: "dark", "light", "system".
// Everything resolves to a concrete "dark" | "light" effective theme
// which gets stamped on <html class="theme-dark|theme-light"> so the
// stylesheet variable overrides take effect.

import { useEffect, useState } from "react";

export type ThemeMode = "dark" | "light" | "system";
export type EffectiveTheme = "dark" | "light";

const STORAGE_KEY = "burpfree:theme";

/** Resolve a mode to an effective theme by consulting the OS when "system". */
export function resolveTheme(mode: ThemeMode): EffectiveTheme {
  if (mode === "system") {
    if (typeof window !== "undefined" && window.matchMedia) {
      return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    }
    return "dark";
  }
  return mode;
}

/** Apply the effective theme to the <html> element. Idempotent. */
export function applyTheme(effective: EffectiveTheme) {
  if (typeof document === "undefined") return;
  document.documentElement.classList.toggle("theme-light", effective === "light");
  document.documentElement.classList.toggle("theme-dark", effective === "dark");
}

/** Read the saved mode, defaulting to "system". */
export function readMode(): ThemeMode {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (raw === "dark" || raw === "light" || raw === "system") return raw;
  } catch {
    /* localStorage unavailable (private window, SSR, …) */
  }
  return "system";
}

/** Persist the mode. */
export function writeMode(mode: ThemeMode) {
  try {
    window.localStorage.setItem(STORAGE_KEY, mode);
  } catch {
    /* nothing we can do */
  }
}

/**
 * Hook that owns the current mode + applies it to the DOM. Returns a
 * tuple of [mode, setMode] plus the resolved effective theme.
 */
export function useTheme(): {
  mode: ThemeMode;
  setMode: (m: ThemeMode) => void;
  effective: EffectiveTheme;
} {
  const [mode, setModeState] = useState<ThemeMode>(() => readMode());
  const [effective, setEffective] = useState<EffectiveTheme>(() => resolveTheme(readMode()));

  // Apply + persist on mode change.
  useEffect(() => {
    const eff = resolveTheme(mode);
    setEffective(eff);
    applyTheme(eff);
    writeMode(mode);
  }, [mode]);

  // Follow OS changes when mode === "system".
  useEffect(() => {
    if (mode !== "system" || typeof window === "undefined" || !window.matchMedia) return;
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => {
      const eff: EffectiveTheme = mq.matches ? "dark" : "light";
      setEffective(eff);
      applyTheme(eff);
    };
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, [mode]);

  return { mode, setMode: setModeState, effective };
}
