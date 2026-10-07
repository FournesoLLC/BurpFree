// FloatingMenu.tsx
//
// Reusable right-click / context menu. Positions itself at an (x, y)
// anchor, flips to stay inside the viewport, closes on Esc / outside
// click / selection, and supports arrow-key navigation.
//
// Usage:
//
//   const [menu, setMenu] = useState<MenuState<Row> | null>(null);
//   <tr onContextMenu={(e) => {
//     e.preventDefault();
//     setMenu({ x: e.clientX, y: e.clientY, data: r });
//   }} />
//   <FloatingMenu
//     state={menu}
//     onClose={() => setMenu(null)}
//     items={menu ? [
//       { label: "Send to Repeater", onClick: () => sendRep(menu.data) },
//       { separator: true },
//       { label: "Delete", onClick: () => del(menu.data), danger: true },
//     ] : []}
//   />

import { useEffect, useLayoutEffect, useRef, useState } from "react";

export interface MenuState<T = unknown> {
  x: number;
  y: number;
  data?: T;
}

export interface MenuItem {
  /** Visible row label. */
  label?: string;
  /** Optional keyboard hint shown on the right (`Ctrl+O`, `Enter`, …). */
  hotkey?: string;
  /** Fires when the user chooses the row. */
  onClick?: () => void;
  /** Grey the row out; it won't fire on click/Enter. */
  disabled?: boolean;
  /** Red-tint the row (destructive action). */
  danger?: boolean;
  /** Hint shown on the row to clarify intent. */
  hint?: string;
  /** Render a divider instead of a row. */
  separator?: boolean;
}

interface Props {
  state: MenuState | null;
  items: MenuItem[];
  onClose: () => void;
  /** Minimum menu width in px (default 220). */
  minWidth?: number;
}

export function FloatingMenu({ state, items, onClose, minWidth = 220 }: Props) {
  const [cursor, setCursor] = useState(0);
  const [pos, setPos] = useState<{ left: number; top: number } | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  // Reset cursor to the first selectable row every open.
  useEffect(() => {
    if (!state) return;
    setCursor(firstSelectable(items, 0));
    setPos({ left: state.x, top: state.y });
  }, [state, items]);

  // After layout, flip into the viewport if we'd overflow.
  useLayoutEffect(() => {
    if (!state || !menuRef.current) return;
    const el = menuRef.current;
    const rect = el.getBoundingClientRect();
    let { left, top } = pos ?? { left: state.x, top: state.y };
    if (left + rect.width + 8 > window.innerWidth) {
      left = Math.max(4, window.innerWidth - rect.width - 8);
    }
    if (top + rect.height + 8 > window.innerHeight) {
      top = Math.max(4, window.innerHeight - rect.height - 8);
    }
    setPos({ left, top });
    // Deliberately only re-run when the menu opens — not on cursor move.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state]);

  // Outside click + Esc close.
  useEffect(() => {
    if (!state) return;
    const onDown = (e: MouseEvent) => {
      if (!menuRef.current) return;
      if (!menuRef.current.contains(e.target as Node)) onClose();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
      } else if (e.key === "ArrowDown") {
        e.preventDefault();
        setCursor((c) => nextSelectable(items, c, 1));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setCursor((c) => nextSelectable(items, c, -1));
      } else if (e.key === "Enter") {
        e.preventDefault();
        activate(items, cursor, onClose);
      } else if (e.key === "Home") {
        e.preventDefault();
        setCursor(firstSelectable(items, 0));
      } else if (e.key === "End") {
        e.preventDefault();
        setCursor(firstSelectable(items, items.length - 1, -1));
      }
    };
    window.addEventListener("mousedown", onDown);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onDown);
      window.removeEventListener("keydown", onKey);
    };
  }, [state, items, cursor, onClose]);

  if (!state) return null;

  return (
    <div
      ref={menuRef}
      className="floating-menu"
      role="menu"
      style={{
        left: pos?.left ?? state.x,
        top: pos?.top ?? state.y,
        minWidth,
      }}
      onContextMenu={(e) => e.preventDefault()}
    >
      {items.map((it, i) => {
        if (it.separator) return <div key={i} className="floating-menu-sep" aria-hidden />;
        const selected = i === cursor;
        const classes = [
          "floating-menu-item",
          selected ? "selected" : "",
          it.disabled ? "disabled" : "",
          it.danger ? "danger" : "",
        ]
          .filter(Boolean)
          .join(" ");
        return (
          <div
            key={i}
            role="menuitem"
            className={classes}
            onMouseEnter={() => setCursor(i)}
            onMouseDown={(e) => {
              // mousedown so our outside-click handler on the document
              // doesn't fire first and close the menu before onClick.
              e.preventDefault();
              if (it.disabled) return;
              it.onClick?.();
              onClose();
            }}
          >
            <span className="floating-menu-label">{it.label}</span>
            {it.hint && <span className="floating-menu-hint">{it.hint}</span>}
            {it.hotkey && <span className="floating-menu-hotkey">{it.hotkey}</span>}
          </div>
        );
      })}
    </div>
  );
}

function firstSelectable(items: MenuItem[], from: number, dir: 1 | -1 = 1): number {
  if (items.length === 0) return 0;
  const step = dir === 1 ? 1 : -1;
  let i = Math.max(0, Math.min(items.length - 1, from));
  for (let n = 0; n < items.length; n++) {
    const it = items[i];
    if (it && !it.separator && !it.disabled) return i;
    i = (i + step + items.length) % items.length;
  }
  return from;
}

function nextSelectable(items: MenuItem[], from: number, dir: 1 | -1): number {
  if (items.length === 0) return 0;
  let i = from;
  for (let n = 0; n < items.length; n++) {
    i = (i + dir + items.length) % items.length;
    const it = items[i];
    if (it && !it.separator && !it.disabled) return i;
  }
  return from;
}

function activate(items: MenuItem[], index: number, onClose: () => void) {
  const it = items[index];
  if (!it || it.separator || it.disabled) return;
  it.onClick?.();
  onClose();
}
