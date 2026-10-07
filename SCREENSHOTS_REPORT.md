# Burp Suite 2026.8 Screenshot Reference Report

**Date**: October 2026
**Source**: Burp Suite Community Edition v2026.8 — Temporary Project
**Purpose**: UI reference screenshots used to drive BurpFree's visual parity work

## Summary

61 screenshots captured from a live Burp Suite Community Edition v2026.8 installation across multiple sessions (Oct 1, Oct 3, Oct 4, Oct 6). The screenshots document every major UI surface, menu structure, dialog, and interaction pattern in Burp's interface. These served as the ground truth for BurpFree's UI parity effort (R896-R970, 240 Burp parity stages).

## Screenshot Categories

### 1. Menu Bar & Navigation (3 screenshots)
- **Burp menu dropdown**: 10 entries — Search [Pro only], Settings, Configuration library, User settings, Burp Infiltrator [Pro only], Burp Clickbandit, Burp Collaborator client [Pro only], Upgrade to Professional, Exit. Menu bar order: Burp | Project | Intruder | Repeater | View | Help.
- **Main tab strip**: Dashboard | Target | Proxy | Intruder | Repeater | Collaborator | Sequencer | Decoder | Comparer | Logger | Organizer | Extensions | Discover | MCP. Orange accent on active tab, 2px top stripe selection indicator.
- **Window title**: "Burp Suite Community Edition v2026.8 - Temporary Project"

### 2. Dashboard (5+ screenshots)
- **Tasks panel**: Left sidebar with "New scan" + "New live task" buttons, filter dropdown, search bar.
- **Live passive crawl task**: Shows task card with "Capturing" toggle, task type "Live passive crawl", scope "Proxy (all traffic)", configuration details.
- **Site map table**: Host | Method | URL | Status code | MIME type columns. Empty state shows network diagram illustration + "No items to show" message.
- **Task progress**: Site map items added, Responses processed, Responses queued counters.
- **Task configuration panel**: Task type, Scope, Configuration, Capturing toggle.
- **Pro upsell banner**: "Time to level up? Catch more bugs with Burp Suite Pro" with orange "Find out more" CTA.

### 3. Repeater Panel (8+ screenshots)
- **Tab strip**: Numbered tabs (1, 2, 3×, 4) with close button on active tab, + button for new tabs.
- **Toolbar**: Send (orange) | Cancel (grey) | ⚙ settings | ◀ ▶ history nav | Burp AI button | Target: URL ✎ HTTP/1 ?
- **Request pane**: Pretty | Raw | Hex sub-tabs. Line-numbered editor with syntax highlighting. Bottom bar: ⓘ ⚙ ← → 🔍 Search | N highlights | Selection info.
- **Response pane**: Pretty | Raw | Hex | Render sub-tabs. Same bottom bar pattern with search + match count.
- **Inspector sidebar**: Vertical rail labels (Inspector | Notes | Custom actions). Accordion sections: Request attributes (2), Request query parameters (0), Request body parameters (0/1), Request cookies (0), Request headers (14/15), Response headers (8/9). Selection panel with "Decoded from" dropdown + "Apply changes" button.
- **Empty state**: Detective mascot illustration + "The message inspector provides a quick way to analyse interesting details and features of HTTP messages" + "Learn more" link.
- **Active request**: PUT /x to pb-mall-files.oss-cn-hangzhou.aliyuncs.com showing 403 Forbidden from AliyunOSS with XML error body.

### 4. Repeater Context Menus (3 screenshots)
- **+ button menu**: New HTTP tab | + New WebSocket tab (green highlight) | New tab group | Close all tabs | Reopen closed tab.
- **Request body right-click**: 25+ entries grouped: Scan | Send to Intruder/Repeater/Sequencer/Comparer/Decoder/Organizer (with Ctrl shortcuts) | Insert Collaborator payload | Open response in browser | Record an issue [Pro] | Request in browser | Engagement tools [Pro] | Change request method | Change body encoding → (Form URL-encoded / Multipart / JSON) | Copy/Copy prettified/Copy URL/Copy as curl command | Save selected text/Paste text/Save item/Save entire history/Paste host/Add to site map | Convert selection | URL-encode as you type | Cut/Copy/Paste | Message editor documentation | Burp Repeater documentation.

### 5. Repeater Dialogs (2 screenshots)
- **Configure target details**: Modal with orange header bar + × close. Fields: Host (text), Override SNI (checkbox), Port (number), Use HTTPS (checkbox). OK/Cancel footer.
- **Repeater settings for this tab**: Dropdown panel with "Restore global defaults" button + 11 toggles: Update Content-Length ✓, Unpack compressed responses ✓, Follow redirections ▸, Process cookies in redirections, Enforce protocol choice on cross-domain redirections, Normalize HTTP/1 line endings ✓, Enable HTTP/1 connection reuse, Enable HTTP/2 connection reuse ✓, Strip Connection header over HTTP/2 ✓, Allow HTTP/2 ALPN override, Streaming response timeout.

### 6. Other Panels (40+ screenshots from Oct 1 series)
- Captured at ~6-second intervals (08:16:11 through 08:22:00), covering systematic walkthrough of every Burp panel: Proxy (intercept, HTTP history, WebSockets, options), Scanner, Target (site map, scope, issues), Intruder, Decoder, Comparer, Sequencer, Logger, Organizer, Extensions, Settings, and various sub-panels.
- Later sessions (Oct 3, Oct 4) captured additional detail views and interaction states.

## Visual Design Tokens Observed

| Token | Value |
|-------|-------|
| Background (dark) | #2b2b2b (warm grey) |
| Panel background | #3c3f41 (raised) |
| Accent (signature orange) | #ed6424 |
| Text primary | #bbbbbb (muted) |
| Text secondary | #808080 |
| Border | #4e5254 |
| Body font | Segoe UI / 11px |
| Mono font | JetBrains Mono / 12px |
| Tab height | 24px flat, 0-radius |
| Table row height | ~18px dense |
| Border radius | 2px (hard edges everywhere) |
| Scrollbar | 12px flat thumb, 2px radius |

## Impact on BurpFree Development

These screenshots directly drove 240 Burp parity stages (R896-R970):
- R888: MenuBar restructured to match Burp menu screenshot
- R893: MessageEditor right-click menu matched to 25-entry screenshot
- R894: Configure Target Details modal matched to dialog screenshot
- R895: Repeater settings menu matched to 11-toggle screenshot
- R896-R918: Complete palette + density overhaul from screenshot color analysis
- R913: Repeater toolbar stripped to match toolbar screenshot exactly

## Disposition

All 61 screenshots have been reviewed and their design tokens extracted into the BurpFree CSS palette and component implementations. The screenshots are now deleted from the repository to reduce repo size (~5.2 MB total) and avoid distributing Burp Suite UI captures. The design knowledge is preserved in this report and in the CSS/component code.
