# Design system

A database-client layout in a neutral graphite palette, dark by default with a full light theme. The design serves one
job: make the *strength of evidence* legible at a glance, in the dense form people already know from database tools.

## Layout

- **Toolbar** (top): workspace, environment mode, active run selector, command palette and theme toggle.
- **Sidebar** (left): pages grouped as Workspace / Catalog / Verification / Results, and below them a **database
  navigator** with the active snapshot's database → schemas → tables (RLS state per table), linking into the schema
  explorer. It collapses to an icon rail; on small screens it becomes a drawer.
- **Editor tab** above the page: the open page and the run it shows.
- **Status bar** (bottom): disposable-lab availability, PostgreSQL version, last run and confirmed violation count.
- Panels have a header bar; lists of findings, policies and cases are dense tables rather than cards.

## Principles

1. **Evidence before decoration.** Every status uses an icon *and* a text label, never colour alone. Colour is reserved
   for evidence and state; chrome stays neutral.
2. **Honest empties.** With no run there is a welcome state and no numbers. Demo data is always tagged `Demo data` and
   `DISPOSABLE LAB`.
3. **Offline.** No CDN or analytics request. IBM Plex Sans and IBM Plex Mono are bundled with the UI and served from
   the same origin; the stacks fall back to system UI and monospace faces.
4. **Quiet motion.** Short colour transitions only; `prefers-reduced-motion` and the Settings toggle disable them.

## Tokens (CSS variables, `src/styles/index.css`)

| Token | Dark | Light | Use |
|---|---|---|---|
| `--bg` / `--surface` / `--surface-low` | `#191b1e` / `#1f2226` / `#1b1d21` | `#eef0f2` / `#f8f9fa` / `#f1f3f5` | page, panels, nested panels |
| `--chrome` | `#141619` | `#e2e5e8` | toolbar, editor tab strip, status bar |
| `--border` / `--sel` | `#2f333a` / `#293441` | `#cdd3d9` / `#d8e3ee` | hairlines, selected rows |
| `--text` / `--muted` | `#d5d7da` / `#8d939a` | `#1e2227` / `#5b626a` | body, secondary |
| `--primary` | `#3e6489` | `#3a6693` | primary action |
| `--teal` | `#94b08e` | `#3b6a4a` | pass, verified |
| `--coral` | `#d98577` | `#a8402f` | fail, confirmed violation |
| `--amber` | `#d0a866` | `#87601a` | inconclusive, static risk, warnings |
| `--violet` | `#aaa4ca` | `#5a4f8c` | expected denial, restrictive policies |
| `--blue` | `#8fb4d8` | `#2c5d8a` | catalog facts, links, focus, SQL keywords |

Light-theme accents are darkened so text meets WCAG AA (≥ 4.5:1) on pale surfaces. The automated audit runs axe-core on all
12 routes in both themes and fails on serious or critical violations.

Typography: 13 px base; UI in IBM Plex Sans, identifiers, SQL and evidence in IBM Plex Mono. Radii are 3–4 px.

## Components (`src/design-system`)

| Component | Notes |
|---|---|
| `Lozenge`, `StatusLozenge`, `EvidenceLozenge`, `SeverityLozenge`, `ProvenanceLozenge` | tag with icon + text; provenance is one of catalog / static / runtime / insufficient |
| `CoverageBar` | stacked pass / fail / inconclusive / not-executed bar against the real denominator; hatched pattern for inconclusive so it survives greyscale |
| `Card`, `Stat`, `EmptyState`, `ErrorState`, `Skeleton`, `ProgressBar` | panels with a header bar, and states; errors are `role="alert"`, empties `role="status"` |
| `Dialog`, `Tip` | Radix primitives with focus trap and escape handling |
| `Terminal` | evidence and CLI transcripts |
| `AsciiHero` | decorative ASCII art, `aria-hidden`, followed by a real text description; a compact variant is used on small screens |
| `Sql` / `SqlBlock` | tokenised highlighting rendered as React text nodes (never `innerHTML`), so policy text cannot inject markup |

## Interaction

- Command palette (`Ctrl/⌘ K`): pages, runs, tables, roles, policies and findings.
- The matrix is an ARIA grid with roving tabindex: arrow keys move, Enter opens evidence, rows and columns are windowed (virtualised).
- The graph has a keyboard-reachable table equivalent (“Show table equivalent”) listing every edge with its provenance.
- Mobile: the sidebar becomes a drawer; wide tables scroll inside their own container and the page never scrolls horizontally.

## Verification

`frontend/e2e/z_a11y.spec.ts` (axe-core, both themes, all routes), `mobile.spec.ts` (no horizontal overflow), and
`journey.spec.ts` (keyboard flows) run in CI. Automated checks do not replace a manual screen-reader pass; none has been
recorded for this release.
