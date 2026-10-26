# Design system — "Midnight Observatory"

A dark-first, instrument-panel look with a full light theme. The design serves one job: make the *strength of evidence*
legible at a glance.

## Principles

1. **Evidence before decoration.** Every status uses an icon *and* a text label, never colour alone.
2. **Honest empties.** With no run there is a welcome state and no numbers. Demo data is always tagged `DEMO` and
   `DISPOSABLE LAB`.
3. **Offline.** No CDN, web font or analytics request. The font stacks fall back to system UI and monospace faces.
4. **Quiet motion.** Short transitions; `prefers-reduced-motion` and the Settings toggle disable them.

## Tokens (CSS variables, `src/styles/index.css`)

| Token | Dark | Light | Use |
|---|---|---|---|
| `--bg` / `--surface` / `--surface-raised` | `#080d15` / `#0f1826` / `#142033` | `#f6f8fc` / `#ffffff` / `#f0f4fa` | page, cards, nested panels |
| `--text` / `--muted` | `#e8eef7` / `#9baac0` | `#182437` / `#4f6076` | body, secondary |
| `--teal` | `#43ddc6` | `#0a6b5d` | pass, verified, primary action |
| `--coral` | `#fb7288` | `#b4233c` | fail, confirmed violation |
| `--amber` | `#f4be61` | `#86580a` | inconclusive, static risk, warnings |
| `--violet` | `#af9bff` | `#5b3fd1` | policies, informational |
| `--blue` | `#7ab6ff` | `#1b5eb0` | catalog facts, links |

Light-theme accents are darkened so text meets WCAG AA (≥ 4.5:1) on pale surfaces. The automated audit runs axe-core on all
12 routes in both themes and fails on serious or critical violations.

Typography: UI in a system sans stack, identifiers, SQL and evidence in a monospace stack; 14 px base.

## Components (`src/design-system`)

| Component | Notes |
|---|---|
| `Lozenge`, `StatusLozenge`, `EvidenceLozenge`, `SeverityLozenge`, `ProvenanceLozenge` | pill with icon + text; provenance is one of catalog / static / runtime / insufficient |
| `CoverageBar` | stacked pass / fail / inconclusive / not-executed bar against the real denominator; hatched pattern for inconclusive so it survives greyscale |
| `Card`, `Stat`, `EmptyState`, `ErrorState`, `Skeleton`, `ProgressBar` | layout and states; errors are `role="alert"`, empties `role="status"` |
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
