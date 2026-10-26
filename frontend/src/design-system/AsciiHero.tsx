const WIDE = `
 ╭───────────────── ACCESS TELEMETRY / 004 ─────────────────╮
 │                                                          │
 │   [ ROLE: tenant_a ] --(GRANT SELECT)--> [ invoices ]    │
 │          │                                ╭──────────╮   │
 │          ╰────(POLICY USING)─────────────▶│ tenant_a │   │
 │                                           ╰──────────╯   │
 │   [ ROLE: tenant_b ] --X--> [ tenant_a / invoices ]      │
 │                                                          │
 │   STATUS:  VERIFIED DENY        MODE:  ISOLATED LAB      │
 ╰──────────────────────────────────────────────────────────╯`;

const COMPACT = `
╭──── ACCESS TELEMETRY ────╮
│ [tenant_a] -SELECT-> [t] │
│ [tenant_b] --X--> [t]    │
│ VERIFIED DENY · LAB      │
╰──────────────────────────╯`;

/** One carefully placed decorative visualization. Hidden from assistive tech; a real description follows. */
export function AsciiHero() {
  return (
    <figure className="m-0">
      <pre aria-hidden="true" className="hidden sm:block mono leading-[1.25] text-violet m-0 overflow-x-auto scroll-thin select-none">{WIDE}</pre>
      <pre aria-hidden="true" className="sm:hidden mono leading-[1.25] text-violet m-0 overflow-x-auto select-none">{COMPACT}</pre>
      <figcaption className="sr-only">
        Illustration: a role for tenant A is granted SELECT on the invoices table and a policy limits it to tenant A rows, while a role for tenant B is verified to be denied.
        This is decorative example text, not scan output.
      </figcaption>
      <p className="mono text-muted mt-2 m-0" aria-hidden="true">$ rls-sentinel test --fixture multi-tenant-saas<span className="cursor-blink">▍</span></p>
    </figure>
  );
}
