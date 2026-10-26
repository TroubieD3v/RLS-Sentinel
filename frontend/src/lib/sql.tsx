import { Fragment, type ReactNode } from "react";

const KEYWORDS = new Set(
  ("select from where and or not in is null true false as on to for using with check create alter drop policy table view function row level security enable disable force " +
    "grant revoke all insert update delete returning set role public permissive restrictive security invoker definer search_path exists case when then else end " +
    "begin commit rollback if language volatile stable owner revoke execute truncate references trigger option").split(" "),
);

/** Tokenize SQL for display. Output is plain React text nodes (never innerHTML), so policy text cannot inject markup. */
export function highlightSql(src: string): ReactNode[] {
  const out: ReactNode[] = [];
  const re = /(--[^\n]*)|('(?:[^']|'')*')|(\b\d+(?:\.\d+)?\b)|([A-Za-z_][A-Za-z0-9_$.]*)(\s*\()?|(\s+|.)/g;
  let m: RegExpExecArray | null;
  let i = 0;
  while ((m = re.exec(src)) !== null) {
    const key = i++;
    if (m[1]) out.push(<span key={key} className="sql-cm">{m[1]}</span>);
    else if (m[2]) out.push(<span key={key} className="sql-str">{m[2]}</span>);
    else if (m[3]) out.push(<span key={key} className="sql-num">{m[3]}</span>);
    else if (m[4]) {
      const word = m[4];
      if (KEYWORDS.has(word.toLowerCase())) out.push(<span key={key} className="sql-kw">{word}</span>);
      else if (m[5]) out.push(<span key={key} className="sql-fn">{word}</span>);
      else out.push(<Fragment key={key}>{word}</Fragment>);
      if (m[5]) out.push(<Fragment key={`${key}p`}>{m[5]}</Fragment>);
    } else out.push(<Fragment key={key}>{m[0]}</Fragment>);
  }
  return out;
}

export function Sql({ text, className }: { text: string | null | undefined; className?: string }) {
  if (text == null) return <span className="text-muted mono">— none —</span>;
  return <code className={`mono whitespace-pre-wrap break-words ${className ?? ""}`}>{highlightSql(text)}</code>;
}

/** Render a SQL block with line numbers and an optional per-line change rail (green + / red −). */
export function SqlBlock({ text, marks, label }: { text: string; marks?: Record<number, "add" | "del">; label?: string }) {
  const lines = text.split("\n");
  return (
    <div className="card-flat overflow-auto scroll-thin" role="group" aria-label={label ?? "SQL"}>
      <table className="w-full border-collapse mono">
        <tbody>
          {lines.map((ln, i) => {
            const mk = marks?.[i + 1];
            return (
              <tr key={i} className={mk === "add" ? "diff-add" : mk === "del" ? "diff-del" : undefined}>
                <td className="select-none text-right text-muted pl-3 pr-2 w-10 align-top">{i + 1}</td>
                <td className="select-none w-5 text-center align-top" aria-label={mk === "add" ? "added line" : mk === "del" ? "removed line" : undefined}>
                  {mk === "add" ? <span className="tone-teal font-bold">+</span> : mk === "del" ? <span className="tone-coral font-bold">−</span> : ""}
                </td>
                <td className="pr-3 whitespace-pre-wrap break-words">{highlightSql(ln)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
