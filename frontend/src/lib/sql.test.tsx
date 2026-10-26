import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Sql } from "./sql";

describe("Sql display", () => {
  it("renders policy text as text nodes, never markup", () => {
    const payload = `tenant_id = 'x' OR '<img src=x onerror=alert(1)>' = ''`;
    const { container } = render(<Sql text={payload} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toBe(payload);
  });
  it("highlights keywords and strings", () => {
    const { container } = render(<Sql text="SELECT 'a' -- note" />);
    expect(container.querySelector(".sql-kw")?.textContent).toBe("SELECT");
    expect(container.querySelector(".sql-str")?.textContent).toBe("'a'");
    expect(container.querySelector(".sql-cm")?.textContent).toBe("-- note");
  });
  it("shows an explicit marker for a missing expression", () => {
    const { container } = render(<Sql text={null} />);
    expect(container.textContent).toBe("— none —");
  });
});
