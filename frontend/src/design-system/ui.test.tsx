import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { CoverageBar, EmptyState, ErrorState, ProgressBar, StatusLozenge } from "./ui";

describe("CoverageBar", () => {
  it("states the real denominator in its accessible name", () => {
    render(<CoverageBar passed={30} failed={8} inconclusive={2} notExecuted={2} total={42} />);
    expect(screen.getByRole("img")).toHaveAccessibleName("30 passed, 8 failed, 2 inconclusive, 2 not executed, of 42 expected assertions");
  });
  it("does not divide by zero", () => {
    render(<CoverageBar passed={0} failed={0} inconclusive={0} notExecuted={0} total={0} />);
    expect(screen.getByText("of 0 expected assertions")).toBeInTheDocument();
  });
});

describe("status never relies on colour alone", () => {
  it.each([["PASS", "Pass"], ["FAIL", "Fail"], ["INCONCLUSIVE", "Inconclusive"], ["ERROR", "Error"]])("%s has a text label", (s, label) => {
    render(<StatusLozenge status={s} />);
    expect(screen.getByText(label)).toBeInTheDocument();
  });
});

describe("states", () => {
  it("ErrorState is an alert and shows the message", () => {
    render(<ErrorState error={new Error("boom")} />);
    expect(screen.getByRole("alert")).toHaveTextContent("boom");
  });
  it("EmptyState announces itself as status", () => {
    render(<EmptyState title="Nothing yet">Run a test.</EmptyState>);
    expect(screen.getByRole("status")).toHaveTextContent("Nothing yet");
  });
  it("ProgressBar clamps to 100%", () => {
    render(<ProgressBar value={9} max={4} label="x" />);
    expect((screen.getByRole("progressbar").firstElementChild as HTMLElement).style.width).toBe("100%");
  });
});
