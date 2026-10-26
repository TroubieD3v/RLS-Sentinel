import { describe, expect, it } from "vitest";
import { groupBy, plural, shortHash, timeAgo } from "./format";

describe("timeAgo", () => {
  const now = Date.parse("2026-01-01T12:00:00Z");
  it("handles missing values honestly", () => expect(timeAgo(null, now)).toBe("never"));
  it("buckets seconds, minutes, hours and days", () => {
    expect(timeAgo("2026-01-01T11:59:58Z", now)).toBe("just now");
    expect(timeAgo("2026-01-01T11:59:30Z", now)).toBe("30s ago");
    expect(timeAgo("2026-01-01T11:50:00Z", now)).toBe("10 min ago");
    expect(timeAgo("2026-01-01T06:00:00Z", now)).toBe("6 h ago");
    expect(timeAgo("2025-12-25T12:00:00Z", now)).toBe("7 d ago");
  });
  it("never reports a negative age for clock skew", () => expect(timeAgo("2026-01-01T12:00:30Z", now)).toBe("just now"));
});

describe("shortHash / plural / groupBy", () => {
  it("strips the sha256 prefix", () => expect(shortHash("sha256:abcdef0123456789", 8)).toBe("abcdef01"));
  it("renders a dash for missing hashes", () => expect(shortHash(undefined)).toBe("—"));
  it("pluralises", () => {
    expect(plural(1, "case")).toBe("1 case");
    expect(plural(2, "policy", "policies")).toBe("2 policies");
  });
  it("groups preserving order", () => {
    expect(groupBy(["a1", "b1", "a2"], (s) => s[0])).toEqual({ a: ["a1", "a2"], b: ["b1"] });
  });
});
