import { describe, expect, it } from "vitest";
import {
  barSeries,
  byImage,
  counts,
  daily,
  fixStats,
  formatBytes,
  formatDate,
  href,
  jsonTokens,
  mergeCves,
  niceTicks,
  overlap,
  parseRoute,
  pinned,
  registryUrl,
  sameImage,
  scannerName,
  withLatest,
} from "./data";
import type { Cve, History, Lifecycle } from "./dynamodb";

function history(scanned_at: string, total = 3, cves_pk = scanned_at): History {
  return {
    sk: `${scanned_at}#docker#trivy`,
    group: "python",
    vendor: "docker",
    image: "python:alpine",
    scanner: "trivy",
    scanner_version: "1",
    scanner_db: "2",
    image_digest: "sha256:0",
    scanned_at,
    cves_pk,
    cve_total: total,
    cve_critical: 1,
    cve_high: 1,
    cve_medium: 0,
    cve_low: 0,
  };
}

function cve(id: string, severity: string, fixed_version = ""): Cve {
  return {
    sk: `${id}#pkg`,
    cve_id: id,
    severity,
    description: "",
    url: "",
    package_name: "pkg",
    installed_version: "1",
    fixed_version,
  };
}

function lifecycle(id: string, dates: Partial<Lifecycle>): Lifecycle {
  return {
    sk: `${id}#pkg`,
    cve_id: id,
    package_name: "pkg",
    severity: "HIGH",
    installed_version: "1",
    fixed_version: "",
    first_seen: "2026-11-01T00:00:00Z",
    ...dates,
  };
}

describe("data", () => {
  it("counts the unknown severity as the rest of the total", () => {
    expect(counts(history("2026-11-20T00:00:00Z", 5))).toEqual({
      critical: 1,
      high: 1,
      medium: 0,
      low: 0,
      unknown: 3,
    });
  });

  it("keeps the last scan of every day, oldest first", () => {
    const items = [
      history("2026-11-21T08:00:00Z"),
      history("2026-11-20T08:00:00Z"),
      history("2026-11-20T20:00:00Z"),
    ];
    expect(daily(items).map((h) => h.scanned_at)).toEqual([
      "2026-11-20T20:00:00Z",
      "2026-11-21T08:00:00Z",
    ]);
  });

  it("adds LATEST scans missing in HISTORY within the range", () => {
    const old = history("2026-10-01T00:00:00Z", 1, "old");
    const known = history("2026-11-20T00:00:00Z", 1, "known");
    const missing = history("2026-11-19T00:00:00Z", 1, "missing");
    expect(
      withLatest([known], [old, known, missing], "2026-11-01").map(
        (h) => h.cves_pk,
      ),
    ).toEqual(["known", "missing"]);
  });

  it("measures how fast CVEs leave the image", () => {
    const stats = fixStats(
      [
        lifecycle("A", {
          fix_seen: "2026-11-03T00:00:00Z",
          removed_at: "2026-11-05T00:00:00Z",
        }),
        lifecycle("B", { removed_at: "2026-11-11T00:00:00Z" }),
        lifecycle("C", { fix_seen: "2026-11-10T00:00:00Z" }),
        lifecycle("D", {}),
      ],
      "2026-11-20T00:00:00Z",
    );
    expect(stats).toEqual({
      removed: 2,
      daysInImage: 7,
      daysToFix: 2,
      openFixable: 1,
      longestWait: 10,
    });
    expect(fixStats([], "2026-11-20").daysInImage).toBeUndefined();
  });

  it("merges the CVEs of all scanners with the worst severity", () => {
    const rows = mergeCves(
      {
        trivy: [cve("CVE-1", "LOW"), cve("CVE-2", "HIGH")],
        grype: [cve("CVE-1", "CRITICAL", "1.1"), cve("CVE-3", "NEW")],
      },
      {
        trivy: [
          lifecycle("CVE-1", { first_seen: "2026-11-05" }),
          // A removed lifecycle of a CVE found again is not its start
          lifecycle("CVE-2", { first_seen: "2026-01-01", removed_at: "x" }),
        ],
        grype: [lifecycle("CVE-1", { first_seen: "2026-11-02" })],
      },
    );
    expect(
      rows.map((r) => [r.cve_id, r.severity, r.scanners, r.first_seen]),
    ).toEqual([
      ["CVE-1", "critical", { trivy: "low", grype: "critical" }, "2026-11-02"],
      ["CVE-2", "high", { trivy: "high" }, undefined],
      ["CVE-3", "unknown", { grype: "unknown" }, undefined],
    ]);
    expect(rows[0].fixed_version).toBe("1.1");
    expect(overlap(rows, ["trivy", "grype"])).toEqual({
      all: 1,
      only: { trivy: 1, grype: 1 },
      severityDiffers: 1,
    });
  });

  it("groups the scans of an image, fewest CVEs on average first", () => {
    const scan = (vendor: string, scanner: string, total: number) => ({
      ...history("2026-11-20T00:00:00Z", total),
      vendor,
      scanner,
    });
    const images = byImage([
      scan("a", "trivy", 1),
      scan("a", "grype", 9),
      scan("b", "trivy", 2),
      scan("b", "grype", 2),
    ]);
    expect(images.map((i) => [i.vendor, i.average])).toEqual([
      ["b", 2],
      ["a", 5],
    ]);
    expect(images[1].scans.map((s) => s.scanner)).toEqual(["grype", "trivy"]);
  });

  it("makes one bar series per scanner with its daily scans", () => {
    const scan = history("2026-11-20T00:00:00Z", 5);
    expect(barSeries([scan], [[scan]])).toEqual([
      {
        name: "Trivy",
        points: [
          {
            label: "2026-11-20T00:00:00Z",
            values: counts(scan),
            notes: ["digest 0", "size -"],
          },
        ],
      },
    ]);
  });

  it("makes round axis ticks covering the maximum", () => {
    expect(niceTicks(0)).toEqual([0, 1]);
    expect(niceTicks(335)).toEqual([0, 100, 200, 300, 400]);
    expect(niceTicks(7)).toEqual([0, 2, 4, 6, 8]);
  });

  it("formats sizes and dates, hiding unknown values", () => {
    expect(formatBytes(undefined)).toBe("-");
    expect(formatBytes(52_400_000)).toBe("52.4 MB");
    expect(formatDate("2026-11-13T10:00:00Z")).toBe("Nov 13, 2026");
    expect(formatDate("1970-01-01T00:00:00Z")).toBe("-");
    expect(formatDate("")).toBe("-");
  });

  it("splits JSON into tokens, keys sorted with pk and sk first", () => {
    const tokens = jsonTokens({
      b: [1, true],
      sk: "s",
      a: "<b>x</b>",
      pk: null,
    });
    expect(tokens.map((t) => t.text).join("")).toBe(
      JSON.stringify(
        { pk: null, sk: "s", a: "<b>x</b>", b: [1, true] },
        null,
        2,
      ),
    );
    expect(tokens.filter((t) => t.kind === "key").map((t) => t.text)).toEqual([
      '"pk"',
      '"sk"',
      '"a"',
      '"b"',
    ]);
    expect(tokens.find((t) => t.kind === "string")?.text).toBe('"s"');
    expect(
      tokens.filter((t) => t.kind === "literal").map((t) => t.text),
    ).toEqual(["null", "true"]);
    expect(tokens.find((t) => t.kind === "number")?.text).toBe("1");
  });

  it("uses the lifecycle of the CVE at the scan time", () => {
    const lifecycles = {
      trivy: [
        lifecycle("CVE-1", {
          first_seen: "2026-11-02",
          removed_at: "2026-11-09",
        }),
      ],
    };
    const firstSeen = (at?: string) =>
      mergeCves({ trivy: [cve("CVE-1", "LOW")] }, lifecycles, at)[0].first_seen;
    expect(firstSeen("2026-11-05")).toBe("2026-11-02");
    expect(firstSeen("2026-11-10")).toBeUndefined();
    expect(firstSeen()).toBeUndefined();
  });

  it("uses a finished lifecycle of a CVE found again, no fix from the future", () => {
    const lifecycles = {
      trivy: [
        // Finished lifecycle (archived key) and the current one
        {
          ...lifecycle("CVE-1", {
            first_seen: "2026-11-01",
            removed_at: "2026-11-05",
          }),
          sk: "CVE-1#pkg#2026-11-05",
        },
        lifecycle("CVE-1", {
          first_seen: "2026-11-20",
          fix_seen: "2026-11-22",
        }),
      ],
    };
    const row = (at?: string) =>
      mergeCves({ trivy: [cve("CVE-1", "LOW")] }, lifecycles, at)[0];
    expect(row("2026-11-03").first_seen).toBe("2026-11-01");
    expect(row("2026-11-21")).toMatchObject({ first_seen: "2026-11-20" });
    expect(row("2026-11-21").fix_seen).toBeUndefined();
    expect(row("2026-11-23").fix_seen).toBe("2026-11-22");
  });

  it("links images to their registry pages", () => {
    expect(registryUrl("quay.io/hummingbird/nodejs:latest")).toBe(
      "https://quay.io/repository/hummingbird/nodejs?tab=tags&tag=latest",
    );
    expect(registryUrl("docker.io/python:alpine")).toBe(
      "https://hub.docker.com/_/python/tags?name=alpine",
    );
    expect(registryUrl("docker.io/ubuntu/nginx:latest")).toBe(
      "https://hub.docker.com/r/ubuntu/nginx/tags?name=latest",
    );
    expect(registryUrl("cgr.dev/chainguard/node:latest")).toBe(
      "https://images.chainguard.dev/directory/image/node/versions",
    );
    expect(registryUrl("registry.suse.com/bci/ruby:latest")).toBe(
      "https://registry.suse.com/repositories/bci-ruby",
    );
    expect(registryUrl("mcr.microsoft.com/dotnet/aspnet:latest")).toBe(
      "https://mcr.microsoft.com/artifact/mar/dotnet/aspnet/tags",
    );
    expect(registryUrl("public.ecr.aws/amazonlinux/amazonlinux:latest")).toBe(
      "https://gallery.ecr.aws/amazonlinux/amazonlinux",
    );
    expect(registryUrl("gcr.io/distroless/static:latest")).toBe(
      "https://github.com/GoogleContainerTools/distroless",
    );
    expect(registryUrl("localhost:5000/app")).toBeUndefined();
    expect(registryUrl("alpine:latest")).toBeUndefined();
  });

  it("knows when scans are of different image versions", () => {
    const a = history("2026-11-20T00:00:00Z");
    expect(sameImage([a, { ...a, scanner: "grype" }])).toBe(true);
    expect(sameImage([a, { ...a, image_digest: "sha256:1" }])).toBe(false);
  });

  it("capitalizes scanner names", () => {
    expect(["trivy", "grype"].map(scannerName)).toEqual(["Trivy", "Grype"]);
  });

  it("pins pull references to the digest", () => {
    expect(pinned("registry.suse.com/bci/ruby:latest", "sha256:1")).toBe(
      "registry.suse.com/bci/ruby@sha256:1",
    );
    expect(pinned("localhost:5000/app", "sha256:1")).toBe(
      "localhost:5000/app@sha256:1",
    );
    expect(pinned("alpine:latest", "unknown")).toBe("alpine:latest");
  });

  it("parses and builds routes", () => {
    expect(parseRoute("")).toEqual({ tab: "overview" });
    expect(parseRoute("#/nope")).toEqual({ tab: "overview" });
    expect(parseRoute(href("image", "python", "docker slim"))).toEqual({
      tab: "image",
      group: "python",
      vendor: "docker slim",
      day: undefined,
    });
    expect(
      parseRoute(href("image", "python", "docker", "2026-11-20")).day,
    ).toBe("2026-11-20");
    expect(parseRoute(href("raw", "2026-11-24"))).toEqual({
      tab: "raw",
      day: "2026-11-24",
    });
  });
});
