// Pure data helpers of the dashboard - no AWS access, tested in data.test.ts
import type { Cve, History, Lifecycle } from "./dynamodb";

export const SEVERITIES = [
  "critical",
  "high",
  "medium",
  "low",
  "unknown",
] as const;
export type Severity = (typeof SEVERITIES)[number];
export type Counts = Record<Severity, number>;

const DAY_MS = 24 * 60 * 60 * 1000;

// Severity counts of a scan - "unknown" is the rest of the total
export function counts(scan: History): Counts {
  const known =
    scan.cve_critical + scan.cve_high + scan.cve_medium + scan.cve_low;
  return {
    critical: scan.cve_critical,
    high: scan.cve_high,
    medium: scan.cve_medium,
    low: scan.cve_low,
    unknown: scan.cve_total - known,
  };
}

// Scanner severity ("HIGH") to a dashboard severity ("high")
export function severityOf(value: string): Severity {
  const severity = value.toLowerCase();
  return (SEVERITIES as readonly string[]).includes(severity)
    ? (severity as Severity)
    : "unknown";
}

export const day = (iso: string): string => iso.slice(0, 10);

// ISO date (YYYY-MM-DD) of "days" days before "now"
export function daysAgo(days: number, now = new Date()): string {
  return new Date(now.getTime() - days * DAY_MS).toISOString().slice(0, 10);
}

export function daysBetween(from: string, to: string): number {
  return Math.max(0, Math.round((Date.parse(to) - Date.parse(from)) / DAY_MS));
}

// The last scan of every day, oldest first
export function daily<T extends History>(items: T[]): T[] {
  const byDay = new Map<string, T>();
  for (const item of [...items].sort((a, b) =>
    a.scanned_at.localeCompare(b.scanned_at),
  )) {
    byDay.set(day(item.scanned_at), item);
  }
  return [...byDay.values()];
}

// HISTORY items plus LATEST items not in them (scans before HISTORY existed) since "from"
export function withLatest(
  history: History[],
  latest: History[],
  from: string,
): History[] {
  const known = new Set(history.map((item) => item.cves_pk));
  return [
    ...history,
    ...latest.filter(
      (item) => !known.has(item.cves_pk) && item.scanned_at >= from,
    ),
  ];
}

// The scans of every image (group + vendor) by all scanners, fewest CVEs (average of the scanners) first
export function byImage<T extends History>(
  scans: T[],
): { vendor: string; scans: T[]; average: number }[] {
  const images = new Map<string, T[]>();
  for (const scan of scans) {
    const key = `${scan.group}#${scan.vendor}`;
    images.set(key, [...(images.get(key) ?? []), scan]);
  }
  return [...images.values()]
    .map((list) => ({
      vendor: list[0].vendor,
      scans: [...list].sort((a, b) => a.scanner.localeCompare(b.scanner)),
      average: list.reduce((sum, s) => sum + s.cve_total, 0) / list.length,
    }))
    .sort((a, b) => a.average - b.average);
}

export function median(values: number[]): number | undefined {
  if (!values.length) {
    return undefined;
  }
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2
    ? sorted[middle]
    : (sorted[middle - 1] + sorted[middle]) / 2;
}

export interface FixStats {
  // CVEs removed from the image
  removed: number;
  // Median days from first seen to removed
  daysInImage?: number;
  // Median days from "fixed version known" to removed
  daysToFix?: number;
  // CVEs still in the image although a fixed version is known
  openFixable: number;
  // Longest wait (days) of openFixable for the fix to reach the image
  longestWait?: number;
}

// How fast a vendor removes CVEs from an image - "latest" is the latest scan
export function fixStats(items: Lifecycle[], latest: string): FixStats {
  const removed = items.filter((item) => item.removed_at);
  const open = items.filter((item) => !item.removed_at && item.fix_seen);
  return {
    removed: removed.length,
    daysInImage: median(
      removed.map((item) => daysBetween(item.first_seen, item.removed_at!)),
    ),
    daysToFix: median(
      removed
        .filter((item) => item.fix_seen)
        .map((item) => daysBetween(item.fix_seen!, item.removed_at!)),
    ),
    openFixable: open.length,
    longestWait: open.length
      ? Math.max(...open.map((item) => daysBetween(item.fix_seen!, latest)))
      : undefined,
  };
}

// One CVE + package of an image with what every scanner says about it
export interface CveRow {
  key: string;
  cve_id: string;
  package_name: string;
  installed_version: string;
  fixed_version: string;
  description: string;
  url: string;
  // Worst severity of all scanners
  severity: Severity;
  // Scanner -> severity, only scanners that found it
  scanners: Record<string, Severity>;
  // Earliest of all scanners (lifecycle)
  first_seen?: string;
  fix_seen?: string;
}

const earliest = (a?: string, b?: string): string | undefined =>
  a && b ? (a < b ? a : b) : (a ?? b);

// Merge the CVEs of all scanners of one image with their lifecycles open at
// the scan time "at" (default: open now)
export function mergeCves(
  cves: Record<string, Cve[]>,
  lifecycles: Record<string, Lifecycle[]> = {},
  at?: string,
): CveRow[] {
  const rows = new Map<string, CveRow>();
  for (const [scanner, items] of Object.entries(cves)) {
    for (const cve of items) {
      const severity = severityOf(cve.severity);
      const row = rows.get(cve.sk) ?? {
        key: cve.sk,
        cve_id: cve.cve_id,
        package_name: cve.package_name,
        installed_version: cve.installed_version,
        fixed_version: cve.fixed_version,
        description: cve.description,
        url: cve.url,
        severity,
        scanners: {},
      };
      row.scanners[scanner] = severity;
      row.fixed_version ||= cve.fixed_version;
      row.description ||= cve.description;
      row.url ||= cve.url;
      if (SEVERITIES.indexOf(severity) < SEVERITIES.indexOf(row.severity)) {
        row.severity = severity;
      }
      rows.set(cve.sk, row);
    }
  }
  for (const items of Object.values(lifecycles)) {
    for (const item of items) {
      const row = rows.get(item.sk);
      const open =
        (!at || item.first_seen <= at) &&
        (!item.removed_at || (at !== undefined && item.removed_at > at));
      if (row && open) {
        row.first_seen = earliest(row.first_seen, item.first_seen);
        row.fix_seen = earliest(row.fix_seen, item.fix_seen);
      }
    }
  }
  return [...rows.values()].sort(
    (a, b) =>
      SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) ||
      a.key.localeCompare(b.key),
  );
}

export interface Overlap {
  // Found by every scanner
  all: number;
  // Found only by this scanner
  only: Record<string, number>;
  // Found by more scanners with different severities
  severityDiffers: number;
}

export function overlap(rows: CveRow[], scanners: string[]): Overlap {
  const result: Overlap = {
    all: 0,
    only: Object.fromEntries(scanners.map((scanner) => [scanner, 0])),
    severityDiffers: 0,
  };
  for (const row of rows) {
    const found = Object.keys(row.scanners);
    if (found.length === scanners.length) {
      result.all++;
    } else if (found.length === 1) {
      result.only[found[0]]++;
    }
    if (new Set(Object.values(row.scanners)).size > 1) {
      result.severityDiffers++;
    }
  }
  return result;
}

// Axis ticks from 0 to >= max in steps of 1, 2 or 5 * 10^n (about 4 steps)
export function niceTicks(max: number): number[] {
  const rough = Math.max(max, 1) / 4;
  const power = 10 ** Math.floor(Math.log10(rough));
  const step = Math.max(
    1,
    [1, 2, 5, 10].map((n) => n * power).find((n) => n >= rough) ?? power * 10,
  );
  const ticks = [0];
  while (ticks[ticks.length - 1] < max) {
    ticks.push(ticks[ticks.length - 1] + step);
  }
  return ticks.length > 1 ? ticks : [0, step];
}

export function formatBytes(bytes?: number): string {
  if (!bytes) {
    return "-";
  }
  return bytes >= 1e9
    ? `${(bytes / 1e9).toFixed(2)} GB`
    : `${(bytes / 1e6).toFixed(1)} MB`;
}

// "Nov 24, 2026" (UTC), "-" for missing dates and reproducible builds (1970)
export function formatDate(iso?: string): string {
  const time = iso ? Date.parse(iso) : NaN;
  if (Number.isNaN(time) || new Date(time).getUTCFullYear() < 2000) {
    return "-";
  }
  return new Date(time).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    timeZone: "UTC",
  });
}

export function formatDay(iso: string): string {
  return new Date(Date.parse(day(iso))).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    timeZone: "UTC",
  });
}

// Web page of an image in its registry (undefined for unknown registries)
export function registryUrl(image: string): string | undefined {
  const match = /^([^/]+)\/(.+?)(?::([^/:@]+))?$/.exec(image);
  if (!match) {
    return undefined;
  }
  const [, registry, repo, tag = "latest"] = match;
  const name = encodeURIComponent(tag);
  switch (registry) {
    case "docker.io":
      return repo.includes("/") && !repo.startsWith("library/")
        ? `https://hub.docker.com/r/${repo}/tags?name=${name}`
        : `https://hub.docker.com/_/${repo.replace(/^library\//, "")}/tags?name=${name}`;
    case "quay.io":
      return `https://quay.io/repository/${repo}?tab=tags&tag=${name}`;
    case "cgr.dev":
      return `https://images.chainguard.dev/directory/image/${repo.split("/").pop()}/versions`;
    case "registry.suse.com":
      return `https://registry.suse.com/repositories/${repo.replaceAll("/", "-")}`;
    case "mcr.microsoft.com":
      return `https://mcr.microsoft.com/artifact/mar/${repo}/tags`;
    case "public.ecr.aws":
      return `https://gallery.ecr.aws/${repo}`;
    case "gcr.io":
      // The GCR console needs a login - the project page lists the images
      return repo.startsWith("distroless/")
        ? "https://github.com/GoogleContainerTools/distroless"
        : undefined;
  }
  return undefined;
}

// "docker pull" reference pinned to the digest: repo:tag -> repo@sha256:...
export function pinned(image: string, digest: string): string {
  return digest.startsWith("sha256:")
    ? `${image.replace(/:[^/:]*$/, "")}@${digest}`
    : image;
}

// Display name of a scanner: "trivy" -> "Trivy"
export const scannerName = (name: string): string =>
  name.charAt(0).toUpperCase() + name.slice(1);

export function shortDigest(digest: string): string {
  return digest.startsWith("sha256:") ? digest.slice(7, 19) : digest;
}

// Links only to https URLs - the URL comes from the scanner data
export function isHttps(url: string | undefined): boolean {
  return url?.startsWith("https://") ?? false;
}

export function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export interface Token {
  kind: "key" | "string" | "number" | "literal" | "punct";
  text: string;
}

// JSON.stringify output split for syntax highlighting (rendered as text, never HTML), keys sorted with pk and sk first
export function jsonTokens(value: unknown): Token[] {
  const rank = (key: string) => ["pk", "sk"].indexOf(key) >>> 0;
  const text =
    JSON.stringify(
      value,
      (_, v: unknown) =>
        v && typeof v === "object" && !Array.isArray(v)
          ? Object.fromEntries(
              Object.entries(v).sort(
                ([a], [b]) => rank(a) - rank(b) || a.localeCompare(b),
              ),
            )
          : v,
      2,
    ) ?? "";
  const tokens: Token[] = [];
  let last = 0;
  for (const match of text.matchAll(
    /("(?:\\.|[^"\\])*")(\s*:)?|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|\b(true|false|null)\b/g,
  )) {
    if (match.index > last) {
      tokens.push({ kind: "punct", text: text.slice(last, match.index) });
    }
    if (match[1]) {
      tokens.push({ kind: match[2] ? "key" : "string", text: match[1] });
      if (match[2]) {
        tokens.push({ kind: "punct", text: match[2] });
      }
    } else {
      tokens.push({ kind: match[3] ? "number" : "literal", text: match[0] });
    }
    last = match.index + match[0].length;
  }
  if (last < text.length) {
    tokens.push({ kind: "punct", text: text.slice(last) });
  }
  return tokens;
}

export const TABS = [
  "overview",
  "compare",
  "image",
  "scanners",
  "raw",
] as const;
export type Tab = (typeof TABS)[number];

// "#/image/python/docker" -> { tab: "image", group: "python", vendor: "docker" }
export interface Route {
  tab: Tab;
  group?: string;
  vendor?: string;
  day?: string;
}

export function parseRoute(hash: string): Route {
  const [tab, ...rest] = hash
    .replace(/^#\/?/, "")
    .split("/")
    .map((part) => decodeURIComponent(part));
  if (!(TABS as readonly string[]).includes(tab)) {
    return { tab: "overview" };
  }
  return tab === "raw"
    ? { tab, day: rest[0] || undefined }
    : {
        tab: tab as Tab,
        group: rest[0] || undefined,
        vendor: rest[1] || undefined,
        day: rest[2] || undefined,
      };
}

export function href(tab: Tab, ...parts: (string | undefined)[]): string {
  return `#/${[tab, ...parts.filter(Boolean).map((p) => encodeURIComponent(p!))].join("/")}`;
}

// Line colors of vendors / scanners
const PALETTE = [
  "#a78bfa",
  "#22d3ee",
  "#f472b6",
  "#34d399",
  "#fbbf24",
  "#60a5fa",
  "#fb7185",
  "#a3e635",
];
export const color = (index: number): string => PALETTE[index % PALETTE.length];
