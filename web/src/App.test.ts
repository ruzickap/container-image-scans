import { render, screen, waitFor, within } from "@testing-library/svelte";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App.svelte";
import type { Cve, History, Lifecycle, Scan } from "./lib/dynamodb";

// Fake data access - no AWS calls
const load = vi.hoisted(() => vi.fn());
vi.mock("./lib/dynamodb", () => ({ load }));

function scan(group: string, vendor: string, scanner: string, total = 2): Scan {
  return {
    sk: `${group}#${vendor}#${scanner}`,
    group,
    group_description: `${group} images`,
    vendor,
    image: `docker.io/${group}:${vendor}`,
    image_description: `${vendor} image`,
    scanner,
    scanner_version: "1.0.0",
    scanner_db: "2026-11-20",
    image_digest: "sha256:0123456789abcdef",
    image_size: 52_400_000,
    image_created: "2026-11-19T00:00:00Z",
    scanned_at: "2026-11-20T00:00:00Z",
    cves_pk: `CVES#${group}#${vendor}#${scanner}`,
    cve_total: total,
    cve_critical: 0,
    cve_high: total,
    cve_medium: 0,
    cve_low: 0,
    cve_fixable: 1,
  };
}

function cve(
  id: string,
  severity: string,
  url = `https://example.com/${id}`,
): Cve {
  return {
    sk: `${id}#pkg`,
    cve_id: id,
    severity,
    description: `<b>${id}</b>`,
    url,
    package_name: "pkg",
    installed_version: "1.0",
    fixed_version: "1.1",
  };
}

// Answers of the fake load(): partition key -> items
function data(partitions: Record<string, unknown[]>) {
  load.mockImplementation(async (pk: string) => partitions[pk] ?? []);
}

// Text of the first cells of every body row of a table
function rows(table: HTMLElement, from: number, cells: number): string[][] {
  return within(table)
    .getAllByRole("row")
    .slice(1)
    .map((row) =>
      within(row)
        .getAllByRole("cell")
        .slice(from, from + cells)
        .map((cell) => cell.textContent?.trim() ?? ""),
    );
}

describe("App", () => {
  beforeEach(() => {
    load.mockReset();
    location.hash = "";
  });

  afterEach(() => {
    location.hash = "";
  });

  it("shows a message when there are no scans", async () => {
    data({});
    render(App);

    expect(await screen.findByText("No scans yet.")).toBeInTheDocument();
    expect(load).toHaveBeenCalledWith("LATEST");
  });

  it("shows the error when DynamoDB fails", async () => {
    load.mockRejectedValue(new Error("AccessDeniedException"));
    render(App);

    expect(
      await screen.findByText("Error: AccessDeniedException"),
    ).toBeInTheDocument();
  });

  it("lists the groups with the images of one scanner, fewest CVEs first", async () => {
    data({
      LATEST: [
        scan("python", "docker", "trivy", 9),
        scan("python", "chainguard", "trivy", 1),
        scan("python", "chainguard", "grype", 5),
        scan("base", "alpine", "trivy"),
      ],
    });
    render(App);

    const python = (
      await screen.findByRole("heading", { name: "python" })
    ).closest("article")!;
    const links = within(python)
      .getAllByRole("link")
      .map((link) => link.getAttribute("href"));
    expect(links).toEqual([
      "#/compare/python",
      "#/image/python/chainguard",
      "https://hub.docker.com/_/python/tags?name=chainguard",
      "#/image/python/docker",
      "https://hub.docker.com/_/python/tags?name=docker",
    ]);
    expect(within(python).getByText("fewest CVEs")).toBeInTheDocument();
    expect(within(python).getAllByText(/52\.4 MB/)).toHaveLength(2);
    expect(screen.getByRole("heading", { name: "base" })).toBeInTheDocument();

    // A click on the row opens the image, unless text is selected in it
    vi.spyOn(window, "getSelection").mockReturnValueOnce({
      toString: () => "docker.io",
    } as Selection);
    await userEvent.click(within(python).getAllByText(/52\.4 MB/)[0]);
    expect(location.hash).toBe("");
    await userEvent.click(within(python).getAllByText(/52\.4 MB/)[0]);
    expect(location.hash).toBe("#/image/python/chainguard");
  });

  it("shows the CVEs of all scanners of an image, safely", async () => {
    location.hash = "#/image/python/docker";
    data({
      LATEST: [
        scan("python", "docker", "trivy"),
        scan("python", "docker", "grype"),
      ],
      "CVES#python#docker#trivy": [
        cve("CVE-2", "LOW"),
        cve("CVE-1", "CRITICAL"),
        cve("CVE-3", "HIGH", "javascript:alert(1)"),
      ],
      "CVES#python#docker#grype": [cve("CVE-1", "HIGH")],
      "LIFECYCLE#python#docker#trivy": [
        {
          sk: "CVE-1#pkg",
          first_seen: "2026-11-10T00:00:00Z",
        } as Lifecycle,
        {
          sk: "CVE-9#pkg",
          cve_id: "CVE-9",
          severity: "MEDIUM",
          package_name: "old",
          first_seen: "2026-11-01T00:00:00Z",
          fix_seen: "2026-11-02T00:00:00Z",
          removed_at: "2026-11-08T00:00:00Z",
        } as Lifecycle,
      ],
    });
    render(App);

    expect(
      await screen.findByRole("heading", { name: "docker.io/python:docker" }),
    ).toBeInTheDocument();
    const [cves, removed] = await screen.findAllByRole("table");
    expect(rows(cves, 1, 2)).toEqual([
      ["CVE-1", "critical"],
      ["CVE-3", "high"],
      ["CVE-2", "low"],
    ]);
    // Found by both scanners, first seen 10 days before the scan
    expect(rows(cves, 6, 3)[0]).toEqual(["GrypeTrivy", "Nov 10, 2026", "10 d"]);
    // Only https URLs become links, scanner text is never rendered as HTML
    expect(
      within(cves)
        .getAllByRole("link")
        .map((link) => link.getAttribute("href")),
    ).toEqual(["https://example.com/CVE-1", "https://example.com/CVE-2"]);

    await userEvent.click(
      screen.getByRole("button", { name: "Details of CVE-1 in pkg" }),
    );
    expect(cves.querySelector("b")).toBeNull();
    expect(within(cves).getByText("<b>CVE-1</b>")).toBeInTheDocument();

    // Removed CVE: 7 days in the image, 6 days from the fix
    expect(rows(removed, 0, 1)).toEqual([["CVE-9"]]);
    expect(rows(removed, 7, 2)).toEqual([["7", "6"]]);
  });

  it("shows only the last selected image when an earlier answer comes later", async () => {
    let answerSlow: (cves: Cve[]) => void = () => {};
    location.hash = "#/image/a/x";
    load.mockImplementation(async (pk: string) => {
      if (pk === "LATEST") {
        return [scan("a", "x", "trivy"), scan("a", "y", "trivy")];
      }
      if (pk === "CVES#a#x#trivy") {
        return new Promise((resolve) => (answerSlow = resolve));
      }
      return pk === "CVES#a#y#trivy" ? [cve("CVE-FAST", "LOW")] : [];
    });
    render(App);

    await userEvent.click(await screen.findByRole("link", { name: "y" }));
    expect(await screen.findByText("CVE-FAST")).toBeInTheDocument();
    answerSlow([cve("CVE-SLOW", "HIGH")]);
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(screen.queryByText("CVE-SLOW")).not.toBeInTheDocument();
    expect(screen.getByText("CVE-FAST")).toBeInTheDocument();
  });

  it("shows the scan of an earlier day with its pinned digest", async () => {
    location.hash = "#/image/python/docker/2026-11-18";
    const old: History = {
      ...scan("python", "docker", "trivy", 7),
      scanned_at: "2026-11-18T00:00:00Z",
      image_digest: "sha256:old",
      cves_pk: "CVES#old",
    };
    data({
      LATEST: [scan("python", "docker", "trivy")],
      "HISTORY#python": [old],
      "CVES#old": [cve("CVE-OLD", "HIGH")],
    });
    render(App);

    expect(
      await screen.findByText("docker pull docker.io/python@sha256:old"),
    ).toBeInTheDocument();
    expect(await screen.findByText("CVE-OLD")).toBeInTheDocument();
    expect(load).toHaveBeenCalledWith("HISTORY#python", [
      "2026-11-18",
      "2026-11-18~",
    ]);
    expect(screen.getByRole("link", { name: "Latest" })).toHaveAttribute(
      "href",
      "#/image/python/docker",
    );
  });

  it("filters the CVEs by severity", async () => {
    location.hash = "#/image/python/docker";
    data({
      LATEST: [scan("python", "docker", "trivy")],
      "CVES#python#docker#trivy": [
        cve("CVE-1", "CRITICAL"),
        cve("CVE-2", "LOW"),
      ],
    });
    render(App);

    await userEvent.click(await screen.findByRole("button", { name: /^low/ }));

    const [cves] = screen.getAllByRole("table");
    expect(rows(cves, 1, 1)).toEqual([["CVE-2"]]);
  });

  it("compares the images of a group over time", async () => {
    location.hash = "#/compare/python";
    const history: History[] = [
      {
        ...scan("python", "docker", "trivy", 5),
        scanned_at: "2026-11-19T00:00:00Z",
        cves_pk: "h1",
      },
    ];
    data({
      LATEST: [
        scan("python", "docker", "trivy"),
        scan("python", "chainguard", "trivy", 0),
      ],
      "HISTORY#python": history,
    });
    render(App);

    expect(
      await screen.findByRole("heading", { name: "Latest scan" }),
    ).toBeInTheDocument();
    expect(load).toHaveBeenCalledWith("HISTORY#python", [
      expect.stringMatching(/^\d{4}-\d{2}-\d{2}$/),
      "~",
    ]);
    const [latest] = screen.getAllByRole("table");
    // Fewest CVEs first, delta to the first day of the range
    expect(rows(latest, 3, 3)).toEqual([
      ["0", "1", "0"],
      ["2", "1", "-3"],
    ]);
  });

  it("shows the fixable CVEs of an image when hovering it", async () => {
    const fix = {
      cve_id: "CVE-FIX",
      severity: "HIGH",
      package_name: "pkg",
      installed_version: "1.0",
      fixed_version: "1.1",
    };
    data({
      LATEST: [
        { ...scan("python", "docker", "trivy"), top_fixable: [fix] },
        // The same CVE from the other scanner is listed once
        { ...scan("python", "docker", "grype"), top_fixable: [fix] },
      ],
    });
    render(App);

    await userEvent.hover(await screen.findByRole("link", { name: "docker" }));

    const popup = await screen.findByRole("tooltip");
    expect(within(popup).getAllByText("CVE-FIX")).toHaveLength(1);
    expect(popup).toHaveTextContent("pkg 1.0 → 1.1");
    // Only LATEST is read - no CVE partition per hover
    expect(load).toHaveBeenCalledTimes(1);
    await userEvent.unhover(screen.getByRole("link", { name: "docker" }));
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();
  });

  it("compares the CVEs of the scanners of an image on request", async () => {
    location.hash = "#/scanners/python";
    data({
      LATEST: [
        scan("python", "docker", "trivy"),
        scan("python", "docker", "grype"),
      ],
      "CVES#python#docker#trivy": [cve("CVE-1", "LOW"), cve("CVE-2", "LOW")],
      "CVES#python#docker#grype": [cve("CVE-1", "HIGH")],
    });
    render(App);

    const button = await screen.findByRole("button", { name: "Compare CVEs" });
    expect(load).not.toHaveBeenCalledWith("CVES#python#docker#trivy");
    await userEvent.click(button);

    // grype, trivy totals, then found by all, only grype, only trivy, differs
    const [table] = screen.getAllByRole("table");
    await waitFor(() =>
      expect(rows(table, 3, 4)).toEqual([["1", "0", "1", "1"]]),
    );
  });

  it("shows the CVEs with a fix first, all when none has a fix", async () => {
    location.hash = "#/image/python/docker";
    data({
      LATEST: [scan("python", "docker", "trivy"), scan("python", "x", "trivy")],
      "CVES#python#docker#trivy": [
        cve("CVE-FIX", "LOW"),
        { ...cve("CVE-NOFIX", "CRITICAL"), fixed_version: "" },
      ],
      "CVES#python#x#trivy": [
        { ...cve("CVE-NOFIX", "CRITICAL"), fixed_version: "" },
      ],
    });
    render(App);

    expect(await screen.findByText("CVE-FIX")).toBeInTheDocument();
    expect(screen.queryByText("CVE-NOFIX")).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /^All 2/ }));
    expect(screen.getByText("CVE-NOFIX")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("link", { name: "x" }));
    expect(await screen.findByText("CVE-NOFIX")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^All 1/ })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
  });

  it("lists only the days with scans", async () => {
    location.hash = "#/raw/2026-11-20";
    data({
      LATEST: [scan("python", "docker", "trivy")],
      DAYS: [{ sk: "2026-11-18" }, { sk: "2026-11-20" }],
    });
    render(App);

    const days = await screen.findByRole("combobox", { name: "Day" });
    expect(
      within(days)
        .getAllByRole("option")
        .map((option) => option.getAttribute("value")),
    ).toEqual(["2026-11-20", "2026-11-18"]);
    expect(screen.getByRole("link", { name: "Previous day" })).toHaveAttribute(
      "href",
      "#/raw/2026-11-18",
    );
  });

  it("shows the raw items of one day", async () => {
    location.hash = "#/raw/2026-11-20";
    data({ LATEST: [scan("python", "docker", "trivy")] });
    render(App);

    await userEvent.click(await screen.findByText("python / docker / Trivy"));
    expect(screen.getByText('"CVES#python#docker#trivy"')).toBeInTheDocument();
    expect(load).toHaveBeenCalledWith("HISTORY#python", [
      "2026-11-20",
      "2026-11-20~",
    ]);
  });
});
