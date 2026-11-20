import { render, screen, within } from "@testing-library/svelte";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App.svelte";
import type { Cve, Scan } from "./lib/dynamodb";

// Fake data access - no AWS calls
const query = vi.hoisted(() => vi.fn());
vi.mock("./lib/dynamodb", () => ({ query }));

function scan(group: string, vendor: string, scanner: string): Scan {
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
    image_digest: "sha256:0",
    scanned_at: "2026-11-20T00:00:00Z",
    cves_pk: `CVES#${group}#${vendor}#${scanner}`,
    cve_total: 2,
    cve_critical: 0,
    cve_high: 1,
    cve_medium: 1,
    cve_low: 0,
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

// Text of the first cells of every body row of a table
function rows(table: HTMLElement, cells: number): string[][] {
  return within(table)
    .getAllByRole("row")
    .slice(1)
    .map((row) =>
      within(row)
        .getAllByRole("cell")
        .slice(0, cells)
        .map((cell) => cell.textContent?.trim() ?? ""),
    );
}

describe("App", () => {
  beforeEach(() => {
    query.mockReset();
  });

  it("shows a message when there are no scans", async () => {
    query.mockResolvedValue([]);
    render(App);

    expect(await screen.findByText("No scans yet.")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("shows the error when DynamoDB fails", async () => {
    query.mockRejectedValue(new Error("AccessDeniedException"));
    render(App);

    expect(
      await screen.findByText("Error: AccessDeniedException"),
    ).toBeInTheDocument();
  });

  it("lists the latest scans sorted by group, vendor and scanner", async () => {
    query.mockResolvedValue([
      scan("python", "docker", "trivy"),
      scan("base", "alpine", "trivy"),
      scan("base", "alpine", "grype"),
    ]);
    render(App);

    await screen.findByRole("table");
    expect(query).toHaveBeenCalledWith("LATEST");
    expect(rows(screen.getByRole("table"), 2)).toEqual([
      ["base", "alpine"],
      ["base", "alpine"],
      ["python", "docker"],
    ]);
    expect(screen.getAllByRole("row")[1]).toHaveTextContent("grype");
    expect(screen.getAllByRole("cell")[0]).toHaveAttribute(
      "title",
      "base images",
    );
    expect(screen.getAllByText("alpine image")).toHaveLength(2);
  });

  it("shows the CVEs of a clicked image sorted by severity, safely", async () => {
    query.mockImplementation(async (pk: string) =>
      pk === "LATEST"
        ? [scan("python", "docker", "trivy")]
        : [
            cve("CVE-2", "LOW"),
            cve("CVE-1", "CRITICAL"),
            cve("CVE-3", "HIGH", "javascript:alert(1)"),
          ],
    );
    render(App);

    await userEvent.click(
      await screen.findByRole("button", { name: "docker.io/python:docker" }),
    );

    expect(query).toHaveBeenCalledWith("CVES#python#docker#trivy");
    expect(await screen.findByRole("heading", { level: 2 })).toHaveTextContent(
      "python / docker: docker.io/python:docker - trivy",
    );
    const cves = screen.getAllByRole("table")[1];
    expect(rows(cves, 2)).toEqual([
      ["CVE-1", "CRITICAL"],
      ["CVE-3", "HIGH"],
      ["CVE-2", "LOW"],
    ]);
    // Only https URLs become links, scanner text is never rendered as HTML
    expect(
      within(cves)
        .getAllByRole("link")
        .map((link) => link.getAttribute("href")),
    ).toEqual(["https://example.com/CVE-1", "https://example.com/CVE-2"]);
    expect(cves.querySelector("b")).toBeNull();
    expect(within(cves).getByText("<b>CVE-1</b>")).toBeInTheDocument();
  });

  // Images a and b: the CVE query of a answers with "answerA" (decided by
  // the test), b answers at once. Clicks a, then b, and waits for b.
  async function clickAThenB(answerA: Promise<Cve[]>): Promise<void> {
    query.mockImplementation(async (pk: string) => {
      if (pk === "LATEST") {
        return [scan("a", "x", "trivy"), scan("b", "y", "trivy")];
      }
      return pk === "CVES#a#x#trivy" ? await answerA : [cve("CVE-FAST", "LOW")];
    });
    render(App);
    await userEvent.click(
      await screen.findByRole("button", { name: "docker.io/a:x" }),
    );
    await userEvent.click(
      screen.getByRole("button", { name: "docker.io/b:y" }),
    );
    expect(await screen.findByText("CVE-FAST")).toBeInTheDocument();
  }

  it("shows only the last clicked image when an earlier answer comes later", async () => {
    let answerSlow: (cves: Cve[]) => void = () => {};
    await clickAThenB(new Promise((resolve) => (answerSlow = resolve)));

    answerSlow([cve("CVE-SLOW", "HIGH")]);
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(screen.queryByText("CVE-SLOW")).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 2 })).toHaveTextContent(
      "b / y",
    );
  });

  it("ignores the error of an earlier click when it comes later", async () => {
    let failSlow: (error: Error) => void = () => {};
    await clickAThenB(new Promise((_, reject) => (failSlow = reject)));

    failSlow(new Error("ThrottlingException"));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(screen.queryByText(/ThrottlingException/)).not.toBeInTheDocument();
    expect(screen.getByText("CVE-FAST")).toBeInTheDocument();
  });

  it("shows the error of the last click", async () => {
    query.mockImplementation(async (pk: string) => {
      if (pk === "LATEST") {
        return [scan("a", "x", "trivy")];
      }
      throw new Error("ThrottlingException");
    });
    render(App);

    await userEvent.click(
      await screen.findByRole("button", { name: "docker.io/a:x" }),
    );

    expect(
      await screen.findByText("Error: ThrottlingException"),
    ).toBeInTheDocument();
  });
});
