"use client";

import { useState, useMemo, useCallback, useEffect } from "react";
import type { ImageGroup, ContainerImage, Scan, Cve } from "@/lib/supabase";
import { fetchCvesForScans } from "@/lib/supabase";
import { CveTooltip } from "@/components/CveTooltip";

interface Props {
  groups: ImageGroup[];
  images: ContainerImage[];
  scans: Scan[];
}

export function CveDetailTab({ groups, images, scans }: Props) {
  const [selectedGroup, setSelectedGroup] = useState<number | "all">("all");
  const [selectedScanner, setSelectedScanner] = useState<string>("all");
  const [selectedDate, setSelectedDate] = useState<string>("");
  const [cves, setCves] = useState<Cve[]>([]);
  const [loadingCves, setLoadingCves] = useState(false);
  const [hoveredCve, setHoveredCve] = useState<string | null>(null);
  const [sortKey, setSortKey] = useState<string>("cve_id");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");

  /* Available dates from scans */
  const dates = useMemo(() => {
    const set = new Set(scans.map((s) => s.scanned_at.slice(0, 10)));
    return Array.from(set).sort().reverse();
  }, [scans]);

  /* Set default date to latest */
  useEffect(() => {
    if (dates.length > 0 && !selectedDate) {
      setSelectedDate(dates[0]);
    }
  }, [dates, selectedDate]);

  /* Filter scans by current selection */
  const filteredScans = useMemo(() => {
    return scans.filter((s) => {
      const scanDate = s.scanned_at.slice(0, 10);
      if (selectedDate && scanDate !== selectedDate) return false;
      if (selectedScanner !== "all" && s.scanner !== selectedScanner)
        return false;
      if (selectedGroup !== "all") {
        const img = images.find((i) => i.id === s.container_image_id);
        if (!img || img.group_id !== selectedGroup) return false;
      }
      return true;
    });
  }, [scans, images, selectedDate, selectedScanner, selectedGroup]);

  /* Load CVEs when filtered scans change */
  const loadCves = useCallback(async () => {
    if (filteredScans.length === 0) {
      setCves([]);
      return;
    }
    setLoadingCves(true);
    try {
      const scanIds = filteredScans.map((s) => s.id);
      const data = await fetchCvesForScans(scanIds);
      setCves(data);
    } catch (err) {
      console.error("Failed to fetch CVEs:", err);
    } finally {
      setLoadingCves(false);
    }
  }, [filteredScans]);

  useEffect(() => {
    loadCves();
  }, [loadCves]);

  /* Build enriched CVE rows with scan + image metadata */
  const rows = useMemo(() => {
    return cves.map((cve) => {
      const scan = filteredScans.find((s) => s.id === cve.scan_id);
      const img = scan
        ? images.find((i) => i.id === scan.container_image_id)
        : undefined;
      const group =
        img ? groups.find((g) => g.id === img.group_id) : undefined;
      return { cve, scan, img, group };
    });
  }, [cves, filteredScans, images, groups]);

  const SEVERITY_ORDER: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    unknown: 4,
  };

  const handleSort = useCallback((key: string) => {
    setSortDir((prev) => (sortKey === key && prev === "asc" ? "desc" : "asc"));
    setSortKey(key);
  }, [sortKey]);

  const sortedRows = useMemo(() => {
    const getValue = (row: (typeof rows)[0]): string | number => {
      switch (sortKey) {
        case "cve_id":
          return row.cve.cve_id;
        case "severity":
          return SEVERITY_ORDER[row.cve.severity.toLowerCase()] ?? 99;
        case "image":
          return row.img?.image ?? "";
        case "group":
          return row.group?.name ?? "";
        case "scanner":
          return row.scan?.scanner ?? "";
        case "package":
          return row.cve.package_name ?? "";
        case "installed":
          return row.cve.installed_version ?? "";
        case "fixed":
          return row.cve.fixed_version ?? "";
        default:
          return "";
      }
    };

    return [...rows].sort((a, b) => {
      const va = getValue(a);
      const vb = getValue(b);
      const cmp = va < vb ? -1 : va > vb ? 1 : 0;
      return sortDir === "asc" ? cmp : -cmp;
    });
  }, [rows, sortKey, sortDir]);

  const sortIndicator = (key: string) =>
    sortKey === key ? (sortDir === "asc" ? " ▲" : " ▼") : "";

  return (
    <div>
      {/* Controls */}
      <div className="controls">
        <div className="control-group">
          <label htmlFor="date-select">Date:</label>
          <select
            id="date-select"
            value={selectedDate}
            onChange={(e) => setSelectedDate(e.target.value)}
          >
            {dates.map((d) => (
              <option key={d} value={d}>
                {d}
              </option>
            ))}
          </select>
        </div>

        <div className="control-group">
          <label htmlFor="group-select">Group:</label>
          <select
            id="group-select"
            value={selectedGroup}
            onChange={(e) =>
              setSelectedGroup(
                e.target.value === "all" ? "all" : Number(e.target.value),
              )
            }
          >
            <option value="all">All groups</option>
            {groups.map((g) => (
              <option key={g.id} value={g.id}>
                {g.name}
              </option>
            ))}
          </select>
        </div>

        <div className="control-group">
          <label htmlFor="scanner-select">Scanner:</label>
          <select
            id="scanner-select"
            value={selectedScanner}
            onChange={(e) => setSelectedScanner(e.target.value)}
          >
            <option value="all">All scanners</option>
            <option value="trivy">trivy</option>
            <option value="grype">grype</option>
          </select>
        </div>
      </div>

      {/* Scan metadata summary */}
      {filteredScans.length > 0 && (
        <div className="card">
          <h3>Scan Info</h3>
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Image</th>
                  <th>Scanner</th>
                  <th>Digest</th>
                  <th>Scanner Version</th>
                  <th>DB Info</th>
                  <th>CVEs</th>
                  <th>Scanned At</th>
                </tr>
              </thead>
              <tbody>
                {filteredScans.map((s) => {
                  const img = images.find(
                    (i) => i.id === s.container_image_id,
                  );
                  return (
                    <tr key={s.id}>
                      <td>{img?.image ?? "?"}</td>
                      <td>{s.scanner}</td>
                      <td title={s.image_digest}>
                        {s.image_digest.slice(0, 20)}...
                      </td>
                      <td>{s.scanner_version}</td>
                      <td
                        title={s.scanner_db_info}
                        style={{ maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                      >
                        {s.scanner_db_info || "-"}
                      </td>
                      <td>{s.cve_count}</td>
                      <td>{s.scanned_at.slice(0, 16).replace("T", " ")}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* CVE table */}
      <div className="card">
        <h2>
          CVEs{" "}
          <span style={{ fontWeight: 400, fontSize: "0.875rem", color: "var(--text-muted)" }}>
            ({sortedRows.length} results)
          </span>
        </h2>

        {loadingCves ? (
          <div className="loading">
            <span className="spinner" />
            Loading CVEs...
          </div>
        ) : sortedRows.length === 0 ? (
          <div className="empty">
            No CVEs found for the selected filters.
          </div>
        ) : (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th className="sortable" onClick={() => handleSort("cve_id")}>
                    CVE ID{sortIndicator("cve_id")}
                  </th>
                  <th className="sortable" onClick={() => handleSort("severity")}>
                    Severity{sortIndicator("severity")}
                  </th>
                  <th className="sortable" onClick={() => handleSort("image")}>
                    Image{sortIndicator("image")}
                  </th>
                  <th className="sortable" onClick={() => handleSort("group")}>
                    Group{sortIndicator("group")}
                  </th>
                  <th className="sortable" onClick={() => handleSort("scanner")}>
                    Scanner{sortIndicator("scanner")}
                  </th>
                  <th className="sortable" onClick={() => handleSort("package")}>
                    Package{sortIndicator("package")}
                  </th>
                  <th className="sortable" onClick={() => handleSort("installed")}>
                    Installed{sortIndicator("installed")}
                  </th>
                  <th className="sortable" onClick={() => handleSort("fixed")}>
                    Fixed{sortIndicator("fixed")}
                  </th>
                </tr>
              </thead>
              <tbody>
                {sortedRows.map((row) => (
                  <tr key={`${row.cve.id}`}>
                    <td className="cve-cell">
                      <span
                        className="cve-link"
                        onMouseEnter={() =>
                          setHoveredCve(String(row.cve.id))
                        }
                        onMouseLeave={() => setHoveredCve(null)}
                      >
                        {row.cve.cve_id}
                      </span>
                      {hoveredCve === String(row.cve.id) && (
                        <CveTooltip cve={row.cve} />
                      )}
                    </td>
                    <td>
                      <span
                        className={`severity severity-${row.cve.severity.toLowerCase()}`}
                      >
                        {row.cve.severity}
                      </span>
                    </td>
                    <td>{row.img?.image ?? "?"}</td>
                    <td>{row.group?.name ?? "?"}</td>
                    <td>{row.scan?.scanner ?? "?"}</td>
                    <td className="truncate-cell" title={row.cve.package_name || undefined}>
                      {row.cve.package_name || "-"}
                    </td>
                    <td>{row.cve.installed_version || "-"}</td>
                    <td>{row.cve.fixed_version || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
