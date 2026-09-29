"use client";

import { useMemo } from "react";
import { Line } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  TimeScale,
} from "chart.js";
import "chartjs-adapter-date-fns";
import type { ImageGroup, ContainerImage, Scan } from "@/lib/supabase";

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  TimeScale,
);

/* Distinct colors for chart lines */
const PALETTE = [
  "#38bdf8",
  "#a78bfa",
  "#fb923c",
  "#4ade80",
  "#f472b6",
  "#facc15",
  "#2dd4bf",
  "#e879f9",
  "#818cf8",
  "#f87171",
];

interface Props {
  groups: ImageGroup[];
  images: ContainerImage[];
  scans: Scan[];
}

export function HistoryCharts({ groups, images, scans }: Props) {
  /* Build one chart per (group x scanner) combination */
  const charts = useMemo(() => {
    const scanners: Array<"trivy" | "grype"> = ["trivy", "grype"];
    const result: Array<{
      title: string;
      datasets: Array<{
        label: string;
        data: Array<{ x: string; y: number }>;
        borderColor: string;
        backgroundColor: string;
      }>;
    }> = [];

    for (const group of groups) {
      for (const scanner of scanners) {
        const groupImages = images.filter((i) => i.group_id === group.id);
        const datasets = groupImages.map((img, idx) => {
          /* Get scans for this image+scanner, sorted by date */
          const imgScans = scans
            .filter(
              (s) =>
                s.container_image_id === img.id && s.scanner === scanner,
            )
            .sort(
              (a, b) =>
                new Date(a.scanned_at).getTime() -
                new Date(b.scanned_at).getTime(),
            );

          const points = imgScans.map((s) => ({
            x: s.scanned_at.slice(0, 10), // YYYY-MM-DD
            y: s.cve_count,
          }));

          const color = PALETTE[idx % PALETTE.length];
          return {
            label: img.image,
            data: points,
            borderColor: color,
            backgroundColor: color + "33",
          };
        });

        result.push({
          title: `${group.name} - ${scanner}`,
          datasets,
        });
      }
    }

    return result;
  }, [groups, images, scans]);

  if (scans.length === 0) {
    return (
      <div className="empty">
        No scan data available yet. Run the nightly scan workflow to populate
        data.
      </div>
    );
  }

  return (
    <div className="charts-grid">
      {charts.map((chart) => (
        <div className="card" key={chart.title}>
          <h2>{chart.title}</h2>
          <div className="chart-container">
            <Line
              data={{ datasets: chart.datasets }}
              options={{
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                  mode: "index",
                  intersect: false,
                },
                scales: {
                  x: {
                    type: "time",
                    time: { unit: "day", tooltipFormat: "yyyy-MM-dd" },
                    ticks: { color: "#94a3b8" },
                    grid: { color: "#1e293b" },
                  },
                  y: {
                    beginAtZero: true,
                    title: {
                      display: true,
                      text: "CVE Count",
                      color: "#94a3b8",
                    },
                    ticks: {
                      color: "#94a3b8",
                      precision: 0,
                    },
                    grid: { color: "#1e293b" },
                  },
                },
                plugins: {
                  legend: {
                    position: "bottom",
                    labels: {
                      color: "#e2e8f0",
                      boxWidth: 12,
                      padding: 16,
                      font: { size: 11 },
                    },
                  },
                  tooltip: {
                    backgroundColor: "#1e293b",
                    titleColor: "#e2e8f0",
                    bodyColor: "#e2e8f0",
                    borderColor: "#334155",
                    borderWidth: 1,
                  },
                },
              }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}
