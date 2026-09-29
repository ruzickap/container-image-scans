"use client";

import { useState, useEffect, useCallback } from "react";
import {
  fetchGroups,
  fetchImages,
  fetchScans,
  type ImageGroup,
  type ContainerImage,
  type Scan,
} from "@/lib/supabase";
import { HistoryCharts } from "@/components/HistoryCharts";
import { CveDetailTab } from "@/components/CveDetailTab";

export default function Home() {
  const [groups, setGroups] = useState<ImageGroup[]>([]);
  const [images, setImages] = useState<ContainerImage[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<"overview" | "details">(
    "overview",
  );

  const loadData = useCallback(async () => {
    try {
      const [g, i, s] = await Promise.all([
        fetchGroups(),
        fetchImages(),
        fetchScans(),
      ]);
      setGroups(g);
      setImages(i);
      setScans(s);
    } catch (err) {
      console.error("Failed to load data:", err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  if (loading) {
    return (
      <div className="container">
        <div className="loading">
          <span className="spinner" />
          Loading scan data...
        </div>
      </div>
    );
  }

  return (
    <div className="container">
      <header>
        <div>
          <h1>Container Image CVE Dashboard</h1>
          <p>
            Comparing vulnerability findings across container images using trivy
            and grype
          </p>
        </div>
      </header>

      <div className="tabs">
        <button
          className={`tab ${activeTab === "overview" ? "active" : ""}`}
          onClick={() => setActiveTab("overview")}
        >
          History Overview
        </button>
        <button
          className={`tab ${activeTab === "details" ? "active" : ""}`}
          onClick={() => setActiveTab("details")}
        >
          CVE Details
        </button>
      </div>

      {activeTab === "overview" && (
        <HistoryCharts groups={groups} images={images} scans={scans} />
      )}

      {activeTab === "details" && (
        <CveDetailTab groups={groups} images={images} scans={scans} />
      )}
    </div>
  );
}
