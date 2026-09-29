import { createClient } from "@supabase/supabase-js";

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL ?? "";
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? "";

export const supabase = createClient(supabaseUrl, supabaseAnonKey);

/* ── Types ─────────────────────────────────────────────────────── */

export interface ImageGroup {
  id: number;
  name: string;
}

export interface ContainerImage {
  id: number;
  image: string;
  group_id: number;
}

export interface Scan {
  id: number;
  container_image_id: number;
  scanner: "trivy" | "grype";
  image_digest: string;
  scanner_version: string;
  scanner_db_info: string;
  cve_count: number;
  scanned_at: string;
}

export interface Cve {
  id: number;
  scan_id: number;
  cve_id: string;
  severity: string;
  description: string;
  help_markdown: string;
  package_name: string;
  installed_version: string;
  fixed_version: string;
}

/* ── Data fetchers ─────────────────────────────────────────────── */

// PostgREST caps responses at 1000 rows; page through with .range().
// Queries must have a deterministic order (end with "id") for stable pages.
const PAGE_SIZE = 1000;

async function fetchAll<T>(
  page: (
    from: number,
    to: number,
  ) => PromiseLike<{ data: T[] | null; error: unknown }>,
): Promise<T[]> {
  const rows: T[] = [];
  for (let from = 0; ; from += PAGE_SIZE) {
    const { data, error } = await page(from, from + PAGE_SIZE - 1);
    if (error) throw error;
    rows.push(...(data ?? []));
    if (!data || data.length < PAGE_SIZE) return rows;
  }
}

export async function fetchGroups(): Promise<ImageGroup[]> {
  const { data, error } = await supabase
    .from("image_groups")
    .select("*")
    .order("name");
  if (error) throw error;
  return data ?? [];
}

export async function fetchImages(): Promise<ContainerImage[]> {
  const { data, error } = await supabase
    .from("container_images")
    .select("*")
    .order("image");
  if (error) throw error;
  return data ?? [];
}

export async function fetchScans(): Promise<Scan[]> {
  return fetchAll<Scan>((from, to) =>
    supabase
      .from("scans")
      .select(
        "id, container_image_id, scanner, image_digest, scanner_version, scanner_db_info, cve_count, scanned_at",
      )
      .order("scanned_at", { ascending: true })
      .order("id")
      .range(from, to),
  );
}

export async function fetchCvesForScan(scanId: number): Promise<Cve[]> {
  return fetchAll<Cve>((from, to) =>
    supabase
      .from("cves")
      .select("*")
      .eq("scan_id", scanId)
      .order("severity")
      .order("cve_id")
      .order("id")
      .range(from, to),
  );
}

export async function fetchCvesForScans(scanIds: number[]): Promise<Cve[]> {
  if (scanIds.length === 0) return [];
  return fetchAll<Cve>((from, to) =>
    supabase
      .from("cves")
      .select("*")
      .in("scan_id", scanIds)
      .order("severity")
      .order("cve_id")
      .order("id")
      .range(from, to),
  );
}
