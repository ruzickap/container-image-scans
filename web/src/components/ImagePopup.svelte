<script lang="ts">
  import {
    counts,
    formatBytes,
    formatDate,
    mergeCves,
    shortDigest,
      scannerName,
  } from "../lib/data";
  import type { Scan } from "../lib/dynamodb";
  import SeverityCounts from "./SeverityCounts.svelte";

  // Latest scans of one image by all scanners
  let {
    scans,
    id,
    side = "below",
    up = false,
  }: {
    scans: Scan[];
    id: string;
    // Next to the card (outside its padding) or below the row
    side?: "right" | "left" | "below";
    // Align to the bottom of the row (rows in the lower half of the window)
    up?: boolean;
  } = $props();

  let first = $derived(scans[0]);
  // Worst fixable CVEs of all scanners - stored in LATEST, no extra reads
  const TOP = 8;
  let rows = $derived(
    mergeCves(
      Object.fromEntries(
        scans.map((s) => [
          s.scanner,
          (s.top_fixable ?? []).map((cve) => ({
            ...cve,
            sk: `${cve.cve_id}#${cve.package_name}`,
            description: "",
            url: "",
          })),
        ]),
      ),
    ).slice(0, TOP),
  );
  let fixable = $derived(Math.max(...scans.map((s) => s.cve_fixable ?? 0)));
  let recorded = $derived(scans.some((s) => s.top_fixable));
</script>

<div class="popup {side}" class:up role="tooltip" {id}>
  <p class="mono ref">{first.image}</p>
  <p class="muted">{first.image_description}</p>
  <dl>
    <dt>Digest</dt>
    <dd class="mono">{shortDigest(first.image_digest)}</dd>
    <dt>Size</dt>
    <dd>{formatBytes(first.image_size)}</dd>
    <dt>Created</dt>
    <dd>{formatDate(first.image_created)}</dd>
    <dt>Scanned</dt>
    <dd>{formatDate(first.scanned_at)}</dd>
  </dl>
  <table>
    <thead>
      <tr>
        <th></th>
        <th>All CVEs</th>
        <th class="num">Total</th>
        <th class="num">Fix available</th>
      </tr>
    </thead>
    <tbody>
      {#each scans as scan (scan.sk)}
        <tr>
          <th scope="row">{scannerName(scan.scanner)}</th>
          <td><SeverityCounts counts={counts(scan)} /></td>
          <td class="num">{scan.cve_total}</td>
          <td class="num fix">{scan.cve_fixable ?? "-"}</td>
        </tr>
      {/each}
    </tbody>
  </table>
  {#if !recorded}
    <p class="muted">Fixable CVEs are listed after the next scan.</p>
  {:else if rows.length}
    <h4>Fix available - update these packages</h4>
    <ul>
      {#each rows as row (row.key)}
        <li>
          <span class="badge sev-{row.severity}">{row.severity}</span>
          <span class="mono">{row.cve_id}</span>
          <span class="pkg"
            >{row.package_name}
            <span class="mono muted">{row.installed_version}</span> →
            <span class="mono fix">{row.fixed_version}</span></span
          >
        </li>
      {/each}
    </ul>
    {#if fixable > rows.length}
      <p class="muted">… more with a fix - click for all</p>
    {/if}
  {:else}
    <p class="fix">No CVE with an available fix.</p>
  {/if}
</div>

<style>
  .popup {
    position: absolute;
    z-index: 20;
    width: 440px;
    background: #1b2130;
    border: 1px solid rgb(167 139 250 / 40%);
    border-radius: 12px;
    padding: 0.85rem 1rem;
    box-shadow: 0 16px 40px rgb(0 0 0 / 55%);
    pointer-events: none;
    font-size: 0.85rem;
  }

  /* The row is inside the card padding (1.25rem) */
  .right {
    top: 0;
    left: calc(100% + 1.75rem);
  }

  .left {
    top: 0;
    right: calc(100% + 1.75rem);
  }

  .below {
    top: calc(100% - 0.25rem);
    left: -0.5rem;
    width: auto;
    right: -0.5rem;
  }

  .up {
    top: auto;
    bottom: 0;
  }

  .below.up {
    bottom: calc(100% - 0.25rem);
  }

  p {
    margin: 0 0 0.35rem;
  }

  .ref {
    font-weight: 600;
    word-break: break-all;
  }

  dl {
    display: grid;
    grid-template-columns: repeat(4, auto);
    gap: 0 0.75rem;
    margin: 0.5rem 0;
  }

  dt {
    color: var(--muted);
    font-size: 0.75rem;
  }

  dd {
    margin: 0;
    grid-row: 2;
  }

  table {
    margin: 0.25rem 0 0.5rem;
  }

  th,
  td {
    padding: 0.2rem 0.4rem 0.2rem 0;
    border: 0;
    font-size: 0.8rem;
  }

  tbody th {
    text-transform: none;
    letter-spacing: 0;
    color: var(--text);
  }

  .fix {
    color: var(--good);
    font-weight: 600;
  }

  h4 {
    margin: 0.5rem 0 0.35rem;
    font-size: 0.8rem;
    font-weight: 500;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  ul {
    list-style: none;
    margin: 0 0 0.35rem;
    padding: 0;
    display: grid;
    gap: 0.3rem;
  }

  li {
    display: flex;
    gap: 0.5rem;
    align-items: baseline;
    flex-wrap: wrap;
  }

  .badge {
    text-transform: capitalize;
    min-width: 4.5rem;
    text-align: center;
  }

  .pkg {
    font-size: 0.8rem;
  }
</style>
