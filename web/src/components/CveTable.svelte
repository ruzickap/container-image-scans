<script lang="ts">
  import { SvelteSet } from "svelte/reactivity";
  import {
    SEVERITIES,
    daysBetween,
    formatDate,
    isHttps,
    type CveRow,
    type Severity,
      scannerName,
  } from "../lib/data";

  let {
    rows,
    scanners,
    latest,
  }: { rows: CveRow[]; scanners: string[]; latest: string } = $props();

  const PAGE = 200;
  let severity = $state<Severity | "all">("all");
  let search = $state("");
  // CVEs with a fix available matter most - shown first
  const FIX = { fix: "Fix available", nofix: "No fix", all: "All" } as const;
  // Writable, reset for new rows: "All" when nothing has a fix
  let fix = $derived<keyof typeof FIX>(
    rows.some((row) => row.fixed_version) ? "fix" : "all",
  );
  const matchesFix = (row: CveRow, value: keyof typeof FIX) =>
    value === "all" || (value === "fix") === Boolean(row.fixed_version);
  let limit = $state(PAGE);
  const expanded = new SvelteSet<string>();

  let filtered = $derived(
    rows.filter(
      (row) =>
        (severity === "all" || row.severity === severity) &&
        matchesFix(row, fix) &&
        `${row.cve_id} ${row.package_name}`
          .toLowerCase()
          .includes(search.trim().toLowerCase()),
    ),
  );

  function toggle(key: string) {
    if (expanded.has(key)) {
      expanded.delete(key);
    } else {
      expanded.add(key);
    }
  }
</script>

<div class="filters">
  <div class="chips" role="group" aria-label="Severity">
    {#each ["all", ...SEVERITIES] as const as value (value)}
      <button
        type="button"
        class="chip"
        aria-pressed={severity === value}
        onclick={() => ((severity = value), (limit = PAGE))}
      >
        <span class={value === "all" ? "" : `sev-${value}`}>{value}</span>
        <span class="muted"
          >{value === "all"
            ? rows.filter((r) => matchesFix(r, fix)).length
            : rows.filter((r) => r.severity === value && matchesFix(r, fix))
                .length}</span
        >
      </button>
    {/each}
  </div>
  <div class="chips" role="group" aria-label="Fix">
    {#each Object.entries(FIX) as [value, label] (value)}
      <button
        type="button"
        class="chip"
        class:fixchip={value === "fix"}
        aria-pressed={fix === value}
        onclick={() => ((fix = value as keyof typeof FIX), (limit = PAGE))}
      >
        {label}
        <span class="muted"
          >{rows.filter((r) => matchesFix(r, value as keyof typeof FIX))
            .length}</span
        >
      </button>
    {/each}
  </div>
  <input
    type="search"
    placeholder="Search CVE or package"
    aria-label="Search CVE or package"
    bind:value={search}
  />
</div>

<div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th><span class="sr-only">Details</span></th>
        <th>CVE</th>
        <th>Severity</th>
        <th>Package</th>
        <th>Installed</th>
        <th>Fixed in</th>
        <th>Found by</th>
        <th>First detected</th>
        <th class="num">Age</th>
      </tr>
    </thead>
    <tbody>
      {#each filtered.slice(0, limit) as row (row.key)}
        <tr>
          <td>
            <button
              type="button"
              class="expand"
              aria-expanded={expanded.has(row.key)}
              aria-label="Details of {row.cve_id} in {row.package_name}"
              onclick={() => toggle(row.key)}>{expanded.has(row.key) ? "▾" : "▸"}</button
            >
          </td>
          <td class="mono">
            {#if isHttps(row.url)}
              <a href={row.url} rel="noopener noreferrer" target="_blank"
                >{row.cve_id}</a
              >
            {:else}
              {row.cve_id}
            {/if}
          </td>
          <td><span class="badge sev-{row.severity}">{row.severity}</span></td>
          <td>{row.package_name}</td>
          <td class="mono">{row.installed_version}</td>
          <td class="mono" class:fixed={row.fixed_version}
            >{row.fixed_version || "-"}</td
          >
          <td>
            {#each scanners as scanner (scanner)}
              {#if row.scanners[scanner]}
                <span
                  class="scanner sev-{row.scanners[scanner]}"
                  title="{scannerName(scanner)}: {row.scanners[scanner]}"
                  >{scannerName(scanner)}</span
                >
              {/if}
            {/each}
          </td>
          <td>{formatDate(row.first_seen)}</td>
          <td class="num"
            >{row.first_seen ? `${daysBetween(row.first_seen, latest)} d` : "-"}</td
          >
        </tr>
        {#if expanded.has(row.key)}
          <tr class="details">
            <td></td>
            <td colspan="8">
              <p>{row.description || "No description."}</p>
              <dl>
                {#each scanners as scanner (scanner)}
                  <dt>{scannerName(scanner)}</dt>
                  <dd class={row.scanners[scanner] ? `sev-${row.scanners[scanner]}` : "muted"}>
                    {row.scanners[scanner] ?? "not found"}
                  </dd>
                {/each}
                <dt>Fix available since</dt>
                <dd>{formatDate(row.fix_seen)}</dd>
              </dl>
            </td>
          </tr>
        {/if}
      {:else}
        <tr><td colspan="9" class="muted">No CVEs match.</td></tr>
      {/each}
    </tbody>
  </table>
</div>
{#if filtered.length > limit}
  <button type="button" class="chip more" onclick={() => (limit += PAGE)}>
    Show more ({filtered.length - limit} left)
  </button>
{/if}

<style>
  .filters {
    display: flex;
    flex-wrap: wrap;
    gap: 0.75rem;
    align-items: center;
    margin-bottom: 0.75rem;
  }

  .filters .chip {
    display: inline-flex;
    gap: 0.4rem;
  }

  .filters [aria-label="Severity"] .chip {
    text-transform: capitalize;
  }

  input[type="search"] {
    margin-left: auto;
    min-width: 240px;
  }

  .fixed {
    color: var(--good);
  }

  .fixchip[aria-pressed="true"] {
    border-color: var(--good);
    background: rgb(52 211 153 / 12%);
  }

  .expand {
    background: none;
    border: 0;
    color: var(--muted);
    cursor: pointer;
    padding: 0 0.25rem;
  }

  .badge {
    text-transform: capitalize;
  }

  .scanner {
    font-size: 0.75rem;
    border: 1px solid currentcolor;
    border-radius: 6px;
    padding: 0 0.35rem;
    margin-right: 0.25rem;
  }

  .details td {
    background: rgb(255 255 255 / 2%);
  }

  .details p {
    margin: 0 0 0.5rem;
    max-width: 900px;
  }

  dl {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.15rem 1rem;
    margin: 0;
  }

  dt {
    color: var(--muted);
    text-transform: capitalize;
  }

  dd {
    margin: 0;
  }

  .more {
    margin-top: 0.75rem;
  }

  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip-path: inset(50%);
  }
</style>
