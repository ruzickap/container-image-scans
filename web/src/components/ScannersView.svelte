<script lang="ts">
  import { SvelteMap } from "svelte/reactivity";
  import {
    color,
    counts,
    daily,
    day,
    daysAgo,
    href,
    mergeCves,
    message,
    overlap,
    withLatest,
    type Overlap,
      scannerName,
  } from "../lib/data";
  import { load, type Cve, type History, type Scan } from "../lib/dynamodb";
  import GroupChips from "./GroupChips.svelte";
  import ImageLink from "./ImageLink.svelte";
  import LineChart from "./LineChart.svelte";
  import SeverityCounts from "./SeverityCounts.svelte";

  let {
    scans,
    group,
    groups,
    range,
  }: { scans: Scan[]; group: string; groups: string[]; range: number } =
    $props();

  let groupScans = $derived(scans.filter((s) => s.group === group));
  let scanners = $derived([...new Set(scans.map((s) => s.scanner))].sort());
  let vendors = $derived([...new Set(groupScans.map((s) => s.vendor))]);
  let from = $derived(daysAgo(range));
  let history = $derived(
    load<History>(`HISTORY#${group}`, [from, "~"]).then((items) =>
      withLatest(items, groupScans, from),
    ),
  );
  // CVEs found by all / only one scanner, loaded per image on request: a
  // CVE partition costs up to ~40 reads of the 2 per second of the table
  const overlaps = new SvelteMap<string, Promise<Overlap>>();

  async function loadOverlap(vendor: string): Promise<Overlap> {
    const list = groupScans.filter((s) => s.vendor === vendor);
    const cves = await Promise.all(list.map((s) => load<Cve>(s.cves_pk)));
    return overlap(
      mergeCves(Object.fromEntries(list.map((s, i) => [s.scanner, cves[i]]))),
      list.map((s) => s.scanner),
    );
  }

  const scanOf = (vendor: string, scanner: string) =>
    groupScans.find((s) => s.vendor === vendor && s.scanner === scanner);
</script>

<section class="stack">
  <div class="page-head">
    <div>
      <h1>Scanners: {group}</h1>
      <p class="muted">
        What does every scanner find in the same image? Differences come from
        the vulnerability databases and how the scanners detect packages.
      </p>
    </div>
    <GroupChips {groups} {group} tab="scanners" />
  </div>

  <article class="card">
    <div class="card-head"><h2>Agreement of the latest scans</h2></div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Image</th>
            {#each scanners as scanner (scanner)}
              <th class="num">{scannerName(scanner)}</th>
            {/each}
            <th class="num">Found by all</th>
            {#each scanners as scanner (scanner)}
              <th class="num">Only {scannerName(scanner)}</th>
            {/each}
            <th class="num">Severity differs</th>
          </tr>
        </thead>
        <tbody>
          {#each vendors as vendor (`${group}#${vendor}`)}
            {@const result = overlaps.get(`${group}#${vendor}`)}
            <tr>
              <td><a href={href("image", group, vendor)}>{vendor}</a></td>
              {#each scanners as scanner (scanner)}
                <td class="num">{scanOf(vendor, scanner)?.cve_total ?? "-"}</td>
              {/each}
              {#if result}
                {#await result}
                  <td colspan={scanners.length + 2} class="muted">Loading ...</td>
                {:then r}
                  <td class="num">{r.all}</td>
                  {#each scanners as scanner (scanner)}
                    <td class="num">{r.only[scanner] ?? "-"}</td>
                  {/each}
                  <td class="num">{r.severityDiffers}</td>
                {:catch error}
                  <td colspan={scanners.length + 2} class="error"
                    >Error: {message(error)}
                    <button
                      type="button"
                      class="chip"
                      onclick={() =>
                        overlaps.set(`${group}#${vendor}`, loadOverlap(vendor))}
                      >Retry</button
                    ></td
                  >
                {/await}
              {:else}
                <td colspan={scanners.length + 2} class="num">
                  <button
                    type="button"
                    class="chip"
                    onclick={() =>
                      overlaps.set(`${group}#${vendor}`, loadOverlap(vendor))}
                    >Compare CVEs</button
                  >
                </td>
              {/if}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </article>

  {#await history}
    <p class="status" role="status">Loading history ...</p>
  {:then items}
    <div class="grid">
      {#each vendors as vendor (vendor)}
        <article class="card">
          <div class="card-head">
            <h3><a href={href("image", group, vendor)}>{vendor}</a></h3>
            <span class="mono muted"><ImageLink
                image={groupScans.find((s) => s.vendor === vendor)!.image}
              /></span>
          </div>
          <LineChart
            title="{vendor} CVEs per scanner"
            height={180}
            series={scanners.map((scanner, i) => ({
              name: scannerName(scanner),
              color: color(i),
              points: daily(
                items.filter(
                  (h) => h.vendor === vendor && h.scanner === scanner,
                ),
              ).map((h) => ({ x: day(h.scanned_at), y: h.cve_total })),
            }))}
          />
          <div class="per-scanner">
            {#each scanners as scanner (scanner)}
              {@const scan = scanOf(vendor, scanner)}
              {#if scan}
                <div>
                  <span class="muted">{scannerName(scanner)}</span>
                  <SeverityCounts counts={counts(scan)} />
                </div>
              {/if}
            {/each}
          </div>
        </article>
      {/each}
    </div>
  {:catch error}
    <p class="error" role="status">Error: {message(error)}</p>
  {/await}
</section>

<style>
  .card-head .mono {
    font-size: 0.75rem;
  }

  .per-scanner {
    display: grid;
    gap: 0.4rem;
    margin-top: 0.75rem;
  }

  .per-scanner > div {
    display: grid;
    grid-template-columns: 4rem 1fr;
    align-items: center;
  }
</style>
