<script lang="ts">
  import { SvelteMap } from "svelte/reactivity";
  import {
    day,
    formatDate,
    href,
    message,
    scannerName,
    withLatest,
  } from "../lib/data";
  import { load, type History, type Scan } from "../lib/dynamodb";
  import DayPicker from "./DayPicker.svelte";
  import Json from "./Json.svelte";

  let {
    scans,
    groups,
    day: selected,
  }: { scans: Scan[]; groups: string[]; day: string } = $props();

  // Partitions loaded on request: pk -> items
  const partitions = new SvelteMap<string, Promise<unknown[]>>();

  // Scans of the day: HISTORY of all groups (+ LATEST of scans older than HISTORY)
  let items = $derived(
    Promise.all(
      groups.map((g) => load<History>(`HISTORY#${g}`, [selected, `${selected}~`])),
    ).then((lists) =>
      withLatest(
        lists.flat(),
        scans.filter((s) => day(s.scanned_at) === selected),
        selected,
      ).sort(
        (a, b) =>
          a.group.localeCompare(b.group) ||
          a.vendor.localeCompare(b.vendor) ||
          a.scanner.localeCompare(b.scanner),
      ),
    ),
  );

  // Days with scans, newest first: DAYS partition + days of LATEST scans older than DAYS
  let days = $derived(
    load<{ sk: string }>("DAYS").then((items) =>
      [
        ...new Set([
          ...items.map((item) => item.sk),
          ...scans.map((s) => day(s.scanned_at)),
        ]),
      ]
        .sort()
        .reverse(),
    ),
  );

  function toggle(pk: string) {
    if (partitions.has(pk)) {
      partitions.delete(pk);
    } else {
      partitions.set(pk, load<unknown>(pk));
    }
  }
</script>

<section class="stack">
  <div class="page-head">
    <div>
      <h1>Raw data</h1>
      <p class="muted">
        The DynamoDB items of one day, as stored. Open a scan to see its
        summary, load its CVEs or their lifecycle.
      </p>
    </div>
    {#await days then list}
      <DayPicker
        days={list}
        {selected}
        link={(value) => href("raw", value)}
      />
    {:catch error}
      <p class="error">Error: {message(error)}</p>
    {/await}
  </div>

  <article class="card">
    <div class="card-head">
      <h2>Scans on {formatDate(selected)}</h2>
    </div>
    {#await items}
      <p class="status" role="status">Loading ...</p>
    {:then list}
      {#each list as item (item.cves_pk)}
        <details>
          <summary>
            <span class="name">{item.group} / {item.vendor} / {scannerName(item.scanner)}</span>
            <span class="muted">{item.cve_total} CVEs · {item.scanned_at}</span>
          </summary>
          <div class="body">
            <Json value={item} />
            <div class="chips">
              <button
                type="button"
                class="chip"
                aria-pressed={partitions.has(item.cves_pk)}
                onclick={() => toggle(item.cves_pk)}>CVES partition</button
              >
              <button
                type="button"
                class="chip"
                aria-pressed={partitions.has(
                  `LIFECYCLE#${item.group}#${item.vendor}#${item.scanner}`,
                )}
                onclick={() =>
                  toggle(`LIFECYCLE#${item.group}#${item.vendor}#${item.scanner}`)}
                >LIFECYCLE partition</button
              >
            </div>
            {#if partitions.has(item.cves_pk)}
              {@render partition(item.cves_pk)}
            {/if}
            {#if partitions.has(`LIFECYCLE#${item.group}#${item.vendor}#${item.scanner}`)}
              {@render partition(
                `LIFECYCLE#${item.group}#${item.vendor}#${item.scanner}`,
              )}
            {/if}
          </div>
        </details>
      {:else}
        <p class="muted">No scans stored for this day.</p>
      {/each}
    {:catch error}
      <p class="error" role="status">Error: {message(error)}</p>
    {/await}
  </article>
</section>

{#snippet partition(pk: string)}
  <div class="partition">
    <h3 class="mono">{pk}</h3>
    {#await partitions.get(pk)}
      <p class="status">Loading ...</p>
    {:then rows}
      <p class="muted">{rows?.length ?? 0} items</p>
      <Json value={rows} />
    {:catch error}
      <p class="error">Error: {message(error)}</p>
    {/await}
  </div>
{/snippet}

<style>
  details {
    border-top: 1px solid var(--border);
  }

  summary {
    cursor: pointer;
    padding: 0.55rem 0;
    display: flex;
    gap: 1rem;
    flex-wrap: wrap;
  }

  .name {
    font-weight: 600;
  }

  .body {
    display: grid;
    gap: 0.75rem;
    padding-bottom: 1rem;
  }

  .partition {
    display: grid;
    gap: 0.35rem;
    margin-top: 0.75rem;
  }

  .partition p {
    margin: 0;
  }
</style>
