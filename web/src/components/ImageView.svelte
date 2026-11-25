<script lang="ts">
  import {
    counts,
    daily,
    day,
    daysAgo,
    daysBetween,
    formatBytes,
    formatDate,
    href,
    mergeCves,
    message,
    overlap,
    pinned,
    severityOf,
    shortDigest,
    withLatest,
      scannerName,
  } from "../lib/data";
  import {
    load,
    type Cve,
    type History,
    type Lifecycle,
    type Scan,
  } from "../lib/dynamodb";
  import CveTable from "./CveTable.svelte";
  import DayPicker from "./DayPicker.svelte";
  import GroupChips from "./GroupChips.svelte";
  import ImageLink from "./ImageLink.svelte";
  import SeverityCounts from "./SeverityCounts.svelte";
  import StackedBars from "./StackedBars.svelte";

  let {
    scans,
    group,
    groups,
    vendor,
    day: selectedDay,
    range,
  }: {
    scans: Scan[];
    group: string;
    groups: string[];
    vendor: string;
    // Shown day (YYYY-MM-DD), default: the latest scans
    day?: string;
    range: number;
  } = $props();

  let vendors = $derived([
    ...new Set(scans.filter((s) => s.group === group).map((s) => s.vendor)),
  ]);
  // Latest scan of this image by every scanner
  let imageScans = $derived(
    scans.filter((s) => s.group === group && s.vendor === vendor),
  );
  let description = $derived(imageScans[0].image_description);
  let from = $derived(daysAgo(range));
  // Daily scans of every scanner (oldest first) and the days with scans (newest first)
  let history = $derived(
    load<History>(`HISTORY#${group}`, [from, "~"]).then((items) => {
      const all = withLatest(items, imageScans, from).filter(
        (h) => h.vendor === vendor,
      );
      const perScanner = imageScans.map((scan) =>
        daily(all.filter((h) => h.scanner === scan.scanner)),
      );
      const days = [
        ...new Set(perScanner.flat().map((h) => day(h.scanned_at))),
      ].sort();
      return { perScanner, days: days.reverse() };
    }),
  );
  // Scans of the shown day (the last of the day by every scanner) + their CVEs
  let shown = $derived(
    scansOf(selectedDay).then((list) => ({
      scans: list,
      details: loadDetails(list),
    })),
  );
  let copied = $state(false);

  async function scansOf(when?: string): Promise<History[]> {
    if (!when) {
      return imageScans;
    }
    const items = await load<History>(`HISTORY#${group}`, [when, `${when}~`]);
    const all = withLatest(items, imageScans, when).filter(
      (h) => h.vendor === vendor && day(h.scanned_at) === when,
    );
    return imageScans
      .map((scan) => daily(all.filter((h) => h.scanner === scan.scanner)).pop())
      .filter((h): h is History => h !== undefined);
  }

  async function loadDetails(list: History[]) {
    const at = list.reduce(
      (latest, s) => (s.scanned_at > latest ? s.scanned_at : latest),
      "",
    );
    const [cves, lifecycles] = await Promise.all([
      Promise.all(list.map((s) => load<Cve>(s.cves_pk))),
      Promise.all(
        list.map((s) =>
          load<Lifecycle>(`LIFECYCLE#${group}#${vendor}#${s.scanner}`),
        ),
      ),
    ]);
    const byScanner = <T,>(values: T[]) =>
      Object.fromEntries(list.map((s, i) => [s.scanner, values[i]]));
    const rows = mergeCves(byScanner(cves), byScanner(lifecycles), at);
    const removed = list
      .flatMap((s, i) =>
        lifecycles[i]
          .filter((item) => item.removed_at && item.removed_at <= at)
          .map((item) => ({ ...item, scanner: s.scanner })),
      )
      .sort(
        (a, b) =>
          b.removed_at!.localeCompare(a.removed_at!) ||
          a.sk.localeCompare(b.sk),
      );
    return {
      at,
      rows,
      removed,
      overlap: overlap(
        rows,
        list.map((s) => s.scanner),
      ),
    };
  }

  async function copy(text: string) {
    await navigator.clipboard.writeText(text);
    copied = true;
    setTimeout(() => (copied = false), 1500);
  }

  const showDay = (value: string) =>
    (location.hash = href("image", group, vendor, value));
</script>

<section class="stack">
  <div class="pickers">
    <GroupChips {groups} {group} tab="image" />
    <nav class="chips" aria-label="Images of {group}">
      {#each vendors as name (name)}
        <a
          class="chip"
          href={href("image", group, name, selectedDay)}
          aria-current={name === vendor ? "page" : undefined}>{name}</a
        >
      {/each}
    </nav>
  </div>

  {#await history then { days }}
    {#if days.length}
      <div class="days">
        <span class="muted">Scan of</span>
        <DayPicker
          {days}
          selected={selectedDay ?? days[0]}
          link={(value) => href("image", group, vendor, value)}
        />
        {#if selectedDay}
          <a class="chip" href={href("image", group, vendor)}>Latest</a>
        {/if}
      </div>
    {/if}
  {:catch error}
    <p class="error">Error: {message(error)}</p>
  {/await}

  {#await shown}
    <p class="status" role="status">Loading ...</p>
  {:then { scans: list, details }}
    {#if !list.length}
      <p class="muted" role="status">
        No scan of this image on {formatDate(selectedDay)}.
      </p>
    {:else}
      {@const current = list[0]}
      {@const ref = pinned(current.image, current.image_digest)}
      <article class="card head">
        <div>
          <p class="muted crumbs">
            <a href={href("compare", group)}>{group}</a> / {vendor}
          </p>
          <h1 class="mono"><ImageLink image={current.image} /></h1>
          <p class="muted">{description}</p>
          <div class="pull">
            <code>docker pull {ref}</code>
            <button type="button" class="chip" onclick={() => copy(`docker pull ${ref}`)}
              >{copied ? "Copied" : "Copy"}</button
            >
          </div>
        </div>
        <dl class="meta">
          <dt>Digest</dt>
          <dd class="mono" title={current.image_digest}>
            {shortDigest(current.image_digest)}
          </dd>
          <dt>Size</dt>
          <dd>
            {current.image_size === undefined
              ? "not recorded yet"
              : formatBytes(current.image_size)}
          </dd>
          <dt>Created</dt>
          <dd>
            {current.image_created === undefined
              ? "not recorded yet"
              : formatDate(current.image_created)}
          </dd>
          <dt>Scanned</dt>
          <dd>{formatDate(current.scanned_at)}</dd>
          {#each list as scan (scan.sk)}
            <dt>{scannerName(scan.scanner)}</dt>
            <dd>
              v{scan.scanner_version}, DB {formatDate(scan.scanner_db)}
            </dd>
          {/each}
        </dl>
      </article>

      <div class="grid scanners">
        {#each list as scan (scan.sk)}
          <article class="card">
            <div class="card-head">
              <h2>{scannerName(scan.scanner)}</h2>
              <span class="total">{scan.cve_total}</span>
            </div>
            <SeverityCounts counts={counts(scan)} bar />
            {#if scan.cve_fixable !== undefined}
              <p class="muted small">
                {scan.cve_fixable} with a fix available
              </p>
            {/if}
          </article>
        {/each}
      </div>

      {#await history then { perScanner }}
        <article class="card">
          <div class="card-head">
            <h2>CVEs over time</h2>
            <span class="muted">last {range} days - click a day</span>
          </div>
          <StackedBars
            title="{vendor} CVEs by severity"
            height={280}
            selected={day(list[0].scanned_at)}
            onselect={showDay}
            series={imageScans.map((scan, i) => ({
              name: scannerName(scan.scanner),
              points: perScanner[i].map((d) => ({
                label: d.scanned_at,
                values: counts(d),
                notes: [
                  `digest ${shortDigest(d.image_digest)}`,
                  `size ${formatBytes(d.image_size)}`,
                ],
              })),
            }))}
          />
        </article>
      {:catch error}
        <p class="error">Error: {message(error)}</p>
      {/await}

      {#await details}
        <p class="status" role="status">Loading CVEs ...</p>
      {:then data}
    <article class="card">
      <div class="card-head">
        <h2>Vulnerabilities</h2>
        <span class="muted">
          {[
            `${data.overlap.all} found by all scanners`,
            ...Object.entries(data.overlap.only).map(
              ([name, count]) => `${count} only by ${scannerName(name)}`,
            ),
            `${data.overlap.severityDiffers} with different severities`,
          ].join(" · ")} ·
          <a href={href("scanners", group)}>compare scanners</a>
        </span>
      </div>
      <CveTable
        rows={data.rows}
        scanners={list.map((s) => s.scanner)}
        latest={data.at}
      />
    </article>

    <article class="card">
      <div class="card-head">
        <h2>Removed CVEs</h2>
        <span class="muted">CVEs which were in the image and were gone by this scan</span>
      </div>
      {#if data.removed.length}
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>CVE</th>
                <th>Severity</th>
                <th>Package</th>
                <th>Scanner</th>
                <th>First detected</th>
                <th>Fix available</th>
                <th>Removed</th>
                <th class="num">Days in image</th>
                <th class="num">Days from fix</th>
              </tr>
            </thead>
            <tbody>
              {#each data.removed as item (`${item.scanner}#${item.sk}`)}
                <tr>
                  <td class="mono">{item.cve_id}</td>
                  <td
                    ><span class="badge sev-{severityOf(item.severity)}"
                      >{severityOf(item.severity)}</span
                    ></td
                  >
                  <td>{item.package_name}</td>
                  <td>{scannerName(item.scanner)}</td>
                  <td>{formatDate(item.first_seen)}</td>
                  <td>{formatDate(item.fix_seen)}</td>
                  <td>{formatDate(item.removed_at)}</td>
                  <td class="num"
                    >{daysBetween(item.first_seen, item.removed_at!)}</td
                  >
                  <td class="num"
                    >{item.fix_seen
                      ? daysBetween(item.fix_seen, item.removed_at!)
                      : "-"}</td
                  >
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {:else}
        <p class="muted">
          No CVE was removed since the CVE tracking started.
        </p>
      {/if}
    </article>
      {:catch error}
        <p class="error" role="status">Error: {message(error)}</p>
      {/await}
    {/if}
  {:catch error}
    <p class="error" role="status">Error: {message(error)}</p>
  {/await}
</section>

<style>
  .pickers {
    display: grid;
    gap: 0.5rem;
  }

  .days {
    display: flex;
    gap: 0.5rem;
    align-items: center;
    flex-wrap: wrap;
  }


  .head {
    display: flex;
    justify-content: space-between;
    gap: 2rem;
    flex-wrap: wrap;
  }

  .crumbs {
    margin: 0;
  }

  h1 {
    font-size: 1.35rem;
    word-break: break-all;
  }

  .head p {
    margin: 0.25rem 0;
  }

  .pull {
    display: flex;
    gap: 0.5rem;
    align-items: center;
    margin-top: 0.75rem;
  }

  .pull code {
    background: #0a0d13;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.3rem 0.7rem;
  }

  .meta {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.2rem 1.25rem;
    margin: 0;
    align-content: start;
  }

  .meta dt {
    color: var(--muted);
  }

  .meta dd {
    margin: 0;
  }

  .scanners {
    grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
  }

  .total {
    font-size: 1.5rem;
    font-weight: 600;
  }

  .small {
    font-size: 0.8rem;
    margin: 0.5rem 0 0;
  }

  .badge {
    text-transform: capitalize;
  }
</style>
