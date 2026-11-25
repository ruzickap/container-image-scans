<script lang="ts">
  import {
    byImage,
    color,
    counts,
    daily,
    day,
    daysAgo,
    fixStats,
    formatBytes,
    formatDate,
    href,
    message,
    shortDigest,
    withLatest,
      scannerName,
  } from "../lib/data";
  import {
    load,
    type History,
    type Lifecycle,
    type Scan,
  } from "../lib/dynamodb";
  import GroupChips from "./GroupChips.svelte";
  import ImageLink from "./ImageLink.svelte";
  import LineChart from "./LineChart.svelte";
  import SeverityCounts from "./SeverityCounts.svelte";
  import StackedBars from "./StackedBars.svelte";

  let {
    scans,
    group,
    groups,
    range,
  }: {
    scans: Scan[];
    group: string;
    groups: string[];
    range: number;
  } = $props();

  // Line style of every scanner: solid, dashed, dotted
  const DASHES = [undefined, "6 4", "2 3"];

  let groupScans = $derived(scans.filter((s) => s.group === group));
  // Images of the group with the latest scan of every scanner, fewest CVEs first
  let images = $derived(byImage(groupScans));
  let scanners = $derived([...new Set(scans.map((s) => s.scanner))].sort());
  let from = $derived(daysAgo(range));
  let history = $derived(
    load<History>(`HISTORY#${group}`, [from, "~"]).then((items) =>
      withLatest(items, groupScans, from),
    ),
  );
  let lifecycles = $derived(
    Promise.all(
      groupScans.map((s) => load<Lifecycle>(`LIFECYCLE#${s.sk}`)),
    ).then((lists) => new Map(groupScans.map((s, i) => [s.sk, lists[i]]))),
  );

  // Daily scans of one image by one scanner
  const days = (items: History[], scan: Scan) =>
    daily(
      items.filter(
        (h) => h.vendor === scan.vendor && h.scanner === scan.scanner,
      ),
    );
  const fmt = (days?: number) => (days === undefined ? "-" : `${days} d`);
</script>

<section class="stack">
  <div class="page-head">
    <div>
      <h1>{group}</h1>
      <p class="muted">
        {groupScans[0]?.group_description} - compare the images by {scanners.map(scannerName).join(
          " and ",
        )} over the last {range} days
      </p>
    </div>
    <GroupChips {groups} {group} tab="compare" />
  </div>

  {#await history}
    <p class="status" role="status">Loading history ...</p>
  {:then items}
    {@const max = Math.max(
      1,
      ...groupScans.flatMap((scan) => days(items, scan).map((d) => d.cve_total)),
    )}
    <article class="card">
      <div class="card-head">
        <h2>Total CVEs per image</h2>
        <span class="muted">
          {#each scanners as scanner, i (scanner)}
            {i ? " · " : ""}{["solid", "dashed", "dotted"][i]} = {scannerName(scanner)}
          {/each}
        </span>
      </div>
      <LineChart
        height={340}
        title="Total CVEs per image"
        series={images.flatMap((image, i) =>
          image.scans.map((scan) => ({
            name: `${image.vendor} · ${scannerName(scan.scanner)}`,
            color: color(i),
            dash: DASHES[scanners.indexOf(scan.scanner)],
            points: days(items, scan).map((d) => ({
              x: day(d.scanned_at),
              y: d.cve_total,
            })),
          })),
        )}
      />
    </article>

    <article class="card">
      <div class="card-head">
        <h2>Latest scan</h2>
        <span class="muted">Δ = change of the total in {range} days</span>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Image</th>
              <th>Scanner</th>
              <th>Severity</th>
              <th class="num">Total</th>
              <th class="num">Fixable</th>
              <th class="num">Δ</th>
              <th>Scanned</th>
            </tr>
          </thead>
          <tbody>
            {#each images as image, i (image.vendor)}
              {#each image.scans as scan, j (scan.sk)}
                {@const list = days(items, scan)}
                {@const delta = list.length
                  ? scan.cve_total - list[0].cve_total
                  : 0}
                <tr class:first={j === 0}>
                  {#if j === 0}
                    <td rowspan={image.scans.length}>
                      <a href={href("image", group, image.vendor)}>
                        <i class="dot" style:background={color(i)}></i>{image.vendor}</a
                      >
                      <div class="mono muted"><ImageLink image={scan.image} /></div>
                      <div class="muted small">
                        {formatBytes(scan.image_size)} · created {formatDate(
                          scan.image_created,
                        )} ·
                        <span class="mono" title={scan.image_digest}
                          >{shortDigest(scan.image_digest)}</span
                        >
                      </div>
                    </td>
                  {/if}
                  <td>{scannerName(scan.scanner)}</td>
                  <td><SeverityCounts counts={counts(scan)} /></td>
                  <td class="num"><b>{scan.cve_total}</b></td>
                  <td class="num">{scan.cve_fixable ?? "-"}</td>
                  <td
                    class="num"
                    class:delta-up={delta > 0}
                    class:delta-down={delta < 0}
                    >{delta > 0 ? "+" : ""}{delta}</td
                  >
                  <td>{formatDate(scan.scanned_at)}</td>
                </tr>
              {/each}
            {/each}
          </tbody>
        </table>
      </div>
    </article>

    <div class="grid charts">
      {#each images as image, i (image.vendor)}
        <article class="card">
          <div class="card-head">
            <h3>
              <i class="dot" style:background={color(i)}></i>
              <a href={href("image", group, image.vendor)}>{image.vendor}</a>
            </h3>
            <span class="mono muted"><ImageLink image={image.scans[0].image} /></span>
          </div>
          <StackedBars
            title="{image.vendor} CVEs by severity"
            {max}
            height={260}
            series={image.scans.map((scan) => ({
              name: scannerName(scan.scanner),
              points: days(items, scan).map((d) => ({
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
      {/each}
    </div>
  {:catch error}
    <p class="error" role="status">Error: {message(error)}</p>
  {/await}

  <article class="card">
    <div class="card-head">
      <h2>How fast are CVEs fixed?</h2>
      <span class="muted">Medians since the CVE tracking started</span>
    </div>
    {#await lifecycles}
      <p class="status">Loading CVE lifecycles ...</p>
    {:then all}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Image</th>
              <th>Scanner</th>
              <th class="num">CVEs removed</th>
              <th class="num">Days in image</th>
              <th class="num">Days from fix to image</th>
              <th class="num">Open with fix</th>
              <th class="num">Longest wait</th>
            </tr>
          </thead>
          <tbody>
            {#each images as image (image.vendor)}
              {#each image.scans as scan, j (scan.sk)}
                {@const stats = fixStats(all.get(scan.sk) ?? [], scan.scanned_at)}
                <tr class:first={j === 0}>
                  {#if j === 0}
                    <td rowspan={image.scans.length}
                      ><a href={href("image", group, image.vendor)}
                        >{image.vendor}</a
                      ></td
                    >
                  {/if}
                  <td>{scannerName(scan.scanner)}</td>
                  <td class="num">{stats.removed}</td>
                  <td class="num">{fmt(stats.daysInImage)}</td>
                  <td class="num">{fmt(stats.daysToFix)}</td>
                  <td class="num">{stats.openFixable}</td>
                  <td class="num">{fmt(stats.longestWait)}</td>
                </tr>
              {/each}
            {/each}
          </tbody>
        </table>
      </div>
      <p class="muted note">
        "Fix" = the first scan which reported a fixed version of the package
        (the fix is available upstream / in the distribution). "Days from fix
        to image" = until the vendor shipped an image without the CVE.
      </p>
    {:catch error}
      <p class="error">Error: {message(error)}</p>
    {/await}
  </article>
</section>

<style>
  .dot {
    display: inline-block;
    width: 0.55rem;
    height: 0.55rem;
    border-radius: 50%;
    margin-right: 0.4rem;
  }

  .card-head .mono {
    font-size: 0.75rem;
  }

  td .mono {
    font-size: 0.75rem;
  }

  .charts {
    grid-template-columns: repeat(auto-fill, minmax(min(100%, 560px), 1fr));
  }

  .small {
    font-size: 0.75rem;
  }

  /* Scanner rows of one image share the image cell - a line only between images */
  tbody td {
    border-bottom: 0;
  }

  tbody tr.first td {
    border-top: 1px solid var(--border);
  }

  .note {
    font-size: 0.8rem;
    margin: 0.75rem 0 0;
  }
</style>
