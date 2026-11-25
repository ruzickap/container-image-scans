<script lang="ts">
  import {
    byImage,
    counts,
    formatBytes,
    formatDate,
    href,
    shortDigest,
      scannerName,
  } from "../lib/data";
  import type { Scan } from "../lib/dynamodb";
  import ImagePopup from "./ImagePopup.svelte";
  import ImageLink from "./ImageLink.svelte";
  import SeverityCounts from "./SeverityCounts.svelte";

  let { scans }: { scans: Scan[] } = $props();

  let scanners = $derived([...new Set(scans.map((s) => s.scanner))].sort());
  // Groups with their images, fewest CVEs (average of the scanners) first
  let groups = $derived(
    [...new Set(scans.map((s) => s.group))].map((group) => {
      const items = scans.filter((s) => s.group === group);
      return {
        group,
        description: items[0].group_description,
        images: byImage(items),
      };
    }),
  );
  let images = $derived(byImage(scans));
  // Image (group#vendor) with the open popup - opens after a short hover, so
  // moving the mouse over the page does not flash a popup for every row
  let popup = $state<string>();
  // Popup next to the card (right if there is room, else left, else below),
  // in the lower half of the window aligned to the bottom of the row
  let side = $state<"right" | "left" | "below">("right");
  let up = $state(false);
  let timer: ReturnType<typeof setTimeout> | undefined;
  function open(key: string, row: Element) {
    clearTimeout(timer);
    timer = setTimeout(() => {
      const card = row.closest(".card")!.getBoundingClientRect();
      const width = 460;
      side =
        card.right + width < innerWidth
          ? "right"
          : card.left - width > 0
            ? "left"
            : "below";
      up = row.getBoundingClientRect().top > innerHeight / 2;
      popup = key;
    }, 250);
  }
  // Click on an image row opens the image - not after selecting text in it
  function go(event: MouseEvent, url: string) {
    if (
      !getSelection()?.toString() &&
      !(event.target as Element).closest("a")
    ) {
      location.hash = url;
    }
  }
  function close() {
    clearTimeout(timer);
    popup = undefined;
  }

  const sum = (scanner: string, value: (s: Scan) => number) =>
    scans
      .filter((s) => s.scanner === scanner)
      .reduce((total, s) => total + value(s), 0);
</script>

<section class="stack">
  <div class="hero">
    <div>
      <h1>Which container image has the fewest vulnerabilities?</h1>
      <p class="muted">
        Images of the same purpose from different vendors, scanned every night
        by {scanners.map(scannerName).join(" and ")}. Select an image for its CVEs and history.
      </p>
    </div>
    <dl class="kpis">
      <div><dt>Images</dt><dd>{images.length}</dd></div>
      <div>
        <dt>CVE-free</dt>
        <dd class="good">
          {images.filter((i) => i.scans.every((s) => !s.cve_total)).length}
        </dd>
      </div>
      {#each scanners as scanner (scanner)}
        <div>
          <dt>{scannerName(scanner)} CVEs</dt>
          <dd>
            {sum(scanner, (s) => s.cve_total)}
            <small class="sev-critical"
              >{sum(scanner, (s) => s.cve_critical)} critical</small
            >
          </dd>
        </div>
      {/each}
    </dl>
  </div>

  <div class="grid">
    {#each groups as g (g.group)}
      <article class="card">
        <div class="card-head">
          <div>
            <h2>{g.group}</h2>
            <span class="muted">{g.description}</span>
          </div>
          <a class="chip" href={href("compare", g.group)}>Compare</a>
        </div>
        <ul>
          {#each g.images as image (image.vendor)}
            {@const first = image.scans[0]}
            {@const key = `${g.group}#${image.vendor}`}
            <li>
              <!-- A box, not a link: its texts stay selectable. The vendor link is the keyboard way in -->
              <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
              <div
                class="row"
                class:active={popup === key}
                onpointerenter={(event) => open(key, event.currentTarget)}
                onpointerleave={close}
                onclick={(event) =>
                  go(event, href("image", g.group, image.vendor))}
              >
                <span class="image">
                  <span class="vendor">
                    <a
                      href={href("image", g.group, image.vendor)}
                      aria-describedby={popup === key
                        ? `popup-${key}`
                        : undefined}
                      onfocus={(event) =>
                        open(key, event.currentTarget.closest(".row")!)}
                      onblur={close}>{image.vendor}</a
                    >
                    {#if image.average === g.images[0].average && g.images.some((i) => i.average > image.average)}
                      <span class="badge best">fewest CVEs</span>
                    {/if}
                  </span>
                  <span class="mono muted ref"><ImageLink image={first.image} /></span>
                  <span class="meta muted">
                    {#if first.image_size}
                      {formatBytes(first.image_size)} · created {formatDate(
                        first.image_created,
                      )} ·
                    {/if}
                    <span class="mono">{shortDigest(first.image_digest)}</span>
                  </span>
                </span>
                <span class="scans">
                  {#each image.scans as scan (scan.sk)}
                    <span class="numbers">
                      <span class="scanner muted">{scannerName(scan.scanner)}</span>
                      <SeverityCounts counts={counts(scan)} bar />
                      <span class="total">{scan.cve_total}</span>
                      <span
                        class="fix"
                        title="CVEs with a fix available"
                        class:none={!scan.cve_fixable}
                        >{scan.cve_fixable === undefined
                          ? ""
                          : `${scan.cve_fixable} fix`}</span
                      >
                    </span>
                  {/each}
                </span>
              </div>
              {#if popup === key}
                <ImagePopup scans={image.scans} id="popup-{key}" {side} {up} />
              {/if}
            </li>
          {/each}
        </ul>
      </article>
    {/each}
  </div>
</section>

<style>
  .hero {
    display: flex;
    justify-content: space-between;
    align-items: end;
    gap: 2rem;
    flex-wrap: wrap;
    margin-bottom: 0.5rem;
  }

  h1 {
    font-size: 1.6rem;
  }

  .hero p {
    max-width: 640px;
    margin: 0.4rem 0 0;
  }

  .kpis {
    display: flex;
    gap: 2rem;
    margin: 0;
  }

  dt {
    color: var(--muted);
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  dd {
    margin: 0;
    font-size: 1.6rem;
    font-weight: 600;
  }

  dd small {
    display: block;
    font-size: 0.75rem;
    font-weight: 500;
  }

  .good {
    color: var(--good);
  }

  h2 {
    font-size: 1.15rem;
  }

  ul {
    list-style: none;
    margin: 0;
    padding: 0;
  }

  li {
    position: relative;
    border-top: 1px solid var(--border);
  }

  .row {
    display: grid;
    gap: 0.4rem;
    padding: 0.6rem 0.5rem;
    margin: 0 -0.5rem;
    border-radius: 10px;
    color: var(--text);
    border: 1px solid transparent;
    transition:
      background 0.15s,
      border-color 0.15s;
  }

  .row {
    cursor: pointer;
  }

  .row:hover,
  .row:focus-within,
  .row.active {
    background: rgb(167 139 250 / 9%);
    border-color: rgb(167 139 250 / 45%);
  }

  .vendor a {
    color: var(--text);
  }

  .row:hover .vendor a,
  .row.active .vendor a {
    color: var(--accent);
  }

  .image {
    display: grid;
    min-width: 0;
  }

  .vendor {
    font-weight: 600;
  }

  .best {
    color: var(--good);
    margin-left: 0.4rem;
  }

  .ref,
  .meta {
    font-size: 0.75rem;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .scans {
    display: grid;
    gap: 0.4rem;
  }

  .numbers {
    display: grid;
    grid-template-columns: 3rem 1fr auto 3.2rem;
    gap: 0.6rem;
    align-items: center;
  }

  .scanner {
    font-size: 0.75rem;
  }

  .total {
    font-size: 1.05rem;
    font-weight: 600;
    min-width: 2.5rem;
    text-align: right;
    font-variant-numeric: tabular-nums;
  }

  .fix {
    color: var(--good);
    font-size: 0.75rem;
    font-weight: 600;
    text-align: right;
  }

  .fix.none {
    color: var(--muted);
    font-weight: 400;
  }

</style>
