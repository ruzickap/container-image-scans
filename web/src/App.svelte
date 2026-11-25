<script lang="ts">
  import CompareView from "./components/CompareView.svelte";
  import ImageView from "./components/ImageView.svelte";
  import Overview from "./components/Overview.svelte";
  import RawView from "./components/RawView.svelte";
  import ScannersView from "./components/ScannersView.svelte";
  import { day, formatDate, href, message, parseRoute } from "./lib/data";
  import { load, type Scan } from "./lib/dynamodb";

  const TABS = [
    { id: "overview", label: "Overview" },
    { id: "compare", label: "Compare" },
    { id: "image", label: "Image" },
    { id: "scanners", label: "Scanners" },
    { id: "raw", label: "Raw data" },
  ] as const;
  // shortcut: max. 90 days - a year of HISTORY#<group> is ~350 reads of the
  // 2 per second of the table, add monthly summary items before longer ranges
  const RANGES = [7, 30, 90];

  let route = $state(parseRoute(location.hash));
  let scans = $state.raw<Scan[]>([]);
  let status = $state("Loading ...");
  let range = $state(30);

  let groups = $derived([...new Set(scans.map((s) => s.group))]);
  let group = $derived(
    route.group && groups.includes(route.group) ? route.group : groups[0],
  );
  let vendor = $derived(
    scans.find((s) => s.group === group && s.vendor === route.vendor)?.vendor ??
      scans.find((s) => s.group === group)?.vendor,
  );
  // Changes only with the day - a new route object alone reloads nothing
  let routeDay = $derived(route.day);
  let lastScan = $derived(
    scans.reduce((a, s) => (s.scanned_at > a ? s.scanned_at : a), ""),
  );

  load<Scan>("LATEST")
    .then((items) => {
      scans = [...items].sort(
        (a, b) =>
          a.group.localeCompare(b.group) ||
          a.vendor.localeCompare(b.vendor) ||
          a.scanner.localeCompare(b.scanner),
      );
      status = items.length ? "" : "No scans yet.";
    })
    .catch((error: unknown) => (status = `Error: ${message(error)}`));
</script>

<svelte:window onhashchange={() => (route = parseRoute(location.hash))} />

<header>
  <div class="bar">
    <a class="brand" href="#/overview">
      <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true">
        <path
          d="M12 2 3 6.5v5c0 5 3.8 9.4 9 10.5 5.2-1.1 9-5.5 9-10.5v-5L12 2Z"
          fill="none"
          stroke="currentColor"
          stroke-width="1.8"
        />
        <path
          d="m8.5 12 2.5 2.5 4.5-5"
          fill="none"
          stroke="currentColor"
          stroke-width="1.8"
        />
      </svg>
      <span>Container Image Scans</span>
    </a>
    <nav aria-label="Views">
      {#each TABS as tab (tab.id)}
        <a
          href={tab.id === "raw"
            ? href("raw")
            : href(tab.id, group, tab.id === "image" ? vendor : undefined)}
          aria-current={route.tab === tab.id ? "page" : undefined}
          >{tab.label}</a
        >
      {/each}
    </nav>
    <div class="controls">
      <label>
        Range
        <select bind:value={range}>
          {#each RANGES as days (days)}
            <option value={days}>{days} days</option>
          {/each}
        </select>
      </label>
    </div>
  </div>
</header>

<main>
  {#if status}
    <p role="status" class={status.startsWith("Error") ? "error" : "status"}>
      {status}
    </p>
  {:else if route.tab === "compare" && group}
    <CompareView {scans} {group} {groups} {range} />
  {:else if route.tab === "image" && group && vendor}
    <ImageView {scans} {group} {groups} {vendor} day={routeDay} {range} />
  {:else if route.tab === "scanners" && group}
    <ScannersView {scans} {group} {groups} {range} />
  {:else if route.tab === "raw"}
    <RawView {scans} {groups} day={routeDay ?? day(lastScan)} />
  {:else}
    <Overview {scans} />
  {/if}
</main>

<footer class="muted">
  Latest scan: {formatDate(lastScan)}.
  <a href="https://github.com/ruzickap/container-image-scans">Source</a>
</footer>

<style>
  header {
    position: sticky;
    top: 0;
    z-index: 10;
    backdrop-filter: blur(12px);
    background: rgb(11 14 20 / 75%);
    border-bottom: 1px solid var(--border);
  }

  .bar {
    max-width: 1400px;
    margin: 0 auto;
    padding: 0.6rem 1.5rem;
    display: flex;
    align-items: center;
    gap: 1.5rem;
    flex-wrap: wrap;
  }

  .brand {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    color: var(--text);
    font-weight: 600;
    font-size: 1rem;
  }

  .brand svg {
    color: var(--accent);
  }

  nav {
    display: flex;
    gap: 0.25rem;
    flex-wrap: wrap;
  }

  nav a {
    color: var(--muted);
    padding: 0.35rem 0.75rem;
    border-radius: 8px;
  }

  nav a:hover {
    color: var(--text);
    text-decoration: none;
    background: rgb(255 255 255 / 4%);
  }

  nav a[aria-current="page"] {
    color: var(--text);
    background: rgb(167 139 250 / 15%);
  }

  .controls {
    margin-left: auto;
    display: flex;
    gap: 0.75rem;
    color: var(--muted);
    font-size: 0.85rem;
  }

  main {
    max-width: 1400px;
    margin: 0 auto;
    padding: 1.5rem;
  }

  footer {
    max-width: 1400px;
    margin: 0 auto;
    padding: 1rem 1.5rem 2rem;
    font-size: 0.8rem;
  }
</style>
