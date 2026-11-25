<script lang="ts">
  import {
    SEVERITIES,
    day,
    formatDate,
    formatDay,
    niceTicks,
    type Counts,
  } from "../lib/data";

  interface Point {
    // ISO time of the scan
    label: string;
    values: Counts;
    // Extra tooltip lines (e.g. image digest)
    notes?: string[];
  }

  // One bar per series (scanner) and day, side by side
  interface Series {
    name: string;
    points: Point[];
  }

  let {
    series,
    max,
    height = 220,
    title = "CVEs by severity",
    selected,
    onselect,
  }: {
    series: Series[];
    max?: number;
    height?: number;
    title?: string;
    // Highlighted day (YYYY-MM-DD)
    selected?: string;
    // Called with the clicked day (YYYY-MM-DD)
    onselect?: (day: string) => void;
  } = $props();

  const PAD = { top: 10, right: 8, bottom: 24, left: 40 };
  const GAP = 3;
  let width = $state(0);
  let hover = $state<number>();

  const total = (values: Counts) =>
    SEVERITIES.reduce((sum, severity) => sum + values[severity], 0);
  // Days of all series, oldest first
  let days = $derived(
    [...new Set(series.flatMap((s) => s.points.map((p) => day(p.label))))].sort(),
  );
  // Point of every series on every day (undefined: no scan that day)
  let grid = $derived(
    days.map((d) =>
      series.map((s) => s.points.find((p) => day(p.label) === d)),
    ),
  );
  let w = $derived(Math.max(width, 240));
  let ticks = $derived(
    niceTicks(
      max ??
        Math.max(
          1,
          ...series.flatMap((s) => s.points.map((p) => total(p.values))),
        ),
    ),
  );
  let top = $derived(ticks[ticks.length - 1]);
  let plotW = $derived(w - PAD.left - PAD.right);
  let plotH = $derived(height - PAD.top - PAD.bottom);
  let slot = $derived(plotW / Math.max(days.length, 1));
  let barW = $derived(
    Math.max(
      2,
      Math.min(26, (slot * 0.75) / series.length - GAP),
    ),
  );
  let groupW = $derived(series.length * (barW + GAP) - GAP);
  // Label every n-th day so the labels do not overlap
  let every = $derived(
    Math.ceil(days.length / Math.max(1, Math.floor(plotW / 56))),
  );
  const y = (value: number) => PAD.top + plotH - (value / top) * plotH;
  const x = (dayIndex: number, seriesIndex: number) =>
    PAD.left +
    dayIndex * slot +
    (slot - groupW) / 2 +
    seriesIndex * (barW + GAP);

  // Bottom-up segments of one bar: critical on top like the severity order
  function segments(values: Counts) {
    let start = 0;
    return [...SEVERITIES].reverse().map((severity) => {
      const segment = { severity, start, end: start + values[severity] };
      start = segment.end;
      return segment;
    });
  }

  function onpointermove(event: PointerEvent) {
    const index = Math.floor((event.offsetX - PAD.left) / slot);
    hover = index >= 0 && index < days.length ? index : undefined;
  }

  let latest = $derived(grid[grid.length - 1] ?? []);
</script>

<div class="chart" bind:clientWidth={width}>
  <div class="legend">
    {#if series.length > 1}
      <span class="order">Bars: {series.map((s) => s.name).join(" | ")}</span>
    {/if}
    {#each SEVERITIES as severity (severity)}
      <span class="severity"
        ><i style:background="var(--{severity})"></i>{severity}</span
      >
    {/each}
  </div>
  {#if days.length}
    <!-- Clicking a bar is a mouse shortcut, the pages offer the days as links / select too -->
    <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_noninteractive_element_interactions -->
    <svg
      width={w}
      {height}
      role="img"
      aria-label="{title}: {days.length} days, latest {series
        .map((s, i) => `${s.name} ${latest[i] ? total(latest[i].values) : '-'}`)
        .join(', ')} CVEs"
      class:clickable={onselect}
      {onpointermove}
      onpointerleave={() => (hover = undefined)}
      onclick={() => hover !== undefined && onselect?.(days[hover])}
    >
      {#each ticks as tick (tick)}
        <line
          class="grid-line"
          x1={PAD.left}
          x2={w - PAD.right}
          y1={y(tick)}
          y2={y(tick)}
        />
        <text class="axis" x={PAD.left - 6} y={y(tick) + 4} text-anchor="end"
          >{tick}</text
        >
      {/each}
      {#each days as d, i (d)}
        {#if hover === i || d === selected}
          <rect
            class={d === selected ? "selected" : "hover"}
            x={PAD.left + i * slot}
            y={PAD.top}
            width={slot}
            height={plotH}
          />
        {/if}
        {#each grid[i] as point, j (series[j].name)}
          {#if point}
            {#each segments(point.values) as segment (segment.severity)}
              {#if segment.end > segment.start}
                <rect
                  x={x(i, j)}
                  y={y(segment.end)}
                  width={barW}
                  height={y(segment.start) - y(segment.end)}
                  fill="var(--{segment.severity})"
                />
              {/if}
            {/each}
            {#if series.length > 1 && barW >= 10}
              <text
                class="bar-name"
                x={x(i, j) + barW / 2}
                y={y(total(point.values)) - 4}
                text-anchor="middle">{series[j].name[0]}</text
              >
            {/if}
          {/if}
        {/each}
        {#if i % every === 0}
          <text
            class="axis"
            x={PAD.left + i * slot + slot / 2}
            y={height - 6}
            text-anchor="middle">{formatDay(d)}</text
          >
        {/if}
      {/each}
    </svg>
    {#if hover !== undefined}
      {@const points = grid[hover]}
      <div
        class="tooltip"
        style:left="{PAD.left + hover * slot + slot / 2}px"
        class:flip={hover > days.length / 2}
      >
        <table>
          <thead>
            <tr>
              <th>{formatDate(days[hover])}</th>
              {#each series as s (s.name)}
                <th class="num">{s.name}</th>
              {/each}
            </tr>
          </thead>
          <tbody>
            {#each SEVERITIES as severity (severity)}
              <tr>
                <td
                  ><i style:background="var(--{severity})"></i>{severity}</td
                >
                {#each points as point, j (series[j].name)}
                  <td class="num">{point ? point.values[severity] : "-"}</td>
                {/each}
              </tr>
            {/each}
            <tr class="total">
              <td>Total</td>
              {#each points as point, j (series[j].name)}
                <td class="num">{point ? total(point.values) : "-"}</td>
              {/each}
            </tr>
          </tbody>
        </table>
        {#each points.find((p) => p)?.notes ?? [] as note (note)}
          <div class="note">{note}</div>
        {/each}
        {#if onselect}
          <div class="note">click to show this day</div>
        {/if}
      </div>
    {/if}
  {:else}
    <p class="muted empty">No scans in this time range yet.</p>
  {/if}
</div>

<style>
  .legend {
    justify-content: flex-end;
  }

  .order {
    margin-right: auto;
  }

  .severity {
    text-transform: capitalize;
  }

  .bar-name {
    fill: var(--muted);
    font-size: 9px;
  }

  .hover {
    fill: rgb(255 255 255 / 6%);
  }

  .selected {
    fill: rgb(167 139 250 / 18%);
  }

  .clickable {
    cursor: pointer;
  }

  .tooltip {
    min-width: 190px;
  }

  table {
    width: auto;
  }

  th,
  td {
    padding: 0.1rem 0 0.1rem 1.2rem;
    border: 0;
    white-space: nowrap;
  }

  th:first-child,
  td:first-child {
    padding-left: 0;
    text-transform: capitalize;
  }

  th {
    color: var(--text);
    font-size: 0.85rem;
    letter-spacing: 0;
    text-transform: none;
  }

  .total td {
    border-top: 1px solid var(--border);
    font-weight: 600;
  }

  .note {
    color: var(--muted);
    font-family: var(--mono);
    font-size: 0.75rem;
    margin-top: 0.25rem;
  }

</style>
