<script lang="ts">
  import { formatDate, formatDay, niceTicks } from "../lib/data";

  interface Series {
    name: string;
    color: string;
    // stroke-dasharray, e.g. "5 4" (default: solid)
    dash?: string;
    // x: ISO date
    points: { x: string; y: number }[];
  }

  let {
    series,
    height = 240,
    title = "CVEs over time",
  }: { series: Series[]; height?: number; title?: string } = $props();

  const PAD = { top: 10, right: 12, bottom: 24, left: 40 };
  let width = $state(0);
  let hover = $state<number>();

  let xs = $derived(
    [...new Set(series.flatMap((s) => s.points.map((p) => p.x)))].sort(),
  );
  let ticks = $derived(
    niceTicks(Math.max(1, ...series.flatMap((s) => s.points.map((p) => p.y)))),
  );
  let w = $derived(Math.max(width, 240));
  let plotW = $derived(w - PAD.left - PAD.right);
  let plotH = $derived(height - PAD.top - PAD.bottom);
  let step = $derived(plotW / Math.max(xs.length - 1, 1));
  let every = $derived(
    Math.ceil(xs.length / Math.max(1, Math.floor(plotW / 56))),
  );
  const px = (x: string) =>
    PAD.left + (xs.length > 1 ? xs.indexOf(x) * step : plotW / 2);
  const py = (value: number) =>
    PAD.top + plotH - (value / ticks[ticks.length - 1]) * plotH;

  function onpointermove(event: PointerEvent) {
    const index = Math.round((event.offsetX - PAD.left) / step);
    hover = xs.length && index >= 0 && index < xs.length ? index : undefined;
  }
</script>

<div class="chart" bind:clientWidth={width}>
  <div class="legend">
    {#each series as s (s.name)}
      <span
        ><svg width="18" height="8" aria-hidden="true"
          ><line
            x1="0"
            x2="18"
            y1="4"
            y2="4"
            stroke={s.color}
            stroke-width="2"
            stroke-dasharray={s.dash}
          /></svg
        >{s.name}</span
      >
    {/each}
  </div>
  {#if xs.length}
    <svg
      width={w}
      {height}
      role="img"
      aria-label="{title}: {series.length} series, {xs.length} days"
      {onpointermove}
      onpointerleave={() => (hover = undefined)}
    >
      {#each ticks as tick (tick)}
        <line
          class="grid-line"
          x1={PAD.left}
          x2={w - PAD.right}
          y1={py(tick)}
          y2={py(tick)}
        />
        <text class="axis" x={PAD.left - 6} y={py(tick) + 4} text-anchor="end"
          >{tick}</text
        >
      {/each}
      {#each xs as x, i (x)}
        {#if i % every === 0}
          <text class="axis" x={px(x)} y={height - 6} text-anchor="middle"
            >{formatDay(x)}</text
          >
        {/if}
      {/each}
      {#if hover !== undefined}
        <line
          class="cursor"
          x1={px(xs[hover])}
          x2={px(xs[hover])}
          y1={PAD.top}
          y2={PAD.top + plotH}
        />
      {/if}
      {#each series as s (s.name)}
        <polyline
          fill="none"
          stroke={s.color}
          stroke-width="2"
          stroke-dasharray={s.dash}
          points={s.points.map((p) => `${px(p.x)},${py(p.y)}`).join(" ")}
        />
        {#each s.points as p (p.x)}
          <circle cx={px(p.x)} cy={py(p.y)} r="2.5" fill={s.color} />
        {/each}
      {/each}
    </svg>
    {#if hover !== undefined}
      {@const x = xs[hover]}
      <div
        class="tooltip"
        style:left="{px(x)}px"
        class:flip={hover > xs.length / 2}
      >
        <strong>{formatDate(x)}</strong>
        {#each series as s (s.name)}
          {@const point = s.points.find((p) => p.x === x)}
          <div class="row">
            <span><i style:background={s.color}></i>{s.name}</span>
            <b>{point ? point.y : "-"}</b>
          </div>
        {/each}
      </div>
    {/if}
  {:else}
    <p class="muted empty">No scans in this time range yet.</p>
  {/if}
</div>

<style>
  .legend svg {
    display: inline;
    margin-right: 0.35rem;
  }

  .cursor {
    stroke: rgb(255 255 255 / 25%);
  }

  .row {
    display: flex;
    justify-content: space-between;
    gap: 1.5rem;
  }

</style>
