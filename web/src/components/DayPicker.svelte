<script lang="ts">
  import { formatDate } from "../lib/data";

  // ← day → navigation over the days with scans
  let {
    days,
    selected,
    link,
  }: {
    // Days with scans (YYYY-MM-DD), newest first
    days: string[];
    selected: string;
    // URL (hash) of a day
    link: (day: string) => string;
  } = $props();

  let index = $derived(days.indexOf(selected));
</script>

<div class="day">
  <a
    class="chip"
    class:disabled={index < 0 || index >= days.length - 1}
    href={link(days[index + 1] ?? selected)}
    aria-label="Previous day">←</a
  >
  <select
    aria-label="Day"
    value={selected}
    onchange={(event) => (location.hash = link(event.currentTarget.value))}
  >
    {#if index < 0}
      <option value={selected}>{formatDate(selected)} (no scans)</option>
    {/if}
    {#each days as value, i (value)}
      <option {value}>{formatDate(value)}{i ? "" : " (latest)"}</option>
    {/each}
  </select>
  <a
    class="chip"
    class:disabled={index <= 0}
    href={link(days[index - 1] ?? selected)}
    aria-label="Next day">→</a
  >
</div>

<style>
  .day {
    display: flex;
    gap: 0.5rem;
    align-items: center;
  }

  .disabled {
    pointer-events: none;
    opacity: 0.35;
  }
</style>
