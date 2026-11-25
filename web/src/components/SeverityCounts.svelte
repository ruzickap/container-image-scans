<script lang="ts">
  import { SEVERITIES, type Counts } from "../lib/data";

  let { counts, bar = false }: { counts: Counts; bar?: boolean } = $props();

  let total = $derived(SEVERITIES.reduce((sum, s) => sum + counts[s], 0));
</script>

<div class="severity">
  {#if bar}
    <div
      class="bar"
      role="img"
      aria-label="{total} CVEs: {SEVERITIES.map((s) => `${counts[s]} ${s}`).join(
        ', ',
      )}"
    >
      {#each SEVERITIES as severity (severity)}
        {#if counts[severity]}
          <span
            style:flex-grow={counts[severity]}
            style:background="var(--{severity})"
          ></span>
        {/if}
      {/each}
    </div>
  {/if}
  <div class="pills">
    {#each SEVERITIES as severity (severity)}
      <span
        class="pill sev-{severity}"
        class:zero={!counts[severity]}
        title={severity}
        >{severity[0].toUpperCase()}<b>{counts[severity]}</b></span
      >
    {/each}
  </div>
</div>

<style>
  .severity {
    display: grid;
    gap: 0.35rem;
  }

  .bar {
    display: flex;
    height: 6px;
    border-radius: 3px;
    overflow: hidden;
    background: var(--border);
  }

  .pills {
    display: flex;
    gap: 0.3rem;
    flex-wrap: wrap;
  }

  .pill {
    display: inline-flex;
    gap: 0.3rem;
    align-items: baseline;
    font-size: 0.75rem;
    border-radius: 6px;
    padding: 0 0.4rem;
    background: rgb(255 255 255 / 4%);
    font-variant-numeric: tabular-nums;
  }

  .pill b {
    color: var(--text);
    font-weight: 600;
  }

  .zero {
    opacity: 0.4;
  }
</style>
