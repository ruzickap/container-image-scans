<script lang="ts">
  import { href, type Tab } from "../lib/data";

  let { groups, group, tab }: { groups: string[]; group: string; tab: Tab } =
    $props();
</script>

<nav class="chips" aria-label="Image groups">
  {#each groups as name (name)}
    <a
      class="chip"
      href={href(tab, name)}
      aria-current={name === group ? "page" : undefined}>{name}</a
    >
  {/each}
</nav>
