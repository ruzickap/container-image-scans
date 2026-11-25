<script lang="ts">
  import { registryUrl } from "../lib/data";

  // Image reference linked to its registry page (when the registry is known)
  let { image }: { image: string } = $props();

  let url = $derived(registryUrl(image));
</script>

{#if url}
  <a
    href={url}
    target="_blank"
    rel="noopener noreferrer"
    title="Open in the registry">{image}</a
  >
{:else}
  {image}
{/if}

<style>
  a {
    color: inherit;
  }

  a:hover {
    color: var(--accent);
    text-decoration: underline;
  }
</style>
