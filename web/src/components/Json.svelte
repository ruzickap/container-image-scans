<script lang="ts">
  import { jsonTokens } from "../lib/data";

  let { value }: { value: unknown } = $props();

  let tokens = $derived(jsonTokens(value));
</script>

<pre class="json"><code
    >{#each tokens as token}<span class={token.kind}>{token.text}</span
      >{/each}</code
  ></pre>

<style>
  .json {
    margin: 0;
    max-height: 480px;
    overflow: auto;
    background: #0a0d13;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.75rem 1rem;
    font-family: var(--mono);
    font-size: 0.8rem;
    line-height: 1.55;
  }

  .key {
    color: #7dd3fc;
  }

  .string {
    color: #a5e3a0;
  }

  .number {
    color: #fbbf77;
  }

  .literal {
    color: #c4a5fd;
  }

  .punct {
    color: var(--muted);
  }
</style>
