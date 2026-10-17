<script lang="ts">
  import type { Snippet } from 'svelte';

  /** One fact about an agent's request, inside the consent form's description list. */
  let { label, children }: { label: string; children: Snippet } = $props();
</script>

<dt class="text-muted">{label}</dt>
<dd class="min-w-0 break-words text-fg">{@render children()}</dd>
