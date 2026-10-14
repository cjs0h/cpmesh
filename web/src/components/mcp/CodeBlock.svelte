<script lang="ts">
  import CopyButton from '../ui/CopyButton.svelte';

  /** Titled, copyable code snippet used by the MCP guide. */
  let { title, code, lang = 'bash' }: { title: string; code: string; lang?: string } = $props();

  const prompt = $derived(lang === 'bash');
</script>

<div class="overflow-hidden rounded-lg border border-border bg-surface">
  <div class="flex items-center justify-between gap-3 border-b border-border bg-bg-deep px-4 py-2">
    <span class="truncate font-mono text-xs text-muted">{title}</span>
    <CopyButton text={code} label="Copy {title}" />
  </div>
  <pre class="overflow-x-auto px-4 py-3 font-mono text-[13px] leading-6 text-fg"><code>{#if prompt}<span class="select-none text-dim">$ </span>{/if}{code}</code></pre>
</div>
