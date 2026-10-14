<script lang="ts">
  import { initials } from '../../lib/format';

  interface Props {
    name?: string | null;
    src?: string | null;
    size?: number;
    class?: string;
  }

  let { name, src, size = 32, class: className = '' }: Props = $props();

  let failed = $state(false);
  const label = $derived(initials(name));
</script>

{#if src && !failed}
  <img {src} alt={name ?? ''} class="shrink-0 rounded-full border border-border object-cover {className}" style="width: {size}px; height: {size}px;" onerror={() => (failed = true)} />
{:else}
  <span
    class="inline-flex shrink-0 items-center justify-center rounded-full bg-ink font-medium uppercase text-white select-none {className}"
    style="width: {size}px; height: {size}px; font-size: {Math.max(10, Math.round(size * 0.36))}px;"
    aria-label={name ?? undefined}
  >
    {label}
  </span>
{/if}
