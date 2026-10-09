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
  // Deterministic flat fill per user so avatars stay distinguishable in lists.
  const fills = ['#ffd93d', '#ff7a59', '#5ad1f0', '#3ddc97', '#b39dff', '#ff9ec4'];
  const fill = $derived.by(() => {
    const s = name ?? '';
    let h = 0;
    for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
    return fills[h % fills.length];
  });
</script>

{#if src && !failed}
  <img {src} alt={name ?? ''} class="shrink-0 rounded-md border-2 border-ink object-cover shadow-xs {className}" style="width: {size}px; height: {size}px;" onerror={() => (failed = true)} />
{:else}
  <span
    class="inline-flex shrink-0 items-center justify-center rounded-md border-2 border-ink font-head uppercase text-ink shadow-xs select-none {className}"
    style="width: {size}px; height: {size}px; font-size: {Math.max(10, Math.round(size * 0.34))}px; background: {fill};"
    aria-label={name ?? undefined}
  >
    {label}
  </span>
{/if}
