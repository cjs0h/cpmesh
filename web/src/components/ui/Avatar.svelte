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
  // Deterministic hue per user so avatars stay distinguishable in lists.
  const hue = $derived.by(() => {
    const s = name ?? '';
    let h = 0;
    for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) % 360;
    return h;
  });
</script>

{#if src && !failed}
  <img
    {src}
    alt={name ?? ''}
    class="shrink-0 rounded-full object-cover ring-1 ring-white/10 {className}"
    style="width: {size}px; height: {size}px;"
    onerror={() => (failed = true)}
  />
{:else}
  <span
    class="inline-flex shrink-0 items-center justify-center rounded-full font-bold uppercase text-white ring-1 ring-white/10 select-none {className}"
    style="width: {size}px; height: {size}px; font-size: {Math.max(10, Math.round(size * 0.36))}px; background: linear-gradient(135deg, hsl({hue} 70% 55%), hsl({(hue + 40) % 360} 65% 40%));"
    aria-label={name ?? undefined}
  >
    {label}
  </span>
{/if}
