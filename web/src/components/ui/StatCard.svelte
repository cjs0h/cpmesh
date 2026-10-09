<script lang="ts">
  import Icon from '../Icon.svelte';
  import NumberTicker from '../magic/NumberTicker.svelte';

  type Accent = 'accent' | 'cyan' | 'mint' | 'gold' | 'rose' | 'violet';

  interface Props {
    label: string;
    value: string | number;
    icon: string;
    accent?: Accent;
    caption?: string;
    /** Draw a bar chart from these values (0–1). */
    trend?: number[];
    delay?: number;
    class?: string;
  }

  let { label, value, icon, accent = 'accent', caption, trend, delay = 0, class: className = '' }: Props = $props();

  const fills: Record<Accent, string> = {
    accent: 'bg-accent',
    cyan: 'bg-cyan',
    mint: 'bg-mint',
    gold: 'bg-yellow',
    rose: 'bg-rose',
    violet: 'bg-violet',
  };
  const shadows: Record<Accent, string> = {
    accent: 'var(--color-accent)',
    cyan: 'var(--color-cyan)',
    mint: 'var(--color-mint)',
    gold: 'var(--color-yellow)',
    rose: 'var(--color-rose)',
    violet: 'var(--color-violet)',
  };

  const numeric = $derived(typeof value === 'number' ? value : Number.isFinite(Number(value)) && /^\d+(\.\d+)?$/.test(String(value)) ? Number(value) : null);
</script>

<div
  class="panel panel-hover group relative overflow-hidden p-5 animate-[fade-up_0.5s_var(--ease-out-expo)_both] {className}"
  style="animation-delay: {delay}ms; --panel-shadow: {shadows[accent]};"
>
  <div class="relative flex items-start justify-between gap-3">
    <div class="min-w-0">
      <p class="font-head text-[11px] uppercase tracking-[0.1em] text-muted">{label}</p>
      <p class="mt-2 font-head text-[32px] leading-none text-ink tabular-nums">
        {#if numeric !== null}
          <NumberTicker value={numeric} />
        {:else}
          {value}
        {/if}
      </p>
      {#if caption}<p class="mt-2 text-[12px] text-dim">{caption}</p>{/if}
    </div>
    <div class="flex h-11 w-11 shrink-0 items-center justify-center rounded-md border-2 border-ink text-ink shadow-xs {fills[accent]}">
      <Icon name={icon} size={20} strokeWidth={2.3} />
    </div>
  </div>

  {#if trend && trend.length > 0}
    <div class="relative mt-4 flex h-9 items-end gap-[3px] border-b-2 border-ink pb-px" aria-hidden="true">
      {#each trend as v, i (i)}
        <span class="flex-1 rounded-t-sm border-2 border-b-0 border-ink {fills[accent]}" style="height: {Math.max(10, Math.min(100, v * 100))}%; opacity: {0.45 + (i / trend.length) * 0.55};"></span>
      {/each}
    </div>
  {/if}
</div>
