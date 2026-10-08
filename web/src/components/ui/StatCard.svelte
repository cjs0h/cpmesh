<script lang="ts">
  import Icon from '../Icon.svelte';

  type Accent = 'accent' | 'cyan' | 'mint' | 'gold' | 'rose' | 'violet';

  interface Props {
    label: string;
    value: string | number;
    icon: string;
    accent?: Accent;
    caption?: string;
    /** Draw a subtle sparkline-ish bar chart from these values (0–1). */
    trend?: number[];
    delay?: number;
    class?: string;
  }

  let { label, value, icon, accent = 'accent', caption, trend, delay = 0, class: className = '' }: Props = $props();

  const palette: Record<Accent, { tile: string; glow: string; bar: string; text: string }> = {
    accent: { tile: 'bg-accent/12 border-accent/25 text-accent', glow: 'rgba(255,122,89,0.18)', bar: 'bg-accent/60', text: 'text-accent' },
    cyan: { tile: 'bg-cyan/12 border-cyan/25 text-cyan', glow: 'rgba(73,198,229,0.18)', bar: 'bg-cyan/60', text: 'text-cyan' },
    mint: { tile: 'bg-mint/12 border-mint/25 text-mint', glow: 'rgba(42,214,160,0.18)', bar: 'bg-mint/60', text: 'text-mint' },
    gold: { tile: 'bg-gold/12 border-gold/25 text-gold', glow: 'rgba(244,201,93,0.18)', bar: 'bg-gold/60', text: 'text-gold' },
    rose: { tile: 'bg-rose/12 border-rose/25 text-rose', glow: 'rgba(248,113,113,0.18)', bar: 'bg-rose/60', text: 'text-rose' },
    violet: { tile: 'bg-violet/12 border-violet/25 text-violet', glow: 'rgba(167,139,250,0.18)', bar: 'bg-violet/60', text: 'text-violet' },
  };
</script>

<div
  class="group relative overflow-hidden rounded-xl border border-border bg-surface p-5 shadow-card transition-[border-color,box-shadow,transform] duration-300 hover:-translate-y-0.5 hover:border-border-strong hover:shadow-pop animate-[fade-up_0.5s_var(--ease-out-expo)_both] {className}"
  style="animation-delay: {delay}ms;"
>
  <div
    class="pointer-events-none absolute -right-10 -top-10 h-32 w-32 rounded-full opacity-70 blur-2xl transition-opacity duration-300 group-hover:opacity-100"
    style="background: radial-gradient(circle, {palette[accent].glow}, transparent 70%);"
  ></div>

  <div class="relative flex items-start justify-between gap-3">
    <div class="min-w-0">
      <p class="text-[13px] font-medium text-muted">{label}</p>
      <p class="mt-1.5 font-display text-[30px] font-semibold leading-none tracking-tight text-fg tabular-nums">{value}</p>
      {#if caption}<p class="mt-2 text-[12px] text-dim">{caption}</p>{/if}
    </div>
    <div class="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border {palette[accent].tile}">
      <Icon name={icon} size={20} />
    </div>
  </div>

  {#if trend && trend.length > 0}
    <div class="relative mt-4 flex h-8 items-end gap-[3px]" aria-hidden="true">
      {#each trend as v, i (i)}
        <span class="flex-1 rounded-sm {palette[accent].bar}" style="height: {Math.max(8, Math.min(100, v * 100))}%; opacity: {0.35 + (i / trend.length) * 0.65};"></span>
      {/each}
    </div>
  {/if}
</div>
