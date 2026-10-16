<script lang="ts">
  import type { DailyCount } from '../../lib/stores/admin.svelte';

  /** Daily counts as a small bar chart: inline SVG, a tooltip per day and a spoken summary. */
  interface Props {
    series: DailyCount[];
    /** Plural noun for what is counted, e.g. "signups". */
    unit: string;
    class?: string;
  }

  let { series, unit, class: className = '' }: Props = $props();

  const WIDTH = 300;
  const HEIGHT = 64;

  const max = $derived(series.reduce((m, p) => Math.max(m, p.count), 0));
  const total = $derived(series.reduce((sum, p) => sum + p.count, 0));
  const peak = $derived(series.reduce<DailyCount | null>((best, p) => (!best || p.count > best.count ? p : best), null));
  const slot = $derived(WIDTH / Math.max(1, series.length));
  const bar = $derived(Math.max(1, slot * 0.7));

  function dayLabel(day: string): string {
    const date = new Date(`${day}T00:00:00`);
    return Number.isNaN(date.getTime()) ? day : date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  }

  const summary = $derived(
    series.length === 0
      ? `No ${unit} recorded`
      : `${total.toLocaleString()} ${unit} from ${dayLabel(series[0].day)} to ${dayLabel(series[series.length - 1].day)}` +
          (peak && peak.count > 0 ? `; most on ${dayLabel(peak.day)} with ${peak.count.toLocaleString()}` : ''),
  );
</script>

<figure class={className}>
  {#if series.length === 0}
    <p class="flex h-16 items-center justify-center rounded-md border border-dashed border-border text-xs text-dim">No data yet</p>
  {:else}
    <svg viewBox="0 0 {WIDTH} {HEIGHT}" preserveAspectRatio="none" class="block h-16 w-full" role="img" aria-label={summary}>
      {#each series as point, i (point.day)}
        {@const height = max > 0 && point.count > 0 ? Math.max((point.count / max) * HEIGHT, 2) : 0}
        {@const x = i * slot + (slot - bar) / 2}
        <g class="group">
          <title>{dayLabel(point.day)}: {point.count.toLocaleString()} {unit}</title>
          <rect x={i * slot} y="0" width={slot} height={HEIGHT} fill="transparent" />
          <rect {x} y={HEIGHT - 1} width={bar} height="1" class="fill-border" />
          {#if height > 0}
            <rect {x} y={HEIGHT - height} width={bar} {height} class="fill-ink transition-[fill] duration-150 group-hover:fill-accent" />
          {/if}
        </g>
      {/each}
    </svg>
    <figcaption class="mt-2 flex justify-between text-[11px] text-dim">
      <span>{dayLabel(series[0].day)}</span>
      <span>{dayLabel(series[series.length - 1].day)}</span>
    </figcaption>
  {/if}
</figure>
