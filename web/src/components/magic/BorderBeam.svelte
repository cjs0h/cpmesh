<script lang="ts">
  /**
   * MagicUI Border Beam: a short gradient streak that travels along the inside
   * of the parent's border. The parent needs `position: relative` and a radius;
   * the beam follows it via `offset-path: rect(... round r)`.
   */
  let {
    size = 60,
    duration = 6,
    delay = 0,
    colorFrom = '#ffd93d',
    colorTo = '#ff7a59',
    borderWidth = 2,
    reverse = false,
    class: className = '',
  }: { size?: number; duration?: number; delay?: number; colorFrom?: string; colorTo?: string; borderWidth?: number; reverse?: boolean; class?: string } = $props();
</script>

<div
  class="pointer-events-none absolute inset-0 rounded-[inherit] border-transparent [mask-clip:padding-box,border-box] [mask-composite:intersect] [mask-image:linear-gradient(transparent,transparent),linear-gradient(#000,#000)] {className}"
  style="border-width: {borderWidth}px; border-style: solid;"
  aria-hidden="true"
>
  <div
    class="animate-border-beam absolute aspect-square"
    style="width: {size}px; offset-path: rect(0 auto auto 0 round {size}px); offset-distance: 0%; background: linear-gradient(to left, {colorFrom}, {colorTo}, transparent); --beam-duration: {duration}s; animation-delay: {-delay}s; animation-direction: {reverse ? 'reverse' : 'normal'};"
  ></div>
</div>
