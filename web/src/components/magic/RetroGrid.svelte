<script lang="ts">
  /**
   * MagicUI Retro Grid, CSS edition: a perspective-tilted grid plane scrolling
   * toward the viewer, faded into the page background at the horizon.
   */
  let {
    angle = 65,
    cellSize = 60,
    opacity = 0.5,
    lineColor = 'rgba(17,17,17,0.35)',
    fadeTo = 'var(--color-bg)',
    class: className = '',
  }: { angle?: number; cellSize?: number; opacity?: number; lineColor?: string; fadeTo?: string; class?: string } = $props();
</script>

<div
  class="pointer-events-none absolute inset-0 overflow-hidden [perspective:200px] {className}"
  style="opacity: {opacity}; --grid-angle: {angle}deg; --cell-size: {cellSize}px; --line: {lineColor};"
  aria-hidden="true"
>
  <div class="absolute inset-0 [transform:rotateX(var(--grid-angle))]">
    <div
      class="animate-retro-grid absolute inset-[0%_0px] -ml-[200%] h-[300vh] w-[600vw] origin-[100%_0_0] [background-image:linear-gradient(to_right,var(--line)_1px,transparent_0),linear-gradient(to_bottom,var(--line)_1px,transparent_0)] [background-repeat:repeat] [background-size:var(--cell-size)_var(--cell-size)]"
    ></div>
  </div>
  <div class="absolute inset-0" style="background: linear-gradient(to top, {fadeTo} 0%, transparent 90%);"></div>
</div>
