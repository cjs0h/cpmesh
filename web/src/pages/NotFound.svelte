<script lang="ts">
  import Button from '../components/ui/Button.svelte';
  import Icon from '../components/Icon.svelte';
</script>

<div class="relative mx-auto flex max-w-lg flex-col items-center py-16 text-center">
  <div class="dot-grid pointer-events-none absolute inset-0 opacity-40 [mask-image:radial-gradient(ellipse_at_center,black,transparent_70%)]"></div>
  <div class="relative">
    <p class="font-mono text-[11px] uppercase tracking-[0.3em] text-dim">error 404</p>
    <h2 class="text-gradient mt-3 font-display text-[clamp(3rem,10vw,5.5rem)] font-bold leading-none tracking-tight">Lost in the mesh</h2>
    <p class="mt-4 text-sm leading-relaxed text-muted">That page was never pasted here. It might have been removed, or the link is encrypted with a key we don't have.</p>
    <div class="mt-8 flex flex-wrap items-center justify-center gap-3">
      <Button href="#/" icon="dashboard">Back to overview</Button>
      <Button href="#/clipboard" variant="outline" icon="history">Clipboard history</Button>
    </div>
    <p class="mt-10 inline-flex items-center gap-1.5 text-[12px] text-dim"><Icon name="lock" size={11} /> Still end-to-end encrypted, even when lost.</p>
  </div>
</div>
