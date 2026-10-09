<script lang="ts">
  import Button from '../components/ui/Button.svelte';
  import Icon from '../components/Icon.svelte';
</script>

<div class="mx-auto flex max-w-lg flex-col items-center py-16 text-center">
  <p class="font-mono text-xs text-muted">Error 404</p>
  <h2 class="mt-3 text-[clamp(2rem,6vw,3.25rem)] font-semibold leading-none tracking-[-0.03em] text-fg">Page not found</h2>
  <p class="mt-4 text-sm leading-relaxed text-muted">That page was never pasted here. It might have been removed, or the link is encrypted with a key we don't have.</p>
  <div class="mt-8 flex flex-wrap items-center justify-center gap-3">
    <Button href="#/" icon="dashboard">Back to overview</Button>
    <Button href="#/clipboard" variant="secondary" icon="history">Clipboard history</Button>
  </div>
  <p class="mt-10 inline-flex items-center gap-1.5 text-xs text-dim"><Icon name="lock" size={11} /> Still end-to-end encrypted, even when lost.</p>
</div>
