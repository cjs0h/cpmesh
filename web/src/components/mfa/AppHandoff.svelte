<script lang="ts">
  import Button from '../ui/Button.svelte';
  import IconTile from '../ui/IconTile.svelte';

  /** Shown once a sign-in was handed to the desktop app ("Sign in with browser"). */
  let { url }: { url: string } = $props();
</script>

<div class="flex flex-col items-center gap-4 py-2 text-center">
  <IconTile icon="check" size={44} />
  <div>
    <h2 class="text-base font-semibold text-fg">You can return to the cpmesh app</h2>
    <p class="mt-1 text-[13px] leading-relaxed text-muted">
      Your sign-in was sent to the app. If it didn't open, use the button below; the link works once, for a minute.
    </p>
  </div>
  <Button href={url} variant="secondary" icon="external-link">Open the cpmesh app</Button>
  <p class="text-xs text-dim">You can close this tab.</p>
</div>
