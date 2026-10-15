<script lang="ts">
  import { dismissBanner, visibleBanner, type BannerTone } from '../../lib/stores/settings.svelte';
  import Icon from '../Icon.svelte';

  /** The announcement set in the admin console; dismissible for the browser session. */
  let { class: className = '' }: { class?: string } = $props();

  const banner = $derived(visibleBanner());

  const tones: Record<BannerTone, { box: string; icon: string; iconColor: string }> = {
    info: { box: 'border-border bg-bg-deep', icon: 'info', iconColor: 'text-muted' },
    warning: { box: 'border-warning/25 bg-warning/5', icon: 'alert-triangle', iconColor: 'text-warning' },
    danger: { box: 'border-danger/25 bg-danger/5', icon: 'alert-circle', iconColor: 'text-danger' },
  };
</script>

{#if banner}
  <div class="flex items-start gap-3 border-b px-4 py-2.5 text-[13px] leading-relaxed text-fg sm:px-6 lg:px-8 {tones[banner.tone].box} {className}" role="status">
    <span class="mt-0.5 shrink-0 {tones[banner.tone].iconColor}"><Icon name={tones[banner.tone].icon} size={15} /></span>
    <p class="min-w-0 flex-1 break-words">{banner.message}</p>
    <button type="button" class="-mr-1 shrink-0 rounded p-1 text-dim transition-colors hover:text-fg" aria-label="Dismiss announcement" onclick={dismissBanner}>
      <Icon name="x" size={14} />
    </button>
  </div>
{/if}
