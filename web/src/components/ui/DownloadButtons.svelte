<script lang="ts">
  import { onMount } from 'svelte';
  import Button from './Button.svelte';
  import { titleCase } from '../../lib/format';
  import { currentDownloads, type PublicDownload } from '../../lib/downloads';

  /** Fetches the public installer links and renders one button per platform. */
  let { size = 'xs', variant = 'outline' }: { size?: 'xs' | 'sm' | 'md'; variant?: 'outline' | 'secondary' | 'primary' } = $props();

  const labels: Record<string, string> = { windows: 'Windows', macos: 'macOS', linux: 'Linux', android: 'Android', ios: 'iOS' };
  const icons: Record<string, string> = { windows: 'windows', macos: 'apple', linux: 'linux', android: 'android', ios: 'smartphone' };

  let links = $state<PublicDownload[]>([]);
  let error = $state('');

  onMount(() => {
    const controller = new AbortController();
    currentDownloads(controller.signal)
      .then((data) => {
        const first = new Map<string, PublicDownload>();
        for (const d of [...data].sort((a, b) => a.sort_order - b.sort_order)) if (!first.has(d.platform)) first.set(d.platform, d);
        links = [...first.values()];
      })
      .catch((cause) => { if (!controller.signal.aborted) error = String(cause); });
    return () => controller.abort();
  });
</script>

{#if error}<span class="text-xs text-danger" role="alert">Downloads unavailable: {error}</span>{/if}
{#each links as dl (dl.id)}
  <Button {variant} {size} icon={icons[dl.platform] ?? 'download'} href={dl.url} external>{labels[dl.platform] ?? titleCase(dl.platform)}</Button>
{/each}
