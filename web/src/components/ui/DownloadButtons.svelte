<script lang="ts">
  import Button from './Button.svelte';
  import { titleCase } from '../../lib/format';

  /** Fetches the public installer links and renders one button per platform. */
  let { size = 'xs', variant = 'outline' }: { size?: 'xs' | 'sm' | 'md'; variant?: 'outline' | 'secondary' | 'primary' } = $props();

  interface DownloadLink {
    id: string;
    url: string;
    platform: string;
    sort_order: number;
  }

  const labels: Record<string, string> = { windows: 'Windows', macos: 'macOS', linux: 'Linux', android: 'Android', ios: 'iOS' };
  const icons: Record<string, string> = { windows: 'windows', macos: 'apple', linux: 'linux', android: 'android', ios: 'smartphone' };

  let links = $state<DownloadLink[]>([]);

  $effect(() => {
    fetch('/api/downloads/current')
      .then((r) => (r.ok ? r.json() : []))
      .then((data: DownloadLink[]) => {
        const first = new Map<string, DownloadLink>();
        for (const d of [...data].sort((a, b) => a.sort_order - b.sort_order)) if (!first.has(d.platform)) first.set(d.platform, d);
        links = [...first.values()];
      })
      .catch(() => {});
  });
</script>

{#each links as dl (dl.id)}
  <Button {variant} {size} icon={icons[dl.platform] ?? 'download'} href={dl.url} external>{labels[dl.platform] ?? titleCase(dl.platform)}</Button>
{/each}
