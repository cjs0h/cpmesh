<script lang="ts">
  import { onMount } from 'svelte';
  import { userState } from '../../lib/stores/user.svelte';
  import { adminState, fetchAdminReleases, adminCreateRelease, adminUpdateRelease, adminDeleteRelease, type AppRelease } from '../../lib/stores/admin.svelte';
  import { toast } from '../../lib/stores/toast.svelte';
  import { push } from 'svelte-spa-router';
  import { createClock } from '../../lib/clock.svelte';
  import { absoluteTime, relativeTime, titleCase } from '../../lib/format';
  import Icon from '../../components/Icon.svelte';
  import Badge from '../../components/ui/Badge.svelte';
  import Button from '../../components/ui/Button.svelte';
  import Card from '../../components/ui/Card.svelte';
  import ConfirmAction from '../../components/ui/ConfirmAction.svelte';
  import Dialog from '../../components/ui/Dialog.svelte';
  import Field from '../../components/ui/Field.svelte';
  import Select from '../../components/ui/Select.svelte';
  import Switch from '../../components/ui/Switch.svelte';
  import EmptyState from '../../components/ui/EmptyState.svelte';
  import Alert from '../../components/ui/Alert.svelte';
  import IconTile from '../../components/ui/IconTile.svelte';
  import CopyButton from '../../components/ui/CopyButton.svelte';

  const clock = createClock();
  let dialogOpen = $state(false);
  let editing = $state<AppRelease | null>(null);
  let error = $state('');
  let saving = $state(false);

  let formVersion = $state('');
  let formPlatform = $state('darwin');
  let formArch = $state('arm64');
  let formDownloadUrl = $state('');
  let formReleaseNotes = $state('');
  let formIsCurrent = $state(true);

  const platformIcons: Record<string, string> = { darwin: 'apple', macos: 'apple', windows: 'windows', linux: 'linux', android: 'android', ios: 'smartphone' };
  const platformLabels: Record<string, string> = { darwin: 'macOS', macos: 'macOS', windows: 'Windows', linux: 'Linux', android: 'Android', ios: 'iOS' };

  onMount(() => {
    if (!userState.isAdmin) {
      push('/');
      return;
    }
    fetchAdminReleases();
  });

  const current = $derived(adminState.releases.filter((r) => r.is_current));
  const sorted = $derived([...adminState.releases].sort((a, b) => Number(b.is_current) - Number(a.is_current) || b.created_at.localeCompare(a.created_at)));

  function startCreate() {
    editing = null;
    formVersion = '';
    formPlatform = 'darwin';
    formArch = 'arm64';
    formDownloadUrl = '';
    formReleaseNotes = '';
    formIsCurrent = true;
    error = '';
    dialogOpen = true;
  }

  function startEdit(release: AppRelease) {
    editing = release;
    formVersion = release.version;
    formPlatform = release.platform;
    formArch = release.arch;
    formDownloadUrl = release.download_url;
    formReleaseNotes = release.release_notes;
    formIsCurrent = release.is_current;
    error = '';
    dialogOpen = true;
  }

  async function handleSave(e: Event) {
    e.preventDefault();
    error = '';
    saving = true;
    const data = {
      version: formVersion.trim(),
      platform: formPlatform,
      arch: formArch,
      download_url: formDownloadUrl.trim(),
      release_notes: formReleaseNotes,
      is_current: formIsCurrent,
    };
    try {
      if (editing) {
        await adminUpdateRelease(editing.id, data);
        toast.success('Release updated', `v${data.version} for ${platformLabels[data.platform] ?? data.platform}`);
      } else {
        await adminCreateRelease(data);
        toast.success('Release published', data.is_current ? 'Clients will see this version on their next update check.' : undefined);
      }
      dialogOpen = false;
    } catch (err: any) {
      error = err.message;
    } finally {
      saving = false;
    }
  }

  async function handleDelete(release: AppRelease) {
    try {
      await adminDeleteRelease(release.id);
      toast.success('Release deleted', `v${release.version} (${release.platform}/${release.arch || 'any'})`);
    } catch (err: any) {
      toast.error('Could not delete release', err.message);
    }
  }
</script>

<div class="mb-5 flex flex-wrap items-center justify-between gap-3">
  <div class="flex flex-wrap items-center gap-2">
    <Badge tone="neutral">{adminState.releases.length} releases</Badge>
    <Badge tone="mint" icon="check">{current.length} current</Badge>
  </div>
  <Button icon="plus" size="sm" onclick={startCreate}>New release</Button>
</div>

{#if current.length > 0}
  <div class="mb-5 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
    {#each current as rel (rel.id)}
      <div class="flex items-center gap-3 rounded-xl border border-mint/25 bg-mint/[0.06] px-3.5 py-3">
        <IconTile icon={platformIcons[rel.platform] ?? 'package'} tone="mint" size={34} />
        <div class="min-w-0">
          <p class="truncate text-[12px] text-muted">{platformLabels[rel.platform] ?? titleCase(rel.platform)} · {rel.arch || 'any'}</p>
          <p class="font-mono text-sm font-semibold text-fg">v{rel.version}</p>
        </div>
      </div>
    {/each}
  </div>
{/if}

<Card padded={false}>
  {#if sorted.length === 0}
    <div class="p-5">
      <EmptyState icon="rocket" title="No releases yet" description="Publish a release per platform/architecture and mark it current to enable in-app auto-updates." compact>
        <Button icon="plus" size="sm" onclick={startCreate}>Publish the first release</Button>
      </EmptyState>
    </div>
  {:else}
    <div class="overflow-x-auto">
      <table class="tbl min-w-[880px]">
        <thead>
          <tr>
            <th>Version</th>
            <th>Platform</th>
            <th>Download URL</th>
            <th>Notes</th>
            <th>Status</th>
            <th>Published</th>
            <th class="text-right"><span class="sr-only">Actions</span></th>
          </tr>
        </thead>
        <tbody>
          {#each sorted as release (release.id)}
            <tr class={release.is_current ? '' : 'opacity-70'}>
              <td><span class="font-mono text-[13px] font-semibold text-fg">v{release.version}</span></td>
              <td>
                <span class="inline-flex items-center gap-2 text-muted">
                  <Icon name={platformIcons[release.platform] ?? 'package'} size={14} />
                  {platformLabels[release.platform] ?? titleCase(release.platform)}
                  <span class="font-mono text-[11.5px] text-dim">{release.arch || 'any'}</span>
                </span>
              </td>
              <td>
                <span class="inline-flex max-w-[260px] items-center gap-1">
                  <a href={release.download_url} target="_blank" rel="noopener" class="truncate font-mono text-[12px] text-accent hover:underline" title={release.download_url}>{release.download_url}</a>
                  <CopyButton text={release.download_url} label="Copy URL" size={12} />
                </span>
              </td>
              <td class="max-w-[220px]"><p class="truncate text-[12.5px] text-muted" title={release.release_notes}>{release.release_notes || '—'}</p></td>
              <td>{#if release.is_current}<Badge tone="mint" dot>Current</Badge>{:else}<Badge tone="neutral">Superseded</Badge>{/if}</td>
              <td class="text-muted"><time datetime={release.created_at} title={absoluteTime(release.created_at)}>{relativeTime(release.created_at, clock.now)}</time></td>
              <td class="text-right">
                <span class="inline-flex items-center gap-1">
                  <Button variant="ghost" size="icon-sm" icon="edit" aria-label="Edit release" onclick={() => startEdit(release)} />
                  <ConfirmAction size="icon-sm" variant="ghost" label="Delete release" confirmLabel="Delete" prompt="Delete?" onconfirm={() => handleDelete(release)} />
                </span>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</Card>

<Dialog bind:open={dialogOpen} title={editing ? `Edit v${editing.version}` : 'New release'} description="Mark one release per platform/architecture as current for auto-update." size="lg">
  <form id="release-form" class="grid grid-cols-1 gap-4 sm:grid-cols-2" onsubmit={handleSave}>
    {#if error}<div class="sm:col-span-2"><Alert tone="danger">{error}</Alert></div>{/if}
    <Field label="Version" bind:value={formVersion} required placeholder="0.2.0" icon="tag" />
    <div class="grid grid-cols-2 gap-3">
      <Select label="Platform" bind:value={formPlatform}>
        <option value="darwin">macOS</option>
        <option value="windows">Windows</option>
        <option value="linux">Linux</option>
        <option value="android">Android</option>
        <option value="ios">iOS</option>
      </Select>
      <Select label="Arch" bind:value={formArch}>
        <option value="arm64">arm64</option>
        <option value="amd64">amd64</option>
        <option value="">Any</option>
      </Select>
    </div>
    <Field label="Download URL" bind:value={formDownloadUrl} required icon="link" placeholder="/api/downloads/cpmesh-0.2.0-darwin-arm64.dmg" class="sm:col-span-2" />
    <div class="flex flex-col gap-1.5 sm:col-span-2">
      <label for="release-notes" class="text-[13px] font-medium text-muted">Release notes</label>
      <textarea
        id="release-notes"
        bind:value={formReleaseNotes}
        rows="4"
        placeholder="What's new in this version…"
        class="w-full resize-y rounded-md border border-border bg-surface-2 px-3.5 py-2.5 text-sm text-fg outline-none transition-[border-color,box-shadow] placeholder:text-dim hover:border-border-strong focus:border-accent focus:shadow-[0_0_0_3px_rgba(255,122,89,0.18)]"
      ></textarea>
    </div>
    <div class="sm:col-span-2">
      <Switch bind:checked={formIsCurrent} label="Current release" description="Advertise this version to clients checking for updates." />
    </div>
  </form>
  {#snippet footer()}
    <Button variant="ghost" onclick={() => (dialogOpen = false)}>Cancel</Button>
    <Button type="submit" form="release-form" loading={saving}>{editing ? 'Save changes' : 'Publish release'}</Button>
  {/snippet}
</Dialog>
