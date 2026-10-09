<script lang="ts">
  import { onMount } from 'svelte';
  import { userState } from '../../lib/stores/user.svelte';
  import {
    adminState,
    fetchAdminDownloads,
    fetchAdminReleases,
    adminCreateDownload,
    adminUpdateDownload,
    adminDeleteDownload,
    adminUploadBinary,
    type DownloadLink,
  } from '../../lib/stores/admin.svelte';
  import { toast } from '../../lib/stores/toast.svelte';
  import { push } from 'svelte-spa-router';
  import { formatBytes, titleCase } from '../../lib/format';
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

  let dialogOpen = $state(false);
  let editing = $state<DownloadLink | null>(null);
  let error = $state('');
  let saving = $state(false);
  let uploading = $state(false);
  let dragging = $state(false);

  let formName = $state('');
  let formUrl = $state('');
  let formPlatform = $state('windows');
  let formArch = $state('amd64');
  let formFormat = $state('exe');
  let formSortOrder = $state<number | null>(0);
  let formIsActive = $state(true);
  let formReleaseId = $state('');

  const platformIcons: Record<string, string> = { windows: 'windows', macos: 'apple', linux: 'linux', android: 'android', ios: 'smartphone' };
  const platformLabels: Record<string, string> = { windows: 'Windows', macos: 'macOS', linux: 'Linux', android: 'Android', ios: 'iOS' };
  const ACCEPT = '.exe,.msi,.dmg,.pkg,.deb,.rpm,.appimage,.apk,.aab,.ipa,.tar.gz,.zip';

  onMount(() => {
    if (!userState.isAdmin) {
      push('/');
      return;
    }
    fetchAdminDownloads();
    fetchAdminReleases();
  });

  const sorted = $derived([...adminState.downloads].sort((a, b) => a.platform.localeCompare(b.platform) || a.sort_order - b.sort_order));

  function startCreate() {
    editing = null;
    formName = '';
    formUrl = '';
    formPlatform = 'windows';
    formArch = 'amd64';
    formFormat = 'exe';
    formSortOrder = 0;
    formIsActive = true;
    formReleaseId = '';
    error = '';
    dialogOpen = true;
  }

  function startEdit(link: DownloadLink) {
    editing = link;
    formName = link.name;
    formUrl = link.url;
    formPlatform = link.platform;
    formArch = link.arch;
    formFormat = link.format;
    formSortOrder = link.sort_order;
    formIsActive = link.is_active;
    formReleaseId = link.release_id || '';
    error = '';
    dialogOpen = true;
  }

  async function handleSave(e: Event) {
    e.preventDefault();
    error = '';
    saving = true;
    const data = {
      name: formName.trim(),
      url: formUrl.trim(),
      platform: formPlatform,
      arch: formArch,
      format: formFormat.trim(),
      sort_order: Number(formSortOrder ?? 0),
      is_active: formIsActive,
      release_id: formReleaseId || null,
    };
    try {
      if (editing) {
        await adminUpdateDownload(editing.id, data);
        toast.success('Download link updated');
      } else {
        await adminCreateDownload(data);
        toast.success('Download link created', 'It is now listed on the public site.');
      }
      dialogOpen = false;
    } catch (err: any) {
      error = err.message;
    } finally {
      saving = false;
    }
  }

  async function uploadFiles(files: FileList | File[] | null | undefined) {
    const file = files?.[0];
    if (!file) return;
    uploading = true;
    try {
      const result = await adminUploadBinary(file);
      const names = result.uploaded.map((f) => `${f.filename} (${formatBytes(f.size)})`).join(', ');
      toast.success('Upload complete', names);
      await fetchAdminDownloads();
    } catch (err: any) {
      toast.error('Upload failed', err.message);
    } finally {
      uploading = false;
    }
  }

  function onFileInput(e: Event) {
    const input = e.target as HTMLInputElement;
    uploadFiles(input.files).finally(() => (input.value = ''));
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    dragging = false;
    uploadFiles(e.dataTransfer?.files);
  }

  async function handleDelete(link: DownloadLink) {
    try {
      await adminDeleteDownload(link.id);
      toast.success('Download link deleted', link.name);
    } catch (err: any) {
      toast.error('Could not delete link', err.message);
    }
  }

  function releaseLabel(id: string | null): string | null {
    if (!id) return null;
    const rel = adminState.releases.find((r) => r.id === id);
    return rel ? `v${rel.version}` : null;
  }
</script>

<div class="mb-5 grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1fr)_320px]">
  <div class="flex flex-wrap items-center gap-2 self-end">
    <Badge tone="neutral">{adminState.downloads.length} links</Badge>
    <Badge tone="mint">{adminState.downloads.filter((d) => d.is_active).length} active</Badge>
    <div class="ml-auto"><Button icon="plus" size="sm" onclick={startCreate}>New link</Button></div>
  </div>

  <!-- Upload dropzone -->
  <label
    class="group relative flex cursor-pointer items-center gap-3 rounded-md border-2 border-dashed px-4 py-3 transition-[background-color,transform,box-shadow] {dragging
      ? 'border-ink bg-yellow shadow-md -translate-x-0.5 -translate-y-0.5'
      : 'border-ink bg-surface shadow-sm hover:bg-surface-2'}"
    ondragover={(e) => { e.preventDefault(); dragging = true; }}
    ondragleave={() => (dragging = false)}
    ondrop={onDrop}
  >
    <IconTile icon={uploading ? 'loader' : 'upload'} tone="accent" size={36} class={uploading ? 'animate-[spin_0.8s_linear_infinite]' : ''} />
    <div class="min-w-0 flex-1">
      <p class="text-[13px] font-semibold text-fg">{uploading ? 'Uploading…' : 'Upload an installer'}</p>
      <p class="truncate text-[12px] text-dim">Drop a file here or click to browse</p>
    </div>
    <input type="file" class="sr-only" accept={ACCEPT} disabled={uploading} onchange={onFileInput} />
  </label>
</div>

<Card padded={false}>
  {#if sorted.length === 0}
    <div class="p-5">
      <EmptyState icon="download" title="No download links" description="Upload an installer, then create a link so it shows up in the Downloads section of the public site." compact>
        <Button icon="plus" size="sm" onclick={startCreate}>Create a link</Button>
      </EmptyState>
    </div>
  {:else}
    <div class="overflow-x-auto">
      <table class="tbl min-w-[880px]">
        <thead>
          <tr>
            <th>Name</th>
            <th>Platform</th>
            <th>Build</th>
            <th>URL</th>
            <th>Release</th>
            <th>Status</th>
            <th class="text-right"><span class="sr-only">Actions</span></th>
          </tr>
        </thead>
        <tbody>
          {#each sorted as link (link.id)}
            <tr class={link.is_active ? '' : 'opacity-60'}>
              <td>
                <div class="flex items-center gap-3">
                  <IconTile icon={platformIcons[link.platform] ?? 'download'} tone="cyan" size={32} />
                  <span class="font-medium text-fg">{link.name}</span>
                </div>
              </td>
              <td class="text-muted">{platformLabels[link.platform] ?? titleCase(link.platform)}</td>
              <td>
                <span class="flex items-center gap-1.5">
                  {#if link.format}<Badge tone="neutral" uppercase>{link.format}</Badge>{/if}
                  {#if link.arch}<span class="font-mono text-[12px] text-dim">{link.arch}</span>{/if}
                </span>
              </td>
              <td>
                <span class="inline-flex max-w-[260px] items-center gap-1">
                  <a href={link.url} target="_blank" rel="noopener" class="truncate font-mono text-[12px] text-accent hover:underline" title={link.url}>{link.url}</a>
                  <CopyButton text={link.url} label="Copy URL" size={12} />
                </span>
              </td>
              <td>
                {#if releaseLabel(link.release_id)}<Badge tone="violet">{releaseLabel(link.release_id)}</Badge>{:else}<span class="text-dim">—</span>{/if}
              </td>
              <td>
                {#if link.is_active}<Badge tone="mint" dot>Active</Badge>{:else}<Badge tone="neutral">Hidden</Badge>{/if}
              </td>
              <td class="text-right">
                <span class="inline-flex items-center gap-1">
                  <Button variant="ghost" size="icon-sm" icon="edit" aria-label="Edit link" onclick={() => startEdit(link)} />
                  <ConfirmAction size="icon-sm" variant="ghost" label="Delete link" confirmLabel="Delete" prompt="Delete?" onconfirm={() => handleDelete(link)} />
                </span>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</Card>

<Dialog bind:open={dialogOpen} title={editing ? 'Edit download link' : 'New download link'} description="Links marked active appear in the public Downloads section." size="lg">
  <form id="download-form" class="grid grid-cols-1 gap-4 sm:grid-cols-2" onsubmit={handleSave}>
    {#if error}<div class="sm:col-span-2"><Alert tone="danger">{error}</Alert></div>{/if}
    <Field label="Name" bind:value={formName} required placeholder="Windows installer" />
    <Field label="Sort order" type="number" bind:value={formSortOrder} hint="Lower numbers show first within a platform" />
    <Field label="URL" bind:value={formUrl} required placeholder="/api/downloads/cpmesh-setup.exe or https://…" icon="link" class="sm:col-span-2" />
    <Select label="Platform" bind:value={formPlatform}>
      <option value="windows">Windows</option>
      <option value="macos">macOS</option>
      <option value="linux">Linux</option>
      <option value="android">Android</option>
      <option value="ios">iOS</option>
    </Select>
    <Select label="Architecture" bind:value={formArch}>
      <option value="amd64">amd64</option>
      <option value="arm64">arm64</option>
      <option value="386">386</option>
      <option value="">Universal / N/A</option>
    </Select>
    <Field label="Format" bind:value={formFormat} placeholder="exe, dmg, apk…" />
    <Select label="Linked release" bind:value={formReleaseId} hint="Optional — ties this link to an auto-update release">
      <option value="">None</option>
      {#each adminState.releases as release (release.id)}
        <option value={release.id}>v{release.version} — {release.platform}/{release.arch || 'any'}{release.is_current ? ' (current)' : ''}</option>
      {/each}
    </Select>
    <div class="sm:col-span-2">
      <Switch bind:checked={formIsActive} label="Active" description="Show this link on the public downloads page." />
    </div>
  </form>
  {#snippet footer()}
    <Button variant="ghost" onclick={() => (dialogOpen = false)}>Cancel</Button>
    <Button type="submit" form="download-form" loading={saving}>{editing ? 'Save changes' : 'Create link'}</Button>
  {/snippet}
</Dialog>
