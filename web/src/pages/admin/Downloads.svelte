<script lang="ts">
  import { onMount } from 'svelte';
  import { push } from 'svelte-spa-router';
  import { ApiError } from '../../lib/api';
  import { can, userState } from '../../lib/stores/user.svelte';
  import {
    adminState,
    fetchAdminDownloads,
    fetchAdminReleases,
    fetchAdminSettings,
    adminCreateDownload,
    adminUpdateDownload,
    adminDeleteDownload,
    errorMessage,
    isMfaRequired,
    type DownloadLink,
  } from '../../lib/stores/admin.svelte';
  import { toast } from '../../lib/stores/toast.svelte';
  import { formatBytes, titleCase } from '../../lib/format';
  import Badge from '../../components/ui/Badge.svelte';
  import Button from '../../components/ui/Button.svelte';
  import Card from '../../components/ui/Card.svelte';
  import ConfirmAction from '../../components/ui/ConfirmAction.svelte';
  import Dialog from '../../components/ui/Dialog.svelte';
  import Field from '../../components/ui/Field.svelte';
  import Select from '../../components/ui/Select.svelte';
  import Skeleton from '../../components/ui/Skeleton.svelte';
  import Switch from '../../components/ui/Switch.svelte';
  import EmptyState from '../../components/ui/EmptyState.svelte';
  import Alert from '../../components/ui/Alert.svelte';
  import IconTile from '../../components/ui/IconTile.svelte';
  import CopyButton from '../../components/ui/CopyButton.svelte';
  import AdminGate from '../../components/admin/AdminGate.svelte';
  import UploadDialog from '../../components/admin/UploadDialog.svelte';

  let loaded = $state(false);
  let loadError = $state('');
  let dialogOpen = $state(false);
  let editing = $state<DownloadLink | null>(null);
  let error = $state('');
  let urlError = $state('');
  let saving = $state(false);
  let uploadOpen = $state(false);
  let uploader = $state<ReturnType<typeof UploadDialog> | null>(null);
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

  const canEdit = $derived(can('manage_content'));
  const uploads = $derived(adminState.settings?.uploads);

  onMount(() => {
    if (!userState.isAdmin) {
      push('/');
      return;
    }
    load();
  });

  async function load() {
    fetchAdminSettings().catch(() => {});
    try {
      await Promise.all([fetchAdminDownloads(), fetchAdminReleases()]);
      loaded = true;
      loadError = '';
    } catch (err) {
      if (!isMfaRequired(err)) loadError = errorMessage(err);
    }
  }

  const sorted = $derived([...adminState.downloads].sort((a, b) => a.platform.localeCompare(b.platform) || a.sort_order - b.sort_order));

  const urlHint = $derived.by(() => {
    const prefixes = adminState.settings?.download_url_prefixes ?? [];
    return prefixes.length
      ? `/api/downloads/<file> for an uploaded installer, or a URL under ${prefixes.join(', ')}`
      : '/api/downloads/<file> for an uploaded installer, or any https URL';
  });

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
    urlError = '';
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
    urlError = '';
    dialogOpen = true;
  }

  async function handleSave(e: Event) {
    e.preventDefault();
    error = '';
    urlError = '';
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
    } catch (err) {
      // The server's URL allowlist (DOWNLOAD_URL_PREFIXES) belongs next to the URL field
      if (err instanceof ApiError && err.status === 400 && /url/i.test(err.message)) urlError = err.message;
      else if (!isMfaRequired(err)) error = errorMessage(err);
    } finally {
      saving = false;
    }
  }

  function openUpload(files?: FileList | null) {
    uploader?.addFiles(files);
    uploadOpen = true;
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    dragging = false;
    openUpload(e.dataTransfer?.files);
  }

  async function handleDelete(link: DownloadLink) {
    try {
      await adminDeleteDownload(link.id);
      toast.success('Download link deleted', link.name);
    } catch (err) {
      if (!isMfaRequired(err)) toast.error('Could not delete link', errorMessage(err));
    }
  }

  function releaseLabel(id: string | null): string | null {
    if (!id) return null;
    const rel = adminState.releases.find((r) => r.id === id);
    return rel ? `v${rel.version}` : null;
  }
</script>

<AdminGate onunlock={load}>
  <div class="mb-5 grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1fr)_340px]">
    <div class="flex flex-wrap items-center gap-2 self-end">
      <Badge tone="neutral">{adminState.downloads.length} links</Badge>
      <Badge tone="mint">{adminState.downloads.filter((d) => d.is_active).length} active</Badge>
      {#if canEdit}<div class="ml-auto"><Button icon="plus" size="sm" onclick={startCreate}>New link</Button></div>{/if}
    </div>

    {#if canEdit}
      {#if uploads && !uploads.downloads_dir_configured}
        <div class="flex items-center gap-3 rounded-lg border border-dashed border-border-strong bg-bg-deep px-4 py-3">
          <IconTile icon="upload" size={36} />
          <div class="min-w-0">
            <p class="text-[13px] font-medium text-fg">Uploads are off</p>
            <p class="text-[12px] text-dim">Set <code class="font-mono">DOWNLOADS_DIR</code> to host installers on this server.</p>
          </div>
        </div>
      {:else}
        <button
          type="button"
          class="flex items-center gap-3 rounded-lg border border-dashed px-4 py-3 text-left transition-colors duration-150 {dragging ? 'border-ink bg-surface-2' : 'border-border-strong bg-surface hover:bg-bg-deep'}"
          ondragover={(e) => {
            e.preventDefault();
            dragging = true;
          }}
          ondragleave={() => (dragging = false)}
          ondrop={onDrop}
          onclick={() => openUpload()}
        >
          <IconTile icon="upload" size={36} />
          <span class="min-w-0 flex-1">
            <span class="block text-[13px] font-medium text-fg">Upload installers</span>
            <span class="block truncate text-[12px] text-dim">{uploads?.signature_required ? 'With their .sig signatures · drop files here' : 'Drop files here or click to choose'}</span>
          </span>
        </button>
      {/if}
    {/if}
  </div>

  {#if loadError}
    <Alert tone="danger" title="Could not load download links" class="mb-4">
      {loadError}
      <Button variant="link" class="ml-1" onclick={load}>Try again</Button>
    </Alert>
  {/if}

  <Card padded={false}>
    {#if !loaded}
      <div class="flex flex-col gap-4 p-5" aria-busy="true">
        {#each Array(4) as _, i (i)}
          <div class="flex items-center gap-3"><Skeleton class="h-8 w-8" /><Skeleton class="h-3 w-1/4" /><Skeleton class="h-3 w-1/5" /><Skeleton class="ml-auto h-3 w-16" /></div>
        {/each}
      </div>
    {:else if sorted.length === 0}
      <div class="p-5">
        <EmptyState icon="download" title="No download links" description="Upload an installer (a link is created for it), or add a link to a file hosted elsewhere, so it shows up in the Downloads section of the public site." compact>
          {#if canEdit}<Button icon="plus" size="sm" onclick={startCreate}>Create a link</Button>{/if}
        </EmptyState>
      </div>
    {:else}
      <div class="overflow-x-auto">
        <table class="tbl min-w-[1040px]">
          <thead>
            <tr>
              <th>Name</th>
              <th>Platform</th>
              <th>Build</th>
              <th>URL</th>
              <th>File</th>
              <th>Release</th>
              <th>Status</th>
              {#if canEdit}<th class="text-right"><span class="sr-only">Actions</span></th>{/if}
            </tr>
          </thead>
          <tbody>
            {#each sorted as link (link.id)}
              <tr class={link.is_active ? '' : 'opacity-60'}>
                <td>
                  <div class="flex items-center gap-3">
                    <IconTile icon={platformIcons[link.platform] ?? 'download'} size={32} />
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
                  <span class="inline-flex max-w-[240px] items-center gap-1">
                    <a href={link.url} target="_blank" rel="noopener" class="truncate font-mono text-[12px] text-accent hover:underline" title={link.url}>{link.url}</a>
                    <CopyButton text={link.url} label="Copy URL" size={12} />
                  </span>
                </td>
                <td>
                  {#if link.sha256 || link.size_bytes != null}
                    <span class="flex flex-col gap-0.5">
                      {#if link.size_bytes != null}<span class="font-mono text-[12px] text-muted">{formatBytes(link.size_bytes)}</span>{/if}
                      {#if link.sha256}
                        <span class="inline-flex items-center gap-0.5 whitespace-nowrap font-mono text-[11.5px] text-dim" title="SHA-256 {link.sha256}">
                          sha256 {link.sha256.slice(0, 10)}…
                          <CopyButton text={link.sha256} label="Copy SHA-256" size={11} />
                        </span>
                      {/if}
                    </span>
                  {:else}
                    <span class="text-dim">External</span>
                  {/if}
                </td>
                <td>
                  {#if releaseLabel(link.release_id)}<Badge tone="violet">{releaseLabel(link.release_id)}</Badge>{:else}<span class="text-dim">—</span>{/if}
                </td>
                <td>
                  {#if link.is_active}<Badge tone="mint" dot>Active</Badge>{:else}<Badge tone="neutral">Hidden</Badge>{/if}
                </td>
                {#if canEdit}
                  <td class="text-right">
                    <span class="inline-flex items-center gap-1">
                      <Button variant="ghost" size="icon-sm" icon="edit" aria-label="Edit link" onclick={() => startEdit(link)} />
                      <ConfirmAction size="icon-sm" variant="ghost" label="Delete link" confirmLabel="Delete" prompt="Delete?" onconfirm={() => handleDelete(link)} />
                    </span>
                  </td>
                {/if}
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </Card>
</AdminGate>

<UploadDialog bind:this={uploader} bind:open={uploadOpen} signatureRequired={uploads?.signature_required ?? false} onuploaded={() => fetchAdminDownloads().catch(() => {})} />

<Dialog bind:open={dialogOpen} title={editing ? 'Edit download link' : 'New download link'} description="Links marked active appear in the public Downloads section." size="lg">
  <form id="download-form" class="grid grid-cols-1 gap-4 sm:grid-cols-2" onsubmit={handleSave}>
    {#if error}<div class="sm:col-span-2"><Alert tone="danger">{error}</Alert></div>{/if}
    <Field label="Name" bind:value={formName} required placeholder="Windows installer" />
    <Field label="Sort order" type="number" bind:value={formSortOrder} hint="Lower numbers show first within a platform" />
    <Field label="URL" bind:value={formUrl} required placeholder="/api/downloads/cpmesh-setup.exe or https://…" icon="link" hint={urlHint} error={urlError} oninput={() => (urlError = '')} class="sm:col-span-2" />
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
