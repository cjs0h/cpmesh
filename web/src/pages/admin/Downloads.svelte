<script lang="ts">
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
  import { push } from 'svelte-spa-router';

  let editing = $state<DownloadLink | null>(null);
  let creating = $state(false);
  let error = $state('');
  let deleteConfirm = $state<string | null>(null);
  let uploading = $state(false);
  let uploadMsg = $state('');

  let formName = $state('');
  let formUrl = $state('');
  let formPlatform = $state('windows');
  let formArch = $state('amd64');
  let formFormat = $state('exe');
  let formSortOrder = $state(0);
  let formIsActive = $state(true);
  let formReleaseId = $state<string>('');

  $effect(() => {
    if (!userState.isAdmin) {
      push('/');
      return;
    }
    fetchAdminDownloads();
    fetchAdminReleases();
  });

  function resetForm() {
    formName = '';
    formUrl = '';
    formPlatform = 'windows';
    formArch = 'amd64';
    formFormat = 'exe';
    formSortOrder = 0;
    formIsActive = true;
    formReleaseId = '';
    error = '';
  }

  function startCreate() {
    resetForm();
    creating = true;
    editing = null;
  }

  function startEdit(link: DownloadLink) {
    formName = link.name;
    formUrl = link.url;
    formPlatform = link.platform;
    formArch = link.arch;
    formFormat = link.format;
    formSortOrder = link.sort_order;
    formIsActive = link.is_active;
    formReleaseId = link.release_id || '';
    editing = link;
    creating = false;
    error = '';
  }

  function cancelForm() {
    creating = false;
    editing = null;
    error = '';
  }

  async function handleSave() {
    error = '';
    const data = {
      name: formName,
      url: formUrl,
      platform: formPlatform,
      arch: formArch,
      format: formFormat,
      sort_order: formSortOrder,
      is_active: formIsActive,
      release_id: formReleaseId || null,
    };

    try {
      if (editing) {
        await adminUpdateDownload(editing.id, data);
      } else {
        await adminCreateDownload(data);
      }
      cancelForm();
    } catch (err: any) {
      error = err.message;
    }
  }

  async function handleUpload(e: Event) {
    const input = e.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;

    uploading = true;
    uploadMsg = '';
    error = '';
    try {
      const result = await adminUploadBinary(file);
      uploadMsg = `Uploaded ${result.uploaded.map(f => f.filename).join(', ')}`;
      await fetchAdminDownloads();
    } catch (err: any) {
      error = err.message;
    } finally {
      uploading = false;
      input.value = '';
    }
  }

  async function handleDelete(id: string) {
    try {
      await adminDeleteDownload(id);
      deleteConfirm = null;
    } catch (err: any) {
      error = err.message;
      deleteConfirm = null;
    }
  }
</script>

<div>
  <div class="flex items-center justify-between mb-5">
    <h2 class="text-xl font-semibold">Download Links</h2>
    {#if !creating && !editing}
      <div class="flex items-center gap-2">
        <label class="inline-flex items-center gap-1.5 px-4 py-2 border border-border rounded text-[13px] font-medium transition-all duration-150 bg-transparent text-muted hover:bg-bg-hover hover:text-text hover:border-border-hover cursor-pointer">
          {uploading ? 'Uploading...' : 'Upload Binary'}
          <input type="file" class="hidden" onchange={handleUpload} disabled={uploading} accept=".exe,.msi,.dmg,.pkg,.deb,.rpm,.appimage,.apk,.aab,.ipa,.tar.gz,.zip" />
        </label>
        <button class="inline-flex items-center gap-1.5 px-4 py-2 border-none rounded text-[13px] font-medium transition-all duration-150 bg-primary text-white hover:bg-primary-hover hover:shadow-primary" onclick={startCreate}>+ New Link</button>
      </div>
    {/if}
  </div>

  {#if error}
    <div class="flex items-center gap-2 bg-danger-glow border border-danger/30 text-danger px-3.5 py-2.5 rounded text-[13px] mb-4">{error}</div>
  {/if}
  {#if uploadMsg}
    <div class="flex items-center gap-2 bg-success-glow border border-success/30 text-success px-3.5 py-2.5 rounded text-[13px] mb-4">{uploadMsg}</div>
  {/if}

  {#if creating || editing}
    <div class="bg-bg-card border border-border rounded-xl p-6 mb-5">
      <h3 class="text-base font-semibold mb-4">{editing ? 'Edit Download Link' : 'New Download Link'}</h3>
      <form onsubmit={(e) => { e.preventDefault(); handleSave(); }}>
        <div class="grid grid-cols-2 gap-x-5 gap-y-3.5">
          <label class="flex flex-col gap-1.5">
            <span class="text-[13px] text-muted font-medium">Name *</span>
            <input type="text" bind:value={formName} required placeholder="Windows Installer" class="py-2.5 px-3.5 border border-border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)]" />
          </label>
          <label class="flex flex-col gap-1.5 col-span-full">
            <span class="text-[13px] text-muted font-medium">URL *</span>
            <input type="text" bind:value={formUrl} required placeholder="/api/downloads/filename or https://..." class="py-2.5 px-3.5 border border-border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)]" />
          </label>
          <label class="flex flex-col gap-1.5">
            <span class="text-[13px] text-muted font-medium">Platform</span>
            <select bind:value={formPlatform} class="py-2.5 px-3.5 border border-border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)]">
              <option value="windows">Windows</option>
              <option value="macos">macOS</option>
              <option value="linux">Linux</option>
              <option value="android">Android</option>
              <option value="ios">iOS</option>
            </select>
          </label>
          <label class="flex flex-col gap-1.5">
            <span class="text-[13px] text-muted font-medium">Architecture</span>
            <select bind:value={formArch} class="py-2.5 px-3.5 border border-border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)]">
              <option value="amd64">amd64</option>
              <option value="arm64">arm64</option>
              <option value="386">386</option>
              <option value="">N/A</option>
            </select>
          </label>
          <label class="flex flex-col gap-1.5">
            <span class="text-[13px] text-muted font-medium">Format</span>
            <input type="text" bind:value={formFormat} placeholder="exe, dmg, apk..." class="py-2.5 px-3.5 border border-border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)]" />
          </label>
          <label class="flex flex-col gap-1.5">
            <span class="text-[13px] text-muted font-medium">Sort Order</span>
            <input type="number" bind:value={formSortOrder} class="py-2.5 px-3.5 border border-border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)]" />
          </label>
          <label class="flex flex-row items-center gap-2 pt-6">
            <input type="checkbox" bind:checked={formIsActive} class="w-4 h-4 accent-primary" />
            <span class="text-[13px] text-muted font-medium">Active</span>
          </label>
          <label class="flex flex-col gap-1.5 col-span-full">
            <span class="text-[13px] text-muted font-medium">Release</span>
            <select bind:value={formReleaseId} class="py-2.5 px-3.5 border border-border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)]">
              <option value="">None (unlinked)</option>
              {#each adminState.releases as release}
                <option value={release.id}>v{release.version} — {release.platform}/{release.arch}{release.is_current ? ' (current)' : ''}</option>
              {/each}
            </select>
          </label>
        </div>
        <div class="flex gap-2.5 mt-5">
          <button type="submit" class="inline-flex items-center gap-1.5 px-4 py-2 border-none rounded text-[13px] font-medium transition-all duration-150 bg-primary text-white hover:bg-primary-hover hover:shadow-primary">Save</button>
          <button type="button" class="inline-flex items-center gap-1.5 px-4 py-2 border border-border rounded text-[13px] font-medium transition-all duration-150 bg-transparent text-muted hover:bg-bg-hover hover:text-text hover:border-border-hover" onclick={cancelForm}>Cancel</button>
        </div>
      </form>
    </div>
  {/if}

  <div class="bg-bg-card border border-border rounded-xl overflow-hidden">
    <table class="w-full border-collapse">
      <thead>
        <tr>
          <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">Name</th>
          <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">Platform</th>
          <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">Arch</th>
          <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">Format</th>
          <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">URL</th>
          <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">Release</th>
          <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">Active</th>
          <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold"></th>
        </tr>
      </thead>
      <tbody>
        {#each adminState.downloads as link}
          <tr class="transition-colors duration-150 hover:bg-bg-hover">
            <td class="px-[18px] py-[13px] text-sm border-b border-border font-semibold">{link.name}</td>
            <td class="px-[18px] py-[13px] text-sm border-b border-border">{link.platform}</td>
            <td class="px-[18px] py-[13px] text-sm border-b border-border">{link.arch || '—'}</td>
            <td class="px-[18px] py-[13px] text-sm border-b border-border">{link.format || '—'}</td>
            <td class="px-[18px] py-[13px] text-[13px] border-b border-border"><a href={link.url} target="_blank" rel="noopener" class="text-primary no-underline hover:underline">{link.url.length > 50 ? link.url.slice(0, 50) + '...' : link.url}</a></td>
            <td class="px-[18px] py-[13px] text-sm border-b border-border">
              {#if link.release_id}
                {@const rel = adminState.releases.find(r => r.id === link.release_id)}
                {#if rel}
                  <span class="text-[12px]">v{rel.version}</span>
                {:else}
                  <span class="text-muted text-[12px]">—</span>
                {/if}
              {:else}
                <span class="text-muted text-[12px]">—</span>
              {/if}
            </td>
            <td class="px-[18px] py-[13px] text-sm border-b border-border">
              {#if link.is_active}
                <span class="inline-block px-2.5 py-[3px] rounded-full bg-success-glow text-success text-[11px] font-semibold border border-success/20">Active</span>
              {:else}
                <span class="inline-block px-2.5 py-[3px] rounded-full bg-bg-input text-muted text-[11px] font-semibold border border-border">Inactive</span>
              {/if}
            </td>
            <td class="px-[18px] py-[13px] text-sm border-b border-border">
              <div class="flex items-center gap-2">
                <button class="border border-border rounded text-[13px] font-medium py-1.5 px-3 transition-all duration-150 bg-transparent text-muted hover:bg-bg-hover hover:text-text hover:border-border-hover" onclick={() => startEdit(link)}>Edit</button>
                {#if deleteConfirm === link.id}
                  <div class="flex items-center gap-2">
                    <span class="text-[13px] text-warning font-medium">Delete?</span>
                    <button class="border-none rounded text-[13px] font-medium py-1.5 px-3 transition-all duration-150 bg-danger text-white hover:bg-danger-hover" onclick={() => handleDelete(link.id)}>Yes</button>
                    <button class="border border-border rounded text-[13px] font-medium py-1.5 px-3 transition-all duration-150 bg-transparent text-muted hover:bg-bg-hover hover:text-text hover:border-border-hover" onclick={() => (deleteConfirm = null)}>No</button>
                  </div>
                {:else}
                  <button class="border border-border rounded text-[13px] font-medium py-1.5 px-3 transition-all duration-150 bg-transparent text-muted hover:bg-bg-hover hover:text-text hover:border-border-hover" onclick={() => (deleteConfirm = link.id)}>Delete</button>
                {/if}
              </div>
            </td>
          </tr>
        {:else}
          <tr><td colspan="8" class="text-muted text-center p-6">No download links yet.</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
</div>
