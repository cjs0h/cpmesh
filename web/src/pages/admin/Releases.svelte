<script lang="ts">
  import { userState } from '../../lib/stores/user.svelte';
  import {
    adminState,
    fetchAdminReleases,
    adminCreateRelease,
    adminUpdateRelease,
    adminDeleteRelease,
    type AppRelease,
  } from '../../lib/stores/admin.svelte';
  import { push } from 'svelte-spa-router';

  let editing = $state<AppRelease | null>(null);
  let creating = $state(false);
  let error = $state('');
  let deleteConfirm = $state<string | null>(null);

  let formVersion = $state('');
  let formPlatform = $state('darwin');
  let formArch = $state('arm64');
  let formDownloadUrl = $state('');
  let formReleaseNotes = $state('');
  let formIsCurrent = $state(true);

  $effect(() => {
    if (!userState.isAdmin) {
      push('/');
      return;
    }
    fetchAdminReleases();
  });

  function resetForm() {
    formVersion = '';
    formPlatform = 'darwin';
    formArch = 'arm64';
    formDownloadUrl = '';
    formReleaseNotes = '';
    formIsCurrent = true;
    error = '';
  }

  function startCreate() {
    resetForm();
    creating = true;
    editing = null;
  }

  function startEdit(release: AppRelease) {
    formVersion = release.version;
    formPlatform = release.platform;
    formArch = release.arch;
    formDownloadUrl = release.download_url;
    formReleaseNotes = release.release_notes;
    formIsCurrent = release.is_current;
    editing = release;
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
      version: formVersion,
      platform: formPlatform,
      arch: formArch,
      download_url: formDownloadUrl,
      release_notes: formReleaseNotes,
      is_current: formIsCurrent,
    };

    try {
      if (editing) {
        await adminUpdateRelease(editing.id, data);
      } else {
        await adminCreateRelease(data);
      }
      cancelForm();
    } catch (err: any) {
      error = err.message;
    }
  }

  async function handleDelete(id: string) {
    try {
      await adminDeleteRelease(id);
      deleteConfirm = null;
    } catch (err: any) {
      error = err.message;
      deleteConfirm = null;
    }
  }
</script>

<div>
  <div class="flex items-center justify-between mb-5">
    <h2 class="text-xl font-semibold">App Releases</h2>
    {#if !creating && !editing}
      <button class="inline-flex items-center gap-1.5 px-4 py-2 border-none rounded text-[13px] font-medium transition-all duration-150 bg-primary text-white hover:bg-primary-hover hover:shadow-primary" onclick={startCreate}>+ New Release</button>
    {/if}
  </div>

  <p class="text-muted text-[13px] mb-4">Manage app versions for auto-update. Mark a release as "Current" for each platform/arch to make it available to clients checking for updates.</p>

  {#if error}
    <div class="flex items-center gap-2 bg-danger-glow border border-danger/30 text-danger px-3.5 py-2.5 rounded text-[13px] mb-4">{error}</div>
  {/if}

  {#if creating || editing}
    <div class="bg-bg-card border border-border rounded-xl p-6 mb-5">
      <h3 class="text-base font-semibold mb-4">{editing ? 'Edit Release' : 'New Release'}</h3>
      <form onsubmit={(e) => { e.preventDefault(); handleSave(); }}>
        <div class="grid grid-cols-2 gap-x-5 gap-y-3.5">
          <label class="flex flex-col gap-1.5">
            <span class="text-[13px] text-muted font-medium">Version *</span>
            <input type="text" bind:value={formVersion} required placeholder="0.2.0" class="py-2.5 px-3.5 border border-border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)]" />
          </label>
          <label class="flex flex-col gap-1.5">
            <span class="text-[13px] text-muted font-medium">Platform</span>
            <select bind:value={formPlatform} class="py-2.5 px-3.5 border border-border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)]">
              <option value="darwin">macOS</option>
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
              <option value="android">Android</option>
              <option value="ios">iOS</option>
            </select>
          </label>
          <label class="flex flex-col gap-1.5">
            <span class="text-[13px] text-muted font-medium">Architecture</span>
            <select bind:value={formArch} class="py-2.5 px-3.5 border border-border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)]">
              <option value="arm64">arm64</option>
              <option value="amd64">amd64</option>
              <option value="">Any</option>
            </select>
          </label>
          <label class="flex flex-col gap-1.5 col-span-full">
            <span class="text-[13px] text-muted font-medium">Download URL *</span>
            <input type="text" bind:value={formDownloadUrl} required placeholder="/api/downloads/cpmesh-0.2.0-darwin-arm64.dmg or https://cpmesh.com/..." class="py-2.5 px-3.5 border border-border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)]" />
          </label>
          <label class="flex flex-col gap-1.5 col-span-full">
            <span class="text-[13px] text-muted font-medium">Release Notes</span>
            <textarea bind:value={formReleaseNotes} rows="3" placeholder="What's new in this version..." class="py-2.5 px-3.5 border border-border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)] resize-y"></textarea>
          </label>
          <label class="flex flex-row items-center gap-2">
            <input type="checkbox" bind:checked={formIsCurrent} class="w-4 h-4 accent-primary" />
            <span class="text-[13px] text-muted font-medium">Current release (advertised to clients)</span>
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
          <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">Version</th>
          <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">Platform</th>
          <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">Arch</th>
          <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">Download URL</th>
          <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">Current</th>
          <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold"></th>
        </tr>
      </thead>
      <tbody>
        {#each adminState.releases as release}
          <tr class="transition-colors duration-150 hover:bg-bg-hover">
            <td class="px-[18px] py-[13px] text-sm border-b border-border font-semibold">{release.version}</td>
            <td class="px-[18px] py-[13px] text-sm border-b border-border">{release.platform}</td>
            <td class="px-[18px] py-[13px] text-sm border-b border-border">{release.arch || '—'}</td>
            <td class="px-[18px] py-[13px] text-[13px] border-b border-border"><a href={release.download_url} target="_blank" rel="noopener" class="text-primary no-underline hover:underline">{release.download_url.length > 50 ? release.download_url.slice(0, 50) + '...' : release.download_url}</a></td>
            <td class="px-[18px] py-[13px] text-sm border-b border-border">
              {#if release.is_current}
                <span class="inline-block px-2.5 py-[3px] rounded-full bg-success-glow text-success text-[11px] font-semibold border border-success/20">Current</span>
              {:else}
                <span class="inline-block px-2.5 py-[3px] rounded-full bg-bg-input text-muted text-[11px] font-semibold border border-border">Old</span>
              {/if}
            </td>
            <td class="px-[18px] py-[13px] text-sm border-b border-border">
              <div class="flex items-center gap-2">
                <button class="border border-border rounded text-[13px] font-medium py-1.5 px-3 transition-all duration-150 bg-transparent text-muted hover:bg-bg-hover hover:text-text hover:border-border-hover" onclick={() => startEdit(release)}>Edit</button>
                {#if deleteConfirm === release.id}
                  <div class="flex items-center gap-2">
                    <span class="text-[13px] text-warning font-medium">Delete?</span>
                    <button class="border-none rounded text-[13px] font-medium py-1.5 px-3 transition-all duration-150 bg-danger text-white hover:bg-danger-hover" onclick={() => handleDelete(release.id)}>Yes</button>
                    <button class="border border-border rounded text-[13px] font-medium py-1.5 px-3 transition-all duration-150 bg-transparent text-muted hover:bg-bg-hover hover:text-text hover:border-border-hover" onclick={() => (deleteConfirm = null)}>No</button>
                  </div>
                {:else}
                  <button class="border border-border rounded text-[13px] font-medium py-1.5 px-3 transition-all duration-150 bg-transparent text-muted hover:bg-bg-hover hover:text-text hover:border-border-hover" onclick={() => (deleteConfirm = release.id)}>Delete</button>
                {/if}
              </div>
            </td>
          </tr>
        {:else}
          <tr><td colspan="6" class="text-muted text-center p-6">No releases yet. Create one to enable auto-updates.</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
</div>
