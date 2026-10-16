<script lang="ts">
  import { adminUploadBinary, ensureRecentAuth, errorMessage, type UploadedFile } from '../../lib/stores/admin.svelte';
  import { toast } from '../../lib/stores/toast.svelte';
  import { formatBytes } from '../../lib/format';
  import Icon from '../Icon.svelte';
  import Alert from '../ui/Alert.svelte';
  import Badge from '../ui/Badge.svelte';
  import Button from '../ui/Button.svelte';
  import CopyButton from '../ui/CopyButton.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Switch from '../ui/Switch.svelte';

  /**
   * Uploads installers with their update signatures. `.sig` files are matched to the
   * installer they are named after (`<installer>.sig`), or attached to one explicitly.
   */
  interface Props {
    open?: boolean;
    /** The server only accepts installers signed with its update key. */
    signatureRequired?: boolean;
    onuploaded?: (files: UploadedFile[]) => void;
  }

  let { open = $bindable(false), signatureRequired = false, onuploaded }: Props = $props();

  const MAX_UPLOAD_BYTES = 500 * 1024 * 1024;
  const ACCEPT = '.exe,.msi,.dmg,.pkg,.deb,.rpm,.appimage,.apk,.aab,.ipa,.tar.gz,.zip,.sig';

  let installers = $state<File[]>([]);
  let signatureFiles = $state<File[]>([]);
  let attached = $state<Record<string, File>>({});
  let replace = $state(false);
  let uploading = $state(false);
  let error = $state('');
  let results = $state<UploadedFile[] | null>(null);
  let dragging = $state(false);
  let signatureInput = $state<HTMLInputElement | null>(null);
  let signatureFor = '';

  const rows = $derived(
    installers.map((file) => ({ file, signature: attached[file.name] ?? signatureFiles.find((s) => s.name === `${file.name}.sig`) ?? null })),
  );
  const unmatched = $derived(signatureFiles.filter((s) => !installers.some((f) => s.name === `${f.name}.sig`)));
  const unsigned = $derived(rows.filter((r) => !r.signature).length);
  const tooLarge = $derived(installers.filter((f) => f.size > MAX_UPLOAD_BYTES).map((f) => f.name));
  const canUpload = $derived(installers.length > 0 && tooLarge.length === 0 && !(signatureRequired && unsigned > 0));

  /** Stages installers and `.sig` files; a file with the same name replaces the earlier one. */
  export function addFiles(list: FileList | File[] | null | undefined) {
    if (!list?.length) return;
    results = null;
    error = '';
    for (const file of Array.from(list)) {
      if (file.name.toLowerCase().endsWith('.sig')) signatureFiles = [...signatureFiles.filter((s) => s.name !== file.name), file];
      else installers = [...installers.filter((f) => f.name !== file.name), file];
    }
  }

  function removeInstaller(name: string) {
    installers = installers.filter((f) => f.name !== name);
    delete attached[name];
  }

  function removeSignature(installer: string, signature: File) {
    if (attached[installer] === signature) delete attached[installer];
    else signatureFiles = signatureFiles.filter((s) => s !== signature);
  }

  function chooseSignature(installer: string) {
    signatureFor = installer;
    signatureInput?.click();
  }

  function onSignatureChosen(e: Event) {
    const input = e.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    if (file && signatureFor) attached[signatureFor] = file;
    input.value = '';
  }

  function onFilesChosen(e: Event) {
    const input = e.currentTarget as HTMLInputElement;
    addFiles(input.files);
    input.value = '';
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    dragging = false;
    addFiles(e.dataTransfer?.files);
  }

  function reset() {
    installers = [];
    signatureFiles = [];
    attached = {};
    replace = false;
    error = '';
    results = null;
  }

  function close() {
    open = false;
    if (!uploading) reset();
  }

  async function upload() {
    error = '';
    if (!(await ensureRecentAuth('Confirm it’s you to upload installers.'))) return;
    uploading = true;
    try {
      const signatures: Record<string, File> = {};
      for (const row of rows) if (row.signature) signatures[row.file.name] = row.signature;
      const { uploaded } = await adminUploadBinary(installers, { signatures, replace });
      results = uploaded;
      toast.success(uploaded.length === 1 ? 'Installer uploaded' : `${uploaded.length} installers uploaded`, 'Each file is listed under Download links.');
      onuploaded?.(uploaded);
    } catch (err) {
      error = errorMessage(err);
    } finally {
      uploading = false;
    }
  }
</script>

<Dialog bind:open title={results ? 'Upload complete' : 'Upload installers'} description={results ? 'Share the checksums so people can verify their download.' : 'Files are stored in the downloads directory and served from /api/downloads/.'} size="lg" onclose={() => !uploading && reset()}>
  {#if results}
    <div class="overflow-x-auto rounded-md border border-border">
      <table class="tbl">
        <thead>
          <tr>
            <th>File</th>
            <th class="text-right">Size</th>
            <th>SHA-256</th>
            <th>Signature</th>
          </tr>
        </thead>
        <tbody>
          {#each results as file (file.filename)}
            <tr>
              <td><span class="break-all font-mono text-[12.5px] text-fg">{file.filename}</span></td>
              <td class="text-right font-mono text-[12.5px] text-muted">{formatBytes(file.size)}</td>
              <td>
                <span class="inline-flex items-center gap-1 font-mono text-[12px] text-muted" title={file.sha256}>
                  {file.sha256.slice(0, 12)}…
                  <CopyButton text={file.sha256} label="Copy SHA-256 of {file.filename}" size={12} />
                </span>
              </td>
              <td>{#if file.signed}<Badge tone="mint" icon="check">Signed</Badge>{:else}<Badge tone="neutral">Unsigned</Badge>{/if}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {:else}
    <div class="flex flex-col gap-4">
      <label
        class="flex cursor-pointer items-center gap-3 rounded-lg border border-dashed px-4 py-4 transition-colors duration-150 focus-within:border-ink {dragging ? 'border-ink bg-surface-2' : 'border-border-strong bg-bg-deep hover:bg-surface-2'}"
        ondragover={(e) => {
          e.preventDefault();
          dragging = true;
        }}
        ondragleave={() => (dragging = false)}
        ondrop={onDrop}
      >
        <span class="flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-border bg-surface text-muted"><Icon name="upload" size={16} /></span>
        <span class="min-w-0 flex-1">
          <span class="block text-[13px] font-medium text-fg">Choose installers and signatures</span>
          <span class="block text-[12px] text-dim">Drop files here or click to browse. A file named <code class="font-mono">&lt;installer&gt;.sig</code> is matched to its installer.</span>
        </span>
        <input type="file" class="sr-only" multiple accept={ACCEPT} disabled={uploading} onchange={onFilesChosen} />
      </label>

      {#if signatureRequired}
        <Alert tone="info" title="Signatures are required">This server only accepts installers signed with its update key (<code class="font-mono">UPDATER_PUBLIC_KEY</code>). Add each installer’s <code class="font-mono">.sig</code> file made by the release build.</Alert>
      {/if}

      {#if rows.length > 0}
        <ul class="divide-y divide-border rounded-md border border-border">
          {#each rows as row (row.file.name)}
            <li class="flex flex-col gap-2 px-3.5 py-3 sm:flex-row sm:items-center">
              <div class="flex min-w-0 flex-1 items-center gap-2.5">
                <span class="text-dim"><Icon name="package" size={15} /></span>
                <div class="min-w-0">
                  <p class="truncate font-mono text-[12.5px] text-fg" title={row.file.name}>{row.file.name}</p>
                  <p class="text-[11.5px] {tooLarge.includes(row.file.name) ? 'text-danger' : 'text-dim'}">{formatBytes(row.file.size)}{tooLarge.includes(row.file.name) ? ' · larger than the 500 MB limit' : ''}</p>
                </div>
              </div>
              <div class="flex shrink-0 items-center gap-1.5">
                {#if row.signature}
                  <Badge tone="mint" icon="check" title={row.signature.name}>Signature</Badge>
                  <Button variant="ghost" size="icon-sm" icon="x" aria-label="Remove the signature of {row.file.name}" onclick={() => row.signature && removeSignature(row.file.name, row.signature)} />
                {:else}
                  <Badge tone={signatureRequired ? 'gold' : 'neutral'}>No signature</Badge>
                  <Button variant="outline" size="xs" icon="plus" onclick={() => chooseSignature(row.file.name)}>Add .sig</Button>
                {/if}
                <Button variant="ghost" size="icon-sm" icon="trash" aria-label="Remove {row.file.name}" onclick={() => removeInstaller(row.file.name)} />
              </div>
            </li>
          {/each}
        </ul>
      {/if}

      {#if unmatched.length > 0}
        <Alert tone="warning" title="Signatures without an installer">
          {unmatched.map((s) => s.name).join(', ')} {unmatched.length === 1 ? 'does' : 'do'} not match a selected installer. Name each signature after its installer, or use “Add .sig” on the installer.
        </Alert>
      {/if}

      <Switch bind:checked={replace} label="Replace existing files" description="Overwrite files with the same name. Without this, a name that already exists stops the upload." />

      {#if error}<Alert tone="danger" title="Upload failed">{error}</Alert>{/if}
      <input bind:this={signatureInput} type="file" class="sr-only" accept=".sig" tabindex="-1" aria-hidden="true" onchange={onSignatureChosen} />
    </div>
  {/if}

  {#snippet footer()}
    {#if results}
      <Button variant="ghost" icon="upload" onclick={reset}>Upload more</Button>
      <Button onclick={close}>Done</Button>
    {:else}
      <Button variant="ghost" onclick={close}>Cancel</Button>
      <Button icon="upload" loading={uploading} disabled={!canUpload} onclick={upload}>
        {installers.length > 1 ? `Upload ${installers.length} files` : 'Upload'}
      </Button>
    {/if}
  {/snippet}
</Dialog>
