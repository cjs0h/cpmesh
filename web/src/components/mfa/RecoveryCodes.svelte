<script lang="ts">
  import { downloadText, recoveryCodesText } from '../../lib/mfa';
  import Alert from '../ui/Alert.svelte';
  import Button from '../ui/Button.svelte';

  /** New recovery codes, shown once. With `onconfirm`, the user confirms they saved them to continue. */
  interface Props {
    codes: string[];
    /** Account named in the downloaded file. */
    account?: string;
    onconfirm?: () => void | Promise<void>;
  }

  let { codes, account = '', onconfirm }: Props = $props();

  let copied = $state(false);
  let busy = $state(false);
  let timer: ReturnType<typeof setTimeout> | null = null;

  async function copyAll() {
    try {
      await navigator.clipboard.writeText(codes.join('\n'));
      copied = true;
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => (copied = false), 1800);
    } catch {
      /* clipboard unavailable (insecure context): the codes stay selectable */
    }
  }

  function download() {
    downloadText('cpmesh-recovery-codes.txt', recoveryCodesText(codes, account));
  }

  async function confirm() {
    busy = true;
    try {
      await onconfirm?.();
    } finally {
      busy = false;
    }
  }
</script>

<div class="flex flex-col gap-4">
  <Alert tone="warning" title="Save your recovery codes">
    If you lose your authenticator app or passkey, each code signs you in once. They won't be shown again.
  </Alert>

  <ol class="grid grid-cols-1 gap-x-3 gap-y-1.5 rounded-md border border-border bg-bg-deep px-4 py-3 font-mono text-[12.5px] text-fg sm:grid-cols-2" aria-label="Recovery codes">
    {#each codes as code (code)}
      <li class="select-all whitespace-nowrap">{code}</li>
    {/each}
  </ol>

  <div class="flex flex-wrap gap-2">
    <Button variant="secondary" size="sm" icon={copied ? 'check' : 'copy'} onclick={copyAll}>{copied ? 'Copied' : 'Copy all'}</Button>
    <Button variant="secondary" size="sm" icon="download" onclick={download}>Download</Button>
  </div>

  {#if onconfirm}
    <Button size="lg" class="w-full" loading={busy} onclick={confirm}>I saved these codes</Button>
  {/if}
</div>
