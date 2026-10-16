<script lang="ts">
  import { onMount } from 'svelte';
  import { enableTotp, errorMessage, normalizeOtp, startTotpSetup, svgDataUrl, type EnrollResult, type MfaTransport, type TotpSetup } from '../../lib/mfa';
  import Alert from '../ui/Alert.svelte';
  import Button from '../ui/Button.svelte';
  import CopyButton from '../ui/CopyButton.svelte';
  import Spinner from '../ui/Spinner.svelte';
  import CodeField from './CodeField.svelte';

  /** Sets up an authenticator app: scan the QR code (or type the key), then confirm a code from the app. */
  interface Props {
    send: MfaTransport;
    onenrolled: (result: EnrollResult) => void | Promise<void>;
    onback?: () => void;
  }

  let { send, onenrolled, onback }: Props = $props();

  let setup = $state<TotpSetup | null>(null);
  let loadError = $state('');
  let code = $state('');
  let error = $state('');
  let busy = $state(false);

  const qrSrc = $derived(setup?.qr_svg ? svgDataUrl(setup.qr_svg) : '');
  const groupedSecret = $derived(setup ? setup.secret.replace(/(.{4})(?=.)/g, '$1 ') : '');

  onMount(load);

  async function load() {
    loadError = '';
    try {
      setup = await startTotpSetup(send);
    } catch (err) {
      loadError = errorMessage(err);
    }
  }

  async function confirm(value: string) {
    if (busy) return;
    const digits = normalizeOtp(value);
    if (digits.length !== 6) {
      error = 'Enter the 6-digit code from your authenticator app.';
      return;
    }
    busy = true;
    error = '';
    try {
      await onenrolled(await enableTotp(send, digits));
    } catch (err) {
      error = errorMessage(err);
      code = '';
    } finally {
      busy = false;
    }
  }

  function submit(e: Event) {
    e.preventDefault();
    confirm(code);
  }
</script>

{#if loadError}
  <div class="flex flex-col gap-3">
    <Alert tone="danger">{loadError}</Alert>
    <div class="flex gap-2">
      {#if onback}<Button variant="ghost" icon="arrow-left" onclick={onback}>Back</Button>{/if}
      <Button variant="secondary" icon="refresh" onclick={load}>Try again</Button>
    </div>
  </div>
{:else if !setup}
  <div class="flex items-center justify-center gap-2 py-10 text-[13px] text-muted">
    <Spinner size={16} /> Preparing your key…
  </div>
{:else}
  <form onsubmit={submit} class="flex flex-col gap-4">
    <p class="text-[13px] leading-relaxed text-muted">
      Scan the QR code with an authenticator app such as 1Password, Google Authenticator or Authy.
    </p>
    {#if qrSrc}
      <img src={qrSrc} alt="QR code to add cpmesh to your authenticator app" width="176" height="176" class="mx-auto rounded-md border border-border bg-white p-2" />
    {/if}
    <div class="rounded-md border border-border bg-bg-deep px-3 py-2.5">
      <p class="text-xs text-muted">Can't scan it? Enter this key in the app instead.</p>
      <div class="mt-1 flex items-center justify-between gap-2">
        <code class="min-w-0 break-words font-mono text-[13px] text-fg">{groupedSecret}</code>
        <CopyButton text={setup.secret} label="Copy key" />
      </div>
      <a href={setup.otpauth_uri} class="mt-2 inline-block text-xs text-muted underline underline-offset-4 hover:text-fg sm:hidden">Open in an authenticator app on this device</a>
    </div>
    <CodeField label="Code from the app" bind:value={code} error={error || undefined} oncomplete={confirm} />
    <div class="flex gap-2">
      {#if onback}<Button variant="ghost" icon="arrow-left" onclick={onback}>Back</Button>{/if}
      <Button type="submit" class="flex-1" loading={busy}>Turn on</Button>
    </div>
  </form>
{/if}
