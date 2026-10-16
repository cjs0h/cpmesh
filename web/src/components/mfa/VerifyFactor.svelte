<script lang="ts">
  import { errorMessage, normalizeOtp, PasskeyError, passkeysSupported, verifyFactor, verifyWithPasskey, type MfaMethod, type MfaTransport, type VerifyResult } from '../../lib/mfa';
  import Alert from '../ui/Alert.svelte';
  import Button from '../ui/Button.svelte';
  import Field from '../ui/Field.svelte';
  import CodeField from './CodeField.svelte';

  /** Confirms one of the account's second factors: authenticator app code, passkey or recovery code. */
  interface Props {
    send: MfaTransport;
    methods: MfaMethod[];
    /** Called with the new tokens once a factor checked out. */
    onverified: (result: VerifyResult) => void | Promise<void>;
    submitLabel?: string;
    /** Adds a Cancel button next to the submit button. */
    oncancel?: () => void;
  }

  let { send, methods, onverified, submitLabel = 'Verify', oncancel }: Props = $props();

  type View = 'totp' | 'passkey' | 'recovery';

  const supported = passkeysSupported();
  const hasTotp = $derived(methods.includes('totp'));
  const hasPasskey = $derived(methods.includes('webauthn'));
  const hasRecovery = $derived(methods.includes('recovery'));

  // Accounts with an authenticator app start there; passkey-only accounts at the passkey
  let view = $state<View>(firstView());
  let code = $state('');
  let recoveryCode = $state('');
  let busy = $state(false);
  let error = $state('');
  let notice = $state('');

  function firstView(): View {
    if (methods.includes('totp')) return 'totp';
    if (methods.includes('webauthn')) return 'passkey';
    return 'recovery';
  }

  function show(next: View) {
    view = next;
    error = '';
    notice = '';
  }

  async function run(attempt: () => Promise<VerifyResult>) {
    if (busy) return;
    busy = true;
    error = '';
    notice = '';
    try {
      await onverified(await attempt());
    } catch (err) {
      if (err instanceof PasskeyError && err.cancelled) notice = err.message;
      else error = errorMessage(err);
      code = '';
    } finally {
      busy = false;
    }
  }

  function verifyCode(value: string) {
    const digits = normalizeOtp(value);
    if (digits.length !== 6) {
      error = 'Enter the 6-digit code from your authenticator app.';
      return;
    }
    run(() => verifyFactor(send, { method: 'totp', code: digits }));
  }

  function submitCode(e: Event) {
    e.preventDefault();
    verifyCode(code);
  }

  function submitRecovery(e: Event) {
    e.preventDefault();
    const value = recoveryCode.trim();
    if (!value) {
      error = 'Enter one of your recovery codes.';
      return;
    }
    run(() => verifyFactor(send, { method: 'recovery', code: value }));
  }

  function usePasskey() {
    show('passkey');
    run(() => verifyWithPasskey(send));
  }
</script>

{#snippet buttons()}
  <div class="flex gap-2">
    {#if oncancel}<Button variant="ghost" size="lg" disabled={busy} onclick={oncancel}>Cancel</Button>{/if}
    <Button type="submit" size="lg" class="flex-1" loading={busy}>{submitLabel}</Button>
  </div>
{/snippet}

<div class="flex flex-col gap-4">
  {#if error}<Alert tone="danger">{error}</Alert>{/if}
  {#if notice}<Alert tone="info">{notice}</Alert>{/if}

  {#if methods.length === 0}
    <Alert tone="warning">
      This account has no second factor you can use here. Ask the administrator of this server to reset two-factor authentication for you.
    </Alert>
  {:else if view === 'totp'}
    <form onsubmit={submitCode} class="flex flex-col gap-4">
      <CodeField
        label="Authentication code"
        hint="Open your authenticator app and enter the code for cpmesh."
        bind:value={code}
        autofocus
        oncomplete={verifyCode}
      />
      {@render buttons()}
    </form>
  {:else if view === 'recovery'}
    <form onsubmit={submitRecovery} class="flex flex-col gap-4">
      <Field
        label="Recovery code"
        bind:value={recoveryCode}
        placeholder="xxxx-xxxx-xxxx-xxxx"
        autocomplete="off"
        autocapitalize="none"
        spellcheck={false}
        hint="Each recovery code works once."
        inputClass="font-mono"
      />
      {@render buttons()}
    </form>
  {:else if supported}
    <p class="text-[13px] leading-relaxed text-muted">
      Use the passkey you saved for this account with Touch ID, Face ID, Windows Hello, your phone or a security key.
    </p>
    <div class="flex gap-2">
      {#if oncancel}<Button variant="ghost" size="lg" disabled={busy} onclick={oncancel}>Cancel</Button>{/if}
      <Button size="lg" icon="key" class="flex-1" loading={busy} onclick={usePasskey}>Use a passkey</Button>
    </div>
  {:else}
    <Alert tone="warning">
      This browser doesn't support passkeys. {hasTotp || hasRecovery ? 'Use another option below.' : 'Open cpmesh in a browser that supports them.'}
    </Alert>
  {/if}

  {#if (hasTotp && view !== 'totp') || (hasPasskey && supported && view !== 'passkey') || (hasRecovery && view !== 'recovery')}
    <div class="flex flex-col items-start gap-2 border-t border-border pt-4">
      {#if hasTotp && view !== 'totp'}
        <Button variant="link" icon="smartphone" class="text-[13px]" onclick={() => show('totp')}>Use your authenticator app</Button>
      {/if}
      {#if hasPasskey && supported && view !== 'passkey'}
        <Button variant="link" icon="key" class="text-[13px]" disabled={busy} onclick={usePasskey}>Use a passkey</Button>
      {/if}
      {#if hasRecovery && view !== 'recovery'}
        <Button variant="link" icon="lock" class="text-[13px]" onclick={() => show('recovery')}>Use a recovery code</Button>
      {/if}
    </div>
  {/if}
</div>
