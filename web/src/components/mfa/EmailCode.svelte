<script lang="ts">
  import { onMount } from 'svelte';
  import { ApiError } from '../../lib/api';
  import { errorMessage, normalizeOtp, sendEmailCode, verifyEmailCode, type MfaTransport } from '../../lib/mfa';
  import Alert from '../ui/Alert.svelte';
  import Button from '../ui/Button.svelte';
  import CodeField from './CodeField.svelte';

  /**
   * Before setting up a factor after a password sign-in, the user confirms a code emailed
   * to the account, so a leaked password alone can't enroll someone else's authenticator.
   */
  interface Props {
    send: MfaTransport;
    emailHint: string | null;
    /** Called with the new sign-in ticket, which replaces the old one. */
    onconfirmed: (ticket: string) => void;
  }

  let { send, emailHint, onconfirmed }: Props = $props();

  let hint = $state<string | null>(null);
  let sending = $state(false);
  let sent = $state(false);
  let verifying = $state(false);
  let code = $state('');
  let error = $state('');
  let notice = $state('');

  const destination = $derived(hint ?? emailHint ?? 'your email address');

  onMount(requestCode);

  async function requestCode() {
    sending = true;
    error = '';
    notice = '';
    try {
      const result = await sendEmailCode(send);
      hint = result.email_hint ?? hint;
      sent = true;
    } catch (err) {
      // 429: one was sent moments ago, and it still works
      if (err instanceof ApiError && err.status === 429) {
        sent = true;
        notice = errorMessage(err);
      } else {
        error = errorMessage(err);
      }
    } finally {
      sending = false;
    }
  }

  async function verify(value: string) {
    if (verifying) return;
    const digits = normalizeOtp(value);
    if (digits.length !== 6) {
      error = 'Enter the 6-digit code from the email.';
      return;
    }
    verifying = true;
    error = '';
    notice = '';
    try {
      onconfirmed(await verifyEmailCode(send, digits));
    } catch (err) {
      error = errorMessage(err);
      code = '';
    } finally {
      verifying = false;
    }
  }

  function submit(e: Event) {
    e.preventDefault();
    verify(code);
  }
</script>

<form onsubmit={submit} class="flex flex-col gap-4">
  <p class="text-[13px] leading-relaxed text-muted">
    {#if sent}
      We emailed a code to <span class="font-medium text-fg">{destination}</span>. Enter it to confirm it's you before you set up two-factor authentication.
    {:else}
      First, confirm it's you with a code we email to <span class="font-medium text-fg">{destination}</span>.
    {/if}
  </p>
  {#if error}<Alert tone="danger">{error}</Alert>{/if}
  {#if notice}<Alert tone="info">{notice}</Alert>{/if}
  <CodeField label="Code from the email" bind:value={code} autofocus oncomplete={verify} />
  <Button type="submit" size="lg" class="w-full" loading={verifying}>Continue</Button>
  <p class="text-center text-[13px] text-muted">
    Didn't get it?
    <Button variant="link" class="text-[13px]" disabled={sending} onclick={requestCode}>{sending ? 'Sending…' : 'Send a new code'}</Button>
  </p>
</form>
