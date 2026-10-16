<script lang="ts">
  import { addPasskey, defaultPasskeyName, errorMessage, PasskeyError, type EnrollResult, type MfaTransport } from '../../lib/mfa';
  import Alert from '../ui/Alert.svelte';
  import Button from '../ui/Button.svelte';
  import Field from '../ui/Field.svelte';

  /** Creates a passkey on this device and registers it. */
  interface Props {
    send: MfaTransport;
    onenrolled: (result: EnrollResult) => void | Promise<void>;
    onback?: () => void;
  }

  let { send, onenrolled, onback }: Props = $props();

  let name = $state(defaultPasskeyName());
  let error = $state('');
  let notice = $state('');
  let busy = $state(false);

  async function create(e: Event) {
    e.preventDefault();
    busy = true;
    error = '';
    notice = '';
    try {
      await onenrolled(await addPasskey(send, name.trim()));
    } catch (err) {
      if (err instanceof PasskeyError && err.cancelled) notice = err.message;
      else error = errorMessage(err);
    } finally {
      busy = false;
    }
  }
</script>

<form onsubmit={create} class="flex flex-col gap-4">
  <p class="text-[13px] leading-relaxed text-muted">
    Your browser will ask you to save a passkey with Touch ID, Face ID, Windows Hello, your phone or a security key.
  </p>
  <Field label="Passkey name" bind:value={name} maxlength={60} autocomplete="off" hint="Helps you tell your passkeys apart later." />
  {#if error}<Alert tone="danger">{error}</Alert>{/if}
  {#if notice}<Alert tone="info">{notice}</Alert>{/if}
  <div class="flex gap-2">
    {#if onback}<Button variant="ghost" icon="arrow-left" onclick={onback}>Back</Button>{/if}
    <Button type="submit" class="flex-1" icon="key" loading={busy}>Create passkey</Button>
  </div>
</form>
