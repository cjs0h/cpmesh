<script lang="ts">
  import { passkeysSupported, type EnrollResult, type MfaTransport } from '../../lib/mfa';
  import Icon from '../Icon.svelte';
  import Badge from '../ui/Badge.svelte';
  import IconTile from '../ui/IconTile.svelte';
  import PasskeySetup from './PasskeySetup.svelte';
  import TotpSetup from './TotpSetup.svelte';

  /** Picks and sets up a second factor: an authenticator app or a passkey. */
  interface Props {
    send: MfaTransport;
    /** Whether the server accepts passkeys. */
    passkeysAvailable: boolean;
    onenrolled: (result: EnrollResult) => void | Promise<void>;
  }

  let { send, passkeysAvailable, onenrolled }: Props = $props();

  let method = $state<'totp' | 'webauthn' | null>(null);
  const supported = passkeysSupported();
  const passkeyNote = $derived(
    !passkeysAvailable ? 'Not enabled on this server.' : !supported ? "This browser doesn't support passkeys." : '',
  );

  const option =
    'flex w-full items-center gap-3 rounded-lg border border-border bg-surface p-3.5 text-left transition-colors duration-150 ' +
    'hover:border-border-strong hover:bg-bg-deep disabled:pointer-events-none disabled:opacity-60';
</script>

{#if method === 'totp'}
  <TotpSetup {send} {onenrolled} onback={() => (method = null)} />
{:else if method === 'webauthn'}
  <PasskeySetup {send} {onenrolled} onback={() => (method = null)} />
{:else}
  <div class="flex flex-col gap-3">
    <button type="button" class={option} onclick={() => (method = 'totp')}>
      <IconTile icon="smartphone" />
      <span class="min-w-0 flex-1">
        <span class="flex flex-wrap items-center gap-2 text-sm font-medium text-fg">Authenticator app <Badge>Recommended</Badge></span>
        <span class="mt-0.5 block text-[13px] text-muted">6-digit codes from 1Password, Google Authenticator, Authy or a similar app.</span>
      </span>
      <Icon name="chevron-right" size={16} class="text-dim" />
    </button>
    <button type="button" class={option} disabled={!!passkeyNote} onclick={() => (method = 'webauthn')}>
      <IconTile icon="key" />
      <span class="min-w-0 flex-1">
        <span class="block text-sm font-medium text-fg">Passkey</span>
        <span class="mt-0.5 block text-[13px] text-muted">{passkeyNote || 'Touch ID, Face ID, Windows Hello, your phone or a security key.'}</span>
      </span>
      <Icon name="chevron-right" size={16} class="text-dim" />
    </button>
    <p class="text-xs leading-relaxed text-dim">
      The desktop app asks for a code from an authenticator app, so we recommend setting one up. You can add more methods later in Settings.
    </p>
  </div>
{/if}
