<script lang="ts">
  import { onMount, type Snippet } from 'svelte';
  import { adminGate } from '../../lib/stores/admin.svelte';
  import { requestStepUp } from '../../lib/stores/reauth.svelte';
  import Button from '../ui/Button.svelte';
  import EmptyState from '../ui/EmptyState.svelte';

  /**
   * Wraps an admin page. The console only answers sessions confirmed with a second
   * factor; when the server refuses (`mfa_required`), the page is replaced by the way
   * forward: confirm the second factor now, or set one up first.
   */
  interface Props {
    /** Reloads the page's data once the session is confirmed. */
    onunlock?: () => unknown;
    children: Snippet;
  }

  let { onunlock, children }: Props = $props();
  let busy = $state(false);

  // An answer from another page may be stale (2FA was set up since): ask again
  onMount(() => {
    adminGate.required = false;
  });

  async function confirm() {
    busy = true;
    try {
      if (!(await requestStepUp('Confirm your second factor to open the admin console.'))) return;
      adminGate.required = false;
      await onunlock?.();
    } finally {
      busy = false;
    }
  }

  async function retry() {
    busy = true;
    try {
      await onunlock?.();
    } finally {
      busy = false;
    }
  }
</script>

{#if adminGate.required}
  {#if adminGate.enrolled}
    <EmptyState icon="shield-check" title="Confirm your second factor to continue" description="The admin console needs a session confirmed with your authenticator app or a passkey.">
      <Button icon="shield-check" loading={busy} onclick={confirm}>Confirm it's you</Button>
    </EmptyState>
  {:else}
    <EmptyState icon="lock" title="Set up two-factor authentication to use the admin console" description="Add an authenticator app or a passkey to your account. Staff accounts need a second factor to manage this server.">
      <Button href="#/settings" icon="shield">Set up two-factor authentication</Button>
      {#if onunlock}<Button variant="ghost" icon="refresh" loading={busy} onclick={retry}>Try again</Button>{/if}
    </EmptyState>
  {/if}
{:else}
  {@render children()}
{/if}
