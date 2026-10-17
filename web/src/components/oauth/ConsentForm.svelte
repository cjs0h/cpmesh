<script lang="ts">
  import { onMount, type Snippet } from 'svelte';
  import { defaultScopes, SCOPE_INFO, scopeLabel, type Decision, type Scope } from '../../lib/oauth';
  import { resetUserState, userState } from '../../lib/stores/user.svelte';
  import { disconnectWS } from '../../lib/ws';
  import Alert from '../ui/Alert.svelte';
  import Button from '../ui/Button.svelte';
  import IconTile from '../ui/IconTile.svelte';
  import Switch from '../ui/Switch.svelte';

  /**
   * What an AI agent asks for and the user's answer: the agent as it describes itself,
   * a switch per scope it asked for, then Approve or Deny. Nothing is approved
   * without a click on Approve.
   */
  interface Props {
    clientName: string;
    /** As reported by the agent; may be empty. */
    agentName: string;
    /** The scopes the agent asked for: only these are offered. */
    requested: Scope[];
    /** The answer being sent. */
    busy: Decision | null;
    error?: string;
    onapprove: (scopes: Scope[]) => void;
    ondeny: () => void;
    /** Facts about the request: `DetailRow`s. */
    details?: Snippet;
    /** Shown above the buttons. */
    notice?: Snippet;
  }

  let { clientName, agentName, requested, busy, error = '', onapprove, ondeny, details, notice }: Props = $props();

  /** Approve only works after this long, so a click meant for something else can't land on it. */
  const ARM_DELAY_MS = 600;

  const uid = $props.id();
  const defaults = $derived(defaultScopes(requested));
  /** The switches the user flipped; the others keep their defaults. */
  const choices: Partial<Record<Scope, boolean>> = $state({});
  const isOn = (scope: Scope) => choices[scope] ?? defaults.includes(scope);
  const selected = $derived(requested.filter(isOn));
  let armed = $state(false);

  onMount(() => {
    const timer = setTimeout(() => (armed = true), ARM_DELAY_MS);
    return () => clearTimeout(timer);
  });

  function useAnotherAccount() {
    // Signed out, this page shows the sign-in form, then continues with the request
    disconnectWS();
    resetUserState();
  }
</script>

<div class="flex flex-col gap-5">
  <div class="flex items-start gap-3">
    <IconTile icon="sparkles" size={40} />
    <div class="min-w-0">
      <p class="text-[15px] font-medium text-fg">{clientName}</p>
      {#if agentName}
        <p class="mt-0.5 break-words text-sm text-fg"><bdi>{agentName}</bdi></p>
        <p class="mt-0.5 text-xs text-dim">Name reported by the agent. cpmesh can't verify it.</p>
      {:else}
        <p class="mt-0.5 text-xs text-dim">The agent didn't report a name.</p>
      {/if}
    </div>
  </div>

  {#if details}
    <dl class="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 rounded-md border border-border bg-bg-deep px-3.5 py-3 text-[13px]">
      {@render details()}
    </dl>
  {/if}

  <div role="group" aria-labelledby="{uid}-scopes">
    <p id="{uid}-scopes" class="text-[13px] font-medium text-fg">Allow this agent to</p>
    <div class="mt-3 flex flex-col gap-3.5">
      {#each requested as scope (scope)}
        <Switch
          checked={isOn(scope)}
          onchange={(e) => (choices[scope] = e.currentTarget.checked)}
          label={scopeLabel(scope)}
          description={SCOPE_INFO[scope].description}
          disabled={busy !== null}
        />
      {/each}
    </div>
  </div>

  {#if notice}{@render notice()}{/if}
  {#if error}<Alert tone="danger">{error}</Alert>{/if}

  <div class="flex flex-col gap-2">
    <div class="flex gap-2">
      <Button variant="secondary" size="lg" class="flex-1" loading={busy === 'deny'} disabled={busy !== null} onclick={ondeny}>Deny</Button>
      <Button size="lg" class="flex-1" loading={busy === 'approve'} disabled={!armed || busy !== null || selected.length === 0} onclick={() => onapprove(selected)}>
        Approve
      </Button>
    </div>
    {#if selected.length === 0}
      <p class="text-center text-xs text-dim">Turn on at least one permission to approve.</p>
    {/if}
  </div>

  <p class="border-t border-border pt-4 text-center text-xs text-dim">
    Signed in as <span class="font-medium text-fg">{userState.username ? `@${userState.username}` : userState.email}</span>
    ·
    <button type="button" class="underline underline-offset-4 transition-colors hover:text-fg" onclick={useAnotherAccount}>Use another account</button>
  </p>
</div>
