<script lang="ts">
  import { onMount } from 'svelte';
  import { router } from 'svelte-spa-router';
  import { ApiError } from '../lib/api';
  import { errorMessage } from '../lib/mfa';
  import { decideAuthorization, isStepUpRequired, parseAuthorizeRequest, type Decision, type Scope } from '../lib/oauth';
  import ConsentForm from '../components/oauth/ConsentForm.svelte';
  import ConsentShell from '../components/oauth/ConsentShell.svelte';
  import DetailRow from '../components/oauth/DetailRow.svelte';
  import Alert from '../components/ui/Alert.svelte';
  import Button from '../components/ui/Button.svelte';
  import IconTile from '../components/ui/IconTile.svelte';

  // An AI agent on this computer opened `/oauth/authorize`, and the server sent the
  // browser here with the request. Anyone can craft this link: nothing happens until
  // the user answers, and the server checks the answer again.
  const parsed = parseAuthorizeRequest(router.querystring);

  let busy = $state<Decision | null>(null);
  let error = $state('');
  /** The answer was accepted: the browser is on its way to the agent. */
  let sent = $state<Decision | null>(null);

  onMount(() => {
    // The dashboard's pages keep the default title, so give it back when leaving
    const previous = document.title;
    document.title = `Approve ${parsed.request?.clientName ?? 'an AI agent'} — cpmesh`;
    return () => {
      document.title = previous;
    };
  });

  async function decide(decision: Decision, scopes: Scope[] = []) {
    if (!parsed.request || busy) return;
    busy = decision;
    error = '';
    try {
      const url = await decideAuthorization(parsed.request, decision, scopes);
      sent = decision;
      // Top-level navigation to the agent; replacing this page, which can't be answered twice
      window.location.replace(url);
    } catch (err) {
      error = failure(err);
    } finally {
      busy = null;
    }
  }

  function failure(err: unknown): string {
    if (isStepUpRequired(err)) return "Confirm it's you to answer the agent.";
    if (err instanceof ApiError && err.status === 400) {
      return `This request can't be used (${err.message}). Start signing in again from your agent.`;
    }
    return errorMessage(err);
  }
</script>

{#if !parsed.request}
  <ConsentShell title="This link can't be used" subtitle="Start signing in again from your agent.">
    <div class="flex flex-col gap-4">
      <Alert tone="danger" title="The sign-in link is incomplete or was changed">{parsed.error}</Alert>
      <Button href="#/" variant="secondary" size="lg" class="w-full">Go to the dashboard</Button>
    </div>
  </ConsentShell>
{:else if sent}
  <ConsentShell title={sent === 'approve' ? 'Agent approved' : 'Request denied'}>
    <div class="flex flex-col items-center gap-4 py-2 text-center" role="status">
      <IconTile icon={sent === 'approve' ? 'check' : 'x'} size={44} />
      <div>
        <h2 class="text-base font-semibold text-fg">Returning to your agent…</h2>
        <p class="mt-1 text-[13px] leading-relaxed text-muted">
          {#if sent === 'approve'}
            Your browser hands the approval to the agent on this computer. Next, it asks you to pair it on one of your devices.
          {:else}
            Your browser tells the agent on this computer that you said no. It doesn't get access.
          {/if}
        </p>
      </div>
      <p class="text-xs text-dim">You can close this tab once your agent confirms.</p>
    </div>
  </ConsentShell>
{:else}
  {@const request = parsed.request}
  <ConsentShell title="Approve {request.clientName}" subtitle="An AI agent on this computer wants to use your cpmesh account.">
    <ConsentForm
      clientName={request.clientName}
      agentName={request.agentName}
      requested={request.scopes}
      {busy}
      {error}
      onapprove={(scopes) => decide('approve', scopes)}
      ondeny={() => decide('deny')}
    >
      {#snippet details()}
        <DetailRow label="Answer goes to"><span class="font-mono text-[12.5px]">{request.listener}</span> on this computer</DetailRow>
      {/snippet}
      {#snippet notice()}
        <Alert tone="info">After you approve, pair the agent on one of your devices by comparing its 8-digit code. Until then it can't read or send anything.</Alert>
      {/snippet}
    </ConsentForm>
  </ConsentShell>
{/if}
