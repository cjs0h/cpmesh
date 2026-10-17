<script lang="ts">
  import { onMount } from 'svelte';
  import { router } from 'svelte-spa-router';
  import { ApiError } from '../lib/api';
  import { createClock } from '../lib/clock.svelte';
  import { absoluteTime, relativeTime } from '../lib/format';
  import { errorMessage } from '../lib/mfa';
  import {
    approveDeviceRequest,
    denyDeviceRequest,
    formatUserCode,
    isStepUpRequired,
    knownScopes,
    lookupDeviceRequest,
    normalizeUserCode,
    parseScopes,
    SCOPE_INFO,
    type Decision,
    type DeviceRequest,
    type Scope,
  } from '../lib/oauth';
  import ConsentForm from '../components/oauth/ConsentForm.svelte';
  import ConsentShell from '../components/oauth/ConsentShell.svelte';
  import DetailRow from '../components/oauth/DetailRow.svelte';
  import Alert from '../components/ui/Alert.svelte';
  import Badge from '../components/ui/Badge.svelte';
  import Button from '../components/ui/Button.svelte';
  import Field from '../components/ui/Field.svelte';
  import IconTile from '../components/ui/IconTile.svelte';

  // The device flow: an agent without a browser on its computer (SSH, a container)
  // shows a code; the user enters it here (or follows the agent's link, which fills it
  // in), checks the request and answers it.

  type Step = 'enter' | 'review' | 'approved' | 'denied' | 'gone';

  const TOO_MANY = 'Too many attempts. Wait a minute, then try again.';

  const clock = createClock(15_000);

  let step = $state<Step>('enter');
  let code = $state(asTyped(new URLSearchParams(router.querystring ?? '').get('user_code') ?? ''));
  let codeError = $state('');
  let looking = $state(false);
  let request = $state<DeviceRequest | null>(null);
  let busy = $state<Decision | null>(null);
  let error = $state('');
  /** What the agent may do, once approved. */
  let granted = $state<Scope[]>([]);

  onMount(() => {
    // The dashboard's pages keep the default title, so give it back when leaving
    const previous = document.title;
    document.title = 'Approve an AI agent — cpmesh';
    return () => {
      document.title = previous;
    };
  });

  /** The code formatted (`BCDF-GHJK`) when it is one, else as typed. */
  function asTyped(value: string): string {
    const normalized = normalizeUserCode(value);
    return normalized ? formatUserCode(normalized) : value.slice(0, 64);
  }

  async function lookUp(e: SubmitEvent) {
    e.preventDefault();
    const normalized = normalizeUserCode(code);
    if (!normalized) {
      codeError = 'Enter the 8 letters your agent shows, like BCDF-GHJK.';
      return;
    }
    code = formatUserCode(normalized);
    codeError = '';
    looking = true;
    try {
      request = await lookupDeviceRequest(code);
      error = '';
      step = 'review';
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        codeError = 'This code is wrong or has expired, or it was already used. Check it, or start signing in again from your agent.';
      } else if (err instanceof ApiError && err.status === 429) {
        codeError = TOO_MANY;
      } else {
        codeError = errorMessage(err);
      }
    } finally {
      looking = false;
    }
  }

  async function decide(decision: Decision, scopes: Scope[] = []) {
    if (!request || busy) return;
    busy = decision;
    error = '';
    try {
      if (decision === 'approve') {
        const result = await approveDeviceRequest(request.user_code, scopes);
        granted = parseScopes(result.scope) ?? scopes;
        step = 'approved';
      } else {
        await denyDeviceRequest(request.user_code);
        step = 'denied';
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) step = 'gone';
      else if (err instanceof ApiError && err.status === 429) error = TOO_MANY;
      else if (isStepUpRequired(err)) error = "Confirm it's you to answer the agent.";
      else error = errorMessage(err);
    } finally {
      busy = null;
    }
  }

  function startOver() {
    step = 'enter';
    request = null;
    code = '';
    codeError = '';
    error = '';
  }

  /** "expires in 8 min" (never more than is left) until `expiresAt`, then "expired". */
  function expiry(expiresAt: string, now: number): string {
    const left = Date.parse(expiresAt) - now;
    if (Number.isNaN(left)) return '';
    if (left <= 0) return 'expired';
    const minutes = Math.floor(left / 60_000);
    return minutes > 0 ? `expires in ${minutes} min` : 'expires in less than a minute';
  }
</script>

{#if step === 'review' && request}
  {@const r = request}
  <ConsentShell title="Approve {r.client_name ?? 'an AI agent'}" subtitle="Check the request before you answer it.">
    <ConsentForm
      clientName={r.client_name ?? r.client_id}
      agentName={r.agent_name}
      requested={knownScopes(r.scopes)}
      {busy}
      {error}
      onapprove={(scopes) => decide('approve', scopes)}
      ondeny={() => decide('deny')}
    >
      {#snippet details()}
        <DetailRow label="Code"><span class="font-mono tracking-[0.08em]">{r.user_code}</span> <span class="text-muted">· your agent shows the same</span></DetailRow>
        <DetailRow label="IP address"><span class="font-mono text-[12.5px]">{r.requester_ip}</span></DetailRow>
        <DetailRow label="User agent">{#if r.user_agent}<bdi class="font-mono text-[12.5px]">{r.user_agent}</bdi>{:else}<span class="text-muted">Not reported</span>{/if}</DetailRow>
        <DetailRow label="Requested">
          <time datetime={r.created_at} title={absoluteTime(r.created_at)}>{relativeTime(r.created_at, clock.now)}</time>
          <span class="text-muted">· {expiry(r.expires_at, clock.now)}</span>
        </DetailRow>
      {/snippet}
      {#snippet notice()}
        <Alert tone="warning">
          Only approve if you just started this from your AI agent. It still has to be paired on one of your devices before it can read your clipboard.
        </Alert>
      {/snippet}
    </ConsentForm>
    <div class="mt-4 text-center">
      <button type="button" class="text-xs text-muted underline underline-offset-4 transition-colors hover:text-fg" disabled={busy !== null} onclick={startOver}>
        Enter a different code
      </button>
    </div>
  </ConsentShell>
{:else if step === 'approved'}
  <ConsentShell title="Agent approved">
    <div class="flex flex-col items-center gap-4 py-2 text-center" role="status">
      <IconTile icon="check" size={44} />
      <div>
        <h2 class="text-base font-semibold text-fg">Go back to your agent; it continues on its own</h2>
        <p class="mt-1 text-[13px] leading-relaxed text-muted">
          Next, it asks you to pair it on one of your devices. Compare the 8-digit code on both before you confirm.
        </p>
      </div>
      {#if granted.length}
        <ul class="flex flex-wrap justify-center gap-1.5" aria-label="Allowed">
          {#each granted as scope (scope)}
            <li><Badge icon={SCOPE_INFO[scope].icon}>{SCOPE_INFO[scope].short}</Badge></li>
          {/each}
        </ul>
      {/if}
      <Button href="#/mcp" variant="secondary" icon="sparkles">See connected agents</Button>
    </div>
  </ConsentShell>
{:else if step === 'denied'}
  <ConsentShell title="Request denied">
    <div class="flex flex-col items-center gap-4 py-2 text-center" role="status">
      <IconTile icon="x" size={44} />
      <div>
        <h2 class="text-base font-semibold text-fg">The agent doesn't get access</h2>
        <p class="mt-1 text-[13px] leading-relaxed text-muted">It learns that you said no the next time it checks. You can close this tab.</p>
      </div>
    </div>
  </ConsentShell>
{:else if step === 'gone'}
  <ConsentShell title="This request has ended">
    <div class="flex flex-col gap-4">
      <Alert tone="warning">It expired or was already answered. Start signing in again from your agent, then enter its new code.</Alert>
      <Button size="lg" class="w-full" onclick={startOver}>Enter another code</Button>
    </div>
  </ConsentShell>
{:else}
  <ConsentShell title="Approve an AI agent" subtitle="Enter the code your agent shows.">
    <form onsubmit={lookUp} class="flex flex-col gap-4" novalidate>
      <Field
        label="Code from your agent"
        bind:value={code}
        error={codeError}
        hint="8 letters, like BCDF-GHJK"
        required
        maxlength={64}
        autocomplete="off"
        autocapitalize="characters"
        spellcheck="false"
        inputClass="text-center font-mono text-base uppercase tracking-[0.2em]"
      />
      <Button type="submit" size="lg" class="w-full" loading={looking}>Continue</Button>
    </form>
    <p class="mt-5 border-t border-border pt-4 text-center text-xs leading-relaxed text-dim">
      Agents show a code when they can't open a browser on their computer, for example over SSH or in a container.
    </p>
  </ConsentShell>
{/if}
