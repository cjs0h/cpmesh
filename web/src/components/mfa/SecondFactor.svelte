<script lang="ts">
  import { untrack } from 'svelte';
  import { ticketTransport, type EnrollResult, type MfaChallenge, type SessionTokens } from '../../lib/mfa';
  import Button from '../ui/Button.svelte';
  import EmailCode from './EmailCode.svelte';
  import EnrollFactor from './EnrollFactor.svelte';
  import RecoveryCodes from './RecoveryCodes.svelte';
  import VerifyFactor from './VerifyFactor.svelte';

  /**
   * The second step of a sign-in, on the sign-in ticket: confirm a factor the account
   * has, or set one up (after confirming an emailed code when the server asks for it).
   */
  interface Props {
    challenge: MfaChallenge;
    /** Called with the session once the sign-in is complete. */
    oncomplete: (tokens: SessionTokens) => void | Promise<void>;
    /** Back to the first step. */
    oncancel: () => void;
  }

  let { challenge, oncomplete, oncancel }: Props = $props();

  // Confirming the emailed code replaces the ticket, so both start from the challenge
  let ticket = $state(untrack(() => challenge.mfa_token));
  let emailConfirmed = $state(untrack(() => !challenge.email_code_required));
  let enrolled = $state<EnrollResult | null>(null);
  const send = ticketTransport(() => ticket);

  async function handleEnrolled(result: EnrollResult) {
    // The first factor comes with recovery codes: show them before finishing
    if (result.recovery_codes?.length) enrolled = result;
    else await oncomplete(result);
  }
</script>

<div class="flex flex-col gap-5">
  {#if enrolled?.recovery_codes}
    <RecoveryCodes codes={enrolled.recovery_codes} onconfirm={() => oncomplete(enrolled!)} />
  {:else if challenge.stage === 'verify'}
    <VerifyFactor {send} methods={challenge.methods} onverified={oncomplete} />
  {:else if !emailConfirmed}
    <EmailCode
      {send}
      emailHint={challenge.email_hint}
      onconfirmed={(next) => {
        ticket = next;
        emailConfirmed = true;
      }}
    />
  {:else}
    <EnrollFactor {send} passkeysAvailable={challenge.passkeys_available} onenrolled={handleEnrolled} />
  {/if}

  {#if !enrolled}
    <div class="text-center">
      <Button variant="ghost" size="sm" icon="arrow-left" onclick={oncancel}>Back to sign in</Button>
    </div>
  {/if}
</div>
