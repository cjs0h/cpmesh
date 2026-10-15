<script lang="ts">
  // "Confirm it's you" before sensitive actions; opened through `requestStepUp()`.
  import { finishStepUp, reauthState } from '../../lib/stores/reauth.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import StepUpForm from './StepUpForm.svelte';

  function cancel() {
    // Closing the dialog after a success lands here too, once the request is settled
    if (reauthState.open) finishStepUp(false);
  }
</script>

<Dialog
  open={reauthState.open}
  title="Confirm it's you"
  description={reauthState.reason || "For your security, confirm it's you to continue."}
  size="sm"
  onclose={cancel}
>
  {#if reauthState.open}
    <StepUpForm onconfirmed={() => finishStepUp(true)} oncancel={cancel} />
  {/if}
</Dialog>
