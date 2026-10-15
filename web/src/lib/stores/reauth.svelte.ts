// Step-up confirmation ("confirm it's you") shared by the whole app.
//
// Sensitive actions answer `reauth_required` until the user confirms their second
// factor (or their password, when they have none). `api()` calls the registered
// handler, which opens the dialog through `requestStepUp`; the dialog resolves the
// request with `finishStepUp` after storing the refreshed session.

export const reauthState: { open: boolean; reason: string } = $state({
  open: false,
  reason: '',
});

let pending: ((confirmed: boolean) => void) | null = null;

/** Opens the confirmation dialog; resolves `true` once the session was refreshed. */
export function requestStepUp(reason = ''): Promise<boolean> {
  // A second request while the dialog is open waits for the same answer
  if (pending) {
    const previous = pending;
    return new Promise((resolve) => {
      pending = (confirmed) => {
        previous(confirmed);
        resolve(confirmed);
      };
    });
  }
  reauthState.reason = reason;
  reauthState.open = true;
  return new Promise((resolve) => {
    pending = resolve;
  });
}

/** Called by the dialog when the user confirmed (`true`) or cancelled (`false`). */
export function finishStepUp(confirmed: boolean) {
  const resolve = pending;
  pending = null;
  reauthState.open = false;
  reauthState.reason = '';
  resolve?.(confirmed);
}
