import { afterEach, describe, expect, it } from 'vitest';
import { finishStepUp, reauthState, requestStepUp } from './reauth.svelte';

describe('step-up store', () => {
  afterEach(() => {
    // Settle anything a failing test left open
    finishStepUp(false);
  });

  it('opens the dialog with a reason and resolves once confirmed', async () => {
    const answer = requestStepUp('Confirm to remove the passkey.');
    expect(reauthState.open).toBe(true);
    expect(reauthState.reason).toBe('Confirm to remove the passkey.');

    finishStepUp(true);

    await expect(answer).resolves.toBe(true);
    expect(reauthState.open).toBe(false);
    expect(reauthState.reason).toBe('');
  });

  it('resolves false when the user cancels', async () => {
    const answer = requestStepUp();
    expect(reauthState.open).toBe(true);
    expect(reauthState.reason).toBe('');

    finishStepUp(false);

    await expect(answer).resolves.toBe(false);
    expect(reauthState.open).toBe(false);
  });

  it('answers concurrent requests together, keeping the first reason', async () => {
    const first = requestStepUp('first');
    const second = requestStepUp('second');
    expect(reauthState.reason).toBe('first');

    finishStepUp(true);

    await expect(first).resolves.toBe(true);
    await expect(second).resolves.toBe(true);
  });

  it('can be asked again after an answer', async () => {
    const first = requestStepUp();
    finishStepUp(false);
    await expect(first).resolves.toBe(false);

    const second = requestStepUp('again');
    expect(reauthState.open).toBe(true);
    finishStepUp(true);
    await expect(second).resolves.toBe(true);
  });

  it('ignores a finish without a pending request', () => {
    expect(() => finishStepUp(true)).not.toThrow();
    expect(reauthState.open).toBe(false);
  });
});
