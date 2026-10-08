import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { clearToasts, dismissToast, toast, toastState } from './toast.svelte';

describe('toast store', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    clearToasts();
  });

  afterEach(() => {
    clearToasts();
    vi.useRealTimers();
  });

  it('adds toasts with kind, title and description', () => {
    const id = toast.success('Saved', 'Your changes were stored.');
    expect(toastState.items).toHaveLength(1);
    expect(toastState.items[0]).toMatchObject({ id, kind: 'success', title: 'Saved', description: 'Your changes were stored.' });
  });

  it('auto-dismisses after the duration and errors linger longer', () => {
    toast.info('Quick');
    toast.error('Slow');
    expect(toastState.items.map((t) => t.title)).toEqual(['Quick', 'Slow']);

    vi.advanceTimersByTime(4200);
    expect(toastState.items.map((t) => t.title)).toEqual(['Slow']);

    vi.advanceTimersByTime(1800);
    expect(toastState.items).toHaveLength(0);
  });

  it('keeps sticky toasts until dismissed explicitly', () => {
    const id = toast.warning('Stay', undefined, 0);
    vi.advanceTimersByTime(60_000);
    expect(toastState.items).toHaveLength(1);
    dismissToast(id);
    expect(toastState.items).toHaveLength(0);
  });

  it('caps the number of visible toasts', () => {
    for (let i = 0; i < 6; i++) toast.info(`t${i}`);
    expect(toastState.items.map((t) => t.title)).toEqual(['t2', 't3', 't4', 't5']);
  });

  it('dismissing an unknown id is a no-op', () => {
    toast.info('x');
    expect(() => dismissToast(999)).not.toThrow();
    expect(toastState.items).toHaveLength(1);
  });
});
