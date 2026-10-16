import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { confirmAction, confirmState, settleConfirm } from './confirm.svelte';
import { clearToasts, dismissToast, toast, toastState } from './toast.svelte';

describe('confirmAction', () => {
	afterEach(() => settleConfirm(false));

	it('opens a question and resolves with the answer', async () => {
		const answer = confirmAction({ title: 'Remove device?', tone: 'danger' });
		expect(confirmState.current).toMatchObject({ title: 'Remove device?', tone: 'danger' });
		settleConfirm(true);
		await expect(answer).resolves.toBe(true);
		expect(confirmState.current).toBeNull();
	});

	it('treats a dismissal as cancel and ignores a second settle', async () => {
		const answer = confirmAction({ title: 'Clear?' });
		settleConfirm(false);
		settleConfirm(true);
		await expect(answer).resolves.toBe(false);
	});

	it('cancels an open question when a new one replaces it', async () => {
		const first = confirmAction({ title: 'First' });
		const second = confirmAction({ title: 'Second' });
		await expect(first).resolves.toBe(false);
		expect(confirmState.current?.title).toBe('Second');
		settleConfirm(true);
		await expect(second).resolves.toBe(true);
	});
});

describe('toasts', () => {
	beforeEach(() => {
		vi.useFakeTimers();
		clearToasts();
	});

	afterEach(() => {
		clearToasts();
		vi.useRealTimers();
	});

	it('adds and auto-dismisses toasts, keeping errors longer', () => {
		toast.success('Saved', 'Done');
		toast.error('Failed');
		expect(toastState.items.map((t) => [t.kind, t.title])).toEqual([
			['success', 'Saved'],
			['error', 'Failed'],
		]);
		vi.advanceTimersByTime(3700);
		expect(toastState.items.map((t) => t.title)).toEqual(['Failed']);
		vi.advanceTimersByTime(2400);
		expect(toastState.items).toHaveLength(0);
	});

	it('keeps sticky toasts and caps the number shown', () => {
		const sticky = toast.warning('Stay', undefined, 0);
		vi.advanceTimersByTime(60_000);
		expect(toastState.items).toHaveLength(1);
		dismissToast(sticky);
		for (let i = 0; i < 6; i++) toast.info(`t${i}`);
		expect(toastState.items.map((t) => t.title)).toEqual(['t2', 't3', 't4', 't5']);
	});
});
