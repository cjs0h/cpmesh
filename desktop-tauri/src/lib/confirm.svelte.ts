// In-app confirmation dialogs, replacing window.confirm (which webviews render
// inconsistently, or not at all). Rendered once by ConfirmHost in the root layout.

export interface ConfirmOptions {
	title: string;
	description?: string;
	confirmLabel?: string;
	cancelLabel?: string;
	/** Destructive actions get a red confirm button. */
	tone?: 'default' | 'danger';
}

interface PendingConfirm extends ConfirmOptions {
	resolve: (confirmed: boolean) => void;
}

export const confirmState: { current: PendingConfirm | null } = $state({ current: null });

/** Resolves true when the user confirms, false when they cancel or dismiss. */
export function confirmAction(options: ConfirmOptions): Promise<boolean> {
	// A newer question replaces one left open
	confirmState.current?.resolve(false);
	return new Promise((resolve) => {
		confirmState.current = { ...options, resolve };
	});
}

export function settleConfirm(confirmed: boolean) {
	const pending = confirmState.current;
	confirmState.current = null;
	pending?.resolve(confirmed);
}
