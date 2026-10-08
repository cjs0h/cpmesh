<script lang="ts">
	import { onMount } from 'svelte';
	import {
		getDevices,
		removeDevice,
		getPendingDevices,
		beginDeviceApproval,
		confirmDeviceApproval,
		rejectPendingDevice,
		type DeviceInfo,
		type PendingDevice,
		type ApprovalSession
	} from '#lib/api.js';
	import { listen, type UnlistenFn } from '@tauri-apps/api/event';

	let devices = $state<DeviceInfo[]>([]);
	let pendingDevices = $state<PendingDevice[]>([]);
	let loading = $state(true);
	let error = $state('');
	let removingId = $state<string | null>(null);
	let rejectingId = $state<string | null>(null);

	// Approval modal state
	let approvalSession = $state<ApprovalSession | null>(null);
	let approvingDeviceId = $state<string | null>(null);
	let approvingDeviceName = $state('');
	let approving = $state(false);
	let confirming = $state(false);
	let approvalError = $state('');
	let successMessage = $state('');

	function friendlyError(raw: string): string {
		const s = String(raw);
		if (s.includes('version conflict')) return 'Another device updated the encryption keys at the same time. Please try again.';
		if (s.includes('Encryption not initialized')) return 'Encryption is not ready. Try restarting the app.';
		if (s.includes('no active approval session') || s.includes('Session expired')) return 'The approval session expired. Please start over.';
		if (s.includes('session_id mismatch')) return 'The approval session has changed. Please start over.';
		if (s.includes('not the approver')) return 'Only the device that started approval can confirm it.';
		return 'Something went wrong. Please try again.';
	}

	async function loadDevices() {
		loading = true;
		error = '';
		try {
			const [devs, pending] = await Promise.all([
				getDevices(),
				getPendingDevices().catch((e) => {
					console.warn('Failed to load pending devices:', e);
					return [] as PendingDevice[];
				})
			]);
			// Filter out pending/rejected/revoked from the main list — they show in their own section
			const pendingIds = new Set(pending.map((d) => d.id));
			devices = devs.filter((d) => d.status === 'approved' && !pendingIds.has(d.id));
			pendingDevices = pending;
		} catch (e) {
			error = String(e);
			console.error('Failed to load devices:', e);
		} finally {
			loading = false;
		}
	}

	async function handleRemove(id: string, name: string) {
		if (!confirm(`Remove device "${name}"? This cannot be undone.`)) return;
		removingId = id;
		try {
			await removeDevice(id);
			devices = devices.filter((d) => d.id !== id);
		} catch (e) {
			error = `Failed to remove device: ${e}`;
			console.error('handleRemove:', e);
		} finally {
			removingId = null;
		}
	}

	async function handleBeginApproval(device: PendingDevice) {
		approvalError = '';
		approvingDeviceId = device.id;
		approvingDeviceName = device.name;
		approving = true;
		try {
			approvalSession = await beginDeviceApproval(device.id);
		} catch (e) {
			approvalError = friendlyError(String(e));
			console.error('Begin approval failed:', e);
		}
	}

	async function handleConfirmApproval() {
		if (!approvingDeviceId || !approvalSession || confirming) return;
		approvalError = '';
		confirming = true;
		try {
			await confirmDeviceApproval(approvingDeviceId, approvalSession.session_id);
			closeApprovalModal();
			successMessage = 'Device approved successfully.';
			setTimeout(() => { successMessage = ''; }, 3000);
			await loadDevices();
		} catch (e) {
			approvalError = friendlyError(String(e));
			console.error('Confirm approval failed:', e);
		} finally {
			confirming = false;
		}
	}

	async function handleReject(device: PendingDevice) {
		if (!confirm(`Reject device "${device.name}"?`)) return;
		rejectingId = device.id;
		try {
			await rejectPendingDevice(device.id);
			pendingDevices = pendingDevices.filter((d) => d.id !== device.id);
		} catch (e) {
			error = `Failed to reject device: ${e}`;
			console.error('handleReject:', e);
		} finally {
			rejectingId = null;
		}
	}

	function closeApprovalModal() {
		approvalSession = null;
		approvingDeviceId = null;
		approvingDeviceName = '';
		approving = false;
		confirming = false;
		approvalError = '';
	}

	function formatLastSeen(ts?: string): string {
		if (!ts) return 'Never';
		const d = new Date(ts);
		const now = new Date();
		const diff = now.getTime() - d.getTime();
		if (diff < 60000) return 'Just now';
		if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
		if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
		return d.toLocaleDateString();
	}

	function formatDate(ts: string): string {
		return new Date(ts).toLocaleString();
	}

	onMount(() => {
		loadDevices();
		let unlisten: UnlistenFn | undefined;
		listen('device-status-changed', () => loadDevices()).then((u) => { unlisten = u; });
		return () => { unlisten?.(); };
	});
</script>

<div class="devices-page">
	<h1>Devices</h1>

	{#if successMessage}
		<p class="success">{successMessage}</p>
	{/if}

	{#if error}
		<p class="error">{error}</p>
	{/if}

	{#if loading}
		<p class="loading">Loading devices...</p>
	{:else}
		<!-- Pending devices section -->
		{#if pendingDevices.length > 0}
			<div class="section-header">Pending Approval</div>
			<div class="device-list">
				{#each pendingDevices as device (device.id)}
					<div class="device card pending-card">
						<div class="device-info">
							<div class="device-name">
								{device.name}
								<span class="badge pending">Pending</span>
							</div>
							<div class="device-meta">
								Registered: {formatDate(device.created_at)}
							</div>
						</div>
						<div class="device-actions">
							<button class="primary" onclick={() => handleBeginApproval(device)} disabled={approving}>Approve</button>
							<button class="danger" onclick={() => handleReject(device)} disabled={rejectingId === device.id}>
								{rejectingId === device.id ? 'Rejecting...' : 'Reject'}
							</button>
						</div>
					</div>
				{/each}
			</div>
		{/if}

		<!-- Active devices section -->
		{#if devices.length === 0 && pendingDevices.length === 0}
			<p class="empty">No devices registered</p>
		{:else if devices.length > 0}
			{#if pendingDevices.length > 0}
				<div class="section-header">Active Devices</div>
			{/if}
			<div class="device-list">
				{#each devices as device (device.id)}
					<div class="device card">
						<div class="device-info">
							<div class="device-name">
								{device.name}
								<span class="badge" class:online={device.online} class:offline={!device.online}>
									{device.online ? 'Online' : 'Offline'}
								</span>
							</div>
							<div class="device-meta">
								Last seen: {device.online ? 'Now' : formatLastSeen(device.last_seen)}
							</div>
						</div>
						<button class="danger" onclick={() => handleRemove(device.id, device.name)} disabled={removingId === device.id}>
							{removingId === device.id ? 'Removing...' : 'Remove'}
						</button>
					</div>
				{/each}
			</div>
		{/if}
	{/if}
</div>

<!-- Approval code modal -->
{#if approving}
	<div class="modal-overlay" onclick={closeApprovalModal} role="presentation">
		<!-- svelte-ignore a11y_click_events_have_key_events -->
		<div class="modal card" onclick={(e) => e.stopPropagation()} role="dialog" aria-modal="true" tabindex="-1">
			<h2>Approve "{approvingDeviceName}"</h2>

			{#if approvalSession}
				<p class="modal-desc">
					Verify this code matches on the new device, then confirm.
				</p>
				<div class="approval-code">{approvalSession.approval_code}</div>
				{#if approvalError}
					<p class="error">{approvalError}</p>
				{/if}
				<div class="modal-actions">
					<button onclick={closeApprovalModal} disabled={confirming}>Cancel</button>
					<button class="primary" onclick={handleConfirmApproval} disabled={confirming}>
						{confirming ? 'Approving...' : 'Codes Match - Approve'}
					</button>
				</div>
			{:else if approvalError}
				<p class="error">{approvalError}</p>
				<div class="modal-actions">
					<button onclick={closeApprovalModal}>Close</button>
				</div>
			{:else}
				<p class="loading">Starting approval session...</p>
			{/if}
		</div>
	</div>
{/if}

<style>
	.devices-page h1 {
		font-size: 1.25rem;
		margin-bottom: 1rem;
	}

	.section-header {
		font-size: 0.8rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--text-secondary);
		margin-bottom: 0.5rem;
		margin-top: 1.25rem;
	}

	.section-header:first-of-type {
		margin-top: 0;
	}

	.device-list {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.device {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 1rem;
	}

	.pending-card {
		border-color: var(--warning, #eab308);
	}

	.device-name {
		font-weight: 500;
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.device-meta {
		font-size: 0.75rem;
		color: var(--text-secondary);
		margin-top: 0.25rem;
	}

	.device-actions {
		display: flex;
		gap: 0.5rem;
	}

	.badge.pending {
		background: #fef3c7;
		color: #92400e;
	}

	@media (prefers-color-scheme: dark) {
		.badge.pending {
			background: #78350f;
			color: #fde68a;
		}
	}

	.loading, .empty {
		text-align: center;
		color: var(--text-secondary);
		padding: 3rem 0;
	}

	.success {
		color: var(--success, #22c55e);
		font-size: 0.8rem;
		margin-bottom: 0.75rem;
		padding: 0.5rem;
		background: rgba(34, 197, 94, 0.1);
		border-radius: var(--radius, 0.5rem);
	}

	.error {
		color: var(--danger, #ef4444);
		font-size: 0.8rem;
		margin-bottom: 0.75rem;
		padding: 0.5rem;
		background: rgba(239, 68, 68, 0.1);
		border-radius: var(--radius, 0.5rem);
	}

	/* Modal */
	.modal-overlay {
		position: fixed;
		inset: 0;
		background: rgba(0, 0, 0, 0.5);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 100;
	}

	.modal {
		width: 90%;
		max-width: 400px;
		padding: 1.5rem;
	}

	.modal h2 {
		font-size: 1.1rem;
		margin-bottom: 0.75rem;
	}

	.modal-desc {
		font-size: 0.875rem;
		color: var(--text-secondary);
		margin-bottom: 1rem;
	}

	.approval-code {
		font-family: monospace;
		font-size: 2rem;
		font-weight: 700;
		text-align: center;
		letter-spacing: 0.2em;
		padding: 1rem;
		background: var(--bg-secondary, #f9fafb);
		border: 1px solid var(--border);
		border-radius: var(--radius, 0.5rem);
		margin-bottom: 1rem;
	}

	.modal-actions {
		display: flex;
		justify-content: flex-end;
		gap: 0.5rem;
	}

	button.primary {
		background: var(--accent);
		color: white;
		border-color: var(--accent);
	}

	button.primary:hover {
		background: var(--accent-hover);
	}

	@media (max-width: 768px) {
		.device {
			flex-direction: column;
			align-items: flex-start;
			gap: 0.75rem;
		}

		.device button, .device-actions {
			align-self: flex-end;
		}
	}
</style>
