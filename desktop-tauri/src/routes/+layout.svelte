<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { initEventListeners, destroyEventListeners, getAppStateValue, getAvailableUpdate, dismissUpdate } from '$lib/store.svelte';
	import { downloadAndInstallUpdate, getConfig, getMyApprovalStatus, connectToServer, logout, type MyApprovalStatus } from '$lib/api';
	import { isDesktop } from '$lib/platform';
	import '$lib/app.css';

	let { children } = $props();

	let deviceStatus = $state<string>('approved');
	let approvalStatus = $state<MyApprovalStatus | null>(null);
	let approvalPollTimer = $state<ReturnType<typeof setInterval> | null>(null);

	onMount(() => {
		initEventListeners();
		return () => {
			destroyEventListeners();
			if (approvalPollTimer) clearInterval(approvalPollTimer);
		};
	});

	// Reactively read device_status whenever the app becomes configured.
	// This ensures we pick up "pending" status after login (onMount runs too early).
	$effect(() => {
		if (isConfigured) {
			getConfig().then((config) => {
				const status = config.device_status || 'approved';
				if (status !== deviceStatus) {
					deviceStatus = status;
					if (deviceStatus === 'pending') {
						startApprovalPolling();
					}
				}
			}).catch(() => {});
		}
	});

	function startApprovalPolling() {
		if (approvalPollTimer) return; // guard against double-start
		pollApprovalStatus();
		approvalPollTimer = setInterval(pollApprovalStatus, 4000);
	}

	let approvalError = $state('');

	async function pollApprovalStatus() {
		try {
			approvalStatus = await getMyApprovalStatus();
			if (approvalStatus.status === 'approved') {
				// Device was approved! Stop polling and transition
				if (approvalPollTimer) {
					clearInterval(approvalPollTimer);
					approvalPollTimer = null;
				}
				// Connect to initialize keys and websocket
				try {
					await connectToServer();
					deviceStatus = 'approved';
				} catch (e) {
					approvalError = `Failed to initialize encryption: ${e}`;
					console.error('Post-approval connect failed:', e);
				}
			} else if (approvalStatus.status === 'rejected') {
				if (approvalPollTimer) {
					clearInterval(approvalPollTimer);
					approvalPollTimer = null;
				}
				deviceStatus = 'rejected';
			}
		} catch {
			// ignore polling errors
		}
	}

	async function handleLogout() {
		if (approvalPollTimer) clearInterval(approvalPollTimer);
		try { await logout(); } catch { /* ignore */ }
		deviceStatus = 'approved'; // reset
	}

	const appState = $derived(getAppStateValue());
	const isConfigured = $derived(appState !== 'not_configured');
	const isPendingApproval = $derived(isConfigured && deviceStatus === 'pending');
	const isRejected = $derived(isConfigured && deviceStatus === 'rejected');
	const updateInfo = $derived(getAvailableUpdate());
	const desktop = isDesktop();

	let downloading = $state(false);
	let downloadError = $state('');

	async function handleDownloadUpdate() {
		if (!updateInfo) return;
		downloading = true;
		downloadError = '';
		try {
			await downloadAndInstallUpdate(updateInfo.download_url);
			dismissUpdate();
		} catch (e) {
			downloadError = String(e);
		} finally {
			downloading = false;
		}
	}
</script>

{#if !isConfigured}
	{@render children()}
{:else if isPendingApproval}
	<div class="pending-screen">
		<div class="pending-card card">
			<h2>Waiting for Approval</h2>
			<p class="pending-desc">
				This device is pending approval. Open the <strong>Devices</strong> page on an already-approved device and approve this one.
			</p>

			{#if approvalError}
				<p class="approval-error">{approvalError}</p>
				<button class="logout-btn" onclick={() => { approvalError = ''; startApprovalPolling(); }}>Retry</button>
			{:else if approvalStatus?.approval_code}
				<p class="code-label">Verification Code</p>
				<div class="approval-code">{approvalStatus.approval_code}</div>
				<p class="code-hint">Confirm this code matches on the approving device.</p>
			{:else}
				<div class="waiting-steps">
					<p class="steps-label">To approve this device:</p>
					<ol class="steps-list">
						<li>Open <strong>cpmesh</strong> on an already-approved device</li>
						<li>Go to the <strong>Devices</strong> page</li>
						<li>Find this device under <strong>Pending Approval</strong></li>
						<li>Tap <strong>Approve</strong> and verify the codes match</li>
					</ol>
				</div>
				<div class="waiting-indicator">
					<span class="spinner"></span>
					Listening for approval...
				</div>
			{/if}

			<button class="logout-btn" onclick={handleLogout}>Cancel &amp; Log Out</button>
		</div>
	</div>
{:else if isRejected}
	<div class="pending-screen">
		<div class="pending-card card">
			<h2>Device Rejected</h2>
			<p class="pending-desc">
				This device was rejected by another device on your account. You can log out and try again.
			</p>
			<button class="logout-btn" onclick={handleLogout}>Log Out</button>
		</div>
	</div>
{:else}
	<div class="layout">
		<nav class="sidebar">
			<div class="sidebar-header">
				<h2>cpmesh</h2>
			</div>
			<ul class="nav-links">
				<li><a href="/" class:active={$page.url.pathname === '/'}>Status</a></li>
				<li><a href="/history" class:active={$page.url.pathname === '/history'}>History</a></li>
				<li><a href="/devices" class:active={$page.url.pathname === '/devices'}>Devices</a></li>
				<li><a href="/settings" class:active={$page.url.pathname === '/settings'}>Settings</a></li>
			</ul>
		</nav>
		<main class="content">
			{#if updateInfo && desktop}
				<div class="update-banner">
					<div class="update-text">
						<strong>Update available: v{updateInfo.version}</strong>
						{#if updateInfo.release_notes}
							<span class="update-notes"> — {updateInfo.release_notes}</span>
						{/if}
					</div>
					<div class="update-actions">
						{#if downloadError}
							<span class="update-error">{downloadError}</span>
						{/if}
						<button class="update-btn primary" onclick={handleDownloadUpdate} disabled={downloading}>
							{downloading ? 'Downloading...' : 'Download & Install'}
						</button>
						<button class="update-btn dismiss" onclick={dismissUpdate}>Dismiss</button>
					</div>
				</div>
			{/if}
			{@render children()}
		</main>
		<nav class="bottom-nav">
			<a href="/" class:active={$page.url.pathname === '/'}>
				<span class="nav-icon">⚡</span>
				<span class="nav-label">Status</span>
			</a>
			<a href="/history" class:active={$page.url.pathname === '/history'}>
				<span class="nav-icon">📋</span>
				<span class="nav-label">History</span>
			</a>
			<a href="/devices" class:active={$page.url.pathname === '/devices'}>
				<span class="nav-icon">📱</span>
				<span class="nav-label">Devices</span>
			</a>
			<a href="/settings" class:active={$page.url.pathname === '/settings'}>
				<span class="nav-icon">⚙️</span>
				<span class="nav-label">Settings</span>
			</a>
		</nav>
	</div>
{/if}

<style>
	.layout {
		display: flex;
		height: 100vh;
	}

	.sidebar {
		width: 200px;
		min-width: 200px;
		background: var(--bg-secondary);
		border-right: 1px solid var(--border);
		display: flex;
		flex-direction: column;
		padding: 1rem 0;
	}

	.sidebar-header {
		padding: 0 1rem 1rem;
		border-bottom: 1px solid var(--border);
		margin-bottom: 0.5rem;
	}

	.sidebar-header h2 {
		font-size: 1.125rem;
		font-weight: 600;
	}

	.nav-links {
		list-style: none;
		padding: 0.5rem 0;
	}

	.nav-links li a {
		display: block;
		padding: 0.5rem 1rem;
		color: var(--text-secondary);
		text-decoration: none;
		font-size: 0.875rem;
		transition: all 0.15s ease;
	}

	.nav-links li a:hover,
	.nav-links li a.active {
		color: var(--accent);
		background: var(--accent-light);
	}

	.content {
		flex: 1;
		padding: 1.5rem;
		overflow-y: auto;
	}

	.update-banner {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 1rem;
		padding: 0.625rem 1rem;
		margin-bottom: 1rem;
		background: var(--accent-light);
		border: 1px solid var(--accent);
		border-radius: 8px;
		font-size: 0.8125rem;
	}

	.update-text {
		flex: 1;
		min-width: 0;
	}

	.update-notes {
		color: var(--text-secondary);
	}

	.update-actions {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		flex-shrink: 0;
	}

	.update-btn {
		padding: 0.25rem 0.75rem;
		font-size: 0.75rem;
		border-radius: 6px;
		cursor: pointer;
		border: 1px solid transparent;
	}

	.update-btn.primary {
		background: var(--accent);
		color: white;
		border-color: var(--accent);
	}

	.update-btn.primary:hover:not(:disabled) {
		background: var(--accent-hover);
	}

	.update-btn.primary:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}

	.update-btn.dismiss {
		background: transparent;
		border: none;
		color: var(--text-secondary);
		padding: 0.25rem 0.5rem;
	}

	.update-btn.dismiss:hover {
		color: var(--text);
	}

	.update-error {
		color: var(--danger);
		font-size: 0.75rem;
	}

	/* Bottom navigation — hidden on desktop, shown on mobile */
	.bottom-nav {
		display: none;
	}

	/* Pending approval screen */
	.pending-screen {
		display: flex;
		align-items: center;
		justify-content: center;
		height: 100vh;
		padding: 1.5rem;
	}

	.pending-card {
		max-width: 400px;
		width: 100%;
		text-align: center;
	}

	.pending-card h2 {
		font-size: 1.25rem;
		margin-bottom: 0.75rem;
	}

	.pending-desc {
		font-size: 0.875rem;
		color: var(--text-secondary);
		margin-bottom: 1.5rem;
		line-height: 1.5;
	}

	.approval-error {
		color: var(--danger, #ef4444);
		font-size: 0.8rem;
		padding: 0.5rem;
		background: rgba(239, 68, 68, 0.1);
		border-radius: var(--radius, 0.5rem);
		margin-bottom: 1rem;
	}

	.code-label {
		font-size: 0.75rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--text-secondary);
		margin-bottom: 0.5rem;
	}

	.approval-code {
		font-family: monospace;
		font-size: 2rem;
		font-weight: 700;
		letter-spacing: 0.2em;
		padding: 1rem;
		background: var(--bg-secondary, #f9fafb);
		border: 1px solid var(--border);
		border-radius: var(--radius, 0.5rem);
		margin-bottom: 0.5rem;
	}

	.code-hint {
		font-size: 0.75rem;
		color: var(--text-secondary);
		margin-bottom: 1.5rem;
	}

	.waiting-steps {
		text-align: left;
		margin-bottom: 1.25rem;
		padding: 0.75rem 1rem;
		background: var(--bg-secondary, #f9fafb);
		border: 1px solid var(--border);
		border-radius: var(--radius, 0.5rem);
	}

	.steps-label {
		font-size: 0.8rem;
		font-weight: 600;
		color: var(--text-secondary);
		margin-bottom: 0.5rem;
	}

	.steps-list {
		font-size: 0.8rem;
		color: var(--text-secondary);
		padding-left: 1.25rem;
		margin: 0;
		line-height: 1.7;
	}

	.waiting-indicator {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 0.5rem;
		color: var(--text-secondary);
		font-size: 0.875rem;
		margin-bottom: 1.5rem;
	}

	.spinner {
		display: inline-block;
		width: 1rem;
		height: 1rem;
		border: 2px solid var(--border);
		border-top-color: var(--accent);
		border-radius: 50%;
		animation: spin 0.8s linear infinite;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	.logout-btn {
		background: transparent;
		border: 1px solid var(--border);
		color: var(--text-secondary);
		padding: 0.5rem 1rem;
		border-radius: var(--radius, 0.5rem);
		cursor: pointer;
		font-size: 0.8rem;
	}

	.logout-btn:hover {
		color: var(--danger, #ef4444);
		border-color: var(--danger, #ef4444);
	}

	@media (max-width: 768px) {
		.layout {
			flex-direction: column;
		}

		.sidebar {
			display: none;
		}

		.content {
			flex: 1;
			padding: 1rem;
			padding-bottom: calc(4rem + env(safe-area-inset-bottom, 0px));
		}

		.bottom-nav {
			display: flex;
			position: fixed;
			bottom: 0;
			left: 0;
			right: 0;
			background: var(--bg-secondary);
			border-top: 1px solid var(--border);
			padding-bottom: env(safe-area-inset-bottom, 0px);
			z-index: 100;
		}

		.bottom-nav a {
			flex: 1;
			display: flex;
			flex-direction: column;
			align-items: center;
			gap: 0.125rem;
			padding: 0.5rem 0;
			color: var(--text-secondary);
			text-decoration: none;
			font-size: 0.625rem;
			transition: color 0.15s ease;
			min-height: 3rem;
			justify-content: center;
		}

		.bottom-nav a.active {
			color: var(--accent);
		}

		.nav-icon {
			font-size: 1.25rem;
			line-height: 1;
		}

		.nav-label {
			font-weight: 500;
		}
	}
</style>
