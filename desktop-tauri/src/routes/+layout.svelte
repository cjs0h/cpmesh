<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import { listen } from '@tauri-apps/api/event';

	import {
		initEventListeners,
		destroyEventListeners,
		getAppStateValue,
		getAvailableUpdate,
		getStatusValue,
		getSyncError,
		clearSyncError,
		dismissUpdate,
		getPendingDeviceCount,
		setPendingDeviceCount,
	} from '#lib/store.svelte.js';

	import {
		downloadAndInstallUpdate,
		getConfig,
		getMyApprovalStatus,
		getPendingDevices,
		confirmPairing,
		connectToServer,
		logout,
		type MyApprovalStatus,
	} from '#lib/api.js';

	import { isDesktop } from '#lib/platform.js';
	import { initTheme } from '#lib/theme.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import { errorMessage, hasModKey, rememberServerUrl } from '#lib/ui.js';
	import Alert from '#lib/components/ui/Alert.svelte';
	import Button from '#lib/components/ui/Button.svelte';
	import ConfirmHost from '#lib/components/ui/ConfirmHost.svelte';
	import Icon from '#lib/components/ui/Icon.svelte';
	import Kbd from '#lib/components/ui/Kbd.svelte';
	import Logo from '#lib/components/ui/Logo.svelte';
	import Toaster from '#lib/components/ui/Toaster.svelte';
	import PairingScreen from '#lib/components/PairingScreen.svelte';
	import '#lib/app.css';

	initTheme();

	let { children } = $props();

	const nav = [
		{ href: '/', label: 'Overview', icon: 'home', key: '1' },
		{ href: '/history', label: 'History', icon: 'history', key: '2' },
		{ href: '/devices', label: 'Devices', icon: 'monitor', key: '3' },
		{ href: '/settings', label: 'Settings', icon: 'settings', key: '4' },
	];

	let deviceStatus = $state<string>('approved');
	let approvalStatus = $state<MyApprovalStatus | null>(null);
	let approvalPollTimer = $state<ReturnType<typeof setInterval> | null>(null);
	let approvalError = $state('');
	let confirmingPairing = $state(false);
	const pendingCount = $derived(getPendingDeviceCount());

	onMount(() => {
		initEventListeners();
		// The tray and app menus open sections of the window
		let disposed = false;
		let unlistenNavigate: (() => void) | undefined;
		listen<string>('navigate', (event) => {
			if (isConfigured) goto(event.payload);
		})
			.then((unlisten) => {
				if (disposed) unlisten();
				else unlistenNavigate = unlisten;
			})
			.catch(() => {});
		return () => {
			disposed = true;
			unlistenNavigate?.();
			destroyEventListeners();
			if (approvalPollTimer) clearInterval(approvalPollTimer);
		};
	});

	// Reactively read device_status whenever the app becomes configured.
	// This ensures we pick up "pending" status after login (onMount runs too early).
	$effect(() => {
		if (isConfigured) {
			getConfig()
				.then((config) => {
					rememberServerUrl(config.server_url);
					const status = config.device_status || 'approved';
					if (status !== deviceStatus) {
						deviceStatus = status;
						if (deviceStatus === 'pending') {
							startApprovalPolling();
						}
					}
				})
				.catch(() => {});
		}
	});

	// Devices waiting for approval, shown as a count in the navigation
	async function refreshPendingCount() {
		try {
			setPendingDeviceCount((await getPendingDevices()).length);
		} catch {
			// Keep the last known count
		}
	}

	$effect(() => {
		if (appState !== 'connected' || deviceStatus !== 'approved') return;
		void page.url.pathname;
		refreshPendingCount();
		const timer = setInterval(refreshPendingCount, 30_000);
		window.addEventListener('focus', refreshPendingCount);
		return () => {
			clearInterval(timer);
			window.removeEventListener('focus', refreshPendingCount);
		};
	});

	function startApprovalPolling() {
		if (approvalPollTimer) return; // guard against double-start
		pollApprovalStatus();
		approvalPollTimer = setInterval(pollApprovalStatus, 4000);
	}

	async function pollApprovalStatus() {
		try {
			approvalStatus = await getMyApprovalStatus();
			approvalError = '';
			if (approvalStatus.status === 'approved' && approvalStatus.locally_verified) {
				// Device was approved! Stop polling and transition
				if (approvalPollTimer) {
					clearInterval(approvalPollTimer);
					approvalPollTimer = null;
				}
				// Connect to initialize keys and websocket
				try {
					await connectToServer();
					deviceStatus = 'approved';
					toast.success('Device approved', 'This device is now part of your mesh.');
				} catch (e) {
					approvalError = `Failed to initialize encryption: ${errorMessage(e)}`;
					console.error('Post-approval connect failed:', e);
				}
			} else if (approvalStatus.status === 'rejected') {
				if (approvalPollTimer) {
					clearInterval(approvalPollTimer);
					approvalPollTimer = null;
				}
				deviceStatus = 'rejected';
			}
		} catch (e) {
			approvalError = errorMessage(e);
		}
	}

	async function handleConfirmPairing() {
		if (!approvalStatus?.session_id || !approvalStatus.sas) return;
		confirmingPairing = true;
		try {
			await confirmPairing(approvalStatus.session_id, approvalStatus.sas);
			await pollApprovalStatus();
		} catch (e) {
			approvalError = errorMessage(e);
		} finally {
			confirmingPairing = false;
		}
	}

	function retryApproval() {
		approvalError = '';
		startApprovalPolling();
	}

	async function handleLogout() {
		if (approvalPollTimer) clearInterval(approvalPollTimer);
		approvalPollTimer = null;
		try {
			await logout();
		} catch {
			/* ignore */
		}
		deviceStatus = 'approved'; // reset
		approvalStatus = null;
		approvalError = '';
	}

	const appState = $derived(getAppStateValue());
	const status = $derived(getStatusValue());
	const syncError = $derived(getSyncError());
	const isConfigured = $derived(appState !== 'not_configured');
	const isPendingApproval = $derived(isConfigured && deviceStatus === 'pending' && page.url.pathname !== '/devices');
	const isRejected = $derived(isConfigured && deviceStatus === 'rejected');
	const updateInfo = $derived(getAvailableUpdate());
	const desktop = isDesktop();

	let downloading = $state(false);
	let connecting = $state(false);

	async function handleDownloadUpdate() {
		if (!updateInfo) return;
		downloading = true;
		try {
			await downloadAndInstallUpdate(updateInfo.download_url);
			dismissUpdate();
		} catch (e) {
			toast.error('Update failed', errorMessage(e));
		} finally {
			downloading = false;
		}
	}

	async function quickConnect() {
		connecting = true;
		try {
			await connectToServer();
		} catch (e) {
			toast.error('Could not connect', errorMessage(e));
		} finally {
			connecting = false;
		}
	}

	function isActive(href: string) {
		return href === '/' ? page.url.pathname === '/' : page.url.pathname.startsWith(href);
	}

	// ⌘/Ctrl+1…4 switch sections; ⌘/Ctrl+, opens Settings like other desktop apps
	function onKeydown(event: KeyboardEvent) {
		if (!isConfigured || isPendingApproval || isRejected) return;
		if (!hasModKey(event) || event.altKey || event.shiftKey) return;
		const item = nav.find((n) => n.key === event.key);
		const target = item?.href ?? (event.key === ',' ? '/settings' : null);
		if (!target) return;
		event.preventDefault();
		goto(target);
	}

	const statusLabel = $derived(
		appState === 'connected' ? 'Live sync' : appState === 'connecting' ? 'Connecting…' : 'Offline',
	);
</script>

<svelte:window onkeydown={onKeydown} />

{#if !isConfigured}
	{@render children()}
{:else if isPendingApproval}
	<PairingScreen
		mode="pending"
		approval={approvalStatus}
		error={approvalError}
		confirming={confirmingPairing}
		onconfirm={handleConfirmPairing}
		onretry={retryApproval}
		onlogout={handleLogout}
	/>
{:else if isRejected}
	<PairingScreen
		mode="rejected"
		approval={approvalStatus}
		error=""
		confirming={false}
		onconfirm={() => {}}
		onretry={() => {}}
		onlogout={handleLogout}
	/>
{:else}
	<div class="flex h-dvh overflow-hidden bg-bg">
		<nav class="flex w-[216px] shrink-0 flex-col border-r border-border bg-bg-deep max-sm:hidden" aria-label="Main">
			<div class="flex h-14 items-center px-4">
				<Logo size={24} withText />
			</div>

			<ul class="flex flex-1 flex-col gap-0.5 px-2.5 pt-1">
				{#each nav as item (item.href)}
					{@const active = isActive(item.href)}
					<li>
						<a
							href={item.href}
							aria-current={active ? 'page' : undefined}
							class="group flex h-8 items-center gap-2.5 rounded-md px-2.5 text-[13px] transition-colors duration-150
								{active ? 'bg-surface-3/70 font-medium text-fg dark:bg-surface-2' : 'text-muted hover:bg-surface-2 hover:text-fg'}"
						>
							<span class={active ? 'text-fg' : 'text-dim group-hover:text-muted'}>
								<Icon name={item.icon} size={15} strokeWidth={1.75} />
							</span>
							<span class="flex-1">{item.label}</span>
							{#if item.href === '/devices' && pendingCount > 0}
								<span
									class="flex h-[18px] min-w-[18px] items-center justify-center rounded-full bg-accent px-1 text-[11px] font-semibold text-[#0a0a0a] tabular-nums"
									aria-label="{pendingCount} waiting for approval">{pendingCount}</span
								>
							{:else}
								<Kbd keys={['mod', item.key]} class="opacity-0 transition-opacity group-hover:opacity-100" />
							{/if}
						</a>
					</li>
				{/each}
			</ul>

			<div class="border-t border-border p-3">
				<div class="flex items-center gap-2.5 px-1.5">
					<span
						class="status-dot {appState === 'connected' ? 'text-accent' : appState === 'connecting' ? 'text-warning' : 'text-border-strong'}"
						data-live={appState === 'connected'}
					></span>
					<div class="min-w-0 flex-1">
						<p class="text-xs font-medium text-fg">{statusLabel}</p>
						<p class="truncate text-[11px] text-dim" title={status?.device_name}>{status?.device_name || 'This device'}</p>
					</div>
					{#if appState === 'disconnected' && !isActive('/')}
						<Button size="xs" variant="secondary" loading={connecting} onclick={quickConnect}>Connect</Button>
					{/if}
				</div>
			</div>
		</nav>

		<div class="flex min-w-0 flex-1 flex-col">
			{#if updateInfo && desktop}
				<div class="flex items-center gap-3 border-b border-border bg-bg-deep px-6 py-2 text-[13px]" role="status">
					<Icon name="download" size={14} class="text-muted" />
					<p class="min-w-0 flex-1 truncate">
						<span class="font-medium text-fg">cpmesh {updateInfo.version} is available</span>
						{#if updateInfo.release_notes}<span class="text-muted"> — {updateInfo.release_notes}</span>{/if}
					</p>
					<Button size="xs" variant="ghost" onclick={dismissUpdate}>Later</Button>
					<Button size="xs" variant="primary" icon="download" loading={downloading} onclick={handleDownloadUpdate}>
						Install update
					</Button>
				</div>
			{/if}

			<main class="flex-1 overflow-y-auto max-sm:pb-[calc(4rem+env(safe-area-inset-bottom))]">
				<div class="mx-auto w-full max-w-[760px] px-8 pt-7 pb-12 max-sm:px-4 max-sm:pt-5">
					{#if syncError}
						<Alert tone="danger" title="Sync problem" class="mb-6" ondismiss={clearSyncError}>{syncError}</Alert>
					{/if}
					{@render children()}
				</div>
			</main>
		</div>

		<nav
			class="fixed inset-x-0 bottom-0 z-40 hidden border-t border-border bg-bg-deep/95 pb-[env(safe-area-inset-bottom)] backdrop-blur max-sm:flex"
			aria-label="Main"
		>
			{#each nav as item (item.href)}
				{@const active = isActive(item.href)}
				<a
					href={item.href}
					aria-current={active ? 'page' : undefined}
					class="relative flex min-h-14 flex-1 flex-col items-center justify-center gap-1 text-[11px] font-medium {active ? 'text-fg' : 'text-dim'}"
				>
					<Icon name={item.icon} size={19} strokeWidth={1.75} />
					{item.label}
					{#if item.href === '/devices' && pendingCount > 0}
						<span class="absolute top-2 left-[calc(50%+6px)] h-2 w-2 rounded-full bg-accent"></span>
					{/if}
				</a>
			{/each}
		</nav>
	</div>
{/if}

<Toaster />
<ConfirmHost />
