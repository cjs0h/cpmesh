<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { getVersion } from '@tauri-apps/api/app';
	import { listen } from '@tauri-apps/api/event';
	import {
		getConfig,
		updateConfig,
		changePassword,
		checkUpdate,
		downloadAndInstallUpdate,
		logout,
		getUserInfo,
		type AppConfig,
		type UpdateInfo,
		type UserInfo,
	} from '#lib/api.js';
	import { setAppState, getStatusValue } from '#lib/store.svelte.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { isDesktop } from '#lib/platform.js';
	import { getThemePreference, setThemePreference, type ThemePreference } from '#lib/theme.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import { errorMessage, forgetServerUrl, isMacLike, serverHost } from '#lib/ui.js';
	import Alert from '#lib/components/ui/Alert.svelte';
	import Badge from '#lib/components/ui/Badge.svelte';
	import Button from '#lib/components/ui/Button.svelte';
	import Dialog from '#lib/components/ui/Dialog.svelte';
	import Field from '#lib/components/ui/Field.svelte';
	import Kbd from '#lib/components/ui/Kbd.svelte';
	import PageHeader from '#lib/components/ui/PageHeader.svelte';
	import Segmented from '#lib/components/ui/Segmented.svelte';
	import SettingRow from '#lib/components/ui/SettingRow.svelte';
	import SettingsGroup from '#lib/components/ui/SettingsGroup.svelte';
	import Skeleton from '#lib/components/ui/Skeleton.svelte';
	import Switch from '#lib/components/ui/Switch.svelte';
	import EncryptionKeys from '#lib/components/EncryptionKeys.svelte';

	const desktop = isDesktop();
	const status = $derived(getStatusValue());

	let config = $state<AppConfig | null>(null);
	let loading = $state(true);
	let loadError = $state('');
	let user = $state<UserInfo | null>(null);
	let savingKey = $state<string | null>(null);
	let theme = $state<ThemePreference>(getThemePreference());
	let appVersion = $state('');

	// Password change
	let passwordOpen = $state(false);
	let currentPassword = $state('');
	let newPassword = $state('');
	let confirmPassword = $state('');
	let passwordError = $state('');
	let changingPassword = $state(false);

	// Updates
	let updateInfo = $state<UpdateInfo | null>(null);
	let checkingUpdate = $state(false);
	let checkedUpdate = $state(false);
	let updateCheckFailed = $state(false);
	let downloadingUpdate = $state(false);

	let signingOut = $state(false);

	const authProvider = $derived(user?.auth_provider || 'local');
	const displayName = $derived(user?.full_name || user?.username || '');
	const initials = $derived(
		displayName
			.split(/\s+/)
			.filter(Boolean)
			.slice(0, 2)
			.map((part) => part[0]?.toUpperCase())
			.join('') || '?',
	);

	async function loadConfig() {
		loading = true;
		loadError = '';
		try {
			config = await getConfig();
		} catch (e) {
			loadError = errorMessage(e);
		} finally {
			loading = false;
		}
	}

	type ToggleKey = 'auto_connect' | 'autostart' | 'notifications_enabled';

	async function toggleSetting(key: ToggleKey) {
		if (!config || savingKey) return;
		const prev = config[key];
		config[key] = !prev;
		savingKey = key;
		try {
			await updateConfig({ [key]: config[key] });
		} catch (e) {
			config[key] = prev; // rollback on failure
			toast.error('Couldn’t save that setting', errorMessage(e));
		} finally {
			savingKey = null;
		}
	}

	function openPasswordDialog() {
		currentPassword = '';
		newPassword = '';
		confirmPassword = '';
		passwordError = '';
		passwordOpen = true;
	}

	async function handlePasswordChange(event: SubmitEvent) {
		event.preventDefault();
		passwordError = '';
		if (newPassword.length < 8) {
			passwordError = 'Use at least 8 characters for your new password.';
			return;
		}
		if (newPassword !== confirmPassword) {
			passwordError = 'The new passwords don’t match.';
			return;
		}
		changingPassword = true;
		try {
			// The backend signs this device out once the password changed
			await changePassword(currentPassword, newPassword);
			changingPassword = false;
			passwordOpen = false;
			toast.success('Password changed', 'Sign in again with your new password.', 8000);
		} catch (e) {
			passwordError = errorMessage(e);
		} finally {
			changingPassword = false;
		}
	}

	async function handleCheckUpdate() {
		checkingUpdate = true;
		updateCheckFailed = false;
		try {
			updateInfo = await checkUpdate();
			checkedUpdate = true;
		} catch {
			updateCheckFailed = true;
		} finally {
			checkingUpdate = false;
		}
	}

	async function handleInstallUpdate() {
		if (!updateInfo) return;
		downloadingUpdate = true;
		try {
			await downloadAndInstallUpdate(updateInfo.download_url);
		} catch (e) {
			toast.error('Update failed', errorMessage(e));
		} finally {
			downloadingUpdate = false;
		}
	}

	async function openDashboard() {
		if (!config?.server_url) return;
		try {
			const { openUrl } = await import('@tauri-apps/plugin-opener');
			await openUrl(config.server_url);
		} catch (e) {
			toast.error('Couldn’t open your browser', errorMessage(e));
		}
	}

	async function signOut(options: { switchServer: boolean }) {
		signingOut = true;
		// Before logout: its event can mount the sign-in screen before this resumes
		if (options.switchServer) forgetServerUrl();
		try {
			await logout();
			setAppState('not_configured');
			goto('/');
		} catch (e) {
			toast.error('Couldn’t sign out', errorMessage(e));
		} finally {
			signingOut = false;
		}
	}

	async function handleSwitchServer() {
		const confirmed = await confirmAction({
			title: 'Switch to another server?',
			description: `This signs this device out of ${serverHost(config?.server_url)}. You’ll sign in to the new server next, and approve this device there.`,
			confirmLabel: 'Sign out and switch',
		});
		if (confirmed) await signOut({ switchServer: true });
	}

	async function handleSignOut() {
		const confirmed = await confirmAction({
			title: 'Sign out of cpmesh?',
			description:
				'This device stops syncing until you sign in again. Its keys, clipboard history and preferences stay on it, so it can rejoin the same account without another approval.',
			confirmLabel: 'Sign out',
			tone: 'danger',
		});
		if (confirmed) await signOut({ switchServer: false });
	}

	onMount(() => {
		loadConfig();
		// e.g. Open at Login toggled from the tray menu
		let disposed = false;
		let unlisten: (() => void) | undefined;
		listen('config-changed', () => {
			getConfig()
				.then((next) => (config = next))
				.catch(() => {});
		})
			.then((u) => {
				if (disposed) u();
				else unlisten = u;
			})
			.catch(() => {});
		getUserInfo()
			.then((info) => (user = info))
			.catch(() => {});
		getVersion()
			.then((v) => (appVersion = v))
			.catch(() => {});
		return () => {
			disposed = true;
			unlisten?.();
		};
	});

	const providerLabel = $derived(authProvider === 'local' ? 'Password' : authProvider.charAt(0).toUpperCase() + authProvider.slice(1));
</script>

<svelte:head>
	<title>Settings · cpmesh</title>
</svelte:head>

<PageHeader title="Settings" />

{#if loading}
	<div class="space-y-8" aria-busy="true" aria-label="Loading settings">
		{#each [0, 1, 2] as i (i)}
			<div class="space-y-2">
				<Skeleton class="h-3.5 w-28" />
				<Skeleton class="h-28 w-full rounded-xl" />
			</div>
		{/each}
	</div>
{:else if loadError || !config}
	<Alert tone="danger" title="Couldn’t load settings">
		{loadError}
		{#snippet actions()}
			<Button size="sm" icon="refresh" onclick={loadConfig}>Try again</Button>
		{/snippet}
	</Alert>
{:else}
	<div class="space-y-8">
		<SettingsGroup title="Account">
			<div class="flex items-center gap-3.5 px-4 py-4">
				<span
					class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-ink text-sm font-semibold text-on-ink"
					aria-hidden="true">{initials}</span
				>
				<div class="min-w-0 flex-1">
					{#if user}
						<p class="flex items-center gap-2 truncate text-[13px] font-medium text-fg">
							{displayName}
							{#if user.is_admin}<Badge>Admin</Badge>{/if}
						</p>
						<p class="truncate text-xs text-muted">{user.email || `@${user.username}`}</p>
					{:else}
						<Skeleton class="h-3.5 w-32" />
						<Skeleton class="mt-1.5 h-3 w-44" />
					{/if}
				</div>
				{#if desktop}
					<Button size="sm" iconRight="external-link" onclick={openDashboard}>Web dashboard</Button>
				{/if}
			</div>
			<SettingRow
				label="Sign-in method"
				description={authProvider === 'local'
					? 'Two-factor authentication and passkeys are managed on the web dashboard.'
					: `Your password is managed by ${providerLabel}.`}
			>
				{#snippet control()}
					{#if authProvider === 'local'}
						<Button size="sm" onclick={openPasswordDialog}>Change password</Button>
					{:else}
						<Badge>{providerLabel}</Badge>
					{/if}
				{/snippet}
			</SettingRow>
		</SettingsGroup>

		<EncryptionKeys />

		<SettingsGroup title="Appearance">
			<SettingRow label="Theme" description="Follow your system, or keep cpmesh light or dark.">
				{#snippet control()}
					<Segmented
						label="Theme"
						size="sm"
						bind:value={theme}
						onchange={setThemePreference}
						options={[
							{ value: 'system', label: 'System', icon: 'sun-moon' },
							{ value: 'light', label: 'Light', icon: 'sun' },
							{ value: 'dark', label: 'Dark', icon: 'moon' },
						]}
					/>
				{/snippet}
			</SettingRow>
		</SettingsGroup>

		<SettingsGroup title="Sync and startup">
			<SettingRow label="Connect when cpmesh opens" description="Start syncing as soon as the app launches." for="setting-auto-connect">
				{#snippet control()}
					<Switch
						id="setting-auto-connect"
						label="Connect when cpmesh opens"
						checked={config?.auto_connect ?? false}
						disabled={savingKey !== null}
						onchange={() => toggleSetting('auto_connect')}
					/>
				{/snippet}
			</SettingRow>
			{#if desktop}
				<SettingRow
					label="Open at login"
					description="Start cpmesh quietly in the {isMacLike() ? 'menu bar' : 'system tray'} when you sign in to this computer."
					for="setting-autostart"
				>
					{#snippet control()}
						<Switch
							id="setting-autostart"
							label="Open at login"
							checked={config?.autostart ?? false}
							disabled={savingKey !== null}
							onchange={() => toggleSetting('autostart')}
						/>
					{/snippet}
				</SettingRow>
			{/if}
			<SettingRow label="Clip notifications" description="Show a notification when a clip arrives from another device." for="setting-notifications">
				{#snippet control()}
					<Switch
						id="setting-notifications"
						label="Clip notifications"
						checked={config?.notifications_enabled ?? false}
						disabled={savingKey !== null}
						onchange={() => toggleSetting('notifications_enabled')}
					/>
				{/snippet}
			</SettingRow>
		</SettingsGroup>

		{#if desktop}
			<SettingsGroup title="Keyboard shortcuts">
				<SettingRow label="Show cpmesh from anywhere">
					{#snippet control()}<Kbd keys={['mod', 'shift', 'Space']} />{/snippet}
				</SettingRow>
				<SettingRow label="Switch between sections">
					{#snippet control()}<Kbd keys={['mod', '1']} /><span class="text-xs text-dim">to</span><Kbd keys={['mod', '4']} />{/snippet}
				</SettingRow>
				<SettingRow label="Search history">
					{#snippet control()}<Kbd keys={['mod', 'F']} />{/snippet}
				</SettingRow>
				<SettingRow label="Open settings">
					{#snippet control()}<Kbd keys={['mod', ',']} />{/snippet}
				</SettingRow>
			</SettingsGroup>
		{/if}

		<SettingsGroup title="Connection">
			<SettingRow label="Server" description={config.server_url}>
				{#snippet control()}
					<Button size="sm" loading={signingOut} onclick={handleSwitchServer}>Switch server…</Button>
				{/snippet}
			</SettingRow>
			<SettingRow label="This device" description={config.device_name || status?.device_name || '—'} />
		</SettingsGroup>

		<SettingsGroup title="About">
			<SettingRow
				label="cpmesh {appVersion ? `v${appVersion}` : ''}"
				description={updateInfo
					? `Version ${updateInfo.version} is available.`
					: updateCheckFailed
						? 'Couldn’t check for updates. Try again in a moment.'
						: checkedUpdate
							? 'You’re on the latest version.'
							: 'Updates are checked automatically in the background.'}
			>
				{#snippet control()}
					{#if updateInfo?.download_url}
						<Button size="sm" variant="primary" icon="download" loading={downloadingUpdate} onclick={handleInstallUpdate}>
							Install {updateInfo.version}
						</Button>
					{:else if desktop}
						<Button size="sm" icon="refresh" loading={checkingUpdate} onclick={handleCheckUpdate}>Check for updates</Button>
					{/if}
				{/snippet}
				{#if updateInfo?.release_notes}
					<p class="mt-2 max-w-[56ch] text-xs leading-relaxed whitespace-pre-line text-muted">{updateInfo.release_notes}</p>
				{/if}
			</SettingRow>
		</SettingsGroup>

		<SettingsGroup>
			<SettingRow label="Sign out" description="Stop syncing until you sign in again. This device keeps its keys, clipboard history and preferences.">
				{#snippet control()}
					<Button size="sm" variant="danger-soft" icon="log-out" loading={signingOut} onclick={handleSignOut}>Sign out</Button>
				{/snippet}
			</SettingRow>
		</SettingsGroup>
	</div>
{/if}

<Dialog
	bind:open={passwordOpen}
	locked={changingPassword}
	size="sm"
	title="Change password"
	description="After the change, this device signs out and you sign in again with the new password."
>
	<form id="password-form" class="flex flex-col gap-3.5" onsubmit={handlePasswordChange} novalidate>
		<Field label="Current password" type="password" autocomplete="current-password" bind:value={currentPassword} />
		<Field label="New password" type="password" autocomplete="new-password" hint="At least 8 characters." bind:value={newPassword} />
		<Field label="Confirm new password" type="password" autocomplete="new-password" bind:value={confirmPassword} />
		{#if passwordError}<p class="text-xs text-danger-fg" role="alert">{passwordError}</p>{/if}
	</form>
	{#snippet footer()}
		<Button variant="ghost" disabled={changingPassword} onclick={() => (passwordOpen = false)}>Cancel</Button>
		<Button
			type="submit"
			form="password-form"
			variant="primary"
			loading={changingPassword}
			disabled={!currentPassword || !newPassword || !confirmPassword}
		>
			Change password
		</Button>
	{/snippet}
</Dialog>
