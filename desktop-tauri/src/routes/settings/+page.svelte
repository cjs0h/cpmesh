<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { getConfig, updateConfig, changePassword, checkUpdate, downloadAndInstallUpdate, logout, disconnectFromServer, connectToServer, setupAndLogin, getUserInfo, type AppConfig } from '#lib/api.js';
	import { setAppState, refreshStatus } from '#lib/store.svelte.js';
	import { isDesktop } from '#lib/platform.js';
	import { getVersion } from '@tauri-apps/api/app';

	let config = $state<AppConfig | null>(null);
	let loading = $state(true);
	let settingsError = $state('');
	const desktop = isDesktop();
	let authProvider = $state('local');
	let savingToggle = $state(false);

	// Password change
	let currentPassword = $state('');
	let newPassword = $state('');
	let confirmPassword = $state('');
	let passwordMsg = $state('');
	let passwordError = $state(false);
	let changingPassword = $state(false);

	// Update check
	let updateInfo = $state<import('#lib/api.js').UpdateInfo | null>(null);
	let checkingUpdate = $state(false);
	let updateCheckFailed = $state(false);
	let downloadingUpdate = $state(false);
	let downloadError = $state('');
	let appVersion = $state('0.1.0');

	async function loadConfig() {
		loading = true;
		settingsError = '';
		try {
			config = await getConfig();
		} catch (e) {
			settingsError = 'Failed to load settings.';
			console.error('loadConfig:', e);
		} finally {
			loading = false;
		}
	}

	async function toggleSetting(key: 'auto_connect' | 'autostart' | 'notifications_enabled') {
		if (!config || savingToggle) return;
		const prev = config[key];
		config[key] = !prev;
		savingToggle = true;
		try {
			await updateConfig({ [key]: config[key] });
		} catch (e) {
			config[key] = prev; // rollback on failure
			settingsError = 'Failed to save setting.';
			setTimeout(() => { settingsError = ''; }, 3000);
			console.error('toggleSetting:', e);
		} finally {
			savingToggle = false;
		}
	}

	async function handlePasswordChange() {
		passwordMsg = '';
		passwordError = false;

		if (newPassword !== confirmPassword) {
			passwordMsg = 'Passwords do not match';
			passwordError = true;
			return;
		}
		if (newPassword.length < 6) {
			passwordMsg = 'Password must be at least 6 characters';
			passwordError = true;
			return;
		}

		changingPassword = true;
		try {
			await changePassword(currentPassword, newPassword);
			passwordMsg = 'Password changed successfully';
			currentPassword = '';
			newPassword = '';
			confirmPassword = '';
		} catch (e) {
			passwordMsg = String(e);
			passwordError = true;
		} finally {
			changingPassword = false;
		}
	}

	async function handleCheckUpdate() {
		checkingUpdate = true;
		updateCheckFailed = false;
		try {
			updateInfo = await checkUpdate();
		} catch (e) {
			updateCheckFailed = true;
			console.error('checkUpdate:', e);
		} finally {
			checkingUpdate = false;
		}
	}

	// Change Server flow (multi-step: URL → credentials → done)
	let changeServerStep = $state(0); // 0 = hidden, 1 = URL+device, 2 = login, 3 = done
	let csUrl = $state('');
	let csUsername = $state('');
	let csPassword = $state('');
	let csIsRegister = $state(false);
	let csError = $state('');
	let csLoading = $state(false);

	function startChangeServer() {
		csUrl = config?.server_url ?? '';
		csUsername = '';
		csPassword = '';
		csIsRegister = false;
		csError = '';
		csLoading = false;
		changeServerStep = 1;
	}

	function cancelChangeServer() {
		changeServerStep = 0;
		csError = '';
	}

	async function csSubmitLogin() {
		csError = '';
		csLoading = true;
		try {
			// Disconnect current session
			try { await disconnectFromServer(); } catch {}
			// Full setup: login/register + device registration + key exchange
			await setupAndLogin(
				csUrl.trim().replace(/\/+$/, ''),
				csUsername,
				csPassword,
				csIsRegister
			);
			changeServerStep = 3;
			// Reload config to reflect new values
			await loadConfig();
			await refreshStatus();
		} catch (e) {
			csError = String(e);
		} finally {
			csLoading = false;
		}
	}

	async function csDone() {
		changeServerStep = 0;
		try { await connectToServer(); } catch {}
	}

	let confirmingLogout = $state(false);

	async function handleLogout() {
		try {
			await logout();
			setAppState('not_configured');
			goto('/');
		} catch (e) {
			console.error('Logout failed:', e);
		}
	}

	onMount(() => {
		loadConfig();
		getUserInfo().then((info) => {
			authProvider = info.auth_provider || 'local';
		}).catch(() => {});
		getVersion().then((v) => {
			appVersion = v;
		}).catch(() => {});
	});

	async function handleDownloadAndInstall() {
		if (!updateInfo) return;
		downloadingUpdate = true;
		downloadError = '';
		try {
			await downloadAndInstallUpdate(updateInfo.download_url);
		} catch (e) {
			downloadError = 'Download failed. Please try again.';
			console.error('downloadAndInstall:', e);
		} finally {
			downloadingUpdate = false;
		}
	}
</script>

<div class="settings-page">
	<h1>Settings</h1>

	{#if settingsError}
		<p class="error">{settingsError}</p>
	{/if}

	{#if loading}
		<p>Loading...</p>
	{:else if config}
		<!-- Connection -->
		<section class="card">
			<h2>Connection</h2>

			{#if changeServerStep === 0}
				<!-- Normal display -->
				<div class="setting-row">
					<div>
						<div class="setting-label">Server URL</div>
						<div class="setting-value">{config.server_url}</div>
					</div>
					<button class="small" onclick={startChangeServer}>Change</button>
				</div>
				<div class="setting-row">
					<div>
						<div class="setting-label">Device Name</div>
						<div class="setting-value">{config.device_name}</div>
					</div>
				</div>

			{:else if changeServerStep === 1}
				<!-- Step 1: Server URL -->
				<div class="cs-flow">
					<h3>Change Server — Step 1</h3>
					<p class="muted">Enter the new server URL.</p>
					<input type="url" placeholder="https://your-server.com" bind:value={csUrl} />
					<div class="button-row">
						<button class="small" onclick={cancelChangeServer}>Cancel</button>
						<button class="small primary" onclick={() => changeServerStep = 2} disabled={!csUrl}>
							Next
						</button>
					</div>
				</div>

			{:else if changeServerStep === 2}
				<!-- Step 2: Login / Register -->
				<div class="cs-flow">
					<h3>Change Server — Step 2</h3>
					<p class="muted">Log in or register on <strong>{csUrl}</strong></p>
					<div class="tabs">
						<button class:active={!csIsRegister} onclick={() => csIsRegister = false}>Login</button>
						<button class:active={csIsRegister} onclick={() => csIsRegister = true}>Register</button>
					</div>
					<input type="text" placeholder="Username" bind:value={csUsername} />
					<input type="password" placeholder="Password" bind:value={csPassword} />
					{#if csError}<p class="error">{csError}</p>{/if}
					<div class="button-row">
						<button class="small" onclick={() => changeServerStep = 1}>Back</button>
						<button class="small primary" onclick={csSubmitLogin} disabled={csLoading || !csUsername || !csPassword}>
							{csLoading ? 'Setting up...' : csIsRegister ? 'Register & Setup' : 'Login & Setup'}
						</button>
					</div>
				</div>

			{:else}
				<!-- Step 3: Done -->
				<div class="cs-flow">
					<h3>Server Changed!</h3>
					<p class="muted">Successfully connected to <strong>{csUrl}</strong>.</p>
					<button class="small primary" onclick={csDone}>Done</button>
				</div>
			{/if}

			<div class="setting-row">
				<div>
					<div class="setting-label">Auto-connect on launch</div>
					<div class="setting-desc">Automatically connect when the app starts</div>
				</div>
				<label class="toggle">
					<input type="checkbox" checked={config.auto_connect} onchange={() => toggleSetting('auto_connect')} disabled={savingToggle} />
					<span class="slider"></span>
				</label>
			</div>
			{#if desktop}
			<div class="setting-row">
				<div>
					<div class="setting-label">Start on login</div>
					<div class="setting-desc">Launch cpmesh when you log in</div>
				</div>
				<label class="toggle">
					<input type="checkbox" checked={config.autostart} onchange={() => toggleSetting('autostart')} disabled={savingToggle} />
					<span class="slider"></span>
				</label>
			</div>
			{/if}
		</section>

		<!-- Notifications -->
		<section class="card">
			<h2>Notifications</h2>
			<div class="setting-row">
				<div>
					<div class="setting-label">Clipboard notifications</div>
					<div class="setting-desc">Show a notification when a clipboard entry arrives</div>
				</div>
				<label class="toggle">
					<input type="checkbox" checked={config.notifications_enabled} onchange={() => toggleSetting('notifications_enabled')} disabled={savingToggle} />
					<span class="slider"></span>
				</label>
			</div>
		</section>

		<!-- Password -->
		{#if authProvider === 'local'}
		<section class="card">
			<h2>Change Password</h2>
			<div class="password-form">
				<input type="password" placeholder="Current password" bind:value={currentPassword} />
				<input type="password" placeholder="New password" bind:value={newPassword} />
				<input type="password" placeholder="Confirm new password" bind:value={confirmPassword} />
				{#if passwordMsg}
					<p class:error={passwordError} class:success={!passwordError}>{passwordMsg}</p>
				{/if}
				<button class="primary" onclick={handlePasswordChange} disabled={changingPassword || !currentPassword || !newPassword || !confirmPassword}>
					{changingPassword ? 'Changing...' : 'Change Password'}
				</button>
			</div>
		</section>
		{:else}
		<section class="card">
			<h2>Password</h2>
			<p class="muted">Your account uses <strong>{authProvider}</strong> for authentication. Password is managed by your identity provider.</p>
		</section>
		{/if}

		<!-- About -->
		<section class="card">
			<h2>About</h2>
			<div class="setting-row">
				<div>
					<div class="setting-label">Version</div>
					<div class="setting-value">{appVersion}</div>
				</div>
				{#if desktop}
				<button onclick={handleCheckUpdate} disabled={checkingUpdate}>
					{checkingUpdate ? 'Checking...' : 'Check for Updates'}
				</button>
				{/if}
			</div>
			{#if updateInfo}
				<div class="update-available">
					<p>Update available: <strong>v{updateInfo.version}</strong></p>
					{#if updateInfo.release_notes}
						<p class="muted" style="margin-top: 4px; font-size: 12px;">{updateInfo.release_notes}</p>
					{/if}
					{#if downloadError}
						<p class="error" style="margin-top: 4px;">{downloadError}</p>
					{/if}
					{#if updateInfo.download_url}
						<button class="small primary" onclick={handleDownloadAndInstall} disabled={downloadingUpdate} style="margin-top: 6px; font-size: 13px;">
							{downloadingUpdate ? 'Downloading...' : 'Download & Install'}
						</button>
					{/if}
				</div>
			{:else if updateCheckFailed}
				<p class="error" style="font-size: 12px;">Failed to check for updates.</p>
			{:else if !checkingUpdate}
				<p class="muted" style="font-size: 12px;">You're up to date.</p>
			{/if}
		</section>

		<!-- Danger Zone -->
		<section class="card danger-zone">
			<h2>Danger Zone</h2>
			<div class="setting-row">
				<div>
					<div class="setting-label">Logout &amp; Reset</div>
					<div class="setting-desc">Disconnect and clear all settings. You'll need to set up again.</div>
				</div>
				{#if confirmingLogout}
					<div class="confirm-actions">
						<button class="small danger" onclick={handleLogout}>Confirm</button>
						<button class="small" onclick={() => confirmingLogout = false}>Cancel</button>
					</div>
				{:else}
					<button class="danger" onclick={() => confirmingLogout = true}>Logout</button>
				{/if}
			</div>
		</section>
	{/if}
</div>

<style>
	.settings-page h1 {
		font-size: 1.25rem;
		margin-bottom: 1rem;
	}

	section {
		margin-bottom: 1rem;
	}

	section h2 {
		font-size: 0.875rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--text-secondary);
		margin-bottom: 0.75rem;
	}

	.setting-row {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 0.5rem 0;
	}

	.setting-row + .setting-row {
		border-top: 1px solid var(--border);
	}

	.setting-label {
		font-size: 0.875rem;
		font-weight: 500;
	}

	.setting-desc {
		font-size: 0.75rem;
		color: var(--text-secondary);
	}

	.setting-value {
		font-size: 0.875rem;
		color: var(--text-secondary);
		word-break: break-all;
	}

	.toggle {
		position: relative;
		display: inline-block;
		width: 40px;
		height: 22px;
		flex-shrink: 0;
	}

	.toggle input {
		opacity: 0;
		width: 0;
		height: 0;
	}

	.slider {
		position: absolute;
		cursor: pointer;
		inset: 0;
		background: var(--border);
		border-radius: 22px;
		transition: 0.2s;
	}

	.slider::before {
		content: '';
		position: absolute;
		height: 16px;
		width: 16px;
		left: 3px;
		bottom: 3px;
		background: white;
		border-radius: 50%;
		transition: 0.2s;
	}

	.toggle input:checked + .slider {
		background: var(--accent);
	}

	.toggle input:checked + .slider::before {
		transform: translateX(18px);
	}

	.password-form {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		max-width: 300px;
	}

	.error {
		color: var(--danger);
		font-size: 0.8rem;
	}

	.muted {
		font-size: 0.8rem;
		color: var(--text-secondary);
	}

	.success {
		color: var(--success);
		font-size: 0.8rem;
	}

	.update-available {
		color: var(--accent);
		font-size: 0.875rem;
		margin-top: 0.5rem;
	}

	.cs-flow {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		padding: 0.5rem 0;
	}

	.cs-flow h3 {
		font-size: 0.9rem;
		margin: 0;
	}

	.cs-flow .muted {
		font-size: 0.8rem;
		color: var(--text-secondary);
		margin: 0;
	}

	.cs-flow input {
		max-width: 350px;
	}

	.tabs {
		display: flex;
		gap: 0;
		border-radius: 6px;
		overflow: hidden;
		width: fit-content;
	}

	.tabs button {
		padding: 0.35rem 1rem;
		font-size: 0.8rem;
		border: 1px solid var(--border);
		background: var(--bg-secondary);
		cursor: pointer;
	}

	.tabs button.active {
		background: var(--accent);
		border-color: var(--accent);
		color: white;
	}

	.button-row {
		display: flex;
		gap: 0.5rem;
		margin-top: 0.25rem;
	}

	button.small {
		padding: 0.25rem 0.75rem;
		font-size: 0.75rem;
	}

	button.danger {
		background: var(--danger);
		border-color: var(--danger);
		color: white;
	}

	button.danger:hover {
		opacity: 0.9;
	}

	.danger-zone {
		border: 1px solid var(--danger);
	}

	.danger-zone h2 {
		color: var(--danger);
	}

	.confirm-actions {
		display: flex;
		gap: 0.5rem;
	}
</style>
