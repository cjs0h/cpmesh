<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { getAppStateValue, getStatusValue, refreshStatus } from '$lib/store.svelte';
	import { setupAndLogin, connectToServer, disconnectFromServer, checkSocialStatus, setupWithOAuthTokens, exchangeOAuthCode, type SocialStatus } from '$lib/api';
	import { listen } from '@tauri-apps/api/event';

	const appState = $derived(getAppStateValue());
	const status = $derived(getStatusValue());

	// Setup wizard state
	let wizardStep = $state(1);
	let serverUrl = $state('');
	let username = $state('');
	let password = $state('');
	let passwordConfirm = $state('');
	let email = $state('');
	let fullName = $state('');
	let country = $state('');
	let mobile = $state('');
	let isRegister = $state(false);
	let error = $state('');
	let loading = $state(false);

	// Social login state
	let socialStatus = $state<SocialStatus | null>(null);
	let socialLoading = $state(false);
	let pkceVerifier = $state('');
	let unlistenOAuth: (() => void) | null = null;

	// Generate PKCE code_verifier and code_challenge
	function generatePkce(): { verifier: string; challenge: string } {
		const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
		const array = new Uint8Array(64);
		crypto.getRandomValues(array);
		const verifier = Array.from(array, (b) => charset[b % charset.length]).join('');

		// SHA256 → base64url
		const encoder = new TextEncoder();
		const data = encoder.encode(verifier);
		return { verifier, challenge: '' }; // challenge computed async
	}

	async function computeChallenge(verifier: string): Promise<string> {
		const encoder = new TextEncoder();
		const data = encoder.encode(verifier);
		const hash = await crypto.subtle.digest('SHA-256', data);
		const base64 = btoa(String.fromCharCode(...new Uint8Array(hash)));
		// base64url encoding
		return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
	}

	// Check social status when moving to step 2
	async function goToStep2() {
		wizardStep = 2;
		socialStatus = null;
		if (serverUrl) {
			try {
				socialStatus = await checkSocialStatus(serverUrl.trim().replace(/\/+$/, ''));
			} catch {
				// Social login unavailable — ignore
			}
		}
	}

	// Initiate social login via system browser
	async function handleSocialLogin() {
		error = '';
		socialLoading = true;
		try {
			const { verifier } = generatePkce();
			pkceVerifier = verifier;
			const challenge = await computeChallenge(verifier);

			const baseUrl = serverUrl.trim().replace(/\/+$/, '');
			const loginUrl = `${baseUrl}/api/auth/social/login?client_redirect=${encodeURIComponent('cpmesh://auth/callback')}&code_challenge=${encodeURIComponent(challenge)}&code_challenge_method=S256`;

			// Open in system browser
			const { openUrl } = await import('@tauri-apps/plugin-opener');
			await openUrl(loginUrl);
		} catch (e) {
			error = String(e);
			socialLoading = false;
		}
	}

	// Listen for OAuth callback from deep link
	onMount(async () => {
		unlistenOAuth = await listen<{ code: string }>('oauth-callback', async (event) => {
			const { code } = event.payload;
			if (!code || !pkceVerifier) return;

			error = '';
			loading = true;
			try {
				const baseUrl = serverUrl.trim().replace(/\/+$/, '');
				// Exchange one-time code + verifier for tokens via Rust backend (bypasses CORS)
				const { access_token, refresh_token } = await exchangeOAuthCode(baseUrl, code, pkceVerifier);

				// Complete device setup with the obtained tokens
				await setupWithOAuthTokens(baseUrl, access_token, refresh_token);
				wizardStep = 3;
				await refreshStatus();
			} catch (e) {
				error = String(e);
			} finally {
				loading = false;
				socialLoading = false;
				pkceVerifier = '';
			}
		});
	});

	onDestroy(() => {
		if (unlistenOAuth) unlistenOAuth();
	});

	async function handleSetup() {
		error = '';
		if (isRegister) {
			if (password !== passwordConfirm) {
				error = 'Passwords do not match';
				return;
			}
			if (password.length < 8) {
				error = 'Password must be at least 8 characters';
				return;
			}
			if (!email.includes('@')) {
				error = 'Please enter a valid email';
				return;
			}
			if (fullName.trim().length < 2) {
				error = 'Full name is required';
				return;
			}
		}
		loading = true;
		try {
			await setupAndLogin(
				serverUrl, username, password, isRegister,
				isRegister ? email : undefined,
				isRegister ? fullName : undefined,
				isRegister ? passwordConfirm : undefined,
				isRegister && country ? country : undefined,
				isRegister && mobile ? mobile : undefined,
			);
			wizardStep = 3;
			await refreshStatus();
		} catch (e) {
			error = String(e);
		} finally {
			loading = false;
		}
	}

	let connecting = $state(false);

	async function handleConnect() {
		connecting = true;
		error = '';
		try {
			await connectToServer();
		} catch (e) {
			error = `Connection failed: ${e}`;
		} finally {
			connecting = false;
		}
	}

	async function handleDisconnect() {
		try {
			await disconnectFromServer();
		} catch (e) {
			console.error('Disconnect failed:', e);
		}
	}
</script>

{#if appState === 'not_configured'}
	<!-- Setup Wizard -->
	<div class="wizard">
		<div class="wizard-card card">
			<h1>Welcome to cpmesh</h1>
			<p class="subtitle">Encrypted clipboard sync across your devices</p>

			{#if wizardStep === 1}
				<div class="step">
					<h3>Step 1: Server</h3>
					<p>Enter the URL of your cpmesh server.</p>
					<input
						type="url"
						placeholder="https://your-server.com"
						bind:value={serverUrl}
					/>
					<button class="primary" onclick={goToStep2} disabled={!serverUrl}>
						Next
					</button>
				</div>
			{:else if wizardStep === 2}
				<div class="step">
					<h3>Step 2: Account</h3>

					{#if socialStatus?.enabled}
						<button
							class="social-btn"
							onclick={handleSocialLogin}
							disabled={socialLoading || loading}
						>
							{socialLoading ? 'Waiting for browser...' : `Continue with ${socialStatus.provider}`}
						</button>
						{#if socialLoading}
							<p class="social-hint">Complete sign-in in your browser. This window will update automatically.</p>
						{/if}
						<div class="divider"><span>or</span></div>
					{/if}

					<div class="tabs">
						<button class:active={!isRegister} onclick={() => (isRegister = false)}>Login</button>
						<button class:active={isRegister} onclick={() => (isRegister = true)}>Register</button>
					</div>
					{#if isRegister}
						<input type="text" placeholder="Full Name *" bind:value={fullName} />
						<input type="email" placeholder="Email *" bind:value={email} />
					{/if}
					<input type="text" placeholder={isRegister ? 'Username *' : 'Username or Email'} bind:value={username} />
					<input type="password" placeholder="Password" bind:value={password} />
					{#if isRegister}
						<input type="password" placeholder="Confirm Password *" bind:value={passwordConfirm} />
						<input type="text" placeholder="Country (optional)" bind:value={country} />
						<input type="tel" placeholder="Mobile (optional)" bind:value={mobile} />
					{/if}
					{#if error}
						<p class="error">{error}</p>
					{/if}
					<div class="button-row">
						<button onclick={() => (wizardStep = 1)}>Back</button>
						<button class="primary" onclick={handleSetup} disabled={loading || !username || !password || (isRegister && (!email || !fullName || !passwordConfirm))}>
							{loading ? 'Setting up...' : isRegister ? 'Register & Connect' : 'Login & Connect'}
						</button>
					</div>
				</div>
			{:else}
				<div class="step">
					<h3>All Set!</h3>
					<p>Your device is configured and ready to sync.</p>
					<button class="primary" onclick={handleConnect}>Connect Now</button>
				</div>
			{/if}
		</div>
	</div>
{:else}
	<!-- Status Page -->
	<div class="status-page">
		<h1>Status</h1>

		{#if error}
			<p class="error status-error">{error}</p>
		{/if}

		<div class="status-grid">
			<div class="card status-main">
				<div class="status-indicator" class:connected={appState === 'connected'} class:connecting={appState === 'connecting'}>
					<span class="dot"></span>
					<span class="label">
						{#if appState === 'connected'}Connected
						{:else if appState === 'connecting'}Connecting...
						{:else}Disconnected{/if}
					</span>
				</div>
				{#if appState === 'connected'}
					<button class="danger" onclick={handleDisconnect}>Disconnect</button>
				{:else if appState === 'connecting'}
					<button onclick={handleDisconnect}>Cancel</button>
				{:else}
					<button class="primary" onclick={handleConnect} disabled={connecting}>
						{connecting ? 'Connecting...' : 'Connect'}
					</button>
				{/if}
			</div>

			<div class="card">
				<div class="stat-label">Server</div>
				<div class="stat-value">{status?.server_url || '—'}</div>
			</div>

			<div class="card">
				<div class="stat-label">Device</div>
				<div class="stat-value">{status?.device_name || '—'}</div>
			</div>

			<div class="card">
				<div class="stat-label">Devices Online</div>
				<div class="stat-value">{status?.online_count || 0} / {status?.device_count || 0}</div>
			</div>
		</div>
	</div>
{/if}

<style>
	.wizard {
		display: flex;
		justify-content: center;
		align-items: center;
		min-height: 100vh;
		padding: 2rem;
	}

	.wizard-card {
		max-width: 400px;
		width: 100%;
		text-align: center;
	}

	.wizard-card h1 {
		font-size: 1.5rem;
		margin-bottom: 0.25rem;
	}

	.subtitle {
		color: var(--text-secondary);
		margin-bottom: 1.5rem;
		font-size: 0.875rem;
	}

	.step {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
		text-align: left;
	}

	.step h3 {
		font-size: 1rem;
		text-align: center;
	}

	.step p {
		font-size: 0.875rem;
		color: var(--text-secondary);
		text-align: center;
	}

	.tabs {
		display: flex;
		gap: 0.5rem;
		justify-content: center;
	}

	.tabs button {
		background: none;
		border: none;
		color: var(--text-secondary);
		padding: 0.375rem 0.75rem;
		border-bottom: 2px solid transparent;
	}

	.tabs button.active {
		color: var(--accent);
		border-bottom-color: var(--accent);
	}

	.button-row {
		display: flex;
		gap: 0.5rem;
		justify-content: flex-end;
	}

	.error {
		color: var(--danger);
		font-size: 0.8rem;
	}

	.status-error {
		padding: 0.5rem;
		background: rgba(239, 68, 68, 0.1);
		border-radius: var(--radius, 0.5rem);
		margin-bottom: 1rem;
	}

	.social-btn {
		width: 100%;
		padding: 0.625rem;
		background: var(--accent);
		color: white;
		border: none;
		border-radius: 6px;
		font-size: 0.875rem;
		font-weight: 500;
		cursor: pointer;
	}

	.social-btn:hover:not(:disabled) {
		opacity: 0.9;
	}

	.social-btn:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}

	.social-hint {
		font-size: 0.75rem;
		color: var(--text-secondary);
		text-align: center;
		margin: 0;
	}

	.divider {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		color: var(--text-secondary);
		font-size: 0.75rem;
	}

	.divider::before,
	.divider::after {
		content: '';
		flex: 1;
		height: 1px;
		background: var(--border);
	}

	.status-page h1 {
		font-size: 1.25rem;
		margin-bottom: 1rem;
	}

	.status-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
		gap: 1rem;
	}

	.status-main {
		grid-column: 1 / -1;
		display: flex;
		align-items: center;
		justify-content: space-between;
	}

	.status-indicator {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.dot {
		width: 10px;
		height: 10px;
		border-radius: 50%;
		background: var(--danger);
	}

	.connected .dot {
		background: var(--success);
	}

	.connecting .dot {
		background: var(--warning);
		animation: pulse 1s infinite;
	}

	@keyframes pulse {
		50% { opacity: 0.5; }
	}

	.stat-label {
		font-size: 0.75rem;
		color: var(--text-secondary);
		text-transform: uppercase;
		letter-spacing: 0.05em;
		margin-bottom: 0.25rem;
	}

	.stat-value {
		font-size: 1rem;
		font-weight: 500;
		word-break: break-all;
	}
</style>
