<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { getAppStateValue, getStatusValue, refreshStatus } from '#lib/store.svelte.js';
	import {
		setupAndLogin,
		completeMfaLogin,
		cancelMfaLogin,
		connectToServer,
		disconnectFromServer,
		checkSocialStatus,
		checkBrowserSignIn,
		setupWithOAuthTokens,
		exchangeOAuthCode,
		type MfaCodeMethod,
		type MfaPrompt,
		type SocialStatus,
	} from '#lib/api.js';
	import {
		browserSignInUrl,
		codeChallenge,
		codeMethods,
		createCodeVerifier,
		keepCodeDigits,
		mfaErrorOf,
		mfaView,
		normalizeMfaCode,
		normalizeServerUrl,
		recoveryCodesLeftText,
		socialLoginUrl,
	} from '#lib/auth.js';
	import { isDesktop } from '#lib/platform.js';
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
	let registrationNotice = $state('');
	let loading = $state(false);

	// Sign-in in the system browser: single sign-on, or the web dashboard
	let socialStatus = $state<SocialStatus | null>(null);
	let browserSignIn = $state(false);
	let waitingForBrowser = $state<'sso' | 'dashboard' | null>(null);
	let pkceVerifier = $state('');
	let unlistenOAuth: (() => void) | null = null;
	// The browser hands the sign-in back through a deep link, which only the desktop app registers
	const desktop = isDesktop();

	// Second factor, once the password checked out
	let mfaPrompt = $state<MfaPrompt | null>(null);
	let mfaMethod = $state<MfaCodeMethod>('totp');
	let mfaCode = $state('');
	let codeInput = $state<HTMLInputElement | null>(null);
	let recoveryCodesLeft = $state<number | null>(null);
	const mfaStep = $derived(mfaPrompt ? mfaView(mfaPrompt) : null);
	const mfaCodeMethods = $derived(mfaPrompt ? codeMethods(mfaPrompt) : []);
	const hasPasskey = $derived(mfaPrompt?.methods.includes('webauthn') ?? false);

	// Check what the server offers when moving to step 2
	async function goToStep2() {
		wizardStep = 2;
		socialStatus = null;
		browserSignIn = false;
		const baseUrl = normalizeServerUrl(serverUrl);
		if (baseUrl) {
			await Promise.all([
				checkSocialStatus(baseUrl)
					.then((s) => (socialStatus = s))
					.catch(() => {
						// Social login unavailable — ignore
					}),
				checkBrowserSignIn(baseUrl)
					.then((supported) => (browserSignIn = supported))
					.catch(() => {
						// Older server — no browser sign-in
					}),
			]);
		}
	}

	// Opens a sign-in in the system browser, which returns it through the deep link
	async function openInBrowser(
		kind: 'sso' | 'dashboard',
		urlFor: (baseUrl: string, challenge: string) => string,
	) {
		error = '';
		waitingForBrowser = kind;
		try {
			const verifier = createCodeVerifier();
			pkceVerifier = verifier;
			const url = urlFor(normalizeServerUrl(serverUrl), await codeChallenge(verifier));

			const { openUrl } = await import('@tauri-apps/plugin-opener');
			await openUrl(url);
		} catch (e) {
			error = String(e);
			waitingForBrowser = null;
		}
	}

	// Initiate social login via system browser
	function handleSocialLogin() {
		return openInBrowser('sso', socialLoginUrl);
	}

	// The web dashboard also handles passkeys and setting up two-factor authentication
	function handleBrowserSignIn() {
		return openInBrowser('dashboard', browserSignInUrl);
	}

	// A late callback from the abandoned sign-in is ignored without the verifier
	function cancelBrowserSignIn() {
		waitingForBrowser = null;
		pkceVerifier = '';
	}

	// Listen for OAuth callback from deep link
	onMount(async () => {
		unlistenOAuth = await listen<{ code: string }>('oauth-callback', async (event) => {
			const { code } = event.payload;
			if (!code || !pkceVerifier) return;

			error = '';
			loading = true;
			try {
				const baseUrl = normalizeServerUrl(serverUrl);
				// Exchange one-time code + verifier for tokens via Rust backend (bypasses CORS)
				const { access_token, refresh_token } = await exchangeOAuthCode(baseUrl, code, pkceVerifier);

				// Complete device setup with the obtained tokens
				await setupWithOAuthTokens(baseUrl, access_token, refresh_token);
				// The browser also finished any second-factor step shown here
				mfaPrompt = null;
				wizardStep = 3;
				await refreshStatus();
			} catch (e) {
				error = String(e);
			} finally {
				loading = false;
				waitingForBrowser = null;
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
			const step = await setupAndLogin(
				serverUrl, username, password, isRegister,
				isRegister ? email : undefined,
				isRegister ? fullName : undefined,
				isRegister ? passwordConfirm : undefined,
				isRegister && country ? country : undefined,
				isRegister && mobile ? mobile : undefined,
			);
			if (step.status === 'mfa_required') {
				startMfa(step);
				return;
			}
			if (step.status === 'verification_sent') {
				registrationNotice = 'If your details are valid, you will receive a verification email. Check your inbox, then sign in.';
				isRegister = false;
				password = '';
				passwordConfirm = '';
				return;
			}
			wizardStep = 3;
			await refreshStatus();
		} catch (e) {
			error = String(e);
		} finally {
			loading = false;
		}
	}

	function startMfa(prompt: MfaPrompt) {
		mfaPrompt = prompt;
		mfaMethod = codeMethods(prompt)[0] ?? 'totp';
		mfaCode = '';
		// The password did its part; a new sign-in needs it typed again
		password = '';
		passwordConfirm = '';
	}

	function switchMfaMethod() {
		mfaMethod = mfaMethod === 'totp' ? 'recovery' : 'totp';
		mfaCode = '';
		error = '';
	}

	// Typed or pasted authenticator codes keep their digits only
	function handleCodeInput(event: Event & { currentTarget: EventTarget & HTMLInputElement }) {
		const digits = keepCodeDigits(event.currentTarget.value);
		event.currentTarget.value = digits;
		mfaCode = digits;
	}

	function focusOnMount(node: HTMLInputElement) {
		node.focus();
	}

	async function handleMfaSubmit(event: SubmitEvent) {
		event.preventDefault();
		const code = normalizeMfaCode(mfaMethod, mfaCode);
		if (!code) {
			error = mfaMethod === 'totp'
				? 'Enter the 6-digit code from your authenticator app.'
				: 'Enter a recovery code, like abcd-efgh-ijkl-mnop.';
			return;
		}
		error = '';
		loading = true;
		try {
			const done = await completeMfaLogin(mfaMethod, code);
			mfaPrompt = null;
			recoveryCodesLeft = done.recovery_codes_remaining ?? null;
			wizardStep = 3;
			// After a recovery code, the last step says how many are left before moving on
			if (recoveryCodesLeft === null) await refreshStatus();
		} catch (e) {
			const failure = mfaErrorOf(e);
			error = failure.message;
			if (failure.restart) {
				mfaPrompt = null;
			} else {
				// Ready for another try
				if (mfaMethod === 'totp') mfaCode = '';
				codeInput?.focus();
			}
		} finally {
			loading = false;
		}
	}

	// Back to the password form, dropping the paused sign-in
	async function leaveMfa() {
		mfaPrompt = null;
		mfaCode = '';
		error = '';
		try {
			await cancelMfaLogin();
		} catch {
			// Nothing was waiting
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

{#snippet waitingHint()}
	{#if waitingForBrowser}
		<p class="social-hint">
			Complete sign-in in your browser. This window will update automatically.
			<button class="link-btn" onclick={cancelBrowserSignIn}>Cancel</button>
		</p>
	{/if}
{/snippet}

{#snippet browserButton(className: string)}
	<button class={className} onclick={handleBrowserSignIn} disabled={waitingForBrowser !== null || loading}>
		{waitingForBrowser === 'dashboard' ? 'Waiting for browser...' : 'Sign in with browser'}
	</button>
{/snippet}

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
					{#if mfaStep === 'code'}
						<h3>Two-factor authentication</h3>
						<p>
							{mfaMethod === 'totp'
								? 'Enter the 6-digit code from your authenticator app.'
								: 'Enter one of the recovery codes you saved when you set up two-factor authentication.'}
						</p>
						<form class="mfa-form" onsubmit={handleMfaSubmit}>
							{#if mfaMethod === 'totp'}
								<input
									class="code-input"
									type="text"
									inputmode="numeric"
									autocomplete="one-time-code"
									pattern="[0-9]*"
									aria-label="Authentication code"
									value={mfaCode}
									oninput={handleCodeInput}
									bind:this={codeInput}
									use:focusOnMount
								/>
							{:else}
								<input
									class="code-input recovery"
									type="text"
									autocomplete="off"
									autocapitalize="none"
									spellcheck="false"
									placeholder="abcd-efgh-ijkl-mnop"
									aria-label="Recovery code"
									bind:value={mfaCode}
									bind:this={codeInput}
									use:focusOnMount
								/>
							{/if}
							{#if error}
								<p class="error" role="alert">{error}</p>
							{/if}
							<div class="button-row">
								<button type="button" onclick={leaveMfa} disabled={loading}>Back</button>
								<button class="primary" type="submit" disabled={loading || !mfaCode}>
									{loading ? 'Verifying...' : 'Verify'}
								</button>
							</div>
						</form>
						{#if mfaCodeMethods.length > 1}
							<button class="link-btn" onclick={switchMfaMethod} disabled={loading}>
								{mfaMethod === 'totp' ? 'Use a recovery code' : 'Use your authenticator app'}
							</button>
						{/if}
						{#if desktop}
							<div class="divider"><span>or</span></div>
							{@render browserButton('browser-btn')}
							{#if hasPasskey && !waitingForBrowser}
								<p class="social-hint">Use your passkey in the browser.</p>
							{/if}
							{@render waitingHint()}
						{/if}
					{:else if mfaStep === 'passkey'}
						<h3>Two-factor authentication</h3>
						<p>
							{hasPasskey
								? 'This account signs in with a passkey. Passkeys work in your browser, not inside the app.'
								: mfaPrompt?.message}
						</p>
						{#if desktop}
							{@render browserButton('primary')}
							{@render waitingHint()}
						{:else}
							<p>To sign in here, add an authenticator app to your account on the web dashboard.</p>
						{/if}
						{#if error}
							<p class="error" role="alert">{error}</p>
						{/if}
						<div class="button-row">
							<button onclick={leaveMfa} disabled={loading}>Back</button>
						</div>
					{:else if mfaStep === 'enroll'}
						<h3>Set up two-factor authentication</h3>
						<p>
							This account needs two-factor authentication to sign in, and it isn't set up yet.
							Set it up on the web dashboard.
						</p>
						{#if desktop}
							{@render browserButton('primary')}
							{#if !waitingForBrowser}
								<p class="social-hint">Your browser walks you through it, then brings you back here.</p>
							{/if}
							{@render waitingHint()}
						{:else}
							<p>Then sign in here with a code from your authenticator app.</p>
						{/if}
						{#if error}
							<p class="error" role="alert">{error}</p>
						{/if}
						<div class="button-row">
							<button onclick={leaveMfa} disabled={loading}>Back</button>
						</div>
					{:else}
						<h3>Step 2: Account</h3>

						{#if socialStatus?.enabled}
							<button
								class="social-btn"
								onclick={handleSocialLogin}
								disabled={waitingForBrowser !== null || loading}
							>
								{waitingForBrowser === 'sso' ? 'Waiting for browser...' : `Continue with ${socialStatus.provider}`}
							</button>
						{/if}
						{#if desktop && browserSignIn}
							{@render browserButton('browser-btn')}
						{/if}
						{#if socialStatus?.enabled || (desktop && browserSignIn)}
							{@render waitingHint()}
							<div class="divider"><span>or</span></div>
						{/if}

						<div class="tabs">
							<button class:active={!isRegister} onclick={() => (isRegister = false)}>Login</button>
							<button class:active={isRegister} onclick={() => (isRegister = true)}>Register</button>
						</div>
						{#if registrationNotice}<p role="status">{registrationNotice}</p>{/if}
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
								{loading ? 'Setting up...' : isRegister ? 'Register' : 'Login & Connect'}
							</button>
						</div>
					{/if}
				</div>
			{:else}
				<div class="step">
					<h3>All Set!</h3>
					{#if recoveryCodesLeft !== null}
						<p>
							You signed in with a recovery code, so it can't be used again.
							{recoveryCodesLeftText(recoveryCodesLeft)}
							If you lost your authenticator, set up a new one and get new recovery codes on the web dashboard.
						</p>
						<button class="primary" onclick={() => refreshStatus()}>Continue</button>
					{:else}
						<p>Your device is configured and ready to sync.</p>
						<button class="primary" onclick={handleConnect}>Connect Now</button>
					{/if}
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

	.error,
	.step .error {
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

	.browser-btn {
		width: 100%;
		padding: 0.625rem;
		border-radius: 6px;
		font-weight: 500;
	}

	.browser-btn:disabled,
	.link-btn:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}

	.link-btn {
		align-self: center;
		padding: 0;
		border: none;
		background: none;
		color: var(--accent);
		font-size: 0.8rem;
	}

	.link-btn:hover:not(:disabled) {
		background: none;
		text-decoration: underline;
	}

	.social-hint .link-btn {
		font-size: inherit;
	}

	.mfa-form {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}

	.code-input {
		font-family: monospace;
		font-size: 1.25rem;
		letter-spacing: 0.2em;
		text-align: center;
	}

	.code-input.recovery {
		font-size: 1rem;
		letter-spacing: 0.05em;
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
