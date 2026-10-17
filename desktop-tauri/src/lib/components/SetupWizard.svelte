<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { listen } from '@tauri-apps/api/event';
	import { refreshStatus } from '#lib/store.svelte.js';
	import {
		setupAndLogin,
		completeMfaLogin,
		cancelMfaLogin,
		connectToServer,
		checkSocialStatus,
		checkBrowserSignIn,
		setupWithOAuthTokens,
		exchangeOAuthCode,
		resolveSignIn,
		cancelSignIn,
		type LoginStep,
		type MfaCodeMethod,
		type MfaPrompt,
		type SignInAction,
		type SignInDecision,
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
	import { errorMessage, getLastServerUrl, rememberServerUrl, serverHost, toServerUrl } from '#lib/ui.js';
	import Alert from './ui/Alert.svelte';
	import Button from './ui/Button.svelte';
	import Field from './ui/Field.svelte';
	import Icon from './ui/Icon.svelte';
	import Logo from './ui/Logo.svelte';
	import Segmented from './ui/Segmented.svelte';
	import SignInDecisionStep from './SignInDecision.svelte';

	let wizardStep = $state(1);
	let serverInput = $state(getLastServerUrl());
	let serverUrl = $state('');
	let serverError = $state('');
	let checkingServer = $state(false);
	let username = $state('');
	let password = $state('');
	let passwordConfirm = $state('');
	let email = $state('');
	let fullName = $state('');
	let country = $state('');
	let mobile = $state('');
	let mode = $state<'login' | 'register'>('login');
	const isRegister = $derived(mode === 'register');
	let error = $state('');
	let registrationNotice = $state('');
	let loading = $state(false);
	let connecting = $state(false);

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
	const host = $derived(serverHost(serverUrl));
	const offersBrowser = $derived(Boolean(socialStatus?.enabled) || (desktop && browserSignIn));

	// Keys saved on this computer that don't fit the account: the user decides first
	let decision = $state<SignInDecision | null>(null);
	let deciding = $state(false);

	const steps = ['Server', 'Sign in', 'Ready'];

	function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T | undefined> {
		return Promise.race([promise, new Promise<undefined>((resolve) => setTimeout(() => resolve(undefined), ms))]);
	}

	// Check what the server offers before showing the sign-in options
	async function submitServer(event: SubmitEvent) {
		event.preventDefault();
		const url = toServerUrl(serverInput);
		if (!url) {
			serverError = 'Enter a server address, like cpmesh.example.com.';
			return;
		}
		serverError = '';
		serverUrl = url;
		serverInput = url;
		socialStatus = null;
		browserSignIn = false;
		checkingServer = true;
		const baseUrl = normalizeServerUrl(url);
		await withTimeout(
			Promise.all([
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
			]),
			5000,
		);
		checkingServer = false;
		error = '';
		wizardStep = 2;
	}

	function backToServer() {
		error = '';
		registrationNotice = '';
		cancelBrowserSignIn();
		wizardStep = 1;
	}

	async function changeServer() {
		if (mfaPrompt) await leaveMfa();
		backToServer();
	}

	// Opens a sign-in in the system browser, which returns it through the deep link
	async function openInBrowser(kind: 'sso' | 'dashboard', urlFor: (baseUrl: string, challenge: string) => string) {
		error = '';
		waitingForBrowser = kind;
		try {
			const verifier = createCodeVerifier();
			pkceVerifier = verifier;
			const url = urlFor(normalizeServerUrl(serverUrl), await codeChallenge(verifier));

			const { openUrl } = await import('@tauri-apps/plugin-opener');
			await openUrl(url);
		} catch (e) {
			error = errorMessage(e);
			waitingForBrowser = null;
		}
	}

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
				const step = await setupWithOAuthTokens(baseUrl, access_token, refresh_token);
				// The browser also finished any second-factor step shown here
				mfaPrompt = null;
				await afterSignIn(step, baseUrl);
			} catch (e) {
				error = errorMessage(e);
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

	function validateRegistration(): string {
		if (fullName.trim().length < 2) return 'Enter your full name.';
		if (!email.includes('@')) return 'Enter a valid email address.';
		if (password.length < 8) return 'Use at least 8 characters for your password.';
		if (password !== passwordConfirm) return 'The passwords don’t match.';
		return '';
	}

	async function handleSetup(event: SubmitEvent) {
		event.preventDefault();
		error = '';
		decision = null;
		if (isRegister) {
			error = validateRegistration();
			if (error) return;
		}
		loading = true;
		try {
			const step = await setupAndLogin(
				serverUrl,
				username,
				password,
				isRegister,
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
				registrationNotice = 'Check your inbox for a verification email, then sign in here.';
				mode = 'login';
				password = '';
				passwordConfirm = '';
				return;
			}
			await afterSignIn(step);
		} catch (e) {
			error = errorMessage(e);
		} finally {
			loading = false;
		}
	}

	// Where a finished sign-in leads: this device is set up, or the user first decides
	// what happens to keys saved on it
	async function afterSignIn(step: LoginStep, url = serverUrl) {
		if (step.status === 'decision_required') {
			decision = step;
			return;
		}
		decision = null;
		rememberServerUrl(url);
		wizardStep = 3;
		// After a recovery code, the last step says how many are left before moving on
		if (recoveryCodesLeft === null) await refreshStatus();
	}

	async function resolveDecision(action: SignInAction) {
		error = '';
		deciding = true;
		try {
			await afterSignIn(await resolveSignIn(action));
		} catch (e) {
			error = errorMessage(e);
		} finally {
			deciding = false;
		}
	}

	// Back to the sign-in form; nothing about the saved keys changes
	async function cancelDecision() {
		decision = null;
		error = '';
		recoveryCodesLeft = null;
		try {
			await cancelSignIn();
		} catch {
			// Nothing was waiting
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
			error =
				mfaMethod === 'totp'
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
			if (done.decision) {
				decision = done.decision;
				return;
			}
			rememberServerUrl(serverUrl);
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
		cancelBrowserSignIn();
		try {
			await cancelMfaLogin();
		} catch {
			// Nothing was waiting
		}
	}

	async function handleConnect() {
		connecting = true;
		error = '';
		try {
			await connectToServer();
			await refreshStatus();
		} catch (e) {
			error = `Connection failed: ${errorMessage(e)}`;
		} finally {
			connecting = false;
		}
	}

	const canSubmit = $derived(
		Boolean(username && password) && (!isRegister || Boolean(email && fullName && passwordConfirm)),
	);
	const currentStep = $derived(Math.min(wizardStep, 3));
</script>

{#snippet browserButton(variant: 'primary' | 'secondary')}
	<Button
		{variant}
		size="lg"
		class="w-full"
		icon="external-link"
		loading={waitingForBrowser === 'dashboard'}
		disabled={waitingForBrowser !== null || loading}
		onclick={handleBrowserSignIn}
	>
		{waitingForBrowser === 'dashboard' ? 'Waiting for your browser…' : 'Sign in with browser'}
	</Button>
{/snippet}

{#snippet waitingHint()}
	{#if waitingForBrowser}
		<p class="flex items-center justify-center gap-2 text-xs text-muted" role="status">
			Finish signing in in your browser — this window updates by itself.
			<button type="button" class="font-medium text-fg underline decoration-border-strong underline-offset-4 hover:decoration-fg" onclick={cancelBrowserSignIn}>
				Cancel
			</button>
		</p>
	{/if}
{/snippet}

{#snippet divider(label: string)}
	<div class="flex items-center gap-3 text-xs text-dim" role="separator">
		<span class="h-px flex-1 bg-border"></span>{label}<span class="h-px flex-1 bg-border"></span>
	</div>
{/snippet}

{#snippet heading(title: string, description?: string)}
	<div class="mb-6">
		<h1 class="text-xl font-semibold tracking-tight text-fg">{title}</h1>
		{#if description}<p class="mt-1.5 text-[13px] leading-relaxed text-muted">{description}</p>{/if}
	</div>
{/snippet}

{#snippet serverChip()}
	<div class="mb-5 flex items-center gap-2 rounded-lg border border-border bg-bg-deep px-3 py-2 text-[13px]">
		<Icon name="server" size={14} class="text-dim" />
		<span class="min-w-0 flex-1 truncate text-fg" title={serverUrl}>{host}</span>
		<button
			type="button"
			class="text-xs font-medium text-muted underline decoration-border-strong underline-offset-4 hover:text-fg hover:decoration-fg disabled:opacity-50"
			disabled={loading}
			onclick={changeServer}
		>
			Change
		</button>
	</div>
{/snippet}

<div class="flex min-h-dvh bg-bg">
	<!-- Brand panel: the same near-black tile as the logo, in both themes -->
	<aside class="relative hidden w-[clamp(260px,34%,340px)] shrink-0 flex-col overflow-hidden border-r border-transparent bg-[#0a0a0a] px-8 py-8 text-white sm:flex dark:border-white/10 dark:bg-[#141414]">
		<div class="flex items-center gap-2">
			<Logo size={28} />
			<span class="text-[15px] font-semibold tracking-tight">cpmesh</span>
		</div>
		<div class="relative z-10 mt-14">
			<p class="text-[22px] leading-tight font-semibold tracking-tight text-balance">Copy here. Paste on any device you own.</p>
			<ul class="mt-6 space-y-4 text-[13px] leading-snug text-white/70">
				<li class="flex gap-3">
					<Icon name="lock" size={16} class="mt-px text-white" />
					<span><span class="font-medium text-white">End-to-end encrypted.</span> Your relay only ever stores ciphertext.</span>
				</li>
				<li class="flex gap-3">
					<Icon name="server" size={16} class="mt-px text-white" />
					<span><span class="font-medium text-white">Your own server.</span> Nothing passes through anyone else’s cloud.</span>
				</li>
				<li class="flex gap-3">
					<Icon name="fingerprint" size={16} class="mt-px text-white" />
					<span><span class="font-medium text-white">Devices you approve.</span> Each one joins only after you compare its fingerprint.</span>
				</li>
			</ul>
		</div>
		<!-- The mesh mark, drawn large in hairlines; hidden when the window is too short for it -->
		<svg
			class="pointer-events-none absolute right-6 bottom-6 h-[200px] w-[200px] text-[#0a0a0a] [@media(max-height:620px)]:hidden dark:text-[#141414]"
			viewBox="0 0 32 32"
			fill="none"
			aria-hidden="true"
		>
			<path d="M10 22 L16 11 L22 22 Z" stroke="rgb(255 255 255 / 0.14)" stroke-width="0.3" stroke-linejoin="round" />
			<circle cx="16" cy="11" r="2.6" fill="currentColor" stroke="rgb(255 255 255 / 0.14)" stroke-width="0.3" />
			<circle cx="10" cy="22" r="2.6" fill="currentColor" stroke="rgb(255 255 255 / 0.14)" stroke-width="0.3" />
			<circle cx="22" cy="22" r="2.6" fill="#ff5c38" />
		</svg>
	</aside>

	<main class="flex min-w-0 flex-1 flex-col overflow-y-auto">
		<div class="flex items-center justify-between px-8 pt-7 max-sm:px-5">
			<span class="sm:hidden"><Logo size={24} withText /></span>
			<ol class="ml-auto flex items-center gap-2 text-xs" aria-label="Setup progress">
				{#each steps as label, i (label)}
					{@const n = i + 1}
					<li class="flex items-center gap-2" aria-current={n === currentStep ? 'step' : undefined}>
						{#if i > 0}<span class="h-px w-5 bg-border-strong" aria-hidden="true"></span>{/if}
						<span
							class="flex h-5 w-5 items-center justify-center rounded-full border text-[11px] font-medium tabular-nums transition-colors
								{n < currentStep ? 'border-ink bg-ink text-on-ink' : n === currentStep ? 'border-ink text-fg' : 'border-border-strong text-dim'}"
						>
							{#if n < currentStep}<Icon name="check" size={11} strokeWidth={3} />{:else}{n}{/if}
						</span>
						<span class={n === currentStep ? 'font-medium text-fg' : 'text-dim'}>{label}</span>
					</li>
				{/each}
			</ol>
		</div>

		<div class="flex flex-1 items-center justify-center px-8 py-10 max-sm:px-5">
			<div class="w-full max-w-[380px]">
				{#if wizardStep === 1}
					<div class="animate-[rise-in_0.25s_var(--ease-out-expo)]">
						{@render heading('Connect to your server', 'Enter the address of the cpmesh relay you or your team runs.')}
						<form class="flex flex-col gap-4" onsubmit={submitServer} novalidate>
							<Field
								label="Server address"
								type="url"
								icon="globe"
								placeholder="cpmesh.example.com"
								autocomplete="url"
								autocapitalize="none"
								spellcheck={false}
								bind:value={serverInput}
								error={serverError}
								hint="https:// is added for you unless you type http://"
								autofocus
							/>
							<Button type="submit" variant="primary" size="lg" class="w-full" loading={checkingServer} disabled={!serverInput.trim()}>
								{checkingServer ? 'Checking server…' : 'Continue'}
							</Button>
						</form>
					</div>
				{:else if wizardStep === 2}
					<div class="animate-[rise-in_0.25s_var(--ease-out-expo)]">
						{#if decision}
							<SignInDecisionStep
								{decision}
								busy={deciding}
								{error}
								onresolve={resolveDecision}
								oncancel={cancelDecision}
							/>
						{:else if mfaStep === 'code'}
							{@render heading(
								mfaMethod === 'totp' ? 'Enter your verification code' : 'Use a recovery code',
								mfaMethod === 'totp'
									? 'Open your authenticator app and enter the 6-digit code for cpmesh.'
									: 'Enter one of the recovery codes you saved when you set up two-factor authentication.',
							)}
							{@render serverChip()}
							<form class="flex flex-col gap-4" onsubmit={handleMfaSubmit} novalidate>
								{#if mfaMethod === 'totp'}
									<input
										class="h-14 w-full rounded-lg border border-border bg-surface text-center font-mono text-2xl font-medium tracking-[0.5em] text-fg shadow-xs outline-none transition-[border-color,box-shadow] placeholder:text-border-strong focus:border-ink focus:shadow-[0_0_0_3px_color-mix(in_srgb,var(--color-ink)_10%,transparent)]"
										type="text"
										inputmode="numeric"
										autocomplete="one-time-code"
										pattern="[0-9]*"
										placeholder="000000"
										aria-label="Authentication code"
										aria-invalid={error ? 'true' : undefined}
										value={mfaCode}
										oninput={handleCodeInput}
										bind:this={codeInput}
										{@attach focusOnMount}
									/>
								{:else}
									<input
										class="h-12 w-full rounded-lg border border-border bg-surface text-center font-mono text-base tracking-[0.08em] text-fg shadow-xs outline-none transition-[border-color,box-shadow] placeholder:text-dim focus:border-ink focus:shadow-[0_0_0_3px_color-mix(in_srgb,var(--color-ink)_10%,transparent)]"
										type="text"
										autocomplete="off"
										autocapitalize="none"
										spellcheck="false"
										placeholder="abcd-efgh-ijkl-mnop"
										aria-label="Recovery code"
										aria-invalid={error ? 'true' : undefined}
										bind:value={mfaCode}
										bind:this={codeInput}
										{@attach focusOnMount}
									/>
								{/if}
								{#if error}<p class="text-xs text-danger-fg" role="alert">{error}</p>{/if}
								<Button type="submit" variant="primary" size="lg" class="w-full" loading={loading} disabled={!mfaCode}>
									{loading ? 'Verifying…' : 'Verify and continue'}
								</Button>
							</form>
							<div class="mt-4 flex items-center justify-between text-xs">
								<button type="button" class="text-muted hover:text-fg disabled:opacity-50" onclick={leaveMfa} disabled={loading}>
									← Back to password
								</button>
								{#if mfaCodeMethods.length > 1}
									<button type="button" class="font-medium text-fg underline decoration-border-strong underline-offset-4 hover:decoration-fg disabled:opacity-50" onclick={switchMfaMethod} disabled={loading}>
										{mfaMethod === 'totp' ? 'Use a recovery code' : 'Use authenticator app'}
									</button>
								{/if}
							</div>
							{#if desktop}
								<div class="mt-6 flex flex-col gap-3">
									{@render divider(hasPasskey ? 'or use your passkey' : 'or')}
									{@render browserButton('secondary')}
									{@render waitingHint()}
								</div>
							{/if}
						{:else if mfaStep === 'passkey'}
							{@render heading(
								'Sign in with your passkey',
								hasPasskey
									? 'This account uses a passkey. Passkeys work in your browser, so we’ll finish there and bring you back.'
									: mfaPrompt?.message,
							)}
							{@render serverChip()}
							<div class="flex flex-col gap-3">
								{#if desktop}
									{@render browserButton('primary')}
									{@render waitingHint()}
								{:else}
									<Alert>To sign in here, add an authenticator app to your account on the web dashboard.</Alert>
								{/if}
								{#if error}<p class="text-xs text-danger-fg" role="alert">{error}</p>{/if}
								<Button variant="ghost" class="self-start" onclick={leaveMfa} disabled={loading}>← Back to password</Button>
							</div>
						{:else if mfaStep === 'enroll'}
							{@render heading(
								'Set up two-factor authentication',
								'Your account needs a second factor before it can sign in. Set one up on the web dashboard — it brings you back here when you’re done.',
							)}
							{@render serverChip()}
							<div class="flex flex-col gap-3">
								{#if desktop}
									{@render browserButton('primary')}
									{@render waitingHint()}
								{:else}
									<Alert>Set it up on the web dashboard, then sign in here with a code from your authenticator app.</Alert>
								{/if}
								{#if error}<p class="text-xs text-danger-fg" role="alert">{error}</p>{/if}
								<Button variant="ghost" class="self-start" onclick={leaveMfa} disabled={loading}>← Back to password</Button>
							</div>
						{:else}
							{@render heading(isRegister ? 'Create your account' : 'Sign in', undefined)}
							{@render serverChip()}

							{#if offersBrowser}
								<div class="flex flex-col gap-2.5">
									{#if socialStatus?.enabled}
										<Button
											variant="primary"
											size="lg"
											class="w-full"
											loading={waitingForBrowser === 'sso'}
											disabled={waitingForBrowser !== null || loading}
											onclick={handleSocialLogin}
										>
											{waitingForBrowser === 'sso' ? 'Waiting for your browser…' : `Continue with ${socialStatus.provider}`}
										</Button>
									{/if}
									{#if desktop && browserSignIn}
										{@render browserButton(socialStatus?.enabled ? 'secondary' : 'primary')}
									{/if}
									{@render waitingHint()}
								</div>
								<div class="my-5">{@render divider('or use your password')}</div>
							{/if}

							<Segmented
								label="Account"
								stretch
								class="mb-5"
								bind:value={mode}
								onchange={() => (error = '')}
								options={[
									{ value: 'login', label: 'Sign in' },
									{ value: 'register', label: 'Create account' },
								]}
							/>

							{#if registrationNotice}
								<Alert tone="success" class="mb-4" title="Verify your email">{registrationNotice}</Alert>
							{/if}

							<form class="flex flex-col gap-3.5" onsubmit={handleSetup} novalidate>
								{#if isRegister}
									<Field label="Full name" autocomplete="name" bind:value={fullName} />
									<Field label="Email" type="email" autocomplete="email" bind:value={email} />
								{/if}
								<Field
									label={isRegister ? 'Username' : 'Username or email'}
									autocomplete="username"
									autocapitalize="none"
									spellcheck={false}
									bind:value={username}
								/>
								<Field
									label="Password"
									type="password"
									autocomplete={isRegister ? 'new-password' : 'current-password'}
									hint={isRegister ? 'At least 8 characters.' : undefined}
									bind:value={password}
								/>
								{#if isRegister}
									<Field label="Confirm password" type="password" autocomplete="new-password" bind:value={passwordConfirm} />
									<div class="grid grid-cols-2 gap-3">
										<Field label="Country" optional autocomplete="country-name" bind:value={country} />
										<Field label="Mobile" optional type="tel" autocomplete="tel" bind:value={mobile} />
									</div>
								{/if}
								{#if error}<p class="text-xs text-danger-fg" role="alert">{error}</p>{/if}
								<Button type="submit" variant="primary" size="lg" class="mt-1 w-full" loading={loading} disabled={!canSubmit || waitingForBrowser !== null}>
									{loading ? (isRegister ? 'Creating account…' : 'Signing in…') : isRegister ? 'Create account' : 'Sign in'}
								</Button>
							</form>
						{/if}
					</div>
				{:else}
					<div class="animate-[rise-in_0.25s_var(--ease-out-expo)]">
						<div class="mb-5 flex h-11 w-11 items-center justify-center rounded-xl border border-success-line bg-success-soft text-success">
							<Icon name="check" size={20} strokeWidth={2.5} />
						</div>
						{#if recoveryCodesLeft !== null}
							{@render heading('You’re signed in', 'That recovery code is now used up and can’t be used again.')}
							<Alert tone={recoveryCodesLeft <= 2 ? 'warning' : 'info'} class="mb-5" title={recoveryCodesLeftText(recoveryCodesLeft)}>
								If you lost your authenticator, set up a new one and get fresh recovery codes on the web dashboard.
							</Alert>
							<Button variant="primary" size="lg" class="w-full" onclick={() => refreshStatus()}>Continue</Button>
						{:else}
							{@render heading('This device is ready', 'Connect to start syncing your clipboard.')}
							{#if error}<p class="mb-3 text-xs text-danger-fg" role="alert">{error}</p>{/if}
							<Button variant="primary" size="lg" class="w-full" loading={connecting} onclick={handleConnect}>Connect now</Button>
						{/if}
					</div>
				{/if}
			</div>
		</div>
	</main>
</div>
