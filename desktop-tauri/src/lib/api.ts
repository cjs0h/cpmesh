import { invoke } from '@tauri-apps/api/core';

export interface StatusInfo {
	state: string;
	server_url: string;
	device_name: string;
	device_count: number;
	online_count: number;
}

export interface DeviceInfo {
	id: string;
	name: string;
	last_seen?: string;
	online: boolean;
	status: 'pending' | 'approved' | 'rejected' | 'revoked';
	/** Approved devices: whether the relay holds this device's copy of the current key (absent on older servers). */
	has_current_key?: boolean | null;
}

export interface HistoryEntry {
	id: string;
	device_name: string;
	content_type: string;
	preview: string;
	size: number;
	created_at: string;
}

export interface HistoryPage {
	entries: HistoryEntry[];
	has_more: boolean;
}

export interface AppConfig {
	server_url: string;
	device_id: string;
	device_name: string;
	auto_connect: boolean;
	autostart: boolean;
	notifications_enabled: boolean;
	/** The shortcut that shows cpmesh; change it with `setGlobalShortcut`. */
	global_hotkey: string;
	device_status: string;
}

// Tauri command wrappers

export async function getStatus(): Promise<StatusInfo> {
	return invoke('get_status');
}

export async function getAppState(): Promise<string> {
	return invoke('get_app_state');
}

// === Sign-in ===

export type MfaStage = 'verify' | 'enroll';

/** Second factors the app can send itself; passkeys only work in the browser. */
export type MfaCodeMethod = 'totp' | 'recovery';

/** What to ask for after a correct password, when the account needs a second factor. */
export interface MfaPrompt {
	stage: MfaStage;
	/** verify: the methods the account has; enroll: the methods it can set up */
	methods: string[];
	email_code_required: boolean;
	email_hint: string | null;
	passkeys_available: boolean;
	/** The server's explanation */
	message: string;
}

export type LoginStep =
	| { status: 'signed_in' | 'verification_sent' }
	| ({ status: 'mfa_required' } & MfaPrompt)
	| ({ status: 'decision_required' } & SignInDecision);

export interface MfaLoginDone {
	/** Set when a recovery code was used: how many unused ones are left */
	recovery_codes_remaining: number | null;
	/** Set when the user decides about keys saved on this device before it is set up */
	decision: SignInDecision | null;
}

/** What `completeMfaLogin` rejects with. */
export interface MfaLoginError {
	message: string;
	/** The sign-in cannot continue: start again with the password */
	restart: boolean;
}

export async function setupAndLogin(
	serverUrl: string,
	username: string,
	password: string,
	isRegister: boolean,
	email?: string,
	fullName?: string,
	passwordConfirm?: string,
	country?: string,
	mobile?: string,
): Promise<LoginStep> {
	return invoke('setup_and_login', {
		serverUrl,
		username,
		password,
		isRegister,
		email: email || null,
		fullName: fullName || null,
		passwordConfirm: passwordConfirm || null,
		country: country || null,
		mobile: mobile || null,
	});
}

/** Finishes the sign-in `setupAndLogin` paused for a second factor. */
export async function completeMfaLogin(method: MfaCodeMethod, code: string): Promise<MfaLoginDone> {
	return invoke('complete_mfa_login', { method, code });
}

/** Forgets a sign-in waiting for its second factor. */
export async function cancelMfaLogin(): Promise<void> {
	return invoke('cancel_mfa_login');
}

// === Keys saved on this device, at sign-in ===

/** One of the account's devices, as the relay lists it. */
export interface AccountDevice {
	id: string;
	name: string;
	status: 'pending' | 'approved' | 'rejected' | 'revoked';
	last_seen: string | null;
	online: boolean;
}

/** What the user decides before a sign-in can set up this device. */
export type SignInDecision =
	| {
			/** Keys saved by a version that didn't record whose they are */
			kind: 'unknown_keys';
			account: string;
			/** Whether this device's key opens them; otherwise they can only be set aside */
			readable: boolean;
			/** A device on the account with this computer's device key, if there is one */
			matching_device: string | null;
	  }
	| {
			/** Keys recorded as another account's: archived for it, they come back when it signs in here */
			kind: 'other_account_keys';
			account: string;
			owner_server: string;
			/** This account's own keys, archived here earlier, come back too */
			returning: boolean;
	  }
	| { kind: 'unreadable_keys'; account: string }
	| {
			/** The account has this computer registered with device keys it no longer has */
			kind: 'replace_device';
			account: string;
			/** The registration the server says is this computer's, or the likeliest one */
			suggested_device_id: string | null;
			devices: AccountDevice[];
			/** Key backups on this computer */
			backups: number;
			/** The backup holding the suggested registration's device key */
			matching_backup: string | null;
	  };

export type SignInAction =
	| { action: 'use_saved_keys' }
	| { action: 'set_aside_keys' }
	| { action: 'replace_device'; device_id: string; waiting_device_ids: string[] };

/** Continues a sign-in that stopped for a `SignInDecision`. */
export async function resolveSignIn(action: SignInAction): Promise<LoginStep> {
	return invoke('resolve_sign_in', { action });
}

/** Drops a sign-in that was waiting for a decision. */
export async function cancelSignIn(): Promise<void> {
	return invoke('cancel_sign_in');
}

export async function connectToServer(): Promise<void> {
	return invoke('connect');
}

export async function disconnectFromServer(): Promise<void> {
	return invoke('disconnect');
}

export async function getDevices(): Promise<DeviceInfo[]> {
	return invoke('get_devices');
}

/** What happened to the encryption key after removing or verifying a device. */
export interface KeyUpdate {
	/** The verified device lacked the current key and now has it. */
	shared: boolean;
	/** Why the key couldn't change yet; the removal or verification itself succeeded. */
	blocked: string | null;
}

export async function removeDevice(deviceId: string): Promise<KeyUpdate> {
	return invoke('remove_device', { deviceId });
}

/** The account's other approved devices, and how this device trusts each. */
export async function getDeviceTrust(): Promise<KeyMember[]> {
	return invoke('get_device_trust');
}

/** Shares the key with an approved device once both screens show the same pairing code (session from `beginDeviceApproval`). */
export async function confirmKeyShare(deviceId: string, sessionId: string, code: string): Promise<void> {
	return invoke('confirm_key_share', { deviceId, sessionId, code });
}

// === Device Approval ===

export interface PendingDevice {
	id: string;
	name: string;
	created_at: string;
}

export interface ApprovalSession {
	session_id: string;
	/** Full 64-character pairing code over both identity keys. */
	approval_code: string;
	/** Eight-digit short authentication string ("1234 5678"), once both devices have contributed. */
	sas?: string | null;
	expires_at: string;
}

export interface MyApprovalStatus {
	status: 'pending' | 'approved' | 'rejected' | 'revoked';
	approval_code?: string;
	sas?: string | null;
	session_id?: string;
	/** The device on the other end of the pairing. */
	approver_id?: string | null;
	locally_verified: boolean;
}

export async function getPendingDevices(): Promise<PendingDevice[]> {
	return invoke('get_pending_devices');
}

export async function beginDeviceApproval(pendingDeviceId: string): Promise<ApprovalSession> {
	return invoke('begin_device_approval', { pendingDeviceId });
}

/** Approver: advances the committed short-code exchange; `sas` is set once both nonces are known. */
export async function pollDeviceApproval(pendingDeviceId: string, sessionId: string): Promise<ApprovalSession> {
	return invoke('poll_device_approval', { pendingDeviceId, sessionId });
}

export async function confirmDeviceApproval(pendingDeviceId: string, sessionId: string, fingerprint: string): Promise<void> {
	return invoke('confirm_device_approval', { pendingDeviceId, sessionId, fingerprint });
}

export async function confirmPairing(sessionId: string, fingerprint: string): Promise<void> {
	return invoke('confirm_pairing', { sessionId, fingerprint });
}

export async function getOwnIdentity(): Promise<{ device_id: string; fingerprint: string }> {
	return invoke('get_own_identity');
}

export async function verifyDeviceIdentity(deviceId: string, fingerprint: string): Promise<KeyUpdate> {
	return invoke('verify_device_identity', { deviceId, fingerprint });
}

export async function rejectPendingDevice(pendingDeviceId: string): Promise<void> {
	return invoke('reject_pending_device', { pendingDeviceId });
}

export async function getMyApprovalStatus(): Promise<MyApprovalStatus> {
	return invoke('get_my_approval_status');
}

export async function getHistory(page: number, pageSize: number = 20): Promise<HistoryPage> {
	return invoke('get_history', { page, pageSize });
}

export async function searchHistory(query: string): Promise<HistoryEntry[]> {
	return invoke('search_history', { query });
}

export async function copyEntry(entryId: string): Promise<void> {
	return invoke('copy_entry', { entryId });
}

export async function deleteEntry(entryId: string): Promise<void> {
	return invoke('delete_entry', { entryId });
}

export async function clearHistory(): Promise<void> {
	return invoke('clear_history');
}

export async function syncHistory(): Promise<number> {
	return invoke('sync_history');
}

export async function getConfig(): Promise<AppConfig> {
	return invoke('get_config');
}

export async function updateConfig(updates: Partial<Omit<AppConfig, 'global_hotkey'>>): Promise<void> {
	return invoke('update_config', {
		serverUrl: updates.server_url,
		autoConnect: updates.auto_connect,
		autostart: updates.autostart,
		notificationsEnabled: updates.notifications_enabled,
	});
}

/** Where this device keeps its settings, keyring and clipboard history. */
export async function getDataDir(): Promise<string> {
	return invoke('get_data_dir');
}

/** The shortcut that shows cpmesh from any app (desktop only). */
export interface ShortcutStatus {
	/** Accelerator such as "CmdOrCtrl+Shift+Space"; empty when it's turned off. */
	shortcut: string;
	default_shortcut: string;
	/** Whether pressing it reaches cpmesh right now. */
	registered: boolean;
	/** Why the saved shortcut isn't registered. */
	error: string | null;
	/** On Linux Wayland sessions: a command that shows cpmesh, to bind in the desktop's keyboard settings. */
	launch_command: string | null;
}

export async function getGlobalShortcut(): Promise<ShortcutStatus> {
	return invoke('get_global_shortcut');
}

/** Registers and saves a new shortcut, or turns it off with ''. Rejects with the reason when the system refuses it. */
export async function setGlobalShortcut(shortcut: string): Promise<ShortcutStatus> {
	return invoke('set_global_shortcut', { shortcut });
}

/** Puts text on the clipboard, where cpmesh syncs it like anything else copied. */
export async function copyText(text: string): Promise<void> {
	return invoke('plugin:clipboard-manager|write_text', { text });
}

export async function changePassword(currentPassword: string, newPassword: string): Promise<void> {
	return invoke('change_password', { currentPassword, newPassword });
}

export async function logout(): Promise<void> {
	return invoke('logout');
}

export interface UpdateInfo {
	update_available: boolean;
	version: string;
	download_url: string;
	release_notes: string;
}

export async function checkUpdate(): Promise<UpdateInfo | null> {
	return invoke('check_update');
}

export async function downloadAndInstallUpdate(downloadUrl: string): Promise<void> {
	return invoke('download_and_install_update', { downloadUrl });
}

/** Whether a newer version was installed over the running one (it starts after a restart). */
export async function updateInstalled(): Promise<boolean> {
	return invoke('update_installed');
}

/** Restarts cpmesh, into the newer version when one was installed. */
export async function restartApp(): Promise<void> {
	return invoke('restart_app');
}

// === Encryption key recovery ===

/** This device lacks the account's current encryption key. */
export interface KeyProblem {
	server_version: number;
	/** A device that shared the key with this one but isn't verified here yet */
	shared_by: string | null;
}

export interface KeyBackup {
	path: string;
	name: string;
	/** When cpmesh set these keys aside (RFC 3339); null for backups made by hand */
	created_at: string | null;
	reason: string | null;
	/** The server of the account they belong to, when recorded */
	owner_server: string | null;
	/** Whether they are recorded as this account's; null when nothing says whose */
	same_account: boolean | null;
	/** Key versions inside, when the keyring could be opened */
	versions: number[];
	/** Why it can't be restored, when it can't */
	problem: string | null;
}

/** How this device trusts an approved device's identity. */
export type Trust = 'verified' | 'unverified' | 'key_changed' | 'revoked';

/** Another approved device: one may still have the key, and new keys reach it only once it's verified here. */
export interface KeyMember {
	id: string;
	name: string;
	/** Verified on this device (full fingerprint or pairing code, or a signed membership) */
	verified: boolean;
	/** Why it isn't, when it isn't: never verified, its identity changed, or removed earlier */
	trust: Trust;
	/** It published a certified encryption key (an up-to-date cpmesh) */
	can_receive_keys: boolean;
	/** The relay's word on whether it holds the current key; null on older servers */
	has_current_key: boolean | null;
}

export interface KeyRecoveryStatus {
	problem: KeyProblem | null;
	/** Key versions this device has */
	versions: number[];
	/** Backups found on this computer, newest first */
	backups: KeyBackup[];
	/** The account's other approved devices */
	devices: KeyMember[];
	/** Why the devices couldn't be listed */
	devices_error: string | null;
}

export interface RestoredKeys {
	added: number[];
	current_version: number;
}

export async function getKeyProblem(): Promise<KeyProblem | null> {
	return invoke('get_key_problem');
}

export async function getKeyRecoveryStatus(): Promise<KeyRecoveryStatus> {
	return invoke('get_key_recovery_status');
}

/** Describes a backup folder the user chose, before restoring it. */
export async function inspectKeyBackup(path: string): Promise<KeyBackup> {
	return invoke('inspect_key_backup', { path });
}

/** Adds a backup's keys to this device; never replaces a key it has. */
export async function restoreKeyBackup(path: string): Promise<RestoredKeys> {
	return invoke('restore_key_backup', { path });
}

/**
 * Last resort, after the user confirmed the warning: starts a new encryption key because
 * no device and no backup has the current one (`expectedVersion`).
 */
export async function resetEncryption(expectedVersion: number): Promise<number> {
	return invoke('reset_encryption', { expectedVersion });
}

// === OAuth / Social Login ===

export interface SocialStatus {
	enabled: boolean;
	provider: string;
}

export interface UserInfo {
	id: string;
	username: string;
	email: string;
	full_name: string;
	email_verified: boolean;
	auth_provider: string;
	is_admin: boolean;
	avatar_url: string | null;
}

export async function checkSocialStatus(serverUrl: string): Promise<SocialStatus> {
	return invoke('check_social_status', { serverUrl });
}

/** Whether the server's web dashboard can hand a sign-in to the app ("Sign in with browser"). */
export async function checkBrowserSignIn(serverUrl: string): Promise<boolean> {
	return invoke('check_browser_sign_in', { serverUrl });
}

export async function setupWithOAuthTokens(
	serverUrl: string,
	accessToken: string,
	refreshToken: string,
): Promise<LoginStep> {
	return invoke('setup_with_oauth_tokens', { serverUrl, accessToken, refreshToken });
}

export async function getUserInfo(): Promise<UserInfo> {
	return invoke('get_user_info');
}

export interface OAuthTokens {
	access_token: string;
	refresh_token: string;
}

export async function exchangeOAuthCode(
	serverUrl: string,
	code: string,
	codeVerifier: string,
): Promise<OAuthTokens> {
	return invoke('exchange_oauth_code', { serverUrl, code, codeVerifier });
}
