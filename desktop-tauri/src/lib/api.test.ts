import { beforeEach, describe, expect, it, vi } from 'vitest';

const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke }));

import * as api from './api.js';

beforeEach(() => {
	invoke.mockReset();
	invoke.mockResolvedValue(undefined);
});

describe('Tauri command wrappers', () => {
	it.each([
		['getStatus', () => api.getStatus(), 'get_status', undefined],
		['getAppState', () => api.getAppState(), 'get_app_state', undefined],
		[
			'completeMfaLogin (authenticator code)',
			() => api.completeMfaLogin('totp', '123456'),
			'complete_mfa_login',
			{ method: 'totp', code: '123456' },
		],
		[
			'completeMfaLogin (recovery code)',
			() => api.completeMfaLogin('recovery', 'abcdefghijklmnop'),
			'complete_mfa_login',
			{ method: 'recovery', code: 'abcdefghijklmnop' },
		],
		['cancelMfaLogin', () => api.cancelMfaLogin(), 'cancel_mfa_login', undefined],
		['connectToServer', () => api.connectToServer(), 'connect', undefined],
		['disconnectFromServer', () => api.disconnectFromServer(), 'disconnect', undefined],
		['getDevices', () => api.getDevices(), 'get_devices', undefined],
		['removeDevice', () => api.removeDevice('d1'), 'remove_device', { deviceId: 'd1' }],
		['getPendingDevices', () => api.getPendingDevices(), 'get_pending_devices', undefined],
		[
			'beginDeviceApproval',
			() => api.beginDeviceApproval('p1'),
			'begin_device_approval',
			{ pendingDeviceId: 'p1' },
		],
		[
			'pollDeviceApproval',
			() => api.pollDeviceApproval('p1', 's1'),
			'poll_device_approval',
			{ pendingDeviceId: 'p1', sessionId: 's1' },
		],
		[
			'confirmDeviceApproval',
			() => api.confirmDeviceApproval('p1', 's1', '1234 5678'),
			'confirm_device_approval',
			{ pendingDeviceId: 'p1', sessionId: 's1', fingerprint: '1234 5678' },
		],
		[
			'rejectPendingDevice',
			() => api.rejectPendingDevice('p1'),
			'reject_pending_device',
			{ pendingDeviceId: 'p1' },
		],
		['getMyApprovalStatus', () => api.getMyApprovalStatus(), 'get_my_approval_status', undefined],
		['getDeviceTrust', () => api.getDeviceTrust(), 'get_device_trust', undefined],
		[
			'verifyDeviceIdentity',
			() => api.verifyDeviceIdentity('d1', 'AB'.repeat(32)),
			'verify_device_identity',
			{ deviceId: 'd1', fingerprint: 'AB'.repeat(32) },
		],
		[
			'confirmKeyShare',
			() => api.confirmKeyShare('d1', 's1', '1234 5678'),
			'confirm_key_share',
			{ deviceId: 'd1', sessionId: 's1', code: '1234 5678' },
		],
		['getHistory (default page size)', () => api.getHistory(2), 'get_history', { page: 2, pageSize: 20 }],
		['getHistory (custom page size)', () => api.getHistory(0, 50), 'get_history', { page: 0, pageSize: 50 }],
		['searchHistory', () => api.searchHistory('needle'), 'search_history', { query: 'needle' }],
		['copyEntry', () => api.copyEntry('e1'), 'copy_entry', { entryId: 'e1' }],
		['deleteEntry', () => api.deleteEntry('e1'), 'delete_entry', { entryId: 'e1' }],
		['clearHistory', () => api.clearHistory(), 'clear_history', undefined],
		['syncHistory', () => api.syncHistory(), 'sync_history', undefined],
		['getConfig', () => api.getConfig(), 'get_config', undefined],
		['getDataDir', () => api.getDataDir(), 'get_data_dir', undefined],
		['getGlobalShortcut', () => api.getGlobalShortcut(), 'get_global_shortcut', undefined],
		[
			'setGlobalShortcut',
			() => api.setGlobalShortcut('CmdOrCtrl+Alt+V'),
			'set_global_shortcut',
			{ shortcut: 'CmdOrCtrl+Alt+V' },
		],
		['setGlobalShortcut (turn off)', () => api.setGlobalShortcut(''), 'set_global_shortcut', { shortcut: '' }],
		['copyText', () => api.copyText('d-1'), 'plugin:clipboard-manager|write_text', { text: 'd-1' }],
		[
			'changePassword',
			() => api.changePassword('old', 'new'),
			'change_password',
			{ currentPassword: 'old', newPassword: 'new' },
		],
		['logout', () => api.logout(), 'logout', undefined],
		['checkUpdate', () => api.checkUpdate(), 'check_update', undefined],
		[
			'downloadAndInstallUpdate',
			() => api.downloadAndInstallUpdate('https://dl/x.exe'),
			'download_and_install_update',
			{ downloadUrl: 'https://dl/x.exe' },
		],
		[
			'checkSocialStatus',
			() => api.checkSocialStatus('https://s'),
			'check_social_status',
			{ serverUrl: 'https://s' },
		],
		[
			'checkBrowserSignIn',
			() => api.checkBrowserSignIn('https://s'),
			'check_browser_sign_in',
			{ serverUrl: 'https://s' },
		],
		[
			'setupWithOAuthTokens',
			() => api.setupWithOAuthTokens('https://s', 'a', 'r'),
			'setup_with_oauth_tokens',
			{ serverUrl: 'https://s', accessToken: 'a', refreshToken: 'r' },
		],
		['getUserInfo', () => api.getUserInfo(), 'get_user_info', undefined],
		[
			'exchangeOAuthCode',
			() => api.exchangeOAuthCode('https://s', 'code', 'verifier'),
			'exchange_oauth_code',
			{ serverUrl: 'https://s', code: 'code', codeVerifier: 'verifier' },
		],
		[
			'resolveSignIn (set keys aside)',
			() => api.resolveSignIn({ action: 'set_aside_keys' }),
			'resolve_sign_in',
			{ action: { action: 'set_aside_keys' } },
		],
		[
			'resolveSignIn (replace a registration)',
			() => api.resolveSignIn({ action: 'replace_device', device_id: 'd1', waiting_device_ids: ['d2'] }),
			'resolve_sign_in',
			{ action: { action: 'replace_device', device_id: 'd1', waiting_device_ids: ['d2'] } },
		],
		['cancelSignIn', () => api.cancelSignIn(), 'cancel_sign_in', undefined],
		['getKeyProblem', () => api.getKeyProblem(), 'get_key_problem', undefined],
		['getKeyRecoveryStatus', () => api.getKeyRecoveryStatus(), 'get_key_recovery_status', undefined],
		['inspectKeyBackup', () => api.inspectKeyBackup('/b'), 'inspect_key_backup', { path: '/b' }],
		['restoreKeyBackup', () => api.restoreKeyBackup('/b'), 'restore_key_backup', { path: '/b' }],
		['resetEncryption', () => api.resetEncryption(4), 'reset_encryption', { expectedVersion: 4 }],
		['updateInstalled', () => api.updateInstalled(), 'update_installed', undefined],
		['restartApp', () => api.restartApp(), 'restart_app', undefined],
	] as const)('%s invokes the matching command', async (_name, call, command, args) => {
		await call();
		expect(invoke).toHaveBeenCalledTimes(1);
		if (args === undefined) {
			expect(invoke).toHaveBeenCalledWith(command);
		} else {
			expect(invoke).toHaveBeenCalledWith(command, args);
		}
	});

	it('returns whatever the backend resolves', async () => {
		const status = { state: 'connected', server_url: 'https://s', device_name: 'L', device_count: 2, online_count: 1 };
		invoke.mockResolvedValueOnce(status);
		await expect(api.getStatus()).resolves.toEqual(status);
	});

	it('propagates backend errors', async () => {
		invoke.mockRejectedValueOnce('Login failed: invalid credentials');
		await expect(api.connectToServer()).rejects.toBe('Login failed: invalid credentials');
	});
});

describe('setupAndLogin', () => {
	it('passes every field for registration', async () => {
		await api.setupAndLogin('https://s', 'alice', 'pw', true, 'a@x', 'Alice', 'pw', 'GB', '+44');
		expect(invoke).toHaveBeenCalledWith('setup_and_login', {
			serverUrl: 'https://s',
			username: 'alice',
			password: 'pw',
			isRegister: true,
			email: 'a@x',
			fullName: 'Alice',
			passwordConfirm: 'pw',
			country: 'GB',
			mobile: '+44',
		});
	});

	it('normalises omitted and empty optional fields to null for the Rust side', async () => {
		await api.setupAndLogin('https://s', 'alice', 'pw', false, undefined, '', undefined, '', undefined);
		expect(invoke).toHaveBeenCalledWith('setup_and_login', {
			serverUrl: 'https://s',
			username: 'alice',
			password: 'pw',
			isRegister: false,
			email: null,
			fullName: null,
			passwordConfirm: null,
			country: null,
			mobile: null,
		});
	});

	it('returns the second-factor prompt when the sign-in pauses', async () => {
		const step = {
			status: 'mfa_required',
			stage: 'verify',
			methods: ['totp', 'recovery'],
			email_code_required: false,
			email_hint: null,
			passkeys_available: true,
			message: 'Two-factor authentication is required.',
		};
		invoke.mockResolvedValueOnce(step);
		await expect(api.setupAndLogin('https://s', 'alice', 'pw', false)).resolves.toEqual(step);
	});
});

describe('updateConfig', () => {
	it('maps snake_case config keys to the camelCase command arguments', async () => {
		await api.updateConfig({
			server_url: 'https://s',
			auto_connect: false,
			autostart: true,
			notifications_enabled: false,
		});
		expect(invoke).toHaveBeenCalledWith('update_config', {
			serverUrl: 'https://s',
			autoConnect: false,
			autostart: true,
			notificationsEnabled: false,
		});
	});

	it('leaves unspecified fields undefined so the backend keeps current values', async () => {
		await api.updateConfig({ autostart: true });
		const [, args] = invoke.mock.calls[0];
		expect(args).toEqual({
			serverUrl: undefined,
			autoConnect: undefined,
			autostart: true,
			notificationsEnabled: undefined,
		});
	});
});
