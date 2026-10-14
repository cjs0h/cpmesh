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
			'confirmDeviceApproval',
			() => api.confirmDeviceApproval('p1', 's1'),
			'confirm_device_approval',
			{ pendingDeviceId: 'p1', sessionId: 's1' },
		],
		[
			'rejectPendingDevice',
			() => api.rejectPendingDevice('p1'),
			'reject_pending_device',
			{ pendingDeviceId: 'p1' },
		],
		['getMyApprovalStatus', () => api.getMyApprovalStatus(), 'get_my_approval_status', undefined],
		['getHistory (default page size)', () => api.getHistory(2), 'get_history', { page: 2, pageSize: 20 }],
		['getHistory (custom page size)', () => api.getHistory(0, 50), 'get_history', { page: 0, pageSize: 50 }],
		['searchHistory', () => api.searchHistory('needle'), 'search_history', { query: 'needle' }],
		['copyEntry', () => api.copyEntry('e1'), 'copy_entry', { entryId: 'e1' }],
		['deleteEntry', () => api.deleteEntry('e1'), 'delete_entry', { entryId: 'e1' }],
		['clearHistory', () => api.clearHistory(), 'clear_history', undefined],
		['syncHistory', () => api.syncHistory(), 'sync_history', undefined],
		['getConfig', () => api.getConfig(), 'get_config', undefined],
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
});

describe('updateConfig', () => {
	it('maps snake_case config keys to the camelCase command arguments', async () => {
		await api.updateConfig({
			server_url: 'https://s',
			auto_connect: false,
			autostart: true,
			notifications_enabled: false,
			global_hotkey: 'Alt+V',
		});
		expect(invoke).toHaveBeenCalledWith('update_config', {
			serverUrl: 'https://s',
			autoConnect: false,
			autostart: true,
			notificationsEnabled: false,
			globalHotkey: 'Alt+V',
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
			globalHotkey: undefined,
		});
	});
});
