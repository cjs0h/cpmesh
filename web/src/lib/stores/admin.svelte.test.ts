import { beforeEach, describe, expect, it, type Mock } from 'vitest';
import { jsonResponse } from '../../test/setup';
import { ApiError } from '../api';
import {
  adminAssignSubscription,
  adminCreateApiToken,
  adminGate,
  adminRemoveSubscription,
  adminResendVerification,
  adminResetMfa,
  adminRevokeApiToken,
  adminRevokeSessions,
  adminSetRole,
  adminState,
  adminSuspendUser,
  adminTestOidc,
  adminTestSmtp,
  adminUnsuspendUser,
  adminUpdateSettings,
  adminVerifyEmail,
  apiTokenStatus,
  auditActionLabel,
  auditActionTone,
  ensureRecentAuth,
  errorMessage,
  fetchAdminSettings,
  fetchAdminStats,
  fetchAdminUser,
  fetchAdminUsers,
  fetchApiTokens,
  fetchAuditActions,
  fetchAuditLogs,
  isMfaRequired,
  planPrice,
  roleLabel,
  type ApiToken,
} from './admin.svelte';
import { finishStepUp, reauthState } from './reauth.svelte';
import { publicSettings } from './settings.svelte';

const fetchMock = () => fetch as unknown as Mock;

/** The URL, method and parsed JSON body of the `index`th request. */
function request(index = 0) {
  const [url, init = {}] = fetchMock().mock.calls[index];
  return { url, method: init.method ?? 'GET', body: typeof init.body === 'string' ? JSON.parse(init.body) : init.body };
}

function token(overrides: Partial<ApiToken> = {}): ApiToken {
  return {
    id: 't1',
    user_id: 'u1',
    username: 'alice',
    name: 'Release workflow',
    token_prefix: 'cpm_abcdefgh',
    scopes: ['releases:write'],
    expires_at: null,
    last_used_at: null,
    revoked_at: null,
    created_at: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

beforeEach(() => {
  fetchMock().mockReset();
  adminState.users = [];
  adminState.usersTotal = 0;
  adminState.settings = null;
  adminState.apiTokens = [];
  adminState.loading = false;
  adminGate.required = false;
  adminGate.enrolled = false;
  if (reauthState.open) finishStepUp(false);
});

describe('admin users', () => {
  it('encodes search terms and drops responses overtaken by a newer search', async () => {
    let answerFirst: (value: Response) => void = () => {};
    fetchMock()
      .mockReturnValueOnce(new Promise<Response>((resolve) => (answerFirst = resolve)))
      .mockResolvedValueOnce(jsonResponse(200, { items: [{ id: 'new' }], total: 1, page: 1, per_page: 25 }));

    const first = fetchAdminUsers({ q: 'a@example.com' });
    const second = fetchAdminUsers({ q: 'bob smith', plan_id: 'p1' });
    expect(fetchMock().mock.calls[0][0]).toBe('/api/admin/users?q=a%40example.com');
    expect(fetchMock().mock.calls[1][0]).toBe('/api/admin/users?q=bob+smith&plan_id=p1');

    await second;
    answerFirst(jsonResponse(200, { items: [{ id: 'stale' }], total: 9, page: 1, per_page: 25 }));
    expect(await first).toBeNull();
    expect(adminState.users.map((u) => u.id)).toEqual(['new']);
    expect(adminState.usersTotal).toBe(1);
    expect(adminState.loading).toBe(false);
  });

  it('loads one user, escaping the id in the path', async () => {
    fetchMock().mockResolvedValueOnce(jsonResponse(200, { user: { id: 'u1' }, devices: [], recent_activity: [] }));
    const detail = await fetchAdminUser('u1');
    expect(detail.user.id).toBe('u1');
    expect(request().url).toBe('/api/admin/users/u1');

    fetchMock().mockResolvedValueOnce(jsonResponse(400, { error: 'invalid id' }));
    await expect(fetchAdminUser('../settings')).rejects.toThrow('invalid id');
    expect(request(1).url).toBe('/api/admin/users/..%2Fsettings');
  });

  it('sends each account action to its endpoint', async () => {
    fetchMock().mockResolvedValue(jsonResponse(200, { message: 'ok' }));

    await adminAssignSubscription('u1', 'p1');
    await adminRemoveSubscription('u1');
    await adminVerifyEmail('u1');
    await adminResendVerification('u1');
    await adminSuspendUser('u1', 'spam');
    await adminUnsuspendUser('u1');
    await adminRevokeSessions('u1');
    await adminSetRole('u1', 'support');
    await adminResetMfa('u1');

    expect(fetchMock().mock.calls.map((_, i) => request(i))).toEqual([
      { url: '/api/admin/users/u1/subscription', method: 'PUT', body: { plan_id: 'p1' } },
      { url: '/api/admin/users/u1/subscription', method: 'DELETE', body: undefined },
      { url: '/api/admin/users/u1/verify-email', method: 'PUT', body: undefined },
      { url: '/api/admin/users/u1/resend-verification', method: 'POST', body: undefined },
      { url: '/api/admin/users/u1/suspend', method: 'POST', body: { reason: 'spam' } },
      { url: '/api/admin/users/u1/unsuspend', method: 'POST', body: undefined },
      { url: '/api/admin/users/u1/revoke-sessions', method: 'POST', body: undefined },
      { url: '/api/admin/users/u1/role', method: 'PUT', body: { role: 'support' } },
      { url: '/api/admin/users/u1/mfa', method: 'DELETE', body: undefined },
    ]);
    // JSON bodies are labelled as such
    expect(fetchMock().mock.calls[4][1].headers['Content-Type']).toBe('application/json');
  });

  it('rejects with the server message, e.g. the last-owner guard', async () => {
    fetchMock().mockResolvedValueOnce(jsonResponse(409, { error: 'the server needs at least one owner' }));
    const err = (await adminSetRole('u1', 'admin').catch((e: unknown) => e)) as ApiError;
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(409);
    expect(errorMessage(err)).toBe('the server needs at least one owner');
  });
});

describe('admin console 2FA gate', () => {
  it('records that the session needs a second factor, and clears it on the next success', async () => {
    fetchMock().mockResolvedValueOnce(
      jsonResponse(403, { error: 'Confirm your second factor to use the admin console.', code: 'mfa_required', enrolled: true }),
    );
    const err = await fetchAdminStats().catch((e) => e);
    expect(isMfaRequired(err)).toBe(true);
    expect(adminGate).toEqual({ required: true, enrolled: true });

    fetchMock().mockResolvedValueOnce(jsonResponse(200, { total_users: 1 }));
    await fetchAdminStats();
    expect(adminGate.required).toBe(false);
  });

  it('tells accounts without 2FA apart from those that only need to confirm it', async () => {
    fetchMock().mockResolvedValueOnce(
      jsonResponse(403, { error: 'Set up two-factor authentication to use the admin console.', code: 'mfa_required', enrolled: false }),
    );
    await expect(fetchAdminSettings()).rejects.toThrow('Set up two-factor authentication');
    expect(adminGate).toEqual({ required: true, enrolled: false });
  });

  it('ignores other errors', async () => {
    fetchMock().mockResolvedValueOnce(jsonResponse(403, { error: 'your role does not allow this action' }));
    const err = await fetchApiTokens().catch((e) => e);
    expect(isMfaRequired(err)).toBe(false);
    expect(adminGate.required).toBe(false);
    expect(isMfaRequired(new Error('mfa_required'))).toBe(false);
  });
});

describe('admin audit log', () => {
  it('pages and filters entries, and lists the actions', async () => {
    fetchMock()
      .mockResolvedValueOnce(jsonResponse(200, { items: [{ id: 'a1', action: 'login_success' }], total: 120 }))
      .mockResolvedValueOnce(jsonResponse(200, { items: [], total: 0 }))
      .mockResolvedValueOnce(jsonResponse(200, ['login_success', 'admin_suspend_user']));

    const page = await fetchAuditLogs({ limit: 50, offset: 50, user_id: 'u1', action: 'login_success' });
    expect(page.total).toBe(120);
    expect(request(0).url).toBe('/api/admin/audit-logs?limit=50&offset=50&user_id=u1&action=login_success');

    await fetchAuditLogs({ limit: 50, offset: 0, user_id: '', action: '' });
    expect(request(1).url).toBe('/api/admin/audit-logs?limit=50&offset=0');

    expect(await fetchAuditActions()).toEqual(['login_success', 'admin_suspend_user']);
    expect(request(2).url).toBe('/api/admin/audit-logs/actions');
  });

  it('labels actions for people', () => {
    expect(auditActionLabel('admin_suspend_user')).toBe('Suspended');
    expect(auditActionLabel('mfa_passkey_added')).toBe('Added a passkey');
    expect(auditActionLabel('something_new')).toBe('Something new');
    expect(auditActionTone('login_failure')).toBe('rose');
    expect(auditActionTone('admin_reset_mfa')).toBe('gold');
    expect(auditActionTone('login_success')).toBe('neutral');
    expect(roleLabel('owner')).toBe('Owner');
    expect(roleLabel('user')).toBe('Member');
  });
});

describe('admin settings', () => {
  const settings = {
    registration_open: { value: false, override: false, default: true },
    banner: { message: 'Maintenance tonight', tone: 'warning' },
    mfa_policy: 'all',
    passkeys: { enabled: true, rp_id: 'cpmesh.test', origins: ['https://cpmesh.test'] },
    uploads: { signature_required: true, downloads_dir_configured: true },
    download_url_prefixes: [],
    smtp_configured: true,
    oidc_configured: false,
  };

  it('loads settings and sends only the changed ones, with null meaning "back to the default"', async () => {
    fetchMock().mockResolvedValue(jsonResponse(200, settings));

    await fetchAdminSettings();
    expect(adminState.settings?.banner?.tone).toBe('warning');

    await adminUpdateSettings({ registration_open: null });
    await adminUpdateSettings({ banner: { message: 'Hi', tone: 'info' } });
    await adminUpdateSettings({ banner: null });

    expect(request(1)).toEqual({ url: '/api/admin/settings', method: 'PUT', body: { registration_open: null } });
    expect(request(2).body).toEqual({ banner: { message: 'Hi', tone: 'info' } });
    expect(request(3).body).toEqual({ banner: null });
    expect(adminState.settings?.registration_open.default).toBe(true);
  });

  it('shows a saved change on the dashboard without a reload', async () => {
    publicSettings.banner = null;
    publicSettings.registrationOpen = true;
    fetchMock().mockResolvedValueOnce(jsonResponse(200, settings));

    await adminUpdateSettings({ banner: { message: 'Maintenance tonight', tone: 'warning' } });

    expect(publicSettings.banner).toEqual({ message: 'Maintenance tonight', tone: 'warning' });
    expect(publicSettings.registrationOpen).toBe(false);
  });

  it('runs the SMTP and OIDC checks', async () => {
    fetchMock()
      .mockResolvedValueOnce(jsonResponse(200, { message: 'Test email sent successfully.' }))
      .mockResolvedValueOnce(jsonResponse(200, { error: 'OIDC_ISSUER_URL is not configured in env.' }));

    expect((await adminTestSmtp('me@example.com')).message).toContain('sent');
    expect((await adminTestOidc()).error).toContain('OIDC_ISSUER_URL');
    expect(request(0)).toEqual({ url: '/api/admin/test/smtp', method: 'POST', body: { to_email: 'me@example.com' } });
    expect(request(1)).toEqual({ url: '/api/admin/test/oidc', method: 'POST', body: {} });
  });
});

describe('admin API tokens', () => {
  it('lists, creates (secret returned once) and revokes tokens', async () => {
    fetchMock()
      .mockResolvedValueOnce(jsonResponse(200, [token({ id: 'old' })]))
      .mockResolvedValueOnce(jsonResponse(201, { token: 'cpm_secret', api_token: token({ id: 'new', expires_at: '2026-04-01T00:00:00Z' }) }))
      .mockResolvedValueOnce(jsonResponse(204, null));

    await fetchApiTokens();
    const created = await adminCreateApiToken({ name: 'Release workflow', scopes: ['releases:write'], expires_in_days: 90 });
    expect(created.token).toBe('cpm_secret');
    expect(request(1)).toEqual({
      url: '/api/admin/api-tokens',
      method: 'POST',
      body: { name: 'Release workflow', scopes: ['releases:write'], expires_in_days: 90 },
    });
    expect(adminState.apiTokens.map((t) => t.id)).toEqual(['new', 'old']);

    await adminRevokeApiToken('old');
    expect(request(2)).toEqual({ url: '/api/admin/api-tokens/old', method: 'DELETE', body: undefined });
    expect(adminState.apiTokens.find((t) => t.id === 'old')?.revoked_at).toBeTruthy();
    expect(adminState.apiTokens.find((t) => t.id === 'new')?.revoked_at).toBeNull();
  });

  it('sends null for tokens that never expire', async () => {
    fetchMock().mockResolvedValueOnce(jsonResponse(201, { token: 'cpm_x', api_token: token() }));
    await adminCreateApiToken({ name: 'CI', scopes: ['releases:write'], expires_in_days: null });
    expect(request().body.expires_in_days).toBeNull();
  });

  it('tells active, expired and revoked tokens apart', () => {
    const now = Date.parse('2026-06-01T00:00:00Z');
    expect(apiTokenStatus(token(), now)).toBe('active');
    expect(apiTokenStatus(token({ expires_at: '2026-07-01T00:00:00Z' }), now)).toBe('active');
    expect(apiTokenStatus(token({ expires_at: '2026-05-01T00:00:00Z' }), now)).toBe('expired');
    expect(apiTokenStatus(token({ expires_at: '2026-05-01T00:00:00Z', revoked_at: '2026-04-01T00:00:00Z' }), now)).toBe('revoked');
  });
});

describe('admin helpers', () => {
  it('reads plan prices sent as numbers or decimal strings', () => {
    expect(planPrice('12.30')).toBe(12.3);
    expect(planPrice(5)).toBe(5);
    expect(() => planPrice('free')).toThrow('Invalid decimal price');
    expect(() => planPrice(null)).toThrow('Invalid decimal price');
  });

  it('asks for a confirmation before an upload only when the sign-in is not recent', async () => {
    fetchMock().mockResolvedValueOnce(jsonResponse(200, { recent_auth: true }));
    expect(await ensureRecentAuth('Upload')).toBe(true);
    expect(request().url).toBe('/api/mfa');
    expect(reauthState.open).toBe(false);

    fetchMock().mockResolvedValueOnce(jsonResponse(200, { recent_auth: false }));
    const confirmed = ensureRecentAuth('Confirm it’s you to upload installers.');
    await waitUntil(() => reauthState.open);
    expect(reauthState.reason).toBe('Confirm it’s you to upload installers.');
    finishStepUp(true);
    expect(await confirmed).toBe(true);

    fetchMock().mockResolvedValueOnce(jsonResponse(200, { recent_auth: false }));
    const cancelled = ensureRecentAuth('Upload');
    await waitUntil(() => reauthState.open);
    finishStepUp(false);
    expect(await cancelled).toBe(false);

    // When the status can't be read, the upload itself reports the problem
    fetchMock().mockResolvedValueOnce(jsonResponse(500, { error: 'boom' }));
    expect(await ensureRecentAuth('Upload')).toBe(true);
  });
});

/** Lets pending promises settle until `condition` holds. */
async function waitUntil(condition: () => boolean) {
  for (let i = 0; i < 20 && !condition(); i++) await new Promise((resolve) => setTimeout(resolve, 0));
  expect(condition()).toBe(true);
}
