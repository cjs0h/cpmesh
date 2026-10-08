import { beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import { jsonResponse } from '../../test/setup';
import { setTokens, getAccessToken } from '../auth';
import { fetchCurrentUser, resetUserState, userState } from './user.svelte';
import {
  clearAll,
  clipboardState,
  deleteEntry,
  fetchClipboard,
  loadNextPage,
  loadPrevPage,
  prependEntry,
} from './clipboard.svelte';
import { devicesState, fetchDevices, updateDeviceStatus } from './devices.svelte';
import {
  adminCreatePlan,
  adminDeleteUser,
  adminState,
  adminUpdateRelease,
  adminUploadBinary,
  fetchAdminStats,
  fetchAdminUsers,
} from './admin.svelte';

const fetchMock = () => fetch as unknown as Mock;

function entry(id: string) {
  return {
    id,
    user_id: 'u',
    device_id: 'd',
    device_name: 'Laptop',
    content_type: 'text',
    encrypted_data: 'AA==',
    metadata: '',
    created_at: '2026-01-01T00:00:00Z',
  };
}

beforeEach(() => {
  fetchMock().mockReset();
  resetUserState();
  clipboardState.entries = [];
  clipboardState.hasMore = false;
  clipboardState.loading = false;
  clipboardState.offset = 0;
  devicesState.list = [];
  adminState.users = [];
  adminState.stats = null;
  adminState.plans = [];
  adminState.releases = [];
});

describe('user store', () => {
  it('loads the current user and maps snake_case fields', async () => {
    fetchMock().mockResolvedValueOnce(
      jsonResponse(200, {
        id: 'u1',
        username: 'alice',
        email: 'a@example.com',
        full_name: 'Alice',
        avatar_url: 'https://img/a.png',
        email_verified: true,
        auth_provider: 'google',
        is_admin: true,
      }),
    );

    await fetchCurrentUser();

    expect(fetchMock().mock.calls[0][0]).toBe('/api/me');
    expect(userState.id).toBe('u1');
    expect(userState.username).toBe('alice');
    expect(userState.fullName).toBe('Alice');
    expect(userState.avatarUrl).toBe('https://img/a.png');
    expect(userState.emailVerified).toBe(true);
    expect(userState.authProvider).toBe('google');
    expect(userState.isAdmin).toBe(true);
    expect(userState.loaded).toBe(true);
  });

  it('defaults optional fields and still marks loaded on failure', async () => {
    fetchMock().mockResolvedValueOnce(
      jsonResponse(200, { id: 'u1', username: 'bob', email_verified: false, is_admin: false }),
    );
    await fetchCurrentUser();
    expect(userState.email).toBe('');
    expect(userState.fullName).toBe('');
    expect(userState.avatarUrl).toBe('');
    expect(userState.authProvider).toBe('local');

    resetUserState();
    fetchMock().mockResolvedValueOnce(jsonResponse(500, { error: 'boom' }));
    await fetchCurrentUser();
    expect(userState.id).toBe('');
    expect(userState.loaded).toBe(true);
  });

  it('reset clears the state and the stored tokens', () => {
    setTokens('a', 'r');
    userState.id = 'u1';
    userState.isAdmin = true;
    userState.loaded = true;

    resetUserState();

    expect(userState.id).toBe('');
    expect(userState.isAdmin).toBe(false);
    expect(userState.loaded).toBe(false);
    expect(getAccessToken()).toBeNull();
  });
});

describe('clipboard store', () => {
  it('fetches pages of 20 and tracks has_more', async () => {
    fetchMock().mockResolvedValueOnce(
      jsonResponse(200, { entries: [entry('e1'), entry('e2')], has_more: true }),
    );

    const pending = fetchClipboard(true);
    expect(clipboardState.loading).toBe(true);
    await pending;

    expect(fetchMock().mock.calls[0][0]).toBe('/api/clipboard?limit=20&offset=0');
    expect(clipboardState.entries.map((e) => e.id)).toEqual(['e1', 'e2']);
    expect(clipboardState.hasMore).toBe(true);
    expect(clipboardState.loading).toBe(false);
  });

  it('pages forward and backward without going negative', async () => {
    fetchMock().mockResolvedValue(jsonResponse(200, { entries: [], has_more: false }));

    await loadNextPage();
    expect(clipboardState.offset).toBe(20);
    expect(fetchMock().mock.calls.at(-1)?.[0]).toBe('/api/clipboard?limit=20&offset=20');

    await loadNextPage();
    expect(clipboardState.offset).toBe(40);

    await loadPrevPage();
    expect(clipboardState.offset).toBe(20);
    await loadPrevPage();
    await loadPrevPage();
    expect(clipboardState.offset).toBe(0);

    // reset=true rewinds to the first page
    clipboardState.offset = 60;
    await fetchClipboard(true);
    expect(clipboardState.offset).toBe(0);
  });

  it('empties the list on error and tolerates a missing entries field', async () => {
    clipboardState.entries = [entry('old')];
    fetchMock().mockResolvedValueOnce(jsonResponse(500, { error: 'boom' }));
    await fetchClipboard();
    expect(clipboardState.entries).toEqual([]);
    expect(clipboardState.hasMore).toBe(false);
    expect(clipboardState.loading).toBe(false);

    fetchMock().mockResolvedValueOnce(jsonResponse(200, { has_more: false }));
    await fetchClipboard();
    expect(clipboardState.entries).toEqual([]);
  });

  it('deletes a single entry and clears everything', async () => {
    clipboardState.entries = [entry('e1'), entry('e2')];
    clipboardState.hasMore = true;
    clipboardState.offset = 20;
    fetchMock().mockResolvedValue(jsonResponse(204, null));

    await deleteEntry('e1');
    expect(fetchMock().mock.calls[0][0]).toBe('/api/clipboard/e1');
    expect(fetchMock().mock.calls[0][1].method).toBe('DELETE');
    expect(clipboardState.entries.map((e) => e.id)).toEqual(['e2']);

    await clearAll();
    expect(fetchMock().mock.calls[1][0]).toBe('/api/clipboard');
    expect(clipboardState.entries).toEqual([]);
    expect(clipboardState.hasMore).toBe(false);
    expect(clipboardState.offset).toBe(0);
  });

  it('keeps the list intact when a delete fails', async () => {
    clipboardState.entries = [entry('e1')];
    fetchMock().mockResolvedValueOnce(jsonResponse(404, { error: 'not found' }));
    await expect(deleteEntry('e1')).rejects.toThrow('not found');
    expect(clipboardState.entries).toHaveLength(1);
  });

  it('prepends live entries on the first page only, without duplicates', () => {
    clipboardState.entries = [entry('e1')];
    prependEntry(entry('e0'));
    expect(clipboardState.entries.map((e) => e.id)).toEqual(['e0', 'e1']);

    prependEntry(entry('e0'));
    expect(clipboardState.entries).toHaveLength(2);

    clipboardState.offset = 20;
    prependEntry(entry('e-late'));
    expect(clipboardState.entries.map((e) => e.id)).toEqual(['e0', 'e1']);
  });

  it('trims the first page to its size and flags more pages when live entries overflow', () => {
    clipboardState.entries = Array.from({ length: 20 }, (_, i) => entry(`e${i}`));
    expect(clipboardState.hasMore).toBe(false);
    prependEntry(entry('fresh'));
    expect(clipboardState.entries).toHaveLength(20);
    expect(clipboardState.entries[0].id).toBe('fresh');
    expect(clipboardState.entries.at(-1)?.id).toBe('e18');
    expect(clipboardState.hasMore).toBe(true);
  });
});

describe('devices store', () => {
  it('loads devices and toggles online status in place', async () => {
    fetchMock().mockResolvedValueOnce(
      jsonResponse(200, [
        { id: 'd1', name: 'Laptop', last_seen: '', online: false, status: 'approved' },
        { id: 'd2', name: 'Phone', last_seen: '', online: true, status: 'pending' },
      ]),
    );
    await fetchDevices();
    expect(devicesState.list.map((d) => d.id)).toEqual(['d1', 'd2']);
    expect(devicesState.loading).toBe(false);

    updateDeviceStatus('d1', true);
    updateDeviceStatus('d2', false);
    updateDeviceStatus('ghost', true); // unknown ids are ignored
    expect(devicesState.list[0].online).toBe(true);
    expect(devicesState.list[1].online).toBe(false);
    expect(devicesState.list).toHaveLength(2);
  });

  it('clears the list on error', async () => {
    devicesState.list = [{ id: 'd1', name: 'x', last_seen: '', online: false, status: 'approved' }];
    fetchMock().mockResolvedValueOnce(jsonResponse(401, { error: 'nope' }));
    await fetchDevices();
    expect(devicesState.list).toEqual([]);
    expect(devicesState.loading).toBe(false);
  });
});

describe('admin store', () => {
  it('loads users and stats, and removes deleted users locally', async () => {
    fetchMock()
      .mockResolvedValueOnce(jsonResponse(200, [{ id: 'u1', username: 'a' }, { id: 'u2', username: 'b' }]))
      .mockResolvedValueOnce(
        jsonResponse(200, { total_users: 2, total_devices: 3, total_entries: 4, active_connections: 1 }),
      )
      .mockResolvedValueOnce(jsonResponse(204, null));

    await fetchAdminUsers();
    await fetchAdminStats();
    expect(adminState.users).toHaveLength(2);
    expect(adminState.stats?.total_devices).toBe(3);

    await adminDeleteUser('u1');
    expect(fetchMock().mock.calls[2][0]).toBe('/api/admin/users/u1');
    expect(adminState.users.map((u) => u.id)).toEqual(['u2']);
  });

  it('appends created plans and replaces updated releases', async () => {
    fetchMock()
      .mockResolvedValueOnce(jsonResponse(200, { id: 'p1', name: 'Pro' }))
      .mockResolvedValueOnce(jsonResponse(200, { id: 'r1', version: '0.2.0', is_current: true }));

    const plan = await adminCreatePlan({ name: 'Pro' });
    expect(plan.id).toBe('p1');
    expect(adminState.plans.map((p) => p.id)).toEqual(['p1']);
    const [, init] = fetchMock().mock.calls[0];
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body)).toEqual({ name: 'Pro' });

    adminState.releases = [
      { id: 'r1', version: '0.1.0', is_current: false } as (typeof adminState.releases)[number],
      { id: 'r2', version: '0.0.9', is_current: false } as (typeof adminState.releases)[number],
    ];
    await adminUpdateRelease('r1', { version: '0.2.0', is_current: true });
    expect(adminState.releases.map((r) => r.version)).toEqual(['0.2.0', '0.0.9']);
  });

  it('uploads binaries as multipart with the bearer token', async () => {
    setTokens('tok', 'r');
    fetchMock().mockResolvedValueOnce(
      jsonResponse(200, { uploaded: [{ filename: 'a.exe', size: 3, url: '/api/downloads/a.exe' }] }),
    );
    const file = new File([new Uint8Array([1, 2, 3])], 'a.exe');

    const result = await adminUploadBinary(file);

    expect(result.uploaded[0].filename).toBe('a.exe');
    const [url, init] = fetchMock().mock.calls[0];
    expect(url).toBe('/api/admin/downloads/upload');
    expect(init.method).toBe('POST');
    expect(init.headers.Authorization).toBe('Bearer tok');
    expect(init.body).toBeInstanceOf(FormData);
    expect((init.body as FormData).get('file')).toBeInstanceOf(File);
    // No explicit content type: the browser must set the multipart boundary
    expect(init.headers['Content-Type']).toBeUndefined();
  });

  it('surfaces upload errors from the server', async () => {
    fetchMock().mockResolvedValueOnce(jsonResponse(413, { error: 'file too large' }));
    await expect(adminUploadBinary(new File([], 'big.exe'))).rejects.toThrow('file too large');
  });
});
