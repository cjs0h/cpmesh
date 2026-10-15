import { beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import { jsonResponse } from '../../test/setup';
import { dismissBanner, loadPublicSettings, publicSettings, visibleBanner } from './settings.svelte';

const fetchMock = () => fetch as unknown as Mock;

function memorySessionStorage() {
  const items = new Map<string, string>();
  return {
    getItem: (key: string) => items.get(key) ?? null,
    setItem: (key: string, value: string) => void items.set(key, String(value)),
    removeItem: (key: string) => void items.delete(key),
  };
}

const settings = (overrides: Record<string, unknown> = {}) => ({
  registration_open: true,
  banner: null,
  passkeys_available: true,
  mfa_required: true,
  ...overrides,
});

describe('public settings store', () => {
  beforeEach(() => {
    fetchMock().mockReset();
    vi.stubGlobal('sessionStorage', memorySessionStorage());
    publicSettings.loaded = false;
    publicSettings.registrationOpen = true;
    publicSettings.banner = null;
    publicSettings.passkeysAvailable = false;
    publicSettings.mfaRequired = false;
    publicSettings.dismissedBanner = '';
  });

  it('loads the settings without signing the request', async () => {
    localStorage.setItem('cpmesh_access_token', 'session');
    fetchMock().mockResolvedValueOnce(
      jsonResponse(200, settings({ registration_open: false, banner: { message: 'Maintenance at 22:00', tone: 'warning' } })),
    );

    await loadPublicSettings(true);

    const [url, init] = fetchMock().mock.calls[0];
    expect(url).toBe('/api/settings');
    expect(init.headers).not.toHaveProperty('Authorization');
    expect(publicSettings).toMatchObject({
      loaded: true,
      registrationOpen: false,
      banner: { message: 'Maintenance at 22:00', tone: 'warning' },
      passkeysAvailable: true,
      mfaRequired: true,
    });
    expect(visibleBanner()).toEqual({ message: 'Maintenance at 22:00', tone: 'warning' });
  });

  it('shares one request between callers until forced', async () => {
    fetchMock().mockResolvedValue(jsonResponse(200, settings()));

    await Promise.all([loadPublicSettings(true), loadPublicSettings(), loadPublicSettings()]);
    expect(fetch).toHaveBeenCalledTimes(1);

    await loadPublicSettings(true);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('falls back to an info tone and drops empty banners', async () => {
    fetchMock()
      .mockResolvedValueOnce(jsonResponse(200, settings({ banner: { message: '  Hello  ', tone: 'neon' } })))
      .mockResolvedValueOnce(jsonResponse(200, settings({ banner: { message: '   ', tone: 'info' } })));

    await loadPublicSettings(true);
    expect(publicSettings.banner).toEqual({ message: 'Hello', tone: 'info' });

    await loadPublicSettings(true);
    expect(publicSettings.banner).toBeNull();
    expect(visibleBanner()).toBeNull();
  });

  it('keeps the defaults when the request fails, and tries again next time', async () => {
    fetchMock()
      .mockRejectedValueOnce(new TypeError('offline'))
      .mockResolvedValueOnce(jsonResponse(200, settings({ banner: { message: 'Back online', tone: 'info' } })));

    await loadPublicSettings(true);
    expect(publicSettings.loaded).toBe(true);
    expect(publicSettings.registrationOpen).toBe(true);
    expect(publicSettings.banner).toBeNull();

    await loadPublicSettings();
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(publicSettings.banner?.message).toBe('Back online');
  });

  it('hides a dismissed banner for the browser session, until the message changes', async () => {
    fetchMock()
      .mockResolvedValueOnce(jsonResponse(200, settings({ banner: { message: 'Maintenance tonight', tone: 'danger' } })))
      .mockResolvedValueOnce(jsonResponse(200, settings({ banner: { message: 'Maintenance tonight', tone: 'danger' } })))
      .mockResolvedValueOnce(jsonResponse(200, settings({ banner: { message: 'Maintenance moved to Friday', tone: 'warning' } })));

    await loadPublicSettings(true);
    dismissBanner();
    expect(visibleBanner()).toBeNull();
    expect(sessionStorage.getItem('cpmesh_dismissed_banner')).toBe('Maintenance tonight');

    // A reload in the same browser session remembers the dismissal
    publicSettings.dismissedBanner = '';
    await loadPublicSettings(true);
    expect(visibleBanner()).toBeNull();

    await loadPublicSettings(true);
    expect(visibleBanner()).toEqual({ message: 'Maintenance moved to Friday', tone: 'warning' });
  });
});
