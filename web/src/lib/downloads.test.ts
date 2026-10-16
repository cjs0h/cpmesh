import { expect, it, vi } from 'vitest';
import { currentDownloads } from './downloads';
import { jsonResponse } from '../test/setup';

it('distinguishes unavailable and malformed catalogues from an empty release list', async () => {
  vi.mocked(fetch).mockResolvedValueOnce(jsonResponse(500, { error: 'database unavailable' }));
  await expect(currentDownloads()).rejects.toThrow('database unavailable');
  vi.mocked(fetch).mockResolvedValueOnce(jsonResponse(200, {}));
  await expect(currentDownloads()).rejects.toThrow('Invalid download catalogue');
  vi.mocked(fetch).mockResolvedValueOnce(jsonResponse(200, []));
  await expect(currentDownloads()).resolves.toEqual([]);
});

it('accepts public installer JSON and refuses executable URL schemes', async () => {
  const installer = {
    id: 'installer', name: 'cpmesh', url: '/api/downloads/cpmesh.exe',
    platform: 'windows', arch: 'amd64', format: 'exe', sort_order: 0, is_active: true,
  };
  vi.mocked(fetch).mockResolvedValueOnce(jsonResponse(200, [installer]));
  await expect(currentDownloads()).resolves.toEqual([installer]);
  vi.mocked(fetch).mockResolvedValueOnce(jsonResponse(200, [{ ...installer, url: 'javascript:alert(1)' }]));
  await expect(currentDownloads()).rejects.toThrow('Invalid installer URL');
});
