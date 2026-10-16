import { apiWithToken } from './api';
import type { DownloadLink } from './stores/admin.svelte';

export type PublicDownload = Pick<DownloadLink, 'id' | 'name' | 'url' | 'platform' | 'arch' | 'format' | 'sort_order' | 'is_active'>;

export async function currentDownloads(signal?: AbortSignal): Promise<PublicDownload[]> {
  const data = await apiWithToken<unknown>('/api/downloads/current', null, { signal });
  if (!Array.isArray(data)) throw new Error('Invalid download catalogue');
  return data.map((value: unknown) => {
    if (!value || typeof value !== 'object'
        || !('id' in value) || typeof value.id !== 'string'
        || !('name' in value) || typeof value.name !== 'string'
        || !('url' in value) || typeof value.url !== 'string'
        || !('platform' in value) || typeof value.platform !== 'string'
        || !('arch' in value) || typeof value.arch !== 'string'
        || !('format' in value) || typeof value.format !== 'string'
        || !('sort_order' in value) || typeof value.sort_order !== 'number' || !Number.isInteger(value.sort_order)
        || !('is_active' in value) || typeof value.is_active !== 'boolean') {
      throw new Error('Invalid download catalogue entry');
    }
    const url = new URL(value.url, 'https://cpmesh.invalid');
    if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new Error('Invalid installer URL');
    return {
      id: value.id, name: value.name, url: value.url, platform: value.platform,
      arch: value.arch, format: value.format, sort_order: value.sort_order, is_active: value.is_active,
    };
  });
}
