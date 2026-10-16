import { api } from '../api';
import { onSessionEnd } from '../auth';
import { toast } from './toast.svelte';

export interface ClipboardEntry {
  id: string;
  device_id: string;
  device_name: string;
  content_type: string;
  encrypted_size: number;
  created_at: string;
}

export const clipboardState: {
  entries: ClipboardEntry[];
  hasMore: boolean;
  loading: boolean;
  offset: number;
  error: string;
} = $state({
  entries: [],
  hasMore: false,
  loading: false,
  offset: 0,
  error: '',
});

const PAGE_SIZE = 20;
let requestVersion = 0;

export function parseClipboardEntry(value: unknown): ClipboardEntry {
  if (!value || typeof value !== 'object') throw new Error('Invalid clipboard metadata');
  if (!('id' in value) || typeof value.id !== 'string'
      || !('device_id' in value) || typeof value.device_id !== 'string'
      || !('device_name' in value) || typeof value.device_name !== 'string'
      || !('content_type' in value) || typeof value.content_type !== 'string'
      || !('created_at' in value) || typeof value.created_at !== 'string'
      || !('encrypted_size' in value) || typeof value.encrypted_size !== 'number'
      || !Number.isSafeInteger(value.encrypted_size) || value.encrypted_size < 0) {
    throw new Error('Invalid clipboard metadata');
  }
  return {
    id: value.id, device_id: value.device_id, device_name: value.device_name,
    content_type: value.content_type, created_at: value.created_at, encrypted_size: value.encrypted_size,
  };
}

export async function fetchClipboard(reset = false, offset = clipboardState.offset) {
  const request = ++requestVersion;
  const requestedOffset = reset ? 0 : offset;
  clipboardState.loading = true;
  clipboardState.error = '';
  try {
    const data = await api<unknown>(
      `/api/clipboard?metadata_only=true&limit=${PAGE_SIZE}&offset=${requestedOffset}`
    );
    if (!data || typeof data !== 'object' || !('entries' in data) || !Array.isArray(data.entries)
        || !('has_more' in data) || typeof data.has_more !== 'boolean') throw new Error('Invalid clipboard page');
    const entries = data.entries.map(parseClipboardEntry);
    if (request !== requestVersion) return;
    clipboardState.entries = entries;
    clipboardState.offset = requestedOffset;
    clipboardState.hasMore = data.has_more;
  } catch (error) {
    if (request !== requestVersion) return;
    clipboardState.error = error instanceof Error ? error.message : String(error);
    toast.error('Could not load clipboard history', clipboardState.error);
  } finally {
    if (request === requestVersion) clipboardState.loading = false;
  }
}

export async function loadNextPage() {
  await fetchClipboard(false, clipboardState.offset + PAGE_SIZE);
}

export async function loadPrevPage() {
  await fetchClipboard(false, Math.max(0, clipboardState.offset - PAGE_SIZE));
}

/**
 * Inserts an entry pushed over the WebSocket at the top of the first page.
 * Pages other than the first are left untouched so pagination stays stable.
 */
export function prependEntry(entry: ClipboardEntry) {
  if (clipboardState.offset !== 0) return;
  if (clipboardState.entries.some((e) => e.id === entry.id)) return;
  const next = [entry, ...clipboardState.entries];
  if (next.length > PAGE_SIZE) {
    next.length = PAGE_SIZE;
    clipboardState.hasMore = true;
  }
  clipboardState.entries = next;
}

export async function deleteEntry(id: string) {
  await api(`/api/clipboard/${id}`, { method: 'DELETE' });
  clipboardState.entries = clipboardState.entries.filter((e) => e.id !== id);
}

export async function clearAll() {
  await api('/api/clipboard', { method: 'DELETE' });
  clipboardState.entries = [];
  clipboardState.hasMore = false;
  clipboardState.offset = 0;
}

onSessionEnd(() => {
  requestVersion++;
  Object.assign(clipboardState, { entries: [], hasMore: false, loading: false, offset: 0, error: '' });
});
