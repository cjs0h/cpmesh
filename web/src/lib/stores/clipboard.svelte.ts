import { api } from '../api';

export interface ClipboardEntry {
  id: string;
  user_id: string;
  device_id: string;
  device_name: string;
  content_type: string;
  encrypted_data: string;
  metadata: string;
  created_at: string;
}

export const clipboardState: {
  entries: ClipboardEntry[];
  hasMore: boolean;
  loading: boolean;
  offset: number;
} = $state({
  entries: [],
  hasMore: false,
  loading: false,
  offset: 0,
});

const PAGE_SIZE = 20;

export async function fetchClipboard(reset = false) {
  if (reset) clipboardState.offset = 0;
  clipboardState.loading = true;
  try {
    const data = await api<{ entries: ClipboardEntry[]; has_more: boolean }>(
      `/api/clipboard?limit=${PAGE_SIZE}&offset=${clipboardState.offset}`
    );
    clipboardState.entries = data.entries || [];
    clipboardState.hasMore = data.has_more;
  } catch {
    clipboardState.entries = [];
    clipboardState.hasMore = false;
  } finally {
    clipboardState.loading = false;
  }
}

export async function loadNextPage() {
  clipboardState.offset += PAGE_SIZE;
  await fetchClipboard();
}

export async function loadPrevPage() {
  clipboardState.offset = Math.max(0, clipboardState.offset - PAGE_SIZE);
  await fetchClipboard();
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
