/** Human-friendly formatting helpers shared by the dashboard pages. */

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/**
 * Relative time such as "just now", "5m ago", "3h ago", "2d ago". Falls back to
 * a short calendar date once the value is older than a week.
 */
export function relativeTime(value: string | number | Date, now: number = Date.now()): string {
  const date = value instanceof Date ? value : new Date(value);
  const ts = date.getTime();
  if (Number.isNaN(ts)) return '—';

  const diff = now - ts;
  if (diff < 45_000) return 'just now';
  if (diff < HOUR) return `${Math.max(1, Math.round(diff / MINUTE))}m ago`;
  if (diff < DAY) return `${Math.round(diff / HOUR)}h ago`;
  if (diff < 7 * DAY) return `${Math.round(diff / DAY)}d ago`;

  return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

/** Full local date-time string for tooltips. */
export function absoluteTime(value: string | number | Date): string {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString();
}

/** Formats a byte count: 512 B, 1.5 KB, 3.2 MB. */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '—';
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

/** Approximate decoded size of a base64 payload. */
export function base64Size(data: string | null | undefined): number {
  if (!data) return 0;
  const clean = data.replace(/[\r\n=]/g, '');
  return Math.floor((clean.length * 3) / 4);
}

/** Up to two initials for an avatar fallback. */
export function initials(name: string | null | undefined, fallback = '??'): string {
  const trimmed = (name ?? '').trim();
  if (!trimmed) return fallback;
  const parts = trimmed.split(/\s+/).filter(Boolean);
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

/** Shortens long identifiers while keeping both ends visible: `3f9a…c21e`. */
export function truncateMiddle(value: string, keep = 6): string {
  if (!value || value.length <= keep * 2 + 1) return value;
  return `${value.slice(0, keep)}…${value.slice(-keep)}`;
}

/** Compact number display: 1.2k, 4.5M. */
export function compactNumber(value: number): string {
  if (!Number.isFinite(value)) return '—';
  return new Intl.NumberFormat(undefined, { notation: 'compact', maximumFractionDigits: 1 }).format(value);
}

/** Time-of-day greeting for the dashboard header. */
export function greeting(hour: number = new Date().getHours()): string {
  if (hour < 5) return 'Good night';
  if (hour < 12) return 'Good morning';
  if (hour < 18) return 'Good afternoon';
  return 'Good evening';
}

/** Capitalises the first letter of a word such as a content type or platform. */
export function titleCase(value: string | null | undefined): string {
  if (!value) return '';
  return value.charAt(0).toUpperCase() + value.slice(1);
}

export type Tone = 'neutral' | 'accent' | 'cyan' | 'mint' | 'gold' | 'rose' | 'violet';

/** Icon + colour used to represent a clipboard content type. */
export function contentTypeMeta(type: string | null | undefined): { icon: string; tone: Tone; label: string } {
  const t = (type ?? '').toLowerCase();
  if (t.startsWith('image')) return { icon: 'image', tone: 'violet', label: 'Image' };
  if (t.startsWith('file') || t.includes('pdf') || t.includes('zip')) return { icon: 'file', tone: 'gold', label: 'File' };
  if (t === 'url' || t === 'link' || t.includes('uri')) return { icon: 'link', tone: 'cyan', label: 'Link' };
  if (t === 'text' || t.startsWith('text')) return { icon: 'type', tone: 'mint', label: 'Text' };
  if (!t) return { icon: 'package', tone: 'neutral', label: 'Unknown' };
  return { icon: 'package', tone: 'neutral', label: titleCase(t) };
}

/** Icon for a device platform string (best effort). */
export function platformIcon(platform: string | null | undefined): string {
  const p = (platform ?? '').toLowerCase();
  // "darwin" contains "win", so Apple platforms must be matched first.
  if (p.includes('mac') || p.includes('darwin') || p.includes('ios') || p.includes('iphone') || p.includes('ipad')) return 'apple';
  if (p.includes('win')) return 'windows';
  if (p.includes('linux')) return 'linux';
  if (p.includes('android')) return 'android';
  return 'monitor';
}
