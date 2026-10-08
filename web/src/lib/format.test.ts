import { describe, expect, it } from 'vitest';
import {
  absoluteTime,
  base64Size,
  compactNumber,
  contentTypeMeta,
  formatBytes,
  greeting,
  initials,
  platformIcon,
  relativeTime,
  titleCase,
  truncateMiddle,
} from './format';

const NOW = Date.UTC(2026, 9, 8, 12, 0, 0);

describe('relativeTime', () => {
  it('buckets recent timestamps', () => {
    expect(relativeTime(NOW - 10_000, NOW)).toBe('just now');
    expect(relativeTime(NOW - 5 * 60_000, NOW)).toBe('5m ago');
    expect(relativeTime(NOW - 3 * 3_600_000, NOW)).toBe('3h ago');
    expect(relativeTime(NOW - 2 * 86_400_000, NOW)).toBe('2d ago');
  });

  it('falls back to a calendar date after a week', () => {
    const result = relativeTime(NOW - 30 * 86_400_000, NOW);
    expect(result).not.toMatch(/ago$/);
    expect(result.length).toBeGreaterThan(0);
  });

  it('accepts ISO strings and Date objects', () => {
    expect(relativeTime(new Date(NOW - 60_000).toISOString(), NOW)).toBe('1m ago');
    expect(relativeTime(new Date(NOW - 60_000), NOW)).toBe('1m ago');
  });

  it('handles invalid input gracefully', () => {
    expect(relativeTime('not a date', NOW)).toBe('—');
    expect(absoluteTime('not a date')).toBe('—');
  });
});

describe('formatBytes / base64Size', () => {
  it('formats byte sizes with sensible precision', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(1536)).toBe('1.5 KB');
    expect(formatBytes(25 * 1024 * 1024)).toBe('25 MB');
    expect(formatBytes(-1)).toBe('—');
    expect(formatBytes(Number.NaN)).toBe('—');
  });

  it('estimates the decoded size of base64 data', () => {
    expect(base64Size('')).toBe(0);
    expect(base64Size(null)).toBe(0);
    expect(base64Size('AA==')).toBe(1);
    expect(base64Size('aGVsbG8=')).toBe(5);
    expect(base64Size('aGVsbG8gd29ybGQ=')).toBe(11);
  });
});

describe('initials', () => {
  it('derives up to two letters from a name', () => {
    expect(initials('Alice Wonderland')).toBe('AW');
    expect(initials('alice')).toBe('AL');
    expect(initials('Ada Augusta Lovelace')).toBe('AL');
    expect(initials('   ')).toBe('??');
    expect(initials(undefined, 'me')).toBe('me');
  });
});

describe('truncateMiddle', () => {
  it('keeps both ends of long identifiers', () => {
    expect(truncateMiddle('3f9a1b2c3d4e5f6a7b8c9d0e')).toBe('3f9a1b…8c9d0e');
    expect(truncateMiddle('3f9a1b2c3d4e5f6a7b8c9d0e', 4)).toBe('3f9a…9d0e');
    expect(truncateMiddle('short')).toBe('short');
    expect(truncateMiddle('')).toBe('');
  });
});

describe('misc formatting', () => {
  it('compacts large numbers', () => {
    expect(compactNumber(999)).toBe('999');
    expect(compactNumber(1200)).toMatch(/1\.2K/i);
    expect(compactNumber(Number.POSITIVE_INFINITY)).toBe('—');
  });

  it('greets by hour', () => {
    expect(greeting(3)).toBe('Good night');
    expect(greeting(9)).toBe('Good morning');
    expect(greeting(15)).toBe('Good afternoon');
    expect(greeting(21)).toBe('Good evening');
  });

  it('title-cases a word', () => {
    expect(titleCase('text')).toBe('Text');
    expect(titleCase('')).toBe('');
    expect(titleCase(null)).toBe('');
  });

  it('maps content types to icons', () => {
    expect(contentTypeMeta('text')).toMatchObject({ icon: 'type', label: 'Text' });
    expect(contentTypeMeta('image/png')).toMatchObject({ icon: 'image', label: 'Image' });
    expect(contentTypeMeta('file')).toMatchObject({ icon: 'file' });
    expect(contentTypeMeta('url')).toMatchObject({ icon: 'link' });
    expect(contentTypeMeta(undefined)).toMatchObject({ icon: 'package', label: 'Unknown' });
    expect(contentTypeMeta('weird')).toMatchObject({ icon: 'package', label: 'Weird' });
  });

  it('maps platforms to icons', () => {
    expect(platformIcon('Windows 11')).toBe('windows');
    expect(platformIcon('darwin')).toBe('apple');
    expect(platformIcon('linux')).toBe('linux');
    expect(platformIcon('android')).toBe('android');
    expect(platformIcon(null)).toBe('monitor');
  });
});
