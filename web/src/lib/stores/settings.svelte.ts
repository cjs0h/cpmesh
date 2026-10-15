// Public runtime settings (`GET /api/settings`, no sign-in needed): the announcement
// banner, whether sign-up is open, and the second factors this server supports.

import { apiWithToken } from '../api';

export type BannerTone = 'info' | 'warning' | 'danger';

export interface Banner {
  message: string;
  tone: BannerTone;
}

interface PublicSettings {
  loaded: boolean;
  registrationOpen: boolean;
  banner: Banner | null;
  passkeysAvailable: boolean;
  mfaRequired: boolean;
  /** Banner message the user dismissed in this browser session. */
  dismissedBanner: string;
}

export const publicSettings: PublicSettings = $state({
  loaded: false,
  registrationOpen: true,
  banner: null,
  passkeysAvailable: false,
  mfaRequired: false,
  dismissedBanner: '',
});

const DISMISSED_KEY = 'cpmesh_dismissed_banner';
const TONES: readonly BannerTone[] = ['info', 'warning', 'danger'];

let loading: Promise<void> | null = null;

function parseBanner(value: unknown): Banner | null {
  if (!value || typeof value !== 'object') return null;
  const { message, tone } = value as { message?: unknown; tone?: unknown };
  if (typeof message !== 'string' || !message.trim()) return null;
  return { message: message.trim(), tone: TONES.includes(tone as BannerTone) ? (tone as BannerTone) : 'info' };
}

function readDismissed(): string {
  try {
    return sessionStorage.getItem(DISMISSED_KEY) ?? '';
  } catch {
    return '';
  }
}

/** Loads the settings once; later calls share that request. `force` loads them again (e.g. after an admin edit). */
export function loadPublicSettings(force = false): Promise<void> {
  if (!loading || force) loading = fetchPublicSettings();
  return loading;
}

async function fetchPublicSettings(): Promise<void> {
  try {
    const data = await apiWithToken<Record<string, unknown>>('/api/settings', null);
    publicSettings.registrationOpen = data.registration_open !== false;
    publicSettings.banner = parseBanner(data.banner);
    publicSettings.passkeysAvailable = data.passkeys_available === true;
    publicSettings.mfaRequired = data.mfa_required === true;
  } catch {
    // Optional: the defaults apply, and the next caller tries again
    loading = null;
  } finally {
    publicSettings.dismissedBanner = readDismissed();
    publicSettings.loaded = true;
  }
}

/** The banner to show, unless the user dismissed this message during this browser session. */
export function visibleBanner(): Banner | null {
  const banner = publicSettings.banner;
  return banner && banner.message !== publicSettings.dismissedBanner ? banner : null;
}

/** Hides the current banner until the browser session ends or the message changes. */
export function dismissBanner() {
  const message = publicSettings.banner?.message ?? '';
  publicSettings.dismissedBanner = message;
  try {
    sessionStorage.setItem(DISMISSED_KEY, message);
  } catch {
    // Storage unavailable: dismissed for this page only
  }
}
