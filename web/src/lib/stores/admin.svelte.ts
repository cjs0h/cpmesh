import { api, ApiError } from '../api';
import { titleCase } from '../format';
import { requestStepUp } from './reauth.svelte';
import { publicSettings } from './settings.svelte';
import type { Role } from './user.svelte';

// === Types ===

export interface AdminUserRow {
  id: string;
  username: string;
  email: string;
  full_name: string;
  email_verified: boolean;
  auth_provider: string;
  /** Staff (any role but "user"). */
  is_admin: boolean;
  role: Role;
  created_at: string;
  device_count: number;
  subscription_plan_id: string | null;
  subscription_plan_name: string | null;
  suspended_at: string | null;
  mfa_enabled: boolean;
  /** Most recent activity of any of their devices. */
  last_seen: string | null;
}

/** One page of a list. */
export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  per_page: number;
}

export type UserStatusFilter = 'active' | 'suspended' | 'unverified' | 'no_mfa';

export interface AdminUserQuery {
  /** A user ID, an exact email address, or part of a username. */
  q?: string;
  /** A role, or "staff" for every staff role. */
  role?: Role | 'staff' | '';
  status?: UserStatusFilter | '';
  plan_id?: string;
  page?: number;
  per_page?: number;
}

export interface AdminDevice {
  id: string;
  name: string;
  /** approved, pending, rejected or revoked. */
  status: string;
  last_seen: string | null;
  created_at: string;
  online: boolean;
}

export interface AdminUserDetail {
  user: AdminUserRow;
  suspended_reason: string | null;
  devices: AdminDevice[];
  /** Live WebSocket connections. */
  connections: number;
  mfa: {
    enabled: boolean;
    required: boolean;
    totp: boolean;
    passkeys: number;
    recovery_codes_remaining: number;
  };
  recent_activity: AuditLogRow[];
}

export interface DailyCount {
  /** `YYYY-MM-DD` */
  day: string;
  count: number;
}

export interface PlanUsage {
  /** `null` for users without a plan. */
  plan_id: string | null;
  name: string;
  users: number;
}

export interface AdminStats {
  total_users: number;
  total_devices: number;
  total_entries: number;
  active_connections: number;
  pending_devices: number;
  suspended_users: number;
  staff_users: number;
  mfa_users: number;
  active_users_1d: number;
  active_users_7d: number;
  active_users_30d: number;
  /** On-disk size of the stored (encrypted) clipboard data. */
  storage_bytes: number;
  /** Daily counts for the last 30 days, oldest first. */
  signups: DailyCount[];
  active_users: DailyCount[];
  entries: DailyCount[];
  plans: PlanUsage[];
}

export interface AuditLogRow {
  id: string;
  /** Who acted; `null` for anonymous events such as a failed sign-in. */
  user_id: string | null;
  username: string | null;
  /** The account acted on, when it is someone else's. */
  target_user_id: string | null;
  target_username: string | null;
  action: string;
  ip_address: string | null;
  user_agent: string | null;
  details: unknown;
  created_at: string;
}

export interface AuditQuery {
  limit?: number;
  offset?: number;
  /** Entries by or about this user. */
  user_id?: string;
  action?: string;
}

export interface ApiToken {
  id: string;
  user_id: string;
  username: string | null;
  name: string;
  token_prefix: string;
  scopes: string[];
  expires_at: string | null;
  last_used_at: string | null;
  revoked_at: string | null;
  created_at: string;
}

export interface NewApiToken {
  name: string;
  scopes: string[];
  /** 1 to 365, or `null` for a token that never expires. */
  expires_in_days: number | null;
}

export interface CreatedApiToken {
  /** The secret, shown once. */
  token: string;
  api_token: ApiToken;
}

export type ApiTokenStatus = 'active' | 'expired' | 'revoked';

export type BannerTone = 'info' | 'warning' | 'danger';

export interface Banner {
  message: string;
  tone: BannerTone;
}

export interface AdminSettings {
  registration_open: {
    /** In effect now. */
    value: boolean;
    /** Set from the admin console; `null` follows the default. */
    override: boolean | null;
    /** REGISTRATION_OPEN */
    default: boolean;
  };
  banner: Banner | null;
  /** MFA_REQUIRED: every account, or staff only. */
  mfa_policy: 'all' | 'staff';
  passkeys: { enabled: boolean; rp_id: string; origins: string[] };
  uploads: { signature_required: boolean; downloads_dir_configured: boolean };
  /** DOWNLOAD_URL_PREFIXES; empty allows any URL. */
  download_url_prefixes: string[];
  smtp_configured: boolean;
  oidc_configured: boolean;
}

/** Omitted settings stay as they are; `null` goes back to the default. */
export interface AdminSettingsUpdate {
  registration_open?: boolean | null;
  banner?: Banner | null;
}

export interface SubscriptionPlan {
  id: string;
  name: string;
  description: string;
  price: number;
  currency: string;
  billing_period: string;
  max_devices: number;
  max_clipboard_history: number;
  allowed_file_types: string[];
  is_active: boolean;
  sort_order: number;
  created_at: string;
  updated_at: string;
}

/** Plan prices are decimals, which the server sends as strings ("4.99"). */
type PlanResponse = Omit<SubscriptionPlan, 'price'> & { price: number | string };

export interface DownloadLink {
  id: string;
  name: string;
  url: string;
  platform: string;
  arch: string;
  format: string;
  sort_order: number;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  release_id: string | null;
  /** Set for files uploaded to this server. */
  sha256: string | null;
  size_bytes: number | null;
}

export interface AppRelease {
  id: string;
  version: string;
  platform: string;
  arch: string;
  download_url: string;
  release_notes: string;
  is_current: boolean;
  created_at: string;
  updated_at: string;
}

export interface UploadedFile {
  filename: string;
  size: number;
  sha256: string;
  url: string;
  signed: boolean;
}

export interface UploadResult {
  uploaded: UploadedFile[];
}

export interface UploadOptions {
  /** Signature files keyed by the name of the installer they sign. */
  signatures?: Record<string, File>;
  /** Overwrite files that already exist on the server. */
  replace?: boolean;
}

// === Labels ===

export const ROLES: { value: Role; label: string; description: string }[] = [
  { value: 'user', label: 'Member', description: 'No access to the admin console.' },
  { value: 'viewer', label: 'Viewer', description: 'Read-only access to the admin console.' },
  { value: 'support', label: 'Support', description: 'Viewer, plus verifying emails, changing plans, and suspending and signing out members.' },
  { value: 'admin', label: 'Admin', description: 'Support, plus deleting users, resetting 2FA, and managing plans, releases, settings and API tokens.' },
  { value: 'owner', label: 'Owner', description: 'Admin, plus managing staff accounts and roles.' },
];

export function roleLabel(role: string): string {
  return ROLES.find((r) => r.value === role)?.label ?? titleCase(role);
}

export const USER_STATUSES: { value: UserStatusFilter; label: string }[] = [
  { value: 'active', label: 'Active' },
  { value: 'suspended', label: 'Suspended' },
  { value: 'unverified', label: 'Unverified email' },
  { value: 'no_mfa', label: 'No 2FA' },
];

export const API_TOKEN_SCOPES: { value: string; label: string; description: string }[] = [
  { value: 'releases:write', label: 'releases:write', description: 'Publish releases and download links.' },
];

export const BANNER_MAX_LENGTH = 500;

const AUDIT_LABELS: Record<string, string> = {
  login_success: 'Signed in',
  login_failure: 'Sign-in failed',
  register: 'Registered',
  password_change: 'Changed password',
  device_register: 'Added a device',
  device_delete: 'Removed a device',
  device_approve: 'Approved a device',
  device_reject: 'Rejected a device',
  group_key_rotate: 'Rotated the encryption key',
  token_revoke_all: 'Signed out everywhere',
  mfa_challenge: 'Asked for a second factor',
  mfa_failure: 'Second factor rejected',
  mfa_locked: 'Second factor locked',
  mfa_step_up: 'Confirmed it was them',
  mfa_totp_enabled: 'Added an authenticator app',
  mfa_totp_disabled: 'Removed the authenticator app',
  mfa_passkey_added: 'Added a passkey',
  mfa_passkey_removed: 'Removed a passkey',
  mfa_recovery_code_used: 'Used a recovery code',
  mfa_recovery_codes_regenerated: 'Made new recovery codes',
  mfa_email_code_sent: 'Emailed a confirmation code',
  admin_delete_user: 'Deleted a user',
  admin_assign_subscription: 'Changed plan',
  admin_remove_subscription: 'Removed plan',
  admin_verify_email: 'Verified email',
  admin_resend_verification: 'Resent verification email',
  admin_suspend_user: 'Suspended',
  admin_unsuspend_user: 'Reinstated',
  admin_revoke_sessions: 'Signed out by staff',
  admin_set_role: 'Changed role',
  admin_reset_mfa: 'Reset 2FA',
  admin_plan_create: 'Created a plan',
  admin_plan_update: 'Updated a plan',
  admin_plan_delete: 'Deleted a plan',
  admin_download_create: 'Added a download link',
  admin_download_update: 'Updated a download link',
  admin_download_delete: 'Deleted a download link',
  admin_upload: 'Uploaded installers',
  admin_release_create: 'Published a release',
  admin_release_update: 'Updated a release',
  admin_release_delete: 'Deleted a release',
  admin_settings_update: 'Changed site settings',
  admin_test_smtp: 'Tested email delivery',
  admin_test_oidc: 'Tested social login',
  admin_api_token_create: 'Created an API token',
  admin_api_token_revoke: 'Revoked an API token',
};

/** Readable name of an audit action such as `admin_suspend_user`. */
export function auditActionLabel(action: string): string {
  return AUDIT_LABELS[action] ?? titleCase(action.replace(/_/g, ' '));
}

const FAILED_ACTIONS = new Set(['login_failure', 'mfa_failure', 'mfa_locked']);
const SENSITIVE_ACTIONS = new Set([
  'admin_delete_user',
  'admin_suspend_user',
  'admin_reset_mfa',
  'admin_revoke_sessions',
  'admin_set_role',
  'admin_api_token_create',
  'admin_api_token_revoke',
]);

/** Badge tone for an audit action: failures stand out, sensitive staff actions are flagged. */
export function auditActionTone(action: string): 'rose' | 'gold' | 'neutral' {
  if (FAILED_ACTIONS.has(action)) return 'rose';
  if (SENSITIVE_ACTIONS.has(action)) return 'gold';
  return 'neutral';
}

/** Group of an audit action, for grouping the filter options. */
export function auditActionGroup(action: string): 'Account' | 'Two-factor' | 'Admin console' {
  if (action.startsWith('mfa_')) return 'Two-factor';
  if (action.startsWith('admin_')) return 'Admin console';
  return 'Account';
}

/** Whether a token can still be used. */
export function apiTokenStatus(token: ApiToken, now: number = Date.now()): ApiTokenStatus {
  if (token.revoked_at) return 'revoked';
  if (token.expires_at && new Date(token.expires_at).getTime() <= now) return 'expired';
  return 'active';
}

/** A plan price as a number, whether the server sent a number or a decimal string. */
export function planPrice(value: number | string | null | undefined): number {
  const price = typeof value === 'number' ? value : Number.parseFloat(value ?? '');
  return Number.isFinite(price) ? price : 0;
}

// === State ===

export const adminState: {
  users: AdminUserRow[];
  usersTotal: number;
  /** Query string of the user list last shown, so "back to users" restores it. */
  usersQuery: string;
  stats: AdminStats | null;
  plans: SubscriptionPlan[];
  downloads: DownloadLink[];
  releases: AppRelease[];
  settings: AdminSettings | null;
  apiTokens: ApiToken[];
  loading: boolean;
} = $state({
  users: [],
  usersTotal: 0,
  usersQuery: '',
  stats: null,
  plans: [],
  downloads: [],
  releases: [],
  settings: null,
  apiTokens: [],
  loading: false,
});

/**
 * The admin console only answers sessions confirmed with a second factor. When the
 * server refuses (`mfa_required`), `required` is set and `enrolled` tells whether the
 * user can confirm now or must set up 2FA first; the next successful request clears it.
 */
export const adminGate: { required: boolean; enrolled: boolean } = $state({
  required: false,
  enrolled: false,
});

/** Whether `err` is the console asking for a 2FA-confirmed session (shown by the gate, not as an error). */
export function isMfaRequired(err: unknown): err is ApiError {
  return err instanceof ApiError && err.code === 'mfa_required';
}

export function errorMessage(err: unknown): string {
  if (err instanceof Error && err.message) return err.message;
  return typeof err === 'string' && err ? err : 'Something went wrong';
}

async function adminApi<T = unknown>(path: string, options: RequestInit = {}): Promise<T> {
  try {
    const result = await api<T>(path, options);
    adminGate.required = false;
    return result;
  } catch (err) {
    if (isMfaRequired(err)) {
      adminGate.enrolled = err.data.enrolled === true;
      adminGate.required = true;
    }
    throw err;
  }
}

function jsonBody(method: string, body: unknown): RequestInit {
  return { method, body: JSON.stringify(body) };
}

/** `?a=1&b=x` from the parameters that have a value. */
function toQuery(params: object): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue;
    search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : '';
}

const userPath = (id: string) => `/api/admin/users/${encodeURIComponent(id)}`;

/**
 * Sensitive actions need a recent sign-in. A request answered with `reauth_required` is
 * retried after the confirmation, which is fine for small JSON bodies; installer
 * uploads are too large to send twice, so confirm before sending them. Resolves `false`
 * when the user cancels.
 */
export async function ensureRecentAuth(reason: string): Promise<boolean> {
  let recent: boolean | null | undefined;
  try {
    recent = (await api<{ recent_auth?: boolean | null }>('/api/mfa')).recent_auth;
  } catch {
    // Let the upload itself report the problem
    return true;
  }
  return recent === false ? requestStepUp(reason) : true;
}

// === Users ===

let usersRequest = 0;

/**
 * Loads a page of users into `adminState`. A response overtaken by a newer request
 * (e.g. while typing a search) is dropped and resolves `null`.
 */
export async function fetchAdminUsers(query: AdminUserQuery = {}): Promise<Page<AdminUserRow> | null> {
  const request = ++usersRequest;
  adminState.loading = true;
  try {
    const page = await adminApi<Page<AdminUserRow>>(`/api/admin/users${toQuery(query)}`);
    if (request !== usersRequest) return null;
    adminState.users = page.items;
    adminState.usersTotal = page.total;
    return page;
  } catch (err) {
    if (request !== usersRequest) return null;
    throw err;
  } finally {
    if (request === usersRequest) adminState.loading = false;
  }
}

export function fetchAdminUser(id: string): Promise<AdminUserDetail> {
  return adminApi<AdminUserDetail>(userPath(id));
}

export async function adminDeleteUser(id: string) {
  await adminApi(userPath(id), { method: 'DELETE' });
  const remaining = adminState.users.filter((u) => u.id !== id);
  if (remaining.length < adminState.users.length) adminState.usersTotal = Math.max(0, adminState.usersTotal - 1);
  adminState.users = remaining;
}

export function adminAssignSubscription(userId: string, planId: string) {
  return adminApi(`${userPath(userId)}/subscription`, jsonBody('PUT', { plan_id: planId }));
}

export function adminRemoveSubscription(userId: string) {
  return adminApi(`${userPath(userId)}/subscription`, { method: 'DELETE' });
}

export function adminVerifyEmail(userId: string) {
  return adminApi(`${userPath(userId)}/verify-email`, { method: 'PUT' });
}

export function adminResendVerification(userId: string) {
  return adminApi(`${userPath(userId)}/resend-verification`, { method: 'POST' });
}

/** Suspends the account and signs it out everywhere. */
export function adminSuspendUser(userId: string, reason: string) {
  return adminApi(`${userPath(userId)}/suspend`, jsonBody('POST', { reason }));
}

export function adminUnsuspendUser(userId: string) {
  return adminApi(`${userPath(userId)}/unsuspend`, { method: 'POST' });
}

/** Signs the user out on every device. */
export function adminRevokeSessions(userId: string) {
  return adminApi(`${userPath(userId)}/revoke-sessions`, { method: 'POST' });
}

export function adminSetRole(userId: string, role: Role) {
  return adminApi(`${userPath(userId)}/role`, jsonBody('PUT', { role }));
}

/** Removes every second factor of the account and signs it out. */
export function adminResetMfa(userId: string) {
  return adminApi(`${userPath(userId)}/mfa`, { method: 'DELETE' });
}

// === Stats ===

export async function fetchAdminStats(): Promise<AdminStats> {
  const stats = await adminApi<AdminStats>('/api/admin/stats');
  adminState.stats = stats;
  return stats;
}

// === Audit log ===

export function fetchAuditLogs(query: AuditQuery = {}): Promise<{ items: AuditLogRow[]; total: number }> {
  return adminApi(`/api/admin/audit-logs${toQuery(query)}`);
}

/** Every action name the audit log records. */
export function fetchAuditActions(): Promise<string[]> {
  return adminApi<string[]>('/api/admin/audit-logs/actions');
}

// === Plans ===

function toPlan(plan: PlanResponse): SubscriptionPlan {
  return {
    ...plan,
    price: planPrice(plan.price),
    allowed_file_types: Array.isArray(plan.allowed_file_types) ? plan.allowed_file_types : [],
  };
}

export async function fetchAdminPlans(): Promise<SubscriptionPlan[]> {
  const plans = (await adminApi<PlanResponse[]>('/api/admin/plans')).map(toPlan);
  adminState.plans = plans;
  return plans;
}

export async function adminCreatePlan(plan: Partial<SubscriptionPlan>) {
  const created = toPlan(await adminApi<PlanResponse>('/api/admin/plans', jsonBody('POST', plan)));
  adminState.plans = [...adminState.plans, created];
  return created;
}

export async function adminUpdatePlan(id: string, plan: Partial<SubscriptionPlan>) {
  const updated = toPlan(await adminApi<PlanResponse>(`/api/admin/plans/${encodeURIComponent(id)}`, jsonBody('PUT', plan)));
  adminState.plans = adminState.plans.map((p) => (p.id === id ? updated : p));
  return updated;
}

export async function adminDeletePlan(id: string) {
  await adminApi(`/api/admin/plans/${encodeURIComponent(id)}`, { method: 'DELETE' });
  adminState.plans = adminState.plans.filter((p) => p.id !== id);
}

// === Downloads ===

export async function fetchAdminDownloads(): Promise<DownloadLink[]> {
  const downloads = await adminApi<DownloadLink[]>('/api/admin/downloads');
  adminState.downloads = downloads;
  return downloads;
}

export async function adminCreateDownload(link: Partial<DownloadLink>) {
  const created = await adminApi<DownloadLink>('/api/admin/downloads', jsonBody('POST', link));
  adminState.downloads = [...adminState.downloads, created];
  return created;
}

export async function adminUpdateDownload(id: string, link: Partial<DownloadLink>) {
  const updated = await adminApi<DownloadLink>(`/api/admin/downloads/${encodeURIComponent(id)}`, jsonBody('PUT', link));
  adminState.downloads = adminState.downloads.map((d) => (d.id === id ? updated : d));
  return updated;
}

export async function adminDeleteDownload(id: string) {
  await adminApi(`/api/admin/downloads/${encodeURIComponent(id)}`, { method: 'DELETE' });
  adminState.downloads = adminState.downloads.filter((d) => d.id !== id);
}

/**
 * Uploads installers to the downloads directory. Each installer is a `file` field; its
 * signature (if any) is a `signature` field named `<installer>.sig`, which the server
 * requires when it has an update key.
 */
export function adminUploadBinary(files: File | File[], options: UploadOptions = {}): Promise<UploadResult> {
  const form = new FormData();
  for (const file of Array.isArray(files) ? files : [files]) {
    form.append('file', file, file.name);
    const signature = options.signatures?.[file.name];
    if (signature) form.append('signature', signature, `${file.name}.sig`);
  }
  if (options.replace) form.append('replace', 'true');
  return adminApi<UploadResult>('/api/admin/downloads/upload', { method: 'POST', body: form });
}

// === Releases ===

export async function fetchAdminReleases(): Promise<AppRelease[]> {
  const releases = await adminApi<AppRelease[]>('/api/admin/releases');
  adminState.releases = releases;
  return releases;
}

export async function adminCreateRelease(release: Partial<AppRelease>) {
  const created = await adminApi<AppRelease>('/api/admin/releases', jsonBody('POST', release));
  adminState.releases = [created, ...adminState.releases];
  return created;
}

export async function adminUpdateRelease(id: string, release: Partial<AppRelease>) {
  const updated = await adminApi<AppRelease>(`/api/admin/releases/${encodeURIComponent(id)}`, jsonBody('PUT', release));
  adminState.releases = adminState.releases.map((r) => (r.id === id ? updated : r));
  return updated;
}

export async function adminDeleteRelease(id: string) {
  await adminApi(`/api/admin/releases/${encodeURIComponent(id)}`, { method: 'DELETE' });
  adminState.releases = adminState.releases.filter((r) => r.id !== id);
}

// === Runtime settings ===

export async function fetchAdminSettings(): Promise<AdminSettings> {
  const settings = await adminApi<AdminSettings>('/api/admin/settings');
  adminState.settings = settings;
  return settings;
}

export async function adminUpdateSettings(update: AdminSettingsUpdate): Promise<AdminSettings> {
  const settings = await adminApi<AdminSettings>('/api/admin/settings', jsonBody('PUT', update));
  adminState.settings = settings;
  // The dashboard banner reads the public settings, loaded once per page load
  publicSettings.registrationOpen = settings.registration_open.value;
  publicSettings.banner = settings.banner;
  return settings;
}

// === Integration checks ===

export function adminTestSmtp(toEmail: string): Promise<{ message?: string; error?: string }> {
  return adminApi('/api/admin/test/smtp', jsonBody('POST', { to_email: toEmail }));
}

export function adminTestOidc(): Promise<{ message?: string; error?: string; issuer?: string; authorization_endpoint?: string }> {
  return adminApi('/api/admin/test/oidc', jsonBody('POST', {}));
}

// === API tokens ===

export async function fetchApiTokens(): Promise<ApiToken[]> {
  const tokens = await adminApi<ApiToken[]>('/api/admin/api-tokens');
  adminState.apiTokens = tokens;
  return tokens;
}

/** Creates a token; the secret in the result is never shown again. */
export async function adminCreateApiToken(token: NewApiToken): Promise<CreatedApiToken> {
  const created = await adminApi<CreatedApiToken>('/api/admin/api-tokens', jsonBody('POST', token));
  adminState.apiTokens = [created.api_token, ...adminState.apiTokens];
  return created;
}

export async function adminRevokeApiToken(id: string) {
  await adminApi(`/api/admin/api-tokens/${encodeURIComponent(id)}`, { method: 'DELETE' });
  const now = new Date().toISOString();
  adminState.apiTokens = adminState.apiTokens.map((t) => (t.id === id ? { ...t, revoked_at: t.revoked_at ?? now } : t));
}
