import { api } from '../api';

export interface AdminUserRow {
  id: string;
  username: string;
  email: string;
  full_name: string;
  email_verified: boolean;
  auth_provider: string;
  is_admin: boolean;
  created_at: string;
  device_count: number;
  subscription_plan_id: string | null;
  subscription_plan_name: string | null;
}

export interface AdminStats {
  total_users: number;
  total_devices: number;
  total_entries: number;
  active_connections: number;
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
}

export const adminState: {
  users: AdminUserRow[];
  stats: AdminStats | null;
  plans: SubscriptionPlan[];
  downloads: DownloadLink[];
  releases: AppRelease[];
  loading: boolean;
} = $state({
  users: [],
  stats: null,
  plans: [],
  downloads: [],
  releases: [],
  loading: false,
});

// Users
export async function fetchAdminUsers() {
  adminState.loading = true;
  try {
    adminState.users = await api<AdminUserRow[]>('/api/admin/users');
  } catch {
    adminState.users = [];
  } finally {
    adminState.loading = false;
  }
}

export async function fetchAdminStats() {
  try {
    adminState.stats = await api<AdminStats>('/api/admin/stats');
  } catch {
    adminState.stats = null;
  }
}

export async function adminDeleteUser(id: string) {
  await api(`/api/admin/users/${id}`, { method: 'DELETE' });
  adminState.users = adminState.users.filter((u) => u.id !== id);
}

export async function adminAssignSubscription(userId: string, planId: string) {
  await api(`/api/admin/users/${userId}/subscription`, {
    method: 'PUT',
    body: JSON.stringify({ plan_id: planId }),
  });
}

export async function adminRemoveSubscription(userId: string) {
  await api(`/api/admin/users/${userId}/subscription`, { method: 'DELETE' });
}

// Plans
export async function fetchAdminPlans() {
  try {
    adminState.plans = await api<SubscriptionPlan[]>('/api/admin/plans');
  } catch {
    adminState.plans = [];
  }
}

export async function adminCreatePlan(plan: Partial<SubscriptionPlan>) {
  const created = await api<SubscriptionPlan>('/api/admin/plans', {
    method: 'POST',
    body: JSON.stringify(plan),
  });
  adminState.plans = [...adminState.plans, created];
  return created;
}

export async function adminUpdatePlan(id: string, plan: Partial<SubscriptionPlan>) {
  const updated = await api<SubscriptionPlan>(`/api/admin/plans/${id}`, {
    method: 'PUT',
    body: JSON.stringify(plan),
  });
  adminState.plans = adminState.plans.map((p) => (p.id === id ? updated : p));
  return updated;
}

export async function adminDeletePlan(id: string) {
  await api(`/api/admin/plans/${id}`, { method: 'DELETE' });
  adminState.plans = adminState.plans.filter((p) => p.id !== id);
}

// Downloads
export async function fetchAdminDownloads() {
  try {
    adminState.downloads = await api<DownloadLink[]>('/api/admin/downloads');
  } catch {
    adminState.downloads = [];
  }
}

export async function adminCreateDownload(link: Partial<DownloadLink>) {
  const created = await api<DownloadLink>('/api/admin/downloads', {
    method: 'POST',
    body: JSON.stringify(link),
  });
  adminState.downloads = [...adminState.downloads, created];
  return created;
}

export async function adminUpdateDownload(id: string, link: Partial<DownloadLink>) {
  const updated = await api<DownloadLink>(`/api/admin/downloads/${id}`, {
    method: 'PUT',
    body: JSON.stringify(link),
  });
  adminState.downloads = adminState.downloads.map((d) => (d.id === id ? updated : d));
  return updated;
}

export async function adminDeleteDownload(id: string) {
  await api(`/api/admin/downloads/${id}`, { method: 'DELETE' });
  adminState.downloads = adminState.downloads.filter((d) => d.id !== id);
}

// Releases
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

export async function fetchAdminReleases() {
  try {
    adminState.releases = await api<AppRelease[]>('/api/admin/releases');
  } catch {
    adminState.releases = [];
  }
}

export async function adminCreateRelease(release: Partial<AppRelease>) {
  const created = await api<AppRelease>('/api/admin/releases', {
    method: 'POST',
    body: JSON.stringify(release),
  });
  adminState.releases = [created, ...adminState.releases];
  return created;
}

export async function adminUpdateRelease(id: string, release: Partial<AppRelease>) {
  const updated = await api<AppRelease>(`/api/admin/releases/${id}`, {
    method: 'PUT',
    body: JSON.stringify(release),
  });
  adminState.releases = adminState.releases.map((r) => (r.id === id ? updated : r));
  return updated;
}

export async function adminDeleteRelease(id: string) {
  await api(`/api/admin/releases/${id}`, { method: 'DELETE' });
  adminState.releases = adminState.releases.filter((r) => r.id !== id);
}

// File upload
export async function adminUploadBinary(file: File): Promise<{ uploaded: Array<{ filename: string; size: number; url: string }> }> {
  const formData = new FormData();
  formData.append('file', file);

  const token = (await import('../auth')).getAccessToken();
  const res = await fetch('/api/admin/downloads/upload', {
    method: 'POST',
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    body: formData,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || 'Upload failed');
  }
  return res.json();
}

// Test connections
export async function adminTestSmtp(toEmail: string): Promise<{ message?: string; error?: string }> {
  return api('/api/admin/test/smtp', {
    method: 'POST',
    body: JSON.stringify({ to_email: toEmail }),
  });
}

export async function adminTestOidc(): Promise<{ message?: string; error?: string; issuer?: string; authorization_endpoint?: string }> {
  return api('/api/admin/test/oidc', {
    method: 'POST',
    body: JSON.stringify({}),
  });
}
