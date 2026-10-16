import { api } from '../api';
import { clearTokens, onSessionEnd, authGeneration } from '../auth';
import { toast } from './toast.svelte';

export type Role = 'user' | 'viewer' | 'support' | 'admin' | 'owner';

/** Admin console permissions granted by the user's role (see the server's rbac.rs). */
export type Permission =
  | 'view'
  | 'manage_users'
  | 'delete_users'
  | 'reset_mfa'
  | 'manage_content'
  | 'manage_settings'
  | 'manage_api_tokens'
  | 'manage_staff';

interface UserState {
  id: string;
  username: string;
  email: string;
  fullName: string;
  avatarUrl: string;
  emailVerified: boolean;
  authProvider: string;
  /** Staff (any role but "user"): can open the admin console. */
  isAdmin: boolean;
  role: Role;
  permissions: Permission[];
  /** Two-factor authentication: set up, required for this account, and whether this session was confirmed with it. */
  mfa: { enabled: boolean; required: boolean; sessionVerified: boolean };
  loaded: boolean;
  error: string;
}

export const userState: UserState = $state({
  id: '',
  username: '',
  email: '',
  fullName: '',
  avatarUrl: '',
  emailVerified: false,
  authProvider: 'local',
  isAdmin: false,
  role: 'user',
  permissions: [],
  mfa: { enabled: false, required: false, sessionVerified: false },
  loaded: false,
  error: '',
});

/** Whether the signed-in user's role grants `permission`. */
export function can(permission: Permission): boolean {
  return userState.permissions.includes(permission);
}

export async function fetchCurrentUser() {
  const generation = authGeneration();
  userState.error = '';
  try {
    const data = await api<{
      id: string;
      username: string;
      email: string;
      full_name: string;
      avatar_url?: string;
      email_verified: boolean;
      auth_provider: string;
      is_admin: boolean;
      role?: Role;
      permissions?: Permission[];
      mfa?: { enabled: boolean; required: boolean; session_verified: boolean };
    }>('/api/me');
    if (generation !== authGeneration()) return;
    userState.id = data.id;
    userState.username = data.username;
    userState.email = data.email || '';
    userState.fullName = data.full_name || '';
    userState.avatarUrl = data.avatar_url || '';
    userState.emailVerified = data.email_verified;
    userState.authProvider = data.auth_provider || 'local';
    userState.isAdmin = data.is_admin;
    userState.role = data.role ?? (data.is_admin ? 'owner' : 'user');
    userState.permissions = data.permissions ?? [];
    userState.mfa = {
      enabled: data.mfa?.enabled ?? false,
      required: data.mfa?.required ?? false,
      sessionVerified: data.mfa?.session_verified ?? false,
    };
    userState.loaded = true;
  } catch (error) {
    if (generation !== authGeneration()) return;
    userState.error = error instanceof Error ? error.message : String(error);
    toast.error('Could not load your account', userState.error);
    userState.loaded = true;
  }
}

export function resetUserState() {
  clearTokens();
}

onSessionEnd(() => {
  userState.id = '';
  userState.username = '';
  userState.email = '';
  userState.fullName = '';
  userState.avatarUrl = '';
  userState.emailVerified = false;
  userState.authProvider = 'local';
  userState.isAdmin = false;
  userState.role = 'user';
  userState.permissions = [];
  userState.mfa = { enabled: false, required: false, sessionVerified: false };
  userState.loaded = false;
  userState.error = '';
});
