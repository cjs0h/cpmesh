import { api } from '../api';
import { clearTokens } from '../auth';

interface UserState {
  id: string;
  username: string;
  email: string;
  fullName: string;
  avatarUrl: string;
  emailVerified: boolean;
  authProvider: string;
  isAdmin: boolean;
  loaded: boolean;
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
  loaded: false,
});

export async function fetchCurrentUser() {
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
    }>('/api/me');
    userState.id = data.id;
    userState.username = data.username;
    userState.email = data.email || '';
    userState.fullName = data.full_name || '';
    userState.avatarUrl = data.avatar_url || '';
    userState.emailVerified = data.email_verified;
    userState.authProvider = data.auth_provider || 'local';
    userState.isAdmin = data.is_admin;
    userState.loaded = true;
  } catch {
    userState.loaded = true;
  }
}

export function resetUserState() {
  clearTokens();
  userState.id = '';
  userState.username = '';
  userState.email = '';
  userState.fullName = '';
  userState.avatarUrl = '';
  userState.emailVerified = false;
  userState.authProvider = 'local';
  userState.isAdmin = false;
  userState.loaded = false;
}
