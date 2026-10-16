export interface RouteMeta {
  path: string;
  label: string;
  description: string;
  icon: string;
  admin?: boolean;
  /** The page renders its own heading (e.g. the personalised overview). */
  hideTitle?: boolean;
}

/** Navigation + page-header metadata for the authenticated app. */
export const appRoutes: RouteMeta[] = [
  { path: '/', label: 'Overview', description: 'Your devices and recent clipboard activity at a glance.', icon: 'dashboard', hideTitle: true },
  { path: '/clipboard', label: 'Clipboard', description: 'Encrypted history of everything you have copied.', icon: 'clipboard' },
  { path: '/devices', label: 'Devices', description: 'Machines paired to your account and their live status.', icon: 'monitor' },
  { path: '/mcp', label: 'AI agents', description: 'Connect Claude, Cursor, Copilot and other MCP clients to your encrypted clipboard.', icon: 'sparkles' },
  { path: '/settings', label: 'Settings', description: 'Account, plan and security preferences.', icon: 'settings' },
  { path: '/admin/users', label: 'Users', description: 'Everyone registered on this relay.', icon: 'users', admin: true },
  { path: '/admin/plans', label: 'Plans', description: 'Subscription tiers and their limits.', icon: 'star', admin: true },
  { path: '/admin/downloads', label: 'Downloads', description: 'Installer links shown on the public site.', icon: 'download', admin: true },
  { path: '/admin/releases', label: 'Releases', description: 'Versions advertised to clients for auto-update.', icon: 'upload', admin: true },
  { path: '/admin/audit', label: 'Audit log', description: 'Who did what, and when: sign-ins, security changes and admin actions.', icon: 'activity', admin: true },
  { path: '/admin/tokens', label: 'API tokens', description: 'Tokens for automation such as the release workflow.', icon: 'key', admin: true },
  { path: '/admin/settings', label: 'Site Settings', description: 'Registration, announcements and integration checks.', icon: 'sliders', admin: true },
  { path: '/admin/stats', label: 'Stats', description: 'Growth, activity and storage on this relay.', icon: 'bar-chart', admin: true },
];

/** Pages below a navigation entry; they render their own heading. */
const detailRoutes: RouteMeta[] = [
  { path: '/admin/users/:id', label: 'User', description: 'Account details and actions.', icon: 'user', admin: true, hideTitle: true },
];

function matchesPattern(pattern: string, location: string): boolean {
  const want = pattern.split('/');
  const have = location.split('/');
  return want.length === have.length && want.every((part, i) => (part.startsWith(':') ? have[i] !== '' : part === have[i]));
}

export function routeFor(location: string): RouteMeta | undefined {
  return appRoutes.find((r) => r.path === location) ?? detailRoutes.find((r) => matchesPattern(r.path, location));
}

export function isRouteActive(path: string, location: string): boolean {
  if (path === '/') return location === '/';
  return location === path || location.startsWith(`${path}/`);
}
