import { describe, expect, it } from 'vitest';
import { appRoutes, isRouteActive, routeFor } from './routes';

describe('routeFor', () => {
  it('finds navigation entries by exact path', () => {
    expect(routeFor('/admin/audit')?.label).toBe('Audit log');
    expect(routeFor('/')?.label).toBe('Overview');
    expect(routeFor('/nope')).toBeUndefined();
  });

  it('finds detail pages by pattern; they draw their own heading', () => {
    const route = routeFor('/admin/users/0b7c9d2e-1a2b-4c3d-8e9f-001122334455');
    expect(route?.admin).toBe(true);
    expect(route?.hideTitle).toBe(true);
    expect(routeFor('/admin/users/')).toBeUndefined();
    expect(routeFor('/admin/users/a/b')).toBeUndefined();
  });

  it('keeps detail pages out of the navigation', () => {
    expect(appRoutes.some((r) => r.path.includes(':'))).toBe(false);
    expect(isRouteActive('/admin/users', '/admin/users/abc')).toBe(true);
  });
});
