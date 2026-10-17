import { describe, expect, it } from 'vitest';
import type { KeyMember } from './api';
import { resetBlockers } from './recovery.svelte';
import { canShareKeyWith, trustBadge } from './trust';

function member(id: string, overrides: Partial<KeyMember> = {}): KeyMember {
	const trust = overrides.trust ?? 'verified';
	return { id, name: id.toUpperCase(), verified: trust === 'verified', trust, can_receive_keys: true, has_current_key: true, ...overrides };
}

describe('trustBadge', () => {
	it('shows the most pressing status', () => {
		expect(trustBadge(undefined)).toBeNull();
		expect(trustBadge(member('a'))).toBeNull();
		expect(trustBadge(member('a', { trust: 'key_changed', has_current_key: false }))).toEqual({
			label: 'Identity changed',
			tone: 'danger',
		});
		expect(trustBadge(member('a', { trust: 'revoked' }))?.label).toBe('Removed earlier');
		expect(trustBadge(member('a', { can_receive_keys: false, has_current_key: false }))?.label).toBe('Needs an update');
		expect(trustBadge(member('a', { trust: 'unverified', has_current_key: false }))).toEqual({
			label: 'Needs the key',
			tone: 'warning',
		});
		expect(trustBadge(member('a', { trust: 'unverified' }))).toEqual({ label: 'Not verified', tone: 'neutral' });
		expect(trustBadge(member('a', { has_current_key: null }))).toBeNull();
	});
});

describe('canShareKeyWith', () => {
	it('offers sharing with a member the relay lists without the key', () => {
		expect(canShareKeyWith(member('mac', { trust: 'unverified', has_current_key: false }), false)).toBe(true);
		expect(canShareKeyWith(member('mac', { has_current_key: false }), false)).toBe(true);
	});

	it('does not offer what cannot work', () => {
		const keyless = member('mac', { has_current_key: false });
		expect(canShareKeyWith(member('mac'), false)).toBe(false);
		expect(canShareKeyWith(member('mac', { has_current_key: null }), false), 'older servers do not say').toBe(false);
		expect(canShareKeyWith(keyless, true), 'this device lacks it too').toBe(false);
		expect(canShareKeyWith({ ...keyless, trust: 'key_changed', verified: false }, false)).toBe(false);
		expect(canShareKeyWith({ ...keyless, trust: 'revoked', verified: false }, false)).toBe(false);
		expect(canShareKeyWith({ ...keyless, can_receive_keys: false }, false)).toBe(false);
		expect(canShareKeyWith(undefined, false)).toBe(false);
	});

	it('every device it is offered for also keeps new keys from the mesh until shared or verified', () => {
		const devices = [member('fine'), member('mac', { trust: 'unverified', verified: false, has_current_key: false })];
		expect(resetBlockers(devices).map((d) => d.id)).toEqual(['mac']);
	});
});
