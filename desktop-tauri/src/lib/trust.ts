// How the Devices page marks the account's other devices, and when it offers to share
// the encryption key with one. Which devices keep a new key from every member is
// `resetBlockers` in recovery.svelte.ts.

import type { KeyMember } from './api';

export type BadgeTone = 'neutral' | 'warning' | 'danger';

/** The status worth showing next to another approved device, if any. */
export function trustBadge(member: KeyMember | undefined): { label: string; tone: BadgeTone } | null {
	if (!member) return null;
	if (member.trust === 'key_changed') return { label: 'Identity changed', tone: 'danger' };
	if (member.trust === 'revoked') return { label: 'Removed earlier', tone: 'danger' };
	if (!member.can_receive_keys) return { label: 'Needs an update', tone: 'warning' };
	if (member.has_current_key === false) return { label: 'Needs the key', tone: 'warning' };
	if (member.trust === 'unverified') return { label: 'Not verified', tone: 'neutral' };
	return null;
}

/**
 * Whether this device can offer to share the key with `member`: the relay says the member
 * lacks it, this device doesn't lack it too, and the member can be verified with a pairing
 * code and receive keys.
 */
export function canShareKeyWith(member: KeyMember | undefined, ownLacksKey: boolean): boolean {
	return Boolean(
		member &&
			!ownLacksKey &&
			member.has_current_key === false &&
			member.can_receive_keys &&
			(member.trust === 'verified' || member.trust === 'unverified'),
	);
}
