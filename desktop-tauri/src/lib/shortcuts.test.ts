import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { acceleratorKeys, acceleratorText, heldModifierKeys, recordShortcut, shortcutProblem, type KeyPress } from './shortcuts';

/** A key press, with no modifiers held unless given. */
function press(code: string, key: string, held: Partial<KeyPress> = {}): KeyPress {
	return { code, key, ctrlKey: false, altKey: false, shiftKey: false, metaKey: false, ...held };
}

// The Super key's name depends on the system (Win or Super)
beforeEach(() => vi.stubGlobal('navigator', { platform: 'Linux x86_64', userAgent: '' }));
afterEach(() => vi.unstubAllGlobals());

describe('acceleratorKeys and acceleratorText', () => {
	it('list modifiers in the order each platform reads them', () => {
		expect(acceleratorKeys('CmdOrCtrl+Shift+Space', true)).toEqual(['shift', 'mod', 'Space']);
		expect(acceleratorKeys('CmdOrCtrl+Shift+Space', false)).toEqual(['mod', 'shift', 'Space']);
		expect(acceleratorKeys('CmdOrCtrl+Control+Alt+Shift+K', true)).toEqual(['ctrl', 'alt', 'shift', 'mod', 'K']);
		expect(acceleratorKeys('CmdOrCtrl+Alt+Shift+Super+K', false)).toEqual(['super', 'mod', 'alt', 'shift', 'K']);
	});

	it('spell keys the way keyboards print them', () => {
		expect(acceleratorKeys('Alt+ArrowUp', false)).toEqual(['alt', '↑']);
		expect(acceleratorKeys('CmdOrCtrl+Comma', false)).toEqual(['mod', ',']);
		expect(acceleratorKeys('Alt+Numpad5', false)).toEqual(['alt', 'Num 5']);
		expect(acceleratorKeys('Alt+Enter', true)).toEqual(['alt', '↩']);
		expect(acceleratorKeys('Alt+Enter', false)).toEqual(['alt', 'Enter']);
		expect(acceleratorKeys('F9', false)).toEqual(['F9']);
		expect(acceleratorKeys('', false)).toEqual([]);
	});

	it('write shortcuts out for messages', () => {
		expect(acceleratorText('CmdOrCtrl+Shift+Space', true)).toBe('⇧⌘Space');
		expect(acceleratorText('CmdOrCtrl+Shift+Space', false)).toBe('Ctrl+Shift+Space');
		expect(acceleratorText('Control+Alt+V', true)).toBe('⌃⌥V');
		expect(acceleratorText('Alt+Super+V', false)).toBe('Super+Alt+V');
		vi.stubGlobal('navigator', { platform: 'Win32', userAgent: '' });
		expect(acceleratorText('Alt+Super+V', false)).toBe('Win+Alt+V');
	});
});

describe('recordShortcut', () => {
	it('waits while only modifiers are held', () => {
		expect(recordShortcut(press('ControlLeft', 'Control', { ctrlKey: true }), false)).toEqual({ kind: 'pending', keys: ['mod'] });
		expect(recordShortcut(press('MetaRight', 'Meta', { metaKey: true, shiftKey: true }), true)).toEqual({
			kind: 'pending',
			keys: ['shift', 'mod'],
		});
	});

	it('records ⌘ on a Mac and Ctrl elsewhere as the primary modifier', () => {
		expect(recordShortcut(press('Space', ' ', { ctrlKey: true, shiftKey: true }), false)).toEqual({
			kind: 'shortcut',
			accelerator: 'CmdOrCtrl+Shift+Space',
		});
		expect(recordShortcut(press('Space', ' ', { metaKey: true, shiftKey: true }), true)).toEqual({
			kind: 'shortcut',
			accelerator: 'CmdOrCtrl+Shift+Space',
		});
		// ⌃ on a Mac, the Super key elsewhere
		expect(recordShortcut(press('KeyK', 'k', { ctrlKey: true, altKey: true }), true)).toEqual({
			kind: 'shortcut',
			accelerator: 'Control+Alt+K',
		});
		expect(recordShortcut(press('KeyK', 'k', { metaKey: true, altKey: true }), false)).toEqual({
			kind: 'shortcut',
			accelerator: 'Alt+Super+K',
		});
	});

	it('takes letters from the layout on Windows and Linux, and from the key’s position on a Mac', () => {
		// On AZERTY the key printed A is where QWERTY has Q
		expect(recordShortcut(press('KeyQ', 'a', { ctrlKey: true, altKey: true }), false)).toEqual({
			kind: 'shortcut',
			accelerator: 'CmdOrCtrl+Alt+A',
		});
		expect(recordShortcut(press('KeyQ', 'a', { metaKey: true, altKey: true }), true)).toEqual({
			kind: 'shortcut',
			accelerator: 'CmdOrCtrl+Alt+Q',
		});
		// Option types other characters on a Mac; non-Latin layouts print other letters
		expect(recordShortcut(press('KeyV', '√', { metaKey: true, altKey: true }), true)).toEqual({
			kind: 'shortcut',
			accelerator: 'CmdOrCtrl+Alt+V',
		});
		expect(recordShortcut(press('KeyV', 'ر', { ctrlKey: true, altKey: true }), false)).toEqual({
			kind: 'shortcut',
			accelerator: 'CmdOrCtrl+Alt+V',
		});
	});

	it('reads digits, punctuation and other keys by position', () => {
		// Shift turns 1 into ! on a US layout
		expect(recordShortcut(press('Digit1', '!', { ctrlKey: true, shiftKey: true }), false)).toEqual({
			kind: 'shortcut',
			accelerator: 'CmdOrCtrl+Shift+1',
		});
		expect(recordShortcut(press('Period', '>', { altKey: true, shiftKey: true }), false)).toEqual({
			kind: 'shortcut',
			accelerator: 'Alt+Shift+Period',
		});
		expect(recordShortcut(press('ArrowUp', 'ArrowUp', { ctrlKey: true, altKey: true }), false)).toEqual({
			kind: 'shortcut',
			accelerator: 'CmdOrCtrl+Alt+ArrowUp',
		});
		expect(recordShortcut(press('Numpad7', '7', { ctrlKey: true, altKey: true }), false)).toEqual({
			kind: 'shortcut',
			accelerator: 'CmdOrCtrl+Alt+Numpad7',
		});
	});

	it('allows function keys on their own', () => {
		expect(recordShortcut(press('F9', 'F9'), false)).toEqual({ kind: 'shortcut', accelerator: 'F9' });
		expect(recordShortcut(press('F13', 'F13', { shiftKey: true }), true)).toEqual({ kind: 'shortcut', accelerator: 'Shift+F13' });
	});

	it('refuses combinations that would get in the way of typing', () => {
		expect(recordShortcut(press('KeyV', 'V', { shiftKey: true }), false)).toEqual({
			kind: 'invalid',
			keys: ['shift', 'V'],
			reason: 'Include Ctrl or Alt so the shortcut doesn’t get in the way of typing.',
		});
		expect(recordShortcut(press('Space', ' '), true)).toMatchObject({
			kind: 'invalid',
			reason: expect.stringContaining('⌘, ⌥ or ⌃'),
		});
	});

	it('refuses keys that can’t be part of a shortcut', () => {
		expect(recordShortcut(press('CapsLock', 'CapsLock', { ctrlKey: true }), false)).toMatchObject({ kind: 'invalid', keys: ['mod'] });
		expect(recordShortcut(press('IntlBackslash', '<', { ctrlKey: true }), false)).toMatchObject({ kind: 'invalid' });
	});

	it('refuses AltGr, which types characters', () => {
		const event = press('KeyQ', '@', { ctrlKey: true, altKey: true, getModifierState: (key) => key === 'AltGraph' });
		expect(recordShortcut(event, false)).toMatchObject({ kind: 'invalid', reason: expect.stringContaining('AltGr') });
	});

	it('refuses shortcuts that other apps or cpmesh itself rely on', () => {
		expect(recordShortcut(press('KeyV', 'v', { ctrlKey: true }), false)).toMatchObject({
			kind: 'invalid',
			keys: ['mod', 'V'],
			reason: 'Other apps rely on Ctrl+V. Choose a combination they don’t use.',
		});
		expect(recordShortcut(press('KeyF', 'f', { metaKey: true }), true)).toMatchObject({
			kind: 'invalid',
			reason: 'cpmesh already uses ⌘F in its window. Choose another combination.',
		});
		expect(recordShortcut(press('Tab', 'Tab', { altKey: true }), false)).toMatchObject({ kind: 'invalid' });
		expect(recordShortcut(press('Digit2', '2', { ctrlKey: true }), false)).toMatchObject({ kind: 'invalid' });
		// Another modifier makes them fine
		expect(recordShortcut(press('KeyV', 'V', { ctrlKey: true, shiftKey: true }), false)).toEqual({
			kind: 'shortcut',
			accelerator: 'CmdOrCtrl+Shift+V',
		});
	});
});

describe('shortcutProblem', () => {
	it('accepts the default shortcut on every platform', () => {
		expect(shortcutProblem('CmdOrCtrl+Shift+Space', true)).toBeNull();
		expect(shortcutProblem('CmdOrCtrl+Shift+Space', false)).toBeNull();
	});

	it('needs a key', () => {
		expect(shortcutProblem('', false)).toBe('Press one or more modifier keys and then one other key.');
	});
});

describe('heldModifierKeys', () => {
	it('lists the held modifiers in reading order', () => {
		const event = press('KeyA', 'a', { ctrlKey: true, altKey: true, shiftKey: true, metaKey: true });
		expect(heldModifierKeys(event, true)).toEqual(['ctrl', 'alt', 'shift', 'mod']);
		expect(heldModifierKeys(event, false)).toEqual(['super', 'mod', 'alt', 'shift']);
	});
});
