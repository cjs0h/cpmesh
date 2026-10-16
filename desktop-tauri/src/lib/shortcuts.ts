// The global shortcut that shows cpmesh, as the accelerators the backend saves
// ("CmdOrCtrl+Shift+Space"): recording one from a key press, checking it, and spelling it
// for the current platform. `mac` is a parameter so both spellings can be tested.

import { isMacLike, shortcutKeys } from './ui.js';

/** Modifiers in the order an accelerator lists them, as the backend saves them. */
const MODIFIERS = ['CmdOrCtrl', 'Control', 'Alt', 'Shift', 'Super'] as const;
type Modifier = (typeof MODIFIERS)[number];

/** `Kbd` key for each modifier: CmdOrCtrl is ⌘ or Ctrl, Control is ⌃ (macOS only). */
const MODIFIER_KEYS: Record<Modifier, string> = {
	CmdOrCtrl: 'mod',
	Control: 'ctrl',
	Alt: 'alt',
	Shift: 'shift',
	Super: 'super',
};

/** The order people read modifiers in: ⌃⌥⇧⌘ on macOS; Super, Ctrl, Alt, Shift elsewhere. */
const MAC_ORDER: Modifier[] = ['Control', 'Alt', 'Shift', 'CmdOrCtrl', 'Super'];
const OTHER_ORDER: Modifier[] = ['Super', 'CmdOrCtrl', 'Control', 'Alt', 'Shift'];

/** `KeyboardEvent.key` values of keys that only modify others. */
const MODIFIER_NAMES = new Set(['Shift', 'Control', 'Alt', 'AltGraph', 'Meta', 'OS', 'Super', 'Hyper', 'Fn', 'FnLock', 'Symbol', 'SymbolLock']);

/** Keys besides letters, digits, F1–F24 and the numpad digits, by `KeyboardEvent.code`. */
const NAMED_KEYS = new Set([
	'Space',
	'Enter',
	'Tab',
	'Backspace',
	'Delete',
	'Insert',
	'Home',
	'End',
	'PageUp',
	'PageDown',
	'ArrowUp',
	'ArrowDown',
	'ArrowLeft',
	'ArrowRight',
	'Escape',
	'Backquote',
	'Minus',
	'Equal',
	'BracketLeft',
	'BracketRight',
	'Backslash',
	'Semicolon',
	'Quote',
	'Comma',
	'Period',
	'Slash',
	'NumpadAdd',
	'NumpadSubtract',
	'NumpadMultiply',
	'NumpadDivide',
	'NumpadDecimal',
	'NumpadEnter',
	'PrintScreen',
	'ScrollLock',
	'Pause',
]);

const KEY_LABELS: Record<string, string> = {
	ArrowUp: '↑',
	ArrowDown: '↓',
	ArrowLeft: '←',
	ArrowRight: '→',
	Escape: 'Esc',
	PageUp: 'Page Up',
	PageDown: 'Page Down',
	PrintScreen: 'Print Screen',
	ScrollLock: 'Scroll Lock',
	Backquote: '`',
	Minus: '-',
	Equal: '=',
	BracketLeft: '[',
	BracketRight: ']',
	Backslash: '\\',
	Semicolon: ';',
	Quote: "'",
	Comma: ',',
	Period: '.',
	Slash: '/',
	NumpadAdd: 'Num +',
	NumpadSubtract: 'Num -',
	NumpadMultiply: 'Num *',
	NumpadDivide: 'Num /',
	NumpadDecimal: 'Num .',
	NumpadEnter: 'Num Enter',
};

/** What Mac keyboards and menus show for these keys. */
const MAC_KEY_LABELS: Record<string, string> = { Enter: '↩', Backspace: '⌫', Delete: '⌦', Tab: '⇥' };

/** Shortcuts other apps rely on; a global shortcut would take them away from those apps. */
const COMMON_SHORTCUTS = new Set([
	'CmdOrCtrl+A',
	'CmdOrCtrl+C',
	'CmdOrCtrl+V',
	'CmdOrCtrl+X',
	'CmdOrCtrl+Z',
	'CmdOrCtrl+Shift+Z',
	'CmdOrCtrl+Y',
	'CmdOrCtrl+Q',
	'CmdOrCtrl+W',
	'CmdOrCtrl+Tab',
	'CmdOrCtrl+Shift+Tab',
	'Alt+Tab',
	'Alt+Shift+Tab',
	'Alt+F4',
]);

/** cpmesh's own shortcuts in its window, which a global shortcut would swallow. */
const APP_SHORTCUTS = new Set(['CmdOrCtrl+1', 'CmdOrCtrl+2', 'CmdOrCtrl+3', 'CmdOrCtrl+4', 'CmdOrCtrl+Comma', 'CmdOrCtrl+F']);

/** The parts of a `KeyboardEvent` that recording reads. */
export interface KeyPress {
	key: string;
	code: string;
	ctrlKey: boolean;
	altKey: boolean;
	shiftKey: boolean;
	metaKey: boolean;
	getModifierState?(key: string): boolean;
}

export type Recording =
	/** Only modifiers so far; `keys` shows them while the rest is typed. */
	| { kind: 'pending'; keys: string[] }
	/** A combination that can't be used, and why. */
	| { kind: 'invalid'; keys: string[]; reason: string }
	| { kind: 'shortcut'; accelerator: string };

function parse(accelerator: string): { modifiers: Modifier[]; key: string } | null {
	const parts = accelerator.split('+');
	const key = parts.pop();
	if (!key) return null;
	return { modifiers: parts.filter((part): part is Modifier => (MODIFIERS as readonly string[]).includes(part)), key };
}

function isFunctionKey(key: string): boolean {
	return /^F([1-9]|1\d|2[0-4])$/.test(key);
}

function keyLabel(key: string, mac: boolean): string {
	if (mac && key in MAC_KEY_LABELS) return MAC_KEY_LABELS[key];
	if (key in KEY_LABELS) return KEY_LABELS[key];
	const numpad = /^Numpad(\d)$/.exec(key);
	return numpad ? `Num ${numpad[1]}` : key;
}

function modifierKeys(modifiers: Modifier[], mac: boolean): string[] {
	return (mac ? MAC_ORDER : OTHER_ORDER).filter((modifier) => modifiers.includes(modifier)).map((modifier) => MODIFIER_KEYS[modifier]);
}

/** `Kbd` keys for an accelerator, in the platform's order: ⇧ ⌘ Space, or Ctrl Shift Space. */
export function acceleratorKeys(accelerator: string, mac = isMacLike()): string[] {
	const parsed = parse(accelerator);
	if (!parsed) return [];
	return [...modifierKeys(parsed.modifiers, mac), keyLabel(parsed.key, mac)];
}

/** An accelerator as text: "⇧⌘Space" on macOS, "Ctrl+Shift+Space" elsewhere. */
export function acceleratorText(accelerator: string, mac = isMacLike()): string {
	return shortcutKeys(acceleratorKeys(accelerator, mac), mac).join(mac ? '' : '+');
}

function heldModifiers(event: KeyPress, mac: boolean): Modifier[] {
	const held: Modifier[] = [];
	if (mac ? event.metaKey : event.ctrlKey) held.push('CmdOrCtrl');
	if (mac && event.ctrlKey) held.push('Control');
	if (event.altKey) held.push('Alt');
	if (event.shiftKey) held.push('Shift');
	if (!mac && event.metaKey) held.push('Super');
	return held;
}

/** `Kbd` keys for the modifiers held during a key press. */
export function heldModifierKeys(event: KeyPress, mac = isMacLike()): string[] {
	return modifierKeys(heldModifiers(event, mac), mac);
}

function keyOf(event: KeyPress, mac: boolean): string | null {
	// Windows and Linux match letters by what the keyboard layout prints on the key, macOS by
	// where the key is
	if (!mac && /^[a-z]$/i.test(event.key)) return event.key.toUpperCase();
	const letter = /^Key([A-Z])$/.exec(event.code);
	if (letter) return letter[1];
	const digit = /^Digit(\d)$/.exec(event.code);
	if (digit) return digit[1];
	if (isFunctionKey(event.code) || /^Numpad\d$/.test(event.code) || NAMED_KEYS.has(event.code)) return event.code;
	return null;
}

/** Why an accelerator can't be the global shortcut, or null when it can. */
export function shortcutProblem(accelerator: string, mac = isMacLike()): string | null {
	const parsed = parse(accelerator);
	if (!parsed) return 'Press one or more modifier keys and then one other key.';
	if (!isFunctionKey(parsed.key) && !parsed.modifiers.some((modifier) => modifier !== 'Shift')) {
		return mac
			? 'Include ⌘, ⌥ or ⌃ so the shortcut doesn’t get in the way of typing.'
			: 'Include Ctrl or Alt so the shortcut doesn’t get in the way of typing.';
	}
	const text = acceleratorText(accelerator, mac);
	if (APP_SHORTCUTS.has(accelerator)) return `cpmesh already uses ${text} in its window. Choose another combination.`;
	if (COMMON_SHORTCUTS.has(accelerator)) return `Other apps rely on ${text}. Choose a combination they don’t use.`;
	return null;
}

/** Turns a key press into a shortcut, or says what's missing or wrong with it. */
export function recordShortcut(event: KeyPress, mac = isMacLike()): Recording {
	const modifiers = heldModifiers(event, mac);
	const held = modifierKeys(modifiers, mac);
	if (MODIFIER_NAMES.has(event.key) || /^(Shift|Control|Alt|Meta|OS)(Left|Right)$/.test(event.code)) {
		return { kind: 'pending', keys: held };
	}
	if (!mac && event.getModifierState?.('AltGraph')) {
		return { kind: 'invalid', keys: held, reason: 'AltGr types characters, so it can’t be part of a shortcut. Use Ctrl or Alt instead.' };
	}
	const key = keyOf(event, mac);
	if (!key) {
		return { kind: 'invalid', keys: held, reason: 'That key can’t be part of a shortcut. Try a letter, a number or a function key.' };
	}
	const accelerator = [...modifiers, key].join('+');
	const reason = shortcutProblem(accelerator, mac);
	return reason ? { kind: 'invalid', keys: acceleratorKeys(accelerator, mac), reason } : { kind: 'shortcut', accelerator };
}
