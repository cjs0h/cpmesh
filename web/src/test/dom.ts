// Helpers for component tests under happy-dom (`// @vitest-environment happy-dom`).

import { flushSync, mount, unmount, type Component } from 'svelte';
import { expect, vi } from 'vitest';

/** Puts `hash` in the address bar and tells the router, as a navigation would. */
export function goTo(hash: string) {
  history.replaceState(null, '', hash);
  window.dispatchEvent(new HashChangeEvent('hashchange'));
}

const mounted: (() => void)[] = [];

/** Mounts `component` into the document; `cleanup()` removes it. */
export function render<Props extends Record<string, unknown>>(component: Component<Props>, props?: Props) {
  const target = document.createElement('div');
  document.body.append(target);
  const instance = mount(component, { target, props: props ?? ({} as Props) });
  flushSync();
  mounted.push(() => {
    void unmount(instance);
    target.remove();
  });
  return target;
}

/** Unmounts everything `render` mounted. */
export function cleanup() {
  while (mounted.length) mounted.pop()!();
  document.body.innerHTML = '';
}

/** Text of the whole page, with whitespace collapsed. */
export function pageText(): string {
  return (document.body.textContent ?? '').replace(/\s+/g, ' ');
}

/** Waits until the page shows `text`. */
export async function findText(text: string) {
  await vi.waitFor(() => expect(pageText()).toContain(text), { timeout: 2000 });
}

/** The button (or link) whose text is `name`. */
export function button(name: string): HTMLButtonElement {
  const found = [...document.querySelectorAll<HTMLButtonElement>('button, a')].find((el) => el.textContent?.trim() === name);
  if (!found) throw new Error(`no button "${name}" in: ${pageText()}`);
  return found;
}

/** Waits until the button named `name` can be clicked, then clicks it. */
export async function click(name: string) {
  await vi.waitFor(() => expect(button(name).disabled).toBe(false), { timeout: 2000 });
  button(name).click();
  flushSync();
}

/** The checkbox labelled `label` (its label starts with it). */
export function checkbox(label: string): HTMLInputElement {
  const match = [...document.querySelectorAll('label')].find((el) => el.textContent?.trim().startsWith(label));
  const input = match?.querySelector<HTMLInputElement>('input[type="checkbox"]') ?? null;
  if (!input) throw new Error(`no checkbox "${label}"`);
  return input;
}

/** Flips the switch labelled `label`, as a click would. */
export function toggle(label: string) {
  checkbox(label).click();
  flushSync();
}

/** The labels of the page's checkboxes, and whether each is checked. */
export function checkboxes(): [string, boolean][] {
  return [...document.querySelectorAll<HTMLInputElement>('input[type="checkbox"]')].map((input) => [
    input.closest('label')?.querySelector('span.font-medium')?.textContent?.trim() ?? '',
    input.checked,
  ]);
}

/** Types `value` into `input`, as the user would. */
export function type(input: HTMLInputElement, value: string) {
  input.value = value;
  input.dispatchEvent(new Event('input', { bubbles: true }));
  flushSync();
}
