import { push } from 'svelte-spa-router';

/**
 * Makes a table row open `href` (a `#/...` route) when clicked anywhere. The row keeps
 * a real link in one of its cells for keyboard and screen-reader users; this is the
 * mouse shortcut, so clicks on controls and text selections are left alone.
 */
export function rowLink(node: HTMLElement, href: string) {
  let target = href;

  function onclick(event: MouseEvent) {
    if (event.defaultPrevented || event.button !== 0) return;
    if ((event.target as Element | null)?.closest('a, button, input, select, textarea, label, summary')) return;
    if (window.getSelection()?.toString()) return;
    if (event.metaKey || event.ctrlKey) window.open(target, '_blank', 'noopener');
    else push(target.replace(/^#/, ''));
  }

  node.addEventListener('click', onclick);
  return {
    update(next: string) {
      target = next;
    },
    destroy() {
      node.removeEventListener('click', onclick);
    },
  };
}
