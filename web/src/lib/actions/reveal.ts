import type { Action } from 'svelte/action';

export interface RevealOptions {
  /** Delay before the element animates in, in milliseconds. */
  delay?: number;
  /** Fraction of the element that must be visible before revealing. */
  threshold?: number;
  /** Reveal immediately instead of waiting for intersection. */
  immediate?: boolean;
  /** Start blurred and sharpen while fading in (MagicUI BlurFade). */
  blur?: boolean;
  /** Called once when the element is revealed. */
  onreveal?: () => void;
}

// A single shared observer keeps hundreds of revealed cards cheap.
let observer: IntersectionObserver | null = null;
const callbacks = new WeakMap<Element, () => void>();

function getObserver(threshold: number): IntersectionObserver {
  if (observer) return observer;
  observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        callbacks.get(entry.target)?.();
        observer?.unobserve(entry.target);
        callbacks.delete(entry.target);
      }
    },
    { threshold, rootMargin: '0px 0px -8% 0px' }
  );
  return observer;
}

/**
 * Scroll-triggered reveal. Pairs with the `[data-reveal]` styles in app.css:
 * the element starts hidden and gets `data-reveal="in"` once it scrolls into
 * view (or immediately when IntersectionObserver is unavailable).
 */
export const reveal: Action<HTMLElement, RevealOptions | undefined> = (node, options = {}) => {
  const { delay = 0, threshold = 0.12, immediate = false, blur = false, onreveal } = options;
  node.dataset.reveal = 'out';
  if (blur) node.dataset.revealBlur = '';
  if (delay) node.style.setProperty('--reveal-delay', `${delay}ms`);

  const show = () => {
    node.dataset.reveal = 'in';
    onreveal?.();
  };

  if (immediate || typeof IntersectionObserver === 'undefined') {
    // Force a style flush so the hidden state is committed before transitioning in.
    void node.offsetWidth;
    show();
    return;
  }

  const io = getObserver(threshold);
  callbacks.set(node, show);
  io.observe(node);

  return {
    destroy() {
      io.unobserve(node);
      callbacks.delete(node);
    },
  };
};

/** Test hook: drop the shared observer so a fresh one is created. */
export function resetRevealObserver() {
  observer?.disconnect();
  observer = null;
}
