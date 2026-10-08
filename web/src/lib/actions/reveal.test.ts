import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { resetRevealObserver, reveal } from './reveal';

type IOCallback = (entries: Array<Partial<IntersectionObserverEntry>>) => void;

class FakeIntersectionObserver {
  static instances: FakeIntersectionObserver[] = [];
  observed = new Set<Element>();
  callback: IOCallback;
  options: IntersectionObserverInit | undefined;
  observe = vi.fn((el: Element) => this.observed.add(el));
  unobserve = vi.fn((el: Element) => this.observed.delete(el));
  disconnect = vi.fn();

  constructor(callback: IOCallback, options?: IntersectionObserverInit) {
    this.callback = callback;
    this.options = options;
    FakeIntersectionObserver.instances.push(this);
  }

  intersect(el: Element) {
    this.callback([{ isIntersecting: true, target: el }]);
  }
}

function makeNode(): HTMLElement {
  const dataset: Record<string, string> = {};
  const styles = new Map<string, string>();
  return {
    dataset,
    style: {
      setProperty: (k: string, v: string) => styles.set(k, v),
      getPropertyValue: (k: string) => styles.get(k) ?? '',
    },
  } as unknown as HTMLElement;
}

describe('reveal action', () => {
  beforeEach(() => {
    FakeIntersectionObserver.instances = [];
    resetRevealObserver();
    vi.stubGlobal('IntersectionObserver', FakeIntersectionObserver);
  });

  afterEach(() => {
    resetRevealObserver();
  });

  it('hides the node until it intersects, then marks it revealed once', () => {
    const node = makeNode();
    const onreveal = vi.fn();
    reveal(node, { delay: 120, onreveal });

    expect(node.dataset.reveal).toBe('out');
    expect(node.style.getPropertyValue('--reveal-delay')).toBe('120ms');
    expect(onreveal).not.toHaveBeenCalled();

    const io = FakeIntersectionObserver.instances[0];
    expect(io.observe).toHaveBeenCalledWith(node);

    io.intersect(node);
    expect(node.dataset.reveal).toBe('in');
    expect(onreveal).toHaveBeenCalledTimes(1);
    expect(io.unobserve).toHaveBeenCalledWith(node);
  });

  it('shares one observer across many nodes', () => {
    const a = makeNode();
    const b = makeNode();
    reveal(a);
    reveal(b);
    expect(FakeIntersectionObserver.instances).toHaveLength(1);
    expect(FakeIntersectionObserver.instances[0].observed.size).toBe(2);
  });

  it('stops observing when destroyed', () => {
    const node = makeNode();
    const result = reveal(node) as { destroy(): void };
    result.destroy();
    expect(FakeIntersectionObserver.instances[0].unobserve).toHaveBeenCalledWith(node);
  });

  it('reveals immediately when asked or when IntersectionObserver is missing', () => {
    const a = makeNode();
    reveal(a, { immediate: true });
    expect(a.dataset.reveal).toBe('in');
    expect(FakeIntersectionObserver.instances).toHaveLength(0);

    vi.stubGlobal('IntersectionObserver', undefined);
    const b = makeNode();
    reveal(b);
    expect(b.dataset.reveal).toBe('in');
  });
});
