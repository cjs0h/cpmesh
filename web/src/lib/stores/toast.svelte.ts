export type ToastKind = 'success' | 'error' | 'info' | 'warning';

export interface Toast {
  id: number;
  kind: ToastKind;
  title: string;
  description?: string;
  /** Milliseconds before auto-dismiss; 0 keeps the toast until closed. */
  duration: number;
}

export const toastState: { items: Toast[] } = $state({ items: [] });

const DEFAULT_DURATION = 4200;
const MAX_VISIBLE = 4;
let nextId = 1;
const timers = new Map<number, ReturnType<typeof setTimeout>>();

export function dismissToast(id: number) {
  const timer = timers.get(id);
  if (timer) {
    clearTimeout(timer);
    timers.delete(id);
  }
  toastState.items = toastState.items.filter((t) => t.id !== id);
}

export function clearToasts() {
  for (const id of [...timers.keys()]) dismissToast(id);
  toastState.items = [];
}

function push(kind: ToastKind, title: string, description?: string, duration = DEFAULT_DURATION): number {
  const id = nextId++;
  toastState.items = [...toastState.items, { id, kind, title, description, duration }].slice(-MAX_VISIBLE);
  if (duration > 0) {
    timers.set(
      id,
      setTimeout(() => dismissToast(id), duration)
    );
  }
  return id;
}

export const toast = {
  success: (title: string, description?: string, duration?: number) => push('success', title, description, duration),
  error: (title: string, description?: string, duration?: number) => push('error', title, description, duration ?? 6000),
  info: (title: string, description?: string, duration?: number) => push('info', title, description, duration),
  warning: (title: string, description?: string, duration?: number) => push('warning', title, description, duration),
};
