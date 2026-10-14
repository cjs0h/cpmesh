/**
 * Ticking clock for relative timestamps. Call during component initialisation;
 * the interval is cleaned up with the component.
 */
export function createClock(intervalMs = 30_000) {
  let now = $state(Date.now());

  $effect(() => {
    const id = setInterval(() => (now = Date.now()), intervalMs);
    return () => clearInterval(id);
  });

  return {
    get now() {
      return now;
    },
  };
}
