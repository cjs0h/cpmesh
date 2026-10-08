<script lang="ts">
  import Icon from '../Icon.svelte';

  /**
   * Looping "copy → encrypt → relay → decrypt" scene used on the landing and
   * login pages. Pure CSS transitions driven by a small timed state machine;
   * with `prefers-reduced-motion` it renders a single static frame.
   */
  let { compact = false, class: className = '' }: { compact?: boolean; class?: string } = $props();

  type Phase = 'appear' | 'encrypt' | 'toRelay' | 'fanOut' | 'decrypt' | 'fade';

  interface Device {
    id: string;
    name: string;
    icon: string;
    x: number;
    y: number;
    tone: string;
  }

  interface Payload {
    kind: 'text' | 'link' | 'image' | 'file' | 'code';
    icon: string;
    text: string;
    meta: string;
  }

  const devices: Device[] = [
    { id: 'laptop', name: 'MacBook Pro', icon: 'laptop', x: 21, y: 52, tone: '#49c6e5' },
    { id: 'phone', name: 'Pixel 9', icon: 'smartphone', x: 80, y: 24, tone: '#2ad6a0' },
    { id: 'desktop', name: 'Work PC', icon: 'monitor', x: 80, y: 78, tone: '#f4c95d' },
  ];
  const relay = { x: 50, y: 51 };

  const payloads: Payload[] = [
    { kind: 'text', icon: 'type', text: 'Meeting moved to 3pm — bring the Q3 deck', meta: '41 B · text' },
    { kind: 'link', icon: 'link', text: 'https://github.com/cjs0h/cpmesh', meta: '31 B · url' },
    { kind: 'image', icon: 'image', text: 'screenshot-2026-10-08.png', meta: '1.2 MB · image/png' },
    { kind: 'code', icon: 'terminal', text: 'docker compose up -d', meta: '20 B · text' },
    { kind: 'file', icon: 'file', text: 'invoice-0423.pdf', meta: '384 KB · application/pdf' },
  ];

  // Timeline in milliseconds, relative to the start of a cycle.
  const timeline: Array<[Phase, number]> = [
    ['appear', 0],
    ['encrypt', 1000],
    ['toRelay', 1750],
    ['fanOut', 2650],
    ['decrypt', 3550],
    ['fade', 5300],
  ];
  const CYCLE = 5900;

  let phase = $state<Phase>('appear');
  let cycle = $state(0);

  const sourceIdx = $derived(cycle % devices.length);
  const source = $derived(devices[sourceIdx]);
  const targets = $derived(devices.filter((_, i) => i !== sourceIdx));
  const payload = $derived(payloads[cycle % payloads.length]);

  const encrypted = $derived(phase === 'encrypt' || phase === 'toRelay' || phase === 'fanOut');
  const delivered = $derived(phase === 'decrypt' || phase === 'fade');
  const mainVisible = $derived(phase === 'appear' || phase === 'encrypt' || phase === 'toRelay');
  const mainPos = $derived(phase === 'toRelay' ? relay : { x: source.x, y: source.y });
  const targetsOut = $derived(phase === 'fanOut' || delivered);
  const targetsVisible = $derived(phase === 'fanOut' || phase === 'decrypt');

  // Deterministic pseudo-ciphertext so the scramble looks different each cycle.
  const cipher = $derived.by(() => {
    let seed = (Math.imul(cycle + 1, 0x9e3779b1) ^ 0x5bd1e995) >>> 0;
    const hex = '0123456789abcdef';
    let out = '';
    for (let i = 0; i < 22; i++) {
      seed = (Math.imul(seed, 1103515245) + 12345) >>> 0;
      out += hex[(seed >>> 16) & 15];
      if (i % 4 === 3) out += ' ';
    }
    return out.trim();
  });

  const nonce = $derived(cipher.replace(/\s/g, '').slice(0, 8));

  interface LogLine {
    t: string;
    who: string;
    tone: string;
    msg: string;
  }

  function stamp(offset: number): string {
    const d = new Date(Date.now() + offset);
    return d.toTimeString().slice(0, 8);
  }

  const log = $derived.by<LogLine[]>(() => {
    const lines: LogLine[] = [];
    const push = (who: string, tone: string, msg: string) => lines.push({ t: stamp(0), who, tone, msg });
    push(source.id, source.tone, `copied ${payload.kind} (${payload.meta.split(' · ')[0]})`);
    if (phase !== 'appear') push('crypto', '#ff7a59', `AES-256-GCM · nonce ${nonce}`);
    if (phase === 'toRelay' || phase === 'fanOut' || delivered) push('relay', '#9db0c7', 'forwarded ciphertext → 2 devices');
    if (delivered) for (const t of targets) push(t.id, t.tone, 'decrypted ✓ pasted');
    return lines.slice(-4);
  });

  $effect(() => {
    const mq = typeof matchMedia === 'function' ? matchMedia('(prefers-reduced-motion: reduce)') : null;

    let timers: ReturnType<typeof setTimeout>[] = [];
    let loop: ReturnType<typeof setTimeout> | null = null;

    const stop = () => {
      timers.forEach(clearTimeout);
      timers = [];
      if (loop) clearTimeout(loop);
      loop = null;
    };

    const run = () => {
      stop();
      timers = timeline.map(([p, at]) => setTimeout(() => (phase = p), at));
      loop = setTimeout(() => {
        cycle += 1;
        run();
      }, CYCLE);
    };

    // Reduced motion: hold the final "delivered" frame instead of cycling.
    const apply = (reduced: boolean) => {
      if (reduced) {
        stop();
        phase = 'decrypt';
      } else {
        run();
      }
    };

    apply(mq?.matches ?? false);
    const onChange = (e: MediaQueryListEvent) => apply(e.matches);
    mq?.addEventListener('change', onChange);

    return () => {
      stop();
      mq?.removeEventListener('change', onChange);
    };
  });

  function lineActive(d: Device): boolean {
    if (d.id === source.id) return phase === 'toRelay';
    return phase === 'fanOut';
  }
</script>

<div class="relative select-none {className}" aria-hidden="true">
  <!-- Scene -->
  <div class="glass dot-grid relative aspect-[4/3] w-full overflow-hidden rounded-2xl shadow-pop">
    <div class="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_50%_50%,rgba(255,122,89,0.12),transparent_55%)]"></div>

    <!-- Connections -->
    <svg class="absolute inset-0 h-full w-full" viewBox="0 0 100 100" preserveAspectRatio="none">
      {#each devices as d (d.id)}
        <line
          x1={d.x}
          y1={d.y}
          x2={relay.x}
          y2={relay.y}
          vector-effect="non-scaling-stroke"
          class="transition-[stroke] duration-500 {lineActive(d) ? 'sync-line-active' : ''}"
          stroke={lineActive(d) ? d.tone : 'rgba(158,178,201,0.18)'}
          stroke-width="1.5"
          stroke-dasharray={lineActive(d) ? '4 6' : '2 5'}
          stroke-linecap="round"
        />
      {/each}
    </svg>

    <!-- Relay -->
    <div class="absolute -translate-x-1/2 -translate-y-1/2" style="left: {relay.x}%; top: {relay.y}%;">
      <div class="relative flex items-center justify-center" style="width: {compact ? 56 : 68}px; height: {compact ? 56 : 68}px;">
        <span
          class="absolute inset-0 rounded-full border border-accent/40 {phase === 'toRelay' || phase === 'fanOut' ? 'animate-[ping-ring_1.2s_var(--ease-out-expo)_infinite]' : 'opacity-0'}"
        ></span>
        <span
          class="absolute inset-0 rounded-full border transition-[box-shadow,border-color,background-color] duration-500 {phase === 'fanOut' || phase === 'toRelay'
            ? 'border-accent/60 bg-accent/15 shadow-[0_0_40px_rgba(255,122,89,0.45)]'
            : 'border-border-strong bg-surface-2/90 shadow-[0_0_24px_rgba(255,122,89,0.12)]'}"
        ></span>
        <span class="relative text-accent"><Icon name="lock" size={compact ? 20 : 24} /></span>
      </div>
      <div class="mt-2 text-center font-mono text-[10px] uppercase tracking-[0.18em] text-dim">relay</div>
      <div class="text-center font-mono text-[10px] text-dim/70">sees only ciphertext</div>
    </div>

    <!-- Devices -->
    {#each devices as d (d.id)}
      {@const isSource = d.id === source.id}
      {@const highlight = (isSource && (phase === 'appear' || phase === 'encrypt')) || (!isSource && delivered)}
      <div
        class="absolute -translate-x-1/2 -translate-y-1/2 rounded-xl border bg-surface/95 text-center transition-[border-color,box-shadow,transform] duration-500 {compact
          ? 'w-[88px] px-2 py-2'
          : 'w-[112px] px-3 py-3'}"
        style="left: {d.x}%; top: {d.y}%; border-color: {highlight ? d.tone : 'rgba(158,178,201,0.18)'}; box-shadow: {highlight
          ? `0 0 0 1px ${d.tone}33, 0 0 32px ${d.tone}33`
          : '0 10px 30px -12px rgba(0,0,0,0.6)'};"
      >
        <div class="mb-1 flex justify-center" style="color: {d.tone};"><Icon name={d.icon} size={compact ? 18 : 22} /></div>
        <div class="truncate text-[11px] font-semibold text-fg">{d.name}</div>
        <div class="mt-1 flex items-center justify-center gap-1 text-[10px] text-dim">
          <span class="status-dot" style="color: {d.tone};" data-live={highlight}></span>
          {#if isSource && !delivered}
            copied
          {:else if !isSource && delivered}
            <span class="text-mint">pasted</span>
          {:else}
            online
          {/if}
        </div>
      </div>
    {/each}

    <!-- Main payload chip: source → relay -->
    <div
      class="sync-chip absolute -translate-x-1/2 -translate-y-1/2 {mainVisible ? 'opacity-100 scale-100' : 'opacity-0 scale-90'}"
      style="left: {mainPos.x}%; top: {mainPos.y + (phase === 'toRelay' ? 0 : compact ? -16 : -15)}%;"
    >
      {@render chip(encrypted ? 'cipher' : 'plain')}
    </div>

    <!-- Fan-out chips: relay → targets -->
    {#each targets as t (t.id)}
      <div
        class="sync-chip absolute -translate-x-1/2 -translate-y-1/2 {targetsVisible ? 'opacity-100 scale-100' : 'opacity-0 scale-90'}"
        style="left: {targetsOut ? t.x : relay.x}%; top: {targetsOut ? t.y + (compact ? 15 : 14) : relay.y}%;"
      >
        {@render chip(delivered ? 'decrypted' : 'cipher')}
      </div>
    {/each}

    <!-- Corner labels -->
    <div class="absolute left-3 top-3 flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-dim">
      <span class="status-dot text-mint" data-live="true"></span>
      live sync
    </div>
    <div class="absolute right-3 top-3 font-mono text-[10px] uppercase tracking-[0.16em] text-dim">e2e · aes-256-gcm</div>
  </div>

  <!-- Event log -->
  {#if !compact}
    <div class="glass mt-3 rounded-xl px-4 py-3 font-mono text-[11px] leading-5">
      {#each log as line, i (i)}
        <div class="flex gap-3 text-muted animate-[fade-in_0.3s_ease-out]">
          <span class="shrink-0 text-dim">{line.t}</span>
          <span class="w-14 shrink-0 font-semibold" style="color: {line.tone};">{line.who}</span>
          <span class="min-w-0 truncate">{line.msg}</span>
        </div>
      {/each}
    </div>
  {/if}
</div>

{#snippet chip(mode: 'plain' | 'cipher' | 'decrypted')}
  <div
    class="flex items-center gap-2 rounded-lg border px-2.5 py-1.5 shadow-pop backdrop-blur-md transition-[border-color,background-color,color] duration-400 {compact
      ? 'max-w-[136px]'
      : 'max-w-[184px]'} {mode === 'cipher'
      ? 'border-accent/50 bg-[rgba(40,16,10,0.92)] text-accent'
      : mode === 'decrypted'
        ? 'border-mint/50 bg-[rgba(8,40,30,0.92)] text-fg'
        : 'border-cyan/40 bg-surface-2/95 text-fg'}"
  >
    <span class="shrink-0 {mode === 'cipher' ? 'text-accent' : mode === 'decrypted' ? 'text-mint' : 'text-cyan'}">
      <Icon name={mode === 'cipher' ? 'lock' : mode === 'decrypted' ? 'check' : payload.icon} size={13} />
    </span>
    <span class="truncate {mode === 'cipher' ? 'font-mono text-[10.5px] tracking-wide' : 'text-[11.5px] font-medium'}">
      {mode === 'cipher' ? cipher : payload.text}
    </span>
  </div>
{/snippet}

<style>
  .sync-chip {
    transition:
      left 0.85s var(--ease-out-expo),
      top 0.85s var(--ease-out-expo),
      opacity 0.4s ease,
      transform 0.4s var(--ease-spring);
    z-index: 5;
  }
  .sync-line-active {
    animation: dash-flow 0.5s linear infinite;
  }
</style>
