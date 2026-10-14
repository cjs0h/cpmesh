<script lang="ts">
  import Icon from '../Icon.svelte';

  /**
   * Looping "copy → encrypt → relay → decrypt" product demo. Positions are
   * resolved to pixels from the scene size and animated with transform /
   * opacity only, so the loop stays smooth. Static final frame under
   * `prefers-reduced-motion`.
   */
  let { compact = false, class: className = '' }: { compact?: boolean; class?: string } = $props();

  type Phase = 'appear' | 'encrypt' | 'toRelay' | 'fanOut' | 'decrypt' | 'fade';

  interface Device {
    id: string;
    name: string;
    icon: string;
    x: number;
    y: number;
    chip: 'above' | 'below';
  }

  interface Payload {
    kind: string;
    icon: string;
    text: string;
    size: string;
  }

  const devices: Device[] = [
    { id: 'laptop', name: 'MacBook Pro', icon: 'laptop', x: 0.2, y: 0.52, chip: 'above' },
    { id: 'phone', name: 'Pixel 9', icon: 'smartphone', x: 0.8, y: 0.22, chip: 'below' },
    { id: 'desktop', name: 'Work PC', icon: 'monitor', x: 0.8, y: 0.82, chip: 'above' },
  ];
  const relay = { x: 0.5, y: 0.52 };

  const payloads: Payload[] = [
    { kind: 'text', icon: 'type', text: 'Meeting moved to 3pm — bring the Q3 deck', size: '41 B' },
    { kind: 'url', icon: 'link', text: 'https://github.com/cjs0h/cpmesh', size: '31 B' },
    { kind: 'image', icon: 'image', text: 'screenshot-2026-10-08.png', size: '1.2 MB' },
    { kind: 'text', icon: 'terminal', text: 'docker compose up -d', size: '20 B' },
    { kind: 'file', icon: 'file', text: 'invoice-0423.pdf', size: '384 KB' },
  ];

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
  let width = $state(0);
  let height = $state(0);

  const sourceIdx = $derived(cycle % devices.length);
  const source = $derived(devices[sourceIdx]);
  const targets = $derived(devices.filter((_, i) => i !== sourceIdx));
  const payload = $derived(payloads[cycle % payloads.length]);

  const encrypted = $derived(phase === 'encrypt' || phase === 'toRelay' || phase === 'fanOut');
  const delivered = $derived(phase === 'decrypt' || phase === 'fade');
  const mainVisible = $derived(phase === 'appear' || phase === 'encrypt' || phase === 'toRelay');
  const targetsOut = $derived(phase === 'fanOut' || delivered);
  const targetsVisible = $derived(phase === 'fanOut' || phase === 'decrypt');

  // Chip anchors sit a fixed pixel distance from the device card so they never
  // collide with it regardless of the stage's aspect ratio.
  const chipOffsetPx = $derived(compact ? 60 : width < 640 ? 64 : 72);
  function pt(p: { x: number; y: number }) {
    return { x: p.x * width, y: p.y * height };
  }
  function chipPoint(d: Device) {
    const base = pt(d);
    return { x: base.x, y: d.chip === 'above' ? base.y - chipOffsetPx : base.y + chipOffsetPx };
  }
  function px(p: { x: number; y: number }) {
    return `translate3d(${Math.round(p.x)}px, ${Math.round(p.y)}px, 0) translate(-50%, -50%)`;
  }

  const mainTransform = $derived(px(phase === 'toRelay' ? pt(relay) : chipPoint(source)));

  // Deterministic pseudo-ciphertext so the scramble differs each cycle.
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
    who: string;
    msg: string;
    accent?: boolean;
  }
  const LOG_ROWS = 4;
  const log = $derived.by<LogLine[]>(() => {
    const lines: LogLine[] = [{ who: source.id, msg: `copied ${payload.kind} · ${payload.size}` }];
    if (phase !== 'appear') lines.push({ who: 'crypto', msg: `AES-256-GCM · nonce ${nonce}` });
    if (phase === 'toRelay' || phase === 'fanOut' || delivered) lines.push({ who: 'relay', msg: 'forwarded ciphertext → 2 devices' });
    if (delivered) for (const t of targets) lines.push({ who: t.id, msg: 'decrypted · pasted', accent: true });
    const visible = lines.slice(-LOG_ROWS);
    while (visible.length < LOG_ROWS) visible.push({ who: '', msg: '' });
    return visible;
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
    const apply = (reduced: boolean) => {
      if (reduced) {
        stop();
        phase = 'decrypt';
      } else run();
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
    return d.id === source.id ? phase === 'toRelay' : phase === 'fanOut';
  }
</script>

<div class="select-none {className}" aria-hidden="true">
  <div class="relative w-full overflow-hidden rounded-lg border border-border bg-surface {compact ? 'aspect-[4/3]' : 'aspect-square sm:aspect-[16/9] lg:aspect-[2/1]'}" bind:clientWidth={width} bind:clientHeight={height}>
    <!-- Faint dot grid -->
    <div class="pointer-events-none absolute inset-0 opacity-70" style="background-image: radial-gradient(#e5e5e5 1px, transparent 1px); background-size: 22px 22px;"></div>

    <!-- Connections -->
    <svg class="absolute inset-0 h-full w-full" viewBox="0 0 100 100" preserveAspectRatio="none">
      {#each devices as d (d.id)}
        <line
          x1={d.x * 100}
          y1={d.y * 100}
          x2={relay.x * 100}
          y2={relay.y * 100}
          vector-effect="non-scaling-stroke"
          stroke={lineActive(d) ? '#0a0a0a' : '#d4d4d4'}
          stroke-width={lineActive(d) ? 1.5 : 1}
          stroke-dasharray={lineActive(d) ? '4 4' : '2 4'}
          stroke-linecap="round"
          class="transition-[stroke] duration-300 {lineActive(d) ? 'animate-[dash-flow_0.6s_linear_infinite]' : ''}"
        />
      {/each}
    </svg>

    <!-- Scene: rendered once the stage has been measured so nothing animates in from (0,0). -->
    {#if width > 0 && height > 0}
      <!-- Relay -->
      <div class="absolute flex flex-col items-center" style="left: 0; top: 0; transform: {px(pt(relay))};">
        <div class="flex items-center justify-center rounded-full bg-ink text-white transition-transform duration-300 {phase === 'toRelay' || phase === 'fanOut' ? 'scale-110' : ''}" style="width: {compact ? 40 : 48}px; height: {compact ? 40 : 48}px;">
          <Icon name="lock" size={compact ? 16 : 18} />
        </div>
        <span class="mt-2 font-mono text-[10px] uppercase tracking-[0.16em] text-dim">relay</span>
      </div>

      <!-- Devices -->
      {#each devices as d (d.id)}
        {@const isSource = d.id === source.id}
        {@const active = (isSource && (phase === 'appear' || phase === 'encrypt')) || (!isSource && delivered)}
        <div
          class="absolute flex flex-col items-center rounded-lg border bg-surface text-center transition-[border-color,box-shadow] duration-300 {compact ? 'w-[84px] px-2 py-2' : 'w-[108px] px-3 py-2.5'} {active ? 'border-ink shadow-sm' : 'border-border'}"
          style="left: 0; top: 0; transform: {px(pt(d))};"
        >
          <span class="text-fg"><Icon name={d.icon} size={compact ? 16 : 18} strokeWidth={1.75} /></span>
          <span class="mt-1.5 truncate text-[11px] font-medium text-fg">{d.name}</span>
          <span class="mt-0.5 flex items-center gap-1 font-mono text-[10px] text-dim">
            <span class="status-dot {!isSource && delivered ? 'text-accent' : active ? 'text-ink' : 'text-border-strong'}" data-live={active}></span>
            {#if isSource && !delivered}copied{:else if !isSource && delivered}pasted{:else}online{/if}
          </span>
        </div>
      {/each}

      <!-- Main payload chip: source → relay -->
      <div class="sync-chip absolute left-0 top-0 {mainVisible ? 'opacity-100' : 'opacity-0'}" style="transform: {mainTransform};">
        {@render chip(encrypted ? 'cipher' : 'plain')}
      </div>

      <!-- Fan-out chips: relay → targets -->
      {#each targets as t (t.id)}
        <div class="sync-chip absolute left-0 top-0 {targetsVisible ? 'opacity-100' : 'opacity-0'}" style="transform: {px(targetsOut ? chipPoint(t) : pt(relay))};">
          {@render chip(delivered ? 'decrypted' : 'cipher')}
        </div>
      {/each}
    {/if}

    <!-- Corner label -->
    <div class="absolute left-3 top-3 inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-2 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] text-muted">
      <span class="status-dot text-accent" data-live="true"></span>
      live
    </div>
    <div class="absolute right-3 top-3 font-mono text-[10px] uppercase tracking-[0.12em] text-dim">AES-256-GCM</div>
  </div>

  {#if !compact}
    <!-- Event log: fixed height so nothing below shifts -->
    <div class="mt-3 h-[6.25rem] overflow-hidden rounded-lg border border-border bg-bg-deep px-4 py-3 font-mono text-[11.5px] leading-5">
      {#each log as line, i (i)}
        <div class="flex h-5 gap-3 {line.msg ? 'animate-[fade-in_0.3s_ease-out]' : 'invisible'}">
          <span class="w-14 shrink-0 text-fg">{line.who}</span>
          <span class="min-w-0 truncate {line.accent ? 'text-accent' : 'text-muted'}">{line.msg}</span>
        </div>
      {/each}
    </div>
  {/if}
</div>

{#snippet chip(mode: 'plain' | 'cipher' | 'decrypted')}
  <div
    class="flex items-center gap-2 rounded-md border px-2.5 py-1.5 shadow-sm transition-[background-color,color,border-color] duration-300 {compact ? 'max-w-[140px]' : 'max-w-[132px] sm:max-w-[190px]'} {mode === 'cipher'
      ? 'border-ink bg-ink text-white'
      : 'border-border bg-surface text-fg'}"
  >
    <span class="shrink-0 {mode === 'decrypted' ? 'text-accent' : ''}">
      <Icon name={mode === 'cipher' ? 'lock' : mode === 'decrypted' ? 'check' : payload.icon} size={12} />
    </span>
    <span class="truncate {mode === 'cipher' ? 'font-mono text-[10.5px] tracking-wide' : 'text-[11.5px]'}">
      {mode === 'cipher' ? cipher : payload.text}
    </span>
  </div>
{/snippet}

<style>
  .sync-chip {
    transition:
      transform 0.85s var(--ease-out-expo),
      opacity 0.35s ease;
    will-change: transform;
    z-index: 5;
  }
</style>
