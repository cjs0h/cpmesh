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
    /** Which side of the card the payload chip sits on. */
    chip: 'above' | 'below';
  }

  interface Payload {
    kind: 'text' | 'link' | 'image' | 'file' | 'code';
    icon: string;
    text: string;
    meta: string;
  }

  const devices: Device[] = [
    { id: 'laptop', name: 'MacBook Pro', icon: 'laptop', x: 21, y: 52, tone: '#5ad1f0', chip: 'above' },
    { id: 'phone', name: 'Pixel 9', icon: 'smartphone', x: 80, y: 24, tone: '#3ddc97', chip: 'below' },
    { id: 'desktop', name: 'Work PC', icon: 'monitor', x: 80, y: 78, tone: '#ffd93d', chip: 'above' },
  ];
  const relay = { x: 50, y: 51 };

  /** Chip anchor next to a device card, kept clear of the scene edges and corner labels. */
  function chipPos(d: Device) {
    const offset = compact ? 17 : 16;
    return { x: d.x, y: d.chip === 'above' ? d.y - offset : d.y + offset };
  }

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
  const uid = $props.id();

  const sourceIdx = $derived(cycle % devices.length);
  const source = $derived(devices[sourceIdx]);
  const targets = $derived(devices.filter((_, i) => i !== sourceIdx));
  const payload = $derived(payloads[cycle % payloads.length]);

  const encrypted = $derived(phase === 'encrypt' || phase === 'toRelay' || phase === 'fanOut');
  const delivered = $derived(phase === 'decrypt' || phase === 'fade');
  const mainVisible = $derived(phase === 'appear' || phase === 'encrypt' || phase === 'toRelay');
  const mainPos = $derived(phase === 'toRelay' ? relay : chipPos(source));
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

  // The log always renders LOG_ROWS rows (blank ones padded at the end) so the
  // panel keeps a constant height and nothing below the hero shifts.
  const LOG_ROWS = 4;
  const log = $derived.by<LogLine[]>(() => {
    const lines: LogLine[] = [];
    const push = (who: string, tone: string, msg: string) => lines.push({ t: stamp(0), who, tone, msg });
    push(source.id, source.tone, `copied ${payload.kind} (${payload.meta.split(' · ')[0]})`);
    if (phase !== 'appear') push('crypto', '#ff7a59', `AES-256-GCM · nonce ${nonce}`);
    if (phase === 'toRelay' || phase === 'fanOut' || delivered) push('relay', '#fffaf0', 'forwarded ciphertext → 2 devices');
    if (delivered) for (const t of targets) push(t.id, t.tone, 'decrypted ✓ pasted');
    const visible = lines.slice(-LOG_ROWS);
    while (visible.length < LOG_ROWS) visible.push({ t: '', who: '', tone: '', msg: '' });
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

  // Beam direction: source → relay, then relay → targets (MagicUI AnimatedBeam).
  function beamFrom(d: Device) {
    return d.id === source.id ? d : relay;
  }
  function beamTo(d: Device) {
    return d.id === source.id ? relay : d;
  }
</script>

<div class="relative select-none {className}" aria-hidden="true">
  <!-- Scene -->
  <div class="panel panel-lg grid-paper relative aspect-[4/3] w-full overflow-hidden rounded-lg bg-cream" style="--panel-shadow: var(--color-ink);">
    <!-- Connections + animated beams -->
    <svg class="absolute inset-0 h-full w-full" viewBox="0 0 100 100" preserveAspectRatio="none">
      <defs>
        {#each devices as d (d.id)}
          {@const from = beamFrom(d)}
          {@const to = beamTo(d)}
          <linearGradient id="beam-{uid}-{d.id}" gradientUnits="userSpaceOnUse" x1={from.x} y1={from.y} x2={to.x} y2={to.y}>
            <stop offset="0" stop-color={d.tone} stop-opacity="0" />
            <stop offset="0.45" stop-color={d.tone} stop-opacity="0" />
            <stop offset="0.5" stop-color={d.tone} />
            <stop offset="0.65" stop-color="#ff7a59" />
            <stop offset="0.7" stop-color="#ff7a59" stop-opacity="0" />
            <stop offset="1" stop-color="#ff7a59" stop-opacity="0" />
            {#if lineActive(d)}
              <animateTransform attributeName="gradientTransform" type="translate" from="{from.x - to.x} {from.y - to.y}" to="{to.x - from.x} {to.y - from.y}" dur="0.9s" repeatCount="indefinite" />
            {/if}
          </linearGradient>
        {/each}
      </defs>
      {#each devices as d (d.id)}
        <line x1={d.x} y1={d.y} x2={relay.x} y2={relay.y} vector-effect="non-scaling-stroke" stroke="rgba(17,17,17,0.45)" stroke-width="2" stroke-dasharray="3 6" stroke-linecap="round" />
        {#if lineActive(d)}
          <line x1={d.x} y1={d.y} x2={relay.x} y2={relay.y} vector-effect="non-scaling-stroke" stroke="url(#beam-{uid}-{d.id})" stroke-width="4" stroke-linecap="round" />
        {/if}
      {/each}
    </svg>

    <!-- Relay -->
    <div class="absolute -translate-x-1/2 -translate-y-1/2" style="left: {relay.x}%; top: {relay.y}%;">
      <div class="relative flex items-center justify-center" style="width: {compact ? 56 : 68}px; height: {compact ? 56 : 68}px;">
        <span class="absolute inset-0 rounded-full border-2 border-accent {phase === 'toRelay' || phase === 'fanOut' ? 'animate-[ping-ring_1.2s_var(--ease-out-expo)_infinite]' : 'opacity-0'}"></span>
        <span
          class="absolute inset-0 rounded-full border-2 border-ink transition-[background-color,box-shadow,transform] duration-300 {phase === 'fanOut' || phase === 'toRelay'
            ? 'bg-accent shadow-[4px_4px_0_0_#111] -translate-x-0.5 -translate-y-0.5'
            : 'bg-ink shadow-[3px_3px_0_0_#ff7a59]'}"
        ></span>
        <span class="relative {phase === 'fanOut' || phase === 'toRelay' ? 'text-ink' : 'text-yellow'}"><Icon name="lock" size={compact ? 20 : 24} strokeWidth={2.4} /></span>
      </div>
      <div class="mt-2 text-center font-head text-[10px] uppercase tracking-[0.18em] text-ink">relay</div>
      <div class="text-center font-mono text-[10px] text-muted">sees only ciphertext</div>
    </div>

    <!-- Devices -->
    {#each devices as d (d.id)}
      {@const isSource = d.id === source.id}
      {@const highlight = (isSource && (phase === 'appear' || phase === 'encrypt')) || (!isSource && delivered)}
      <div
        class="absolute -translate-x-1/2 -translate-y-1/2 rounded-md border-2 border-ink bg-surface text-center transition-[box-shadow,transform,background-color] duration-300 {compact
          ? 'w-[88px] px-2 py-2'
          : 'w-[112px] px-3 py-3'}"
        style="left: {d.x}%; top: {d.y}%; box-shadow: {highlight ? `5px 5px 0 0 ${d.tone}, 5px 5px 0 2px #111` : '3px 3px 0 0 #111'};"
      >
        <div class="mb-1 flex justify-center">
          <span class="inline-flex h-7 w-7 items-center justify-center rounded border-2 border-ink text-ink" style="background: {d.tone};"><Icon name={d.icon} size={compact ? 14 : 16} strokeWidth={2.4} /></span>
        </div>
        <div class="truncate font-head text-[10.5px] text-ink">{d.name}</div>
        <div class="mt-1 flex items-center justify-center gap-1 font-mono text-[10px] text-muted">
          <span class="status-dot" style="color: {d.tone};" data-live={highlight}></span>
          {#if isSource && !delivered}
            copied
          {:else if !isSource && delivered}
            <span class="font-semibold text-ink">pasted</span>
          {:else}
            online
          {/if}
        </div>
      </div>
    {/each}

    <!-- Main payload chip: source → relay -->
    <div
      class="sync-chip absolute -translate-x-1/2 -translate-y-1/2 {mainVisible ? 'opacity-100 scale-100' : 'opacity-0 scale-90'}"
      style="left: {mainPos.x}%; top: {mainPos.y}%;"
    >
      {@render chip(encrypted ? 'cipher' : 'plain')}
    </div>

    <!-- Fan-out chips: relay → targets -->
    {#each targets as t (t.id)}
      {@const pos = chipPos(t)}
      <div
        class="sync-chip absolute -translate-x-1/2 -translate-y-1/2 {targetsVisible ? 'opacity-100 scale-100' : 'opacity-0 scale-90'}"
        style="left: {targetsOut ? pos.x : relay.x}%; top: {targetsOut ? pos.y : relay.y}%;"
      >
        {@render chip(delivered ? 'decrypted' : 'cipher')}
      </div>
    {/each}

    <!-- Corner labels -->
    <div class="absolute left-3 top-3 inline-flex items-center gap-1.5 rounded-sm border-2 border-ink bg-mint px-2 py-0.5 font-head text-[9.5px] uppercase tracking-[0.14em] text-ink shadow-xs">
      <span class="status-dot text-ink" data-live="true"></span>
      live sync
    </div>
    <div class="absolute right-3 top-3 rounded-sm border-2 border-ink bg-surface px-2 py-0.5 font-mono text-[9.5px] uppercase tracking-[0.14em] text-ink shadow-xs">e2e · aes-256-gcm</div>
  </div>

  <!-- Event log: ink terminal, fixed height so the layout below never shifts -->
  {#if !compact}
    <div class="panel-ink mt-4 h-[6.5rem] overflow-hidden rounded-md px-4 py-3 font-mono text-[11px] leading-5" style="--panel-shadow: var(--color-accent);">
      {#each log as line, i (i)}
        <div class="flex h-5 gap-3 text-cream/85 {line.msg ? 'animate-[fade-in_0.3s_ease-out]' : 'invisible'}">
          <span class="shrink-0 text-cream/50">{line.t}</span>
          <span class="w-14 shrink-0 font-semibold" style="color: {line.tone};">{line.who}</span>
          <span class="min-w-0 truncate">{line.msg}</span>
        </div>
      {/each}
    </div>
  {/if}
</div>

{#snippet chip(mode: 'plain' | 'cipher' | 'decrypted')}
  <div
    class="flex items-center gap-2 rounded-md border-2 border-ink px-2.5 py-1.5 shadow-[3px_3px_0_0_#111] transition-[background-color,color] duration-300 {compact
      ? 'max-w-[136px]'
      : 'max-w-[184px]'} {mode === 'cipher' ? 'bg-ink text-yellow' : mode === 'decrypted' ? 'bg-mint text-ink' : 'bg-cream text-ink'}"
  >
    <span class="shrink-0">
      <Icon name={mode === 'cipher' ? 'lock' : mode === 'decrypted' ? 'check' : payload.icon} size={13} strokeWidth={2.6} />
    </span>
    <span class="truncate {mode === 'cipher' ? 'font-mono text-[10.5px] tracking-wide' : 'text-[11.5px] font-semibold'}">
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
</style>
