<script lang="ts">
  import { onMount } from 'svelte';
  import Icon from '../components/Icon.svelte';
  import Logo from '../components/Logo.svelte';
  import SyncDemo from '../components/landing/SyncDemo.svelte';
  import Button from '../components/ui/Button.svelte';
  import { reveal } from '../lib/actions/reveal';

  const GITHUB_URL = 'https://github.com/cjs0h/cpmesh';

  // --- Downloads (DB-driven) ---
  interface DownloadLink {
    id: string;
    name: string;
    url: string;
    platform: string;
    arch: string;
    format: string;
    sort_order: number;
    is_active: boolean;
  }

  interface PlatformGroup {
    platform: string;
    label: string;
    icon: string;
    links: DownloadLink[];
  }

  const platformMeta: Record<string, { label: string; icon: string; order: number }> = {
    windows: { label: 'Windows', icon: 'windows', order: 1 },
    macos: { label: 'macOS', icon: 'apple', order: 2 },
    linux: { label: 'Linux', icon: 'linux', order: 3 },
    android: { label: 'Android', icon: 'android', order: 4 },
    ios: { label: 'iPhone / iPad', icon: 'smartphone', order: 5 },
  };

  function detectPlatform(): string {
    const ua = navigator.userAgent.toLowerCase();
    const plat = (navigator.platform || '').toLowerCase();
    if (/android/.test(ua)) return 'android';
    if (/iphone|ipad|ipod/.test(ua)) return 'ios';
    if (/win/.test(plat)) return 'windows';
    if (/mac/.test(plat)) return 'macos';
    if (/linux/.test(plat)) return 'linux';
    return '';
  }

  function groupByPlatform(items: DownloadLink[], detected: string): PlatformGroup[] {
    const groups: Record<string, DownloadLink[]> = {};
    for (const item of items) (groups[item.platform] ??= []).push(item);
    return Object.entries(groups)
      .map(([platform, links]) => {
        const meta = platformMeta[platform];
        if (!meta) return null;
        return { platform, label: meta.label, icon: meta.icon, links: [...links].sort((a, b) => a.sort_order - b.sort_order) };
      })
      .filter((g): g is PlatformGroup => g !== null)
      .sort((a, b) => {
        if (a.platform === detected) return -1;
        if (b.platform === detected) return 1;
        return (platformMeta[a.platform]?.order ?? 9) - (platformMeta[b.platform]?.order ?? 9);
      });
  }

  let downloads = $state<DownloadLink[]>([]);
  let detectedPlatform = $state('');
  const dlGroups = $derived(groupByPlatform(downloads, detectedPlatform));
  const detectedGroup = $derived(dlGroups.find((g) => g.platform === detectedPlatform) ?? dlGroups[0]);
  const secondaryGroups = $derived(dlGroups.filter((g) => g.platform !== detectedGroup?.platform));

  onMount(() => {
    detectedPlatform = detectPlatform();
    fetch('/api/downloads/current')
      .then((res) => (res.ok ? res.json() : []))
      .then((data) => (downloads = Array.isArray(data) ? data : []))
      .catch(() => {});
  });

  // --- Navigation ---
  const navLinks = [
    { label: 'Features', id: 'features' },
    { label: 'Security', id: 'security' },
    { label: 'Downloads', id: 'downloads' },
    { label: 'Pricing', id: 'pricing' },
  ];
  let mobileNavOpen = $state(false);
  let scrolled = $state(false);

  $effect(() => {
    const onScroll = () => (scrolled = window.scrollY > 12);
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  });

  function scrollToId(id: string) {
    mobileNavOpen = false;
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // --- Copy helpers ---
  let copiedCmd = $state('');
  async function copyText(text: string, id: string) {
    try {
      await navigator.clipboard.writeText(text);
      copiedCmd = id;
      setTimeout(() => (copiedCmd = ''), 2000);
    } catch {
      /* clipboard unavailable */
    }
  }

  // --- Terminal demo ---
  interface TerminalLine {
    type: 'prompt' | 'output' | 'blank' | 'comment';
    text: string;
    color?: string;
  }
  const terminalLines: TerminalLine[] = [
    { type: 'prompt', text: 'docker compose up -d' },
    { type: 'output', text: '✓ relay listening on :8080 · dashboard at http://localhost:39271', color: '#2ad6a0' },
    { type: 'blank', text: '' },
    { type: 'prompt', text: 'cpmesh pair' },
    { type: 'output', text: '✓ paired 3 devices · ECDH keys exchanged · relay never saw them', color: '#2ad6a0' },
    { type: 'blank', text: '' },
    { type: 'prompt', text: 'cpmesh status' },
    { type: 'output', text: '  macbook-pro    ● connected   12ms', color: '#2ad6a0' },
    { type: 'output', text: '  work-pc        ● connected   18ms', color: '#2ad6a0' },
    { type: 'output', text: '  pixel-9        ● idle', color: '#f4c95d' },
    { type: 'blank', text: '' },
    { type: 'comment', text: '# copy on the mac, paste on the pc. that is the whole workflow.' },
  ];
  let terminalStep = $state(0);
  let terminalStarted = $state(false);
  let terminalRun = $state(0);

  $effect(() => {
    if (!terminalStarted) return;
    void terminalRun;
    const id = setInterval(() => {
      terminalStep += 1;
      if (terminalStep >= terminalLines.length) clearInterval(id);
    }, 520);
    return () => clearInterval(id);
  });

  function replayTerminal() {
    terminalStep = 0;
    terminalRun += 1;
    terminalStarted = true;
  }

  const dockerCompose = `services:
  relay:
    image: ghcr.io/cjs0h/cpmesh:latest
    ports: ["39271:8080"]
    volumes: ["./data:/data"]
    restart: unless-stopped`;

  // --- Content ---
  const pains = [
    { icon: 'send', title: 'Emailing yourself', desc: 'Sending links and snippets to your own inbox. In 2026. Really.' },
    { icon: 'hard-drive', title: 'USB drives', desc: 'Carrying a flash drive between rooms like it is 2005.' },
    { icon: 'cloud', title: 'Big-cloud clipboards', desc: 'Apple, Google and Microsoft sync your clipboard — and can read every word.' },
  ];

  const steps = [
    { num: '01', icon: 'download', title: 'Install', desc: 'Run the relay with one Docker command — or skip it and use ours — then grab the native app.', tone: '#49c6e5' },
    { num: '02', icon: 'key', title: 'Pair', desc: 'Sign in on each device. Keys are exchanged device-to-device over ECDH; the relay only forwards sealed bytes.', tone: '#ff7a59' },
    { num: '03', icon: 'clipboard', title: 'Copy & paste', desc: 'That is it. Text, images and files show up on every device in under a second.', tone: '#2ad6a0' },
  ];

  const platforms = [
    { icon: 'windows', name: 'Windows', desc: 'Tray app, auto-start', tone: '#49c6e5' },
    { icon: 'apple', name: 'macOS', desc: 'Menu-bar native', tone: '#f5f7fb' },
    { icon: 'linux', name: 'Linux', desc: 'Wayland & X11', tone: '#f4c95d' },
    { icon: 'android', name: 'Android', desc: 'Background service', tone: '#2ad6a0' },
    { icon: 'globe', name: 'Web', desc: 'Dashboard & history', tone: '#ff7a59' },
  ];

  const comparison = [
    { feature: 'End-to-end encryption', cpmesh: true, handoff: false, winclip: false, pushbullet: false },
    { feature: 'Self-hosted option', cpmesh: true, handoff: false, winclip: false, pushbullet: false },
    { feature: 'Cross-platform', cpmesh: true, handoff: false, winclip: false, pushbullet: true },
    { feature: 'Open source', cpmesh: true, handoff: false, winclip: false, pushbullet: false },
    { feature: 'Files up to 25 MB', cpmesh: true, handoff: false, winclip: false, pushbullet: true },
    { feature: 'Images', cpmesh: true, handoff: true, winclip: true, pushbullet: true },
    { feature: 'Clipboard history', cpmesh: true, handoff: false, winclip: true, pushbullet: true },
    { feature: 'Free forever', cpmesh: true, handoff: false, winclip: true, pushbullet: false },
  ];

  const quickstart = [
    { id: '1', cmd: 'git clone https://github.com/cjs0h/cpmesh && cd cpmesh' },
    { id: '2', cmd: 'docker compose up -d' },
    { id: '3', cmd: 'open http://localhost:39271' },
  ];

  const stats = [
    { value: 'AES-256', label: 'GCM authenticated encryption', icon: 'lock', tone: 'text-accent' },
    { value: '< 1 s', label: 'copy-to-paste latency', icon: 'zap', tone: 'text-cyan' },
    { value: '5', label: 'native platforms + web', icon: 'layers', tone: 'text-gold' },
    { value: '0 bytes', label: 'readable by the relay', icon: 'eye-off', tone: 'text-mint' },
  ];
</script>

<svelte:head>
  <title>cpmesh — Encrypted clipboard sync across all your devices</title>
  <meta name="description" content="Copy on one device, paste on another. End-to-end encrypted with AES-256-GCM. Open source. Self-host with Docker or use our relay." />
</svelte:head>

{#snippet heading(eyebrow: string, title: string, sub?: string)}
  <div class="mx-auto mb-12 max-w-2xl text-center md:mb-16" use:reveal>
    <p class="mb-3 text-[11px] font-semibold uppercase tracking-[0.2em] text-accent">{eyebrow}</p>
    <h2 class="font-display text-[clamp(1.9rem,4vw,2.9rem)] font-bold leading-[1.05] tracking-tight text-fg">{title}</h2>
    {#if sub}<p class="mx-auto mt-4 max-w-xl text-[15px] leading-relaxed text-muted">{sub}</p>{/if}
  </div>
{/snippet}

<div class="home relative min-h-dvh overflow-x-clip bg-bg text-fg" style="background: radial-gradient(ellipse at 15% 0%, rgba(255,122,89,0.14), transparent 50%), radial-gradient(ellipse at 85% 10%, rgba(73,198,229,0.10), transparent 45%), linear-gradient(180deg, #0a1324 0%, #060d1a 45%, #040911 100%);">
  <!-- Grid + orbs -->
  <div class="pointer-events-none absolute inset-0 opacity-30" style="background-image: linear-gradient(rgba(255,255,255,0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.025) 1px, transparent 1px); background-size: 72px 72px; mask-image: linear-gradient(180deg, rgba(0,0,0,0.7), transparent 60%);"></div>
  <div class="pointer-events-none absolute -right-[6%] -top-[10%] h-[560px] w-[560px] rounded-full opacity-[0.14] blur-[90px]" style="background: radial-gradient(circle, rgba(255,122,89,0.5), transparent 70%); animation: drift 12s ease-in-out infinite;"></div>
  <div class="pointer-events-none absolute -left-[8%] top-[38%] h-[460px] w-[460px] rounded-full opacity-[0.1] blur-[90px]" style="background: radial-gradient(circle, rgba(73,198,229,0.45), transparent 70%); animation: drift 15s ease-in-out infinite 3s;"></div>
  <div class="pointer-events-none absolute bottom-[12%] right-[8%] h-[400px] w-[400px] rounded-full opacity-[0.08] blur-[90px]" style="background: radial-gradient(circle, rgba(42,214,160,0.4), transparent 70%); animation: drift 13s ease-in-out infinite 6s;"></div>

  <!-- ==================== HEADER ==================== -->
  <header class="sticky top-0 z-40 transition-[background-color,border-color,backdrop-filter] duration-300 {scrolled ? 'border-b border-white/[0.06] bg-[rgba(6,13,26,0.78)] backdrop-blur-xl' : 'border-b border-transparent bg-transparent'}">
    <div class="mx-auto flex h-16 max-w-6xl items-center justify-between px-5 sm:px-6">
      <button type="button" class="inline-flex items-center gap-2.5 bg-transparent p-0" onclick={() => scrollToId('top')} aria-label="Back to top">
        <Logo size={32} withText textClass="text-[17px]" />
      </button>

      <nav class="hidden items-center gap-1 md:flex" aria-label="Primary">
        {#each navLinks as link (link.id)}
          <button type="button" class="rounded-md bg-transparent px-3 py-1.5 text-sm font-medium text-muted transition-colors hover:bg-white/[0.04] hover:text-fg" onclick={() => scrollToId(link.id)}>{link.label}</button>
        {/each}
        <a href={GITHUB_URL} target="_blank" rel="noopener" class="ml-1 inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium text-muted transition-colors hover:bg-white/[0.04] hover:text-fg">
          <Icon name="github" size={15} /> GitHub
        </a>
      </nav>

      <div class="flex items-center gap-2">
        <span class="hidden sm:contents"><Button href="#/login" variant="ghost" size="sm">Sign in</Button></span>
        <Button href="#/login" size="sm" iconRight="arrow-right" class="rounded-full">Get started</Button>
        <button type="button" class="ml-1 flex h-9 w-9 items-center justify-center rounded-md text-fg md:hidden" aria-label="Open navigation menu" aria-expanded={mobileNavOpen} onclick={() => (mobileNavOpen = !mobileNavOpen)}>
          <Icon name="menu" size={22} />
        </button>
      </div>
    </div>
  </header>

  {#if mobileNavOpen}
    <div class="fixed inset-0 z-50 flex flex-col items-center justify-center gap-7 bg-[rgba(5,13,26,0.97)] backdrop-blur-2xl animate-[fade-in_0.2s_ease-out]">
      <button type="button" class="absolute right-5 top-5 p-2 text-fg" aria-label="Close navigation" onclick={() => (mobileNavOpen = false)}>
        <Icon name="x" size={24} />
      </button>
      {#each navLinks as link (link.id)}
        <button type="button" class="font-display text-3xl font-bold text-fg transition-colors hover:text-accent" onclick={() => scrollToId(link.id)}>{link.label}</button>
      {/each}
      <a href={GITHUB_URL} target="_blank" rel="noopener" class="inline-flex items-center gap-2 font-display text-3xl font-bold text-fg hover:text-accent"><Icon name="github" size={26} /> GitHub</a>
      <Button href="#/login" size="lg" class="mt-4 rounded-full px-10">Sign in</Button>
    </div>
  {/if}

  <main id="main-content">
    <!-- ==================== HERO ==================== -->
    <section class="relative pb-16 pt-14 md:pb-24 md:pt-24" id="top">
      <div class="mx-auto max-w-6xl px-5 sm:px-6">
        <div class="grid items-center gap-12 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)] lg:gap-14">
          <div class="text-center lg:text-left" use:reveal={{ immediate: true }}>
            <a href="{GITHUB_URL}/releases" target="_blank" rel="noopener" class="group inline-flex items-center gap-2 rounded-full border border-white/[0.08] bg-white/[0.03] py-1.5 pl-1.5 pr-4 text-[13px] text-muted transition-colors hover:border-white/[0.14] hover:text-fg">
              <span class="rounded-full bg-mint/15 px-2 py-0.5 text-[11px] font-bold uppercase tracking-wide text-mint">Open source</span>
              MIT / Apache-2.0 · self-hostable
              <Icon name="arrow-up-right" size={13} class="text-dim transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" />
            </a>

            <h1 class="mt-7 font-display font-bold leading-[0.98] tracking-[-0.045em]">
              <span class="block text-[clamp(2.4rem,4.3vw,3.9rem)] text-fg">Copy anywhere.</span>
              <span class="text-gradient block text-[clamp(2.4rem,4.3vw,3.9rem)]">Paste everywhere.</span>
            </h1>
            <p class="mx-auto mt-6 max-w-lg text-[17px] leading-relaxed text-muted lg:mx-0">
              One clipboard across every device you own — text, images and files — <span class="text-fg">encrypted before it leaves your machine</span>. The relay never sees a readable byte.
            </p>

            <div class="mt-9 flex flex-wrap justify-center gap-3 lg:justify-start">
              <Button href="#/login" size="lg" iconRight="arrow-right" class="rounded-full px-7">Get started free</Button>
              <Button onclick={() => scrollToId('downloads')} variant="secondary" size="lg" icon="download" class="rounded-full px-7">Download the app</Button>
            </div>

            <ul class="mt-8 flex flex-wrap justify-center gap-x-5 gap-y-2 text-[13px] text-muted lg:justify-start">
              {#each ['AES-256-GCM', 'Zero-knowledge relay', 'Sub-second sync', 'No telemetry'] as item (item)}
                <li class="inline-flex items-center gap-1.5"><Icon name="check" size={13} class="text-mint" /> {item}</li>
              {/each}
            </ul>
          </div>

          <div class="mx-auto w-full max-w-[560px] lg:max-w-none" use:reveal={{ immediate: true, delay: 150 }}>
            <SyncDemo />
          </div>
        </div>

        <!-- Stats strip -->
        <div class="mt-16 grid grid-cols-2 gap-3 md:grid-cols-4 md:gap-4" use:reveal={{ delay: 100 }}>
          {#each stats as s (s.label)}
            <div class="glass flex items-center gap-3 rounded-xl px-4 py-3.5">
              <span class="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-white/[0.08] bg-white/[0.03] {s.tone}"><Icon name={s.icon} size={16} /></span>
              <div class="min-w-0">
                <p class="font-display text-lg font-bold leading-none tracking-tight text-fg">{s.value}</p>
                <p class="mt-1 truncate text-[11.5px] text-muted">{s.label}</p>
              </div>
            </div>
          {/each}
        </div>
      </div>
    </section>

    <!-- ==================== THE PROBLEM ==================== -->
    <section class="py-16 md:py-24">
      <div class="mx-auto max-w-5xl px-5 sm:px-6">
        {@render heading('The problem', 'There has to be a better way.', 'Everyone moves data between devices all day. The usual options are embarrassing — or hand your clipboard to a company that can read it.')}

        <div class="grid gap-5 md:grid-cols-2 md:gap-6">
          <div class="flex flex-col gap-3">
            {#each pains as pain, i (pain.title)}
              <div class="flex items-start gap-4 rounded-xl border border-rose/15 bg-[linear-gradient(135deg,rgba(248,113,113,0.05),rgba(12,21,38,0.85))] p-5" use:reveal={{ delay: i * 90 }}>
                <span class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-rose/20 bg-rose/10 text-rose"><Icon name={pain.icon} size={18} /></span>
                <div>
                  <h3 class="text-[15px] font-bold text-fg">{pain.title}</h3>
                  <p class="mt-1 text-sm leading-relaxed text-muted">{pain.desc}</p>
                </div>
              </div>
            {/each}
          </div>

          <div class="ring-card flex flex-col justify-center rounded-2xl p-7" style="--ring-from: rgba(42,214,160,0.6); --ring-to: rgba(73,198,229,0.35);" use:reveal={{ delay: 200 }}>
            <div class="mb-4 inline-flex items-center gap-2.5">
              <Logo size={30} />
              <span class="font-display text-xl font-bold tracking-tight">cpmesh</span>
            </div>
            <p class="text-[15px] leading-relaxed text-muted">Copy on any device. Paste on any other. The relay only ever sees encrypted noise, because your keys never leave your hardware.</p>
            <ul class="mt-5 space-y-3">
              {#each ['Zero-knowledge relay architecture', 'AES-256-GCM on-device encryption', 'Your infrastructure, your rules', 'Every platform, one clipboard'] as point (point)}
                <li class="flex items-center gap-2.5 text-sm text-fg"><Icon name="check-circle" size={15} class="shrink-0 text-mint" /> {point}</li>
              {/each}
            </ul>
          </div>
        </div>
      </div>
    </section>

    <!-- ==================== HOW IT WORKS ==================== -->
    <section class="py-16 md:py-24">
      <div class="mx-auto max-w-5xl px-5 sm:px-6">
        {@render heading('How it works', 'Up and running in three steps', 'No configuration. No key management. Install, pair, start pasting.')}

        <div class="relative grid gap-5 md:grid-cols-3">
          <div class="pointer-events-none absolute left-[16%] right-[16%] top-14 hidden h-px bg-[linear-gradient(90deg,transparent,rgba(158,178,201,0.25),transparent)] md:block"></div>
          {#each steps as step, i (step.num)}
            <article class="glass relative overflow-hidden rounded-2xl p-6 pt-7" use:reveal={{ delay: i * 120 }}>
              <span class="pointer-events-none absolute -right-2 -top-4 select-none font-display text-[5.5rem] font-bold leading-none text-white/[0.04]">{step.num}</span>
              <span class="relative mb-5 inline-flex h-12 w-12 items-center justify-center rounded-xl border" style="background: color-mix(in srgb, {step.tone} 12%, transparent); border-color: color-mix(in srgb, {step.tone} 28%, transparent); color: {step.tone}; box-shadow: 0 0 30px color-mix(in srgb, {step.tone} 18%, transparent);">
                <Icon name={step.icon} size={22} />
              </span>
              <h3 class="font-display text-xl font-bold tracking-tight text-fg">{step.title}</h3>
              <p class="mt-2 text-sm leading-relaxed text-muted">{step.desc}</p>
            </article>
          {/each}
        </div>
      </div>
    </section>

    <!-- ==================== TERMINAL ==================== -->
    <section class="py-16 md:py-24">
      <div class="mx-auto max-w-3xl px-5 sm:px-6">
        {@render heading('See it in action', 'Three commands. Zero ceremony.')}

        <div class="overflow-hidden rounded-2xl border border-white/[0.08] bg-[rgba(6,13,26,0.96)] shadow-pop" use:reveal={{ onreveal: () => (terminalStarted = true) }}>
          <div class="flex items-center gap-2 border-b border-white/[0.06] px-4 py-3">
            <span class="h-3 w-3 rounded-full bg-[#ff5f57]"></span>
            <span class="h-3 w-3 rounded-full bg-[#febc2e]"></span>
            <span class="h-3 w-3 rounded-full bg-[#28c840]"></span>
            <span class="ml-3 font-mono text-[11px] text-dim">zsh — cpmesh</span>
            <button type="button" class="ml-auto inline-flex items-center gap-1 font-mono text-[11px] text-dim hover:text-fg" onclick={replayTerminal}>
              <Icon name="refresh" size={11} /> replay
            </button>
          </div>
          <div class="min-h-[300px] p-5 font-mono text-[13px] leading-7">
            {#each terminalLines as line, i (i)}
              {#if terminalStep > i}
                <div class="animate-[fade-in_0.25s_ease-out]">
                  {#if line.type === 'blank'}
                    <div class="h-4"></div>
                  {:else if line.type === 'prompt'}
                    <div><span class="text-cyan">❯</span> <span class="text-fg">{line.text}</span></div>
                  {:else if line.type === 'comment'}
                    <div class="text-dim">{line.text}</div>
                  {:else if line.text.startsWith('✓')}
                    <div><span style="color: {line.color}">✓</span><span class="text-muted">{line.text.slice(1)}</span></div>
                  {:else if line.text.includes('●')}
                    <div><span class="text-muted">{line.text.split('●')[0]}</span><span style="color: {line.color}">●{line.text.split('●')[1]}</span></div>
                  {:else}
                    <div class="text-muted">{line.text}</div>
                  {/if}
                </div>
              {/if}
            {/each}
            {#if terminalStep < terminalLines.length}
              <span class="ml-0.5 inline-block h-[15px] w-[7px] bg-fg/70 align-middle animate-[blink_1s_step-end_infinite]"></span>
            {/if}
          </div>
        </div>

        <div class="glass mt-5 rounded-xl p-4" use:reveal={{ delay: 120 }}>
          <div class="mb-3 flex items-center justify-between">
            <span class="font-mono text-[11px] text-dim">docker-compose.yml</span>
            <button type="button" class="inline-flex items-center gap-1.5 text-xs transition-colors {copiedCmd === 'docker' ? 'text-mint' : 'text-muted hover:text-fg'}" onclick={() => copyText(dockerCompose, 'docker')}>
              <Icon name={copiedCmd === 'docker' ? 'check' : 'copy'} size={12} />
              {copiedCmd === 'docker' ? 'Copied' : 'Copy'}
            </button>
          </div>
          <pre class="overflow-x-auto font-mono text-[13px] leading-6 text-muted"><code><span class="text-accent">services</span>:
  <span class="text-cyan">relay</span>:
    <span class="text-cyan">image</span>: <span class="text-fg">ghcr.io/cjs0h/cpmesh:latest</span>
    <span class="text-cyan">ports</span>: [<span class="text-gold">"39271:8080"</span>]
    <span class="text-cyan">volumes</span>: [<span class="text-gold">"./data:/data"</span>]
    <span class="text-cyan">restart</span>: <span class="text-fg">unless-stopped</span></code></pre>
        </div>
      </div>
    </section>

    <!-- ==================== FEATURES (bento) ==================== -->
    <section class="py-16 md:py-24" id="features">
      <div class="mx-auto max-w-6xl px-5 sm:px-6">
        {@render heading('Why cpmesh', 'Built for people who care where their data goes')}

        <div class="grid gap-4 md:grid-cols-6">
          <!-- Sub-second sync -->
          <article class="glass relative overflow-hidden rounded-2xl p-6 md:col-span-4" use:reveal>
            <div class="flex items-start justify-between gap-6">
              <div>
                <span class="mb-4 inline-flex h-11 w-11 items-center justify-center rounded-xl border border-cyan/25 bg-cyan/12 text-cyan"><Icon name="zap" size={18} /></span>
                <h3 class="font-display text-xl font-bold tracking-tight">Sub-second sync</h3>
                <p class="mt-2 max-w-md text-sm leading-relaxed text-muted">WebSocket push, not polling. Your clipboard arrives on the other device before you finish switching windows.</p>
              </div>
            </div>
            <div class="mt-6 rounded-xl border border-white/[0.06] bg-black/20 p-4">
              <div class="flex items-center justify-between font-mono text-[11px] text-dim"><span>copy</span><span>relay</span><span>paste</span></div>
              <div class="relative mt-2 h-1.5 rounded-full bg-white/[0.06]">
                <span class="absolute inset-y-0 left-0 w-1/2 rounded-full bg-[linear-gradient(90deg,#49c6e5,#2ad6a0)] opacity-40"></span>
                <span class="latency-dot absolute -top-[5px] h-4 w-4 rounded-full bg-cyan shadow-[0_0_18px_rgba(73,198,229,0.9)]"></span>
              </div>
              <div class="mt-3 flex items-center justify-between font-mono text-[11px]"><span class="text-mint">● 12 ms</span><span class="text-dim">p95 on LAN · 180 ms across continents</span></div>
            </div>
          </article>

          <!-- E2E -->
          <article class="glass relative overflow-hidden rounded-2xl p-6 md:col-span-2" use:reveal={{ delay: 80 }}>
            <span class="mb-4 inline-flex h-11 w-11 items-center justify-center rounded-xl border border-accent/25 bg-accent/12 text-accent"><Icon name="lock" size={18} /></span>
            <h3 class="font-display text-xl font-bold tracking-tight">End-to-end encrypted</h3>
            <p class="mt-2 text-sm leading-relaxed text-muted">AES-256-GCM happens on-device. Keys are born there and die there.</p>
            <div class="relative mt-5 h-10">
              <span class="cipher-swap absolute inset-0 flex items-center rounded-lg border border-cyan/30 bg-surface-2/90 px-3 font-medium text-[12.5px] text-fg">“Meet at 3pm — bring the deck”</span>
              <span class="cipher-swap-alt absolute inset-0 flex items-center rounded-lg border border-accent/40 bg-[rgba(40,16,10,0.9)] px-3 font-mono text-[11px] tracking-wide text-accent">8f3a 1c9e 42b7 d0e5 77aa 91f2</span>
            </div>
          </article>

          <!-- Platforms -->
          <article class="glass rounded-2xl p-6 md:col-span-2" use:reveal={{ delay: 120 }}>
            <span class="mb-4 inline-flex h-11 w-11 items-center justify-center rounded-xl border border-gold/25 bg-gold/12 text-gold"><Icon name="layers" size={18} /></span>
            <h3 class="font-display text-xl font-bold tracking-tight">Every platform</h3>
            <p class="mt-2 text-sm leading-relaxed text-muted">Native Windows, macOS, Linux and Android clients. Plus this web dashboard.</p>
            <div class="mt-5 flex gap-2">
              {#each platforms as p (p.name)}
                <span class="flex h-10 flex-1 items-center justify-center rounded-lg border border-white/[0.06] bg-white/[0.03] transition-colors hover:border-white/[0.14]" style="color: {p.tone};" title={p.name}><Icon name={p.icon} size={18} /></span>
              {/each}
            </div>
          </article>

          <!-- Self-host -->
          <article class="glass rounded-2xl p-6 md:col-span-2" use:reveal={{ delay: 160 }}>
            <span class="mb-4 inline-flex h-11 w-11 items-center justify-center rounded-xl border border-mint/25 bg-mint/12 text-mint"><Icon name="server" size={18} /></span>
            <h3 class="font-display text-xl font-bold tracking-tight">Self-host or use ours</h3>
            <p class="mt-2 text-sm leading-relaxed text-muted">One Docker command on any box you own — or point the apps at our hosted relay.</p>
            <code class="mt-5 flex items-center gap-2 rounded-lg border border-white/[0.06] bg-black/25 px-3 py-2 font-mono text-[12px] text-fg"><span class="text-cyan">❯</span> docker compose up -d</code>
          </article>

          <!-- History -->
          <article class="glass rounded-2xl p-6 md:col-span-2" use:reveal={{ delay: 200 }}>
            <span class="mb-4 inline-flex h-11 w-11 items-center justify-center rounded-xl border border-violet/25 bg-violet/12 text-violet"><Icon name="history" size={18} /></span>
            <h3 class="font-display text-xl font-bold tracking-tight">Clipboard history</h3>
            <p class="mt-2 text-sm leading-relaxed text-muted">Browse, search and restore past clips. Encrypted at rest, under your control.</p>
            <ul class="mt-5 space-y-1.5">
              {#each [['type', 'Text', '2m'], ['image', 'Image', '14m'], ['file', 'PDF', '1h']] as [icon, label, when] (label)}
                <li class="flex items-center gap-2.5 rounded-md border border-white/[0.05] bg-white/[0.02] px-2.5 py-1.5 text-[12px]"><Icon name={icon} size={12} class="text-muted" /><span class="text-fg">{label}</span><span class="ml-auto font-mono text-dim">{when}</span></li>
              {/each}
            </ul>
          </article>

          <!-- Open source -->
          <article class="glass relative overflow-hidden rounded-2xl p-6 md:col-span-6" use:reveal={{ delay: 240 }}>
            <div class="flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
              <div class="max-w-xl">
                <span class="mb-4 inline-flex h-11 w-11 items-center justify-center rounded-xl border border-white/[0.1] bg-white/[0.04] text-fg"><Icon name="github" size={18} /></span>
                <h3 class="font-display text-xl font-bold tracking-tight">Open source. Every line auditable.</h3>
                <p class="mt-2 text-sm leading-relaxed text-muted">Dual-licensed MIT / Apache-2.0. Rust relay, Tauri desktop apps, Kotlin on Android. No telemetry, no tracking, no strings attached.</p>
              </div>
              <div class="flex flex-wrap gap-2">
                {#each ['Rust', 'Svelte', 'Tauri', 'Kotlin', 'PostgreSQL'] as tech (tech)}
                  <span class="rounded-full border border-white/[0.08] bg-white/[0.03] px-3 py-1 font-mono text-[12px] text-muted">{tech}</span>
                {/each}
                <Button href={GITHUB_URL} external variant="secondary" size="sm" icon="github" class="rounded-full">Star on GitHub</Button>
              </div>
            </div>
          </article>
        </div>
      </div>
    </section>

    <!-- ==================== SECURITY ==================== -->
    <section class="py-16 md:py-24" id="security">
      <div class="mx-auto max-w-5xl px-5 sm:px-6">
        {@render heading('Security', 'Zero-knowledge by design', 'Your clipboard is encrypted before it leaves your device. The relay cannot decrypt it. Nobody can — except your own devices.')}

        <div class="glass rounded-2xl p-6 md:p-8" use:reveal>
          <div class="flex flex-col items-center justify-center gap-3 md:flex-row md:gap-2">
            {#each [
              { icon: 'laptop', label: 'Your laptop', sub: 'Hello, world!', tone: '#49c6e5', dim: false },
              { icon: 'lock', label: 'Encrypt', sub: 'AES-256-GCM', tone: '#ff7a59', dim: false },
              { icon: 'cloud', label: 'Relay', sub: '0x7f3a…b2e1', tone: '#9db0c7', dim: true },
              { icon: 'key', label: 'Decrypt', sub: 'ECDH P-256', tone: '#2ad6a0', dim: false },
              { icon: 'smartphone', label: 'Your phone', sub: 'Hello, world!', tone: '#49c6e5', dim: false },
            ] as node, i (node.label)}
              {#if i > 0}
                <span class="text-dim/60 md:block"><Icon name="chevron-right" size={18} class="rotate-90 md:rotate-0" /></span>
              {/if}
              <div class="flex min-w-[124px] flex-col items-center gap-2 rounded-xl border px-4 py-3 {node.dim ? 'opacity-60' : ''}" style="border-color: color-mix(in srgb, {node.tone} 25%, transparent); background: color-mix(in srgb, {node.tone} 5%, transparent);">
                <span style="color: {node.tone};"><Icon name={node.icon} size={24} /></span>
                <span class="text-xs font-bold" style="color: {node.dim ? '#9db0c7' : 'inherit'};">{node.label}</span>
                <span class="rounded px-2 py-0.5 font-mono text-[10px]" style="background: color-mix(in srgb, {node.tone} 10%, transparent); color: {node.tone};">{node.sub}</span>
              </div>
            {/each}
          </div>
          <p class="mt-6 text-center text-sm text-muted">The relay only forwards sealed bytes. It holds no keys and cannot read your data. <span class="font-medium text-fg">Ever.</span></p>
        </div>

        <div class="mt-5 grid gap-4 sm:grid-cols-3">
          {#each [
            { title: 'AES-256-GCM', desc: 'Authenticated encryption for every entry — confidentiality and integrity in one pass.', tone: 'text-accent' },
            { title: 'ECDH P-256', desc: 'Elliptic-curve key agreement between devices. Each device owns its keypair; nothing shared with the server.', tone: 'text-cyan' },
            { title: 'Zero knowledge', desc: 'Compromise the relay and all you get is ciphertext. Your data stays noise.', tone: 'text-mint' },
          ] as card, i (card.title)}
            <div class="glass rounded-xl p-5" use:reveal={{ delay: i * 80 }}>
              <span class="font-mono text-sm font-bold {card.tone}">{card.title}</span>
              <p class="mt-2 text-sm leading-relaxed text-muted">{card.desc}</p>
            </div>
          {/each}
        </div>

        <div class="mt-5 overflow-x-auto rounded-xl border border-white/[0.08] bg-[rgba(6,13,26,0.92)] p-5" use:reveal={{ delay: 120 }}>
          <pre class="font-mono text-[12px] leading-6 sm:text-[13px]"><code><span class="text-dim">// what happens when you copy</span>
<span class="text-muted">plaintext</span>  <span class="text-dim">=</span> <span class="text-cyan">clipboard</span>.<span class="text-fg">read</span>()
<span class="text-muted">shared_key</span> <span class="text-dim">=</span> <span class="text-accent">ECDH</span>(<span class="text-fg">my_private</span>, <span class="text-fg">peer_public</span>)
<span class="text-muted">nonce</span>      <span class="text-dim">=</span> <span class="text-cyan">random</span>(<span class="text-gold">12</span>)
<span class="text-muted">ciphertext</span> <span class="text-dim">=</span> <span class="text-accent">AES_256_GCM</span>.<span class="text-fg">encrypt</span>(<span class="text-muted">shared_key</span>, <span class="text-muted">nonce</span>, <span class="text-muted">plaintext</span>)
<span class="text-cyan">relay</span>.<span class="text-fg">send</span>(<span class="text-muted">ciphertext</span>)  <span class="text-mint">// relay sees only noise</span></code></pre>
        </div>
      </div>
    </section>

    <!-- ==================== PLATFORMS ==================== -->
    <section class="py-16 md:py-24" id="platforms">
      <div class="mx-auto max-w-4xl px-5 sm:px-6">
        {@render heading('Platforms', 'Native on every platform', 'Not a web wrapper. Real native clients built with Tauri and Kotlin, with system-level clipboard integration.')}

        <div class="grid grid-cols-2 gap-4 sm:grid-cols-3 md:grid-cols-5">
          {#each platforms as plat, i (plat.name)}
            <div class="glass rounded-xl p-5 text-center transition-[transform,border-color] duration-300 hover:-translate-y-1 hover:border-white/[0.16]" use:reveal={{ delay: i * 70 }}>
              <div class="mb-3" style="color: {plat.tone};"><Icon name={plat.icon} size={30} /></div>
              <div class="font-display text-sm font-bold">{plat.name}</div>
              <div class="mt-1 text-[11.5px] leading-snug text-muted">{plat.desc}</div>
            </div>
          {/each}
        </div>
      </div>
    </section>

    <!-- ==================== DOWNLOADS ==================== -->
    <section class="py-16 md:py-24" id="downloads">
      <div class="mx-auto max-w-4xl px-5 sm:px-6">
        {@render heading('Downloads', 'Get the app for your platform', 'System-tray integration, background sync and automatic reconnection included.')}

        {#if dlGroups.length > 0}
          {#if detectedGroup}
            <div class="ring-card mb-5 rounded-2xl p-6" style="--ring-from: rgba(73,198,229,0.6); --ring-to: rgba(255,122,89,0.35);" use:reveal>
              <div class="flex flex-col items-start gap-5 sm:flex-row sm:items-center">
                <span class="flex h-14 w-14 shrink-0 items-center justify-center rounded-xl border border-cyan/25 bg-cyan/12 text-cyan"><Icon name={detectedGroup.icon} size={28} /></span>
                <div class="min-w-0 flex-1">
                  <div class="flex flex-wrap items-center gap-2">
                    <h3 class="font-display text-xl font-bold tracking-tight">{detectedGroup.label}</h3>
                    {#if detectedGroup.platform === detectedPlatform}
                      <span class="inline-flex items-center gap-1 rounded-full bg-mint/12 px-2 py-0.5 text-[11px] font-bold uppercase tracking-wide text-mint"><Icon name="check" size={10} /> detected</span>
                    {/if}
                  </div>
                  <p class="mt-1 text-sm text-muted">Latest build for {detectedGroup.label}. Install, sign in, and start syncing in under a minute.</p>
                  {#if detectedGroup.links[0]}
                    <p class="mt-1 font-mono text-[11.5px] text-dim">{detectedGroup.links[0].format ? detectedGroup.links[0].format.toUpperCase() : 'PACKAGE'}{detectedGroup.links[0].arch ? ` · ${detectedGroup.links[0].arch}` : ''}</p>
                  {/if}
                </div>
                <div class="flex w-full flex-col gap-2 sm:w-auto">
                  {#if detectedGroup.links[0]}
                    <Button href={detectedGroup.links[0].url} external size="lg" icon="download" class="rounded-full">Download for {detectedGroup.label}</Button>
                  {/if}
                  {#if detectedGroup.links.length > 1}
                    <div class="flex flex-wrap justify-center gap-3">
                      {#each detectedGroup.links.slice(1) as link (link.id)}
                        <a href={link.url} target="_blank" rel="noopener" class="text-xs text-muted transition-colors hover:text-fg">{link.format ? link.format.toUpperCase() : 'Alt'}{link.arch ? ` · ${link.arch}` : ''}</a>
                      {/each}
                    </div>
                  {/if}
                </div>
              </div>
            </div>
          {/if}

          {#if secondaryGroups.length > 0}
            <div class="grid gap-4 sm:grid-cols-2 md:grid-cols-4">
              {#each secondaryGroups as group, i (group.platform)}
                <div class="glass flex flex-col gap-3 rounded-xl p-5 transition-[transform,border-color] duration-300 hover:-translate-y-1 hover:border-white/[0.16]" use:reveal={{ delay: (i + 1) * 70 }}>
                  <div class="flex items-center gap-3">
                    <span class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-cyan/20 bg-cyan/10 text-cyan"><Icon name={group.icon} size={20} /></span>
                    <div>
                      <div class="font-display text-sm font-bold">{group.label}</div>
                      <div class="text-[11.5px] text-muted">{group.links.length} build{group.links.length !== 1 ? 's' : ''}</div>
                    </div>
                  </div>
                  <div class="mt-auto flex flex-col gap-2">
                    {#if group.links[0]}
                      <Button href={group.links[0].url} external variant="secondary" size="sm" icon="download" class="w-full rounded-full">Download</Button>
                    {/if}
                    {#if group.links.length > 1}
                      <div class="flex flex-wrap justify-center gap-2">
                        {#each group.links.slice(1) as link (link.id)}
                          <a href={link.url} target="_blank" rel="noopener" class="text-[11px] text-muted transition-colors hover:text-fg">{link.format ? link.format.toUpperCase() : 'Alt'}{link.arch ? ` · ${link.arch}` : ''}</a>
                        {/each}
                      </div>
                    {/if}
                  </div>
                </div>
              {/each}
            </div>
          {/if}
        {:else}
          <div class="glass rounded-2xl p-8 text-center" use:reveal>
            <span class="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-xl border border-white/[0.08] bg-white/[0.03] text-muted"><Icon name="package" size={22} /></span>
            <p class="font-display text-lg font-bold">Installers are being prepared</p>
            <p class="mt-1 text-sm text-muted">Native clients are on the way. In the meantime, build from source on GitHub.</p>
            <Button href={GITHUB_URL} external variant="secondary" size="sm" icon="github" class="mt-5 rounded-full">View the repository</Button>
          </div>
        {/if}
      </div>
    </section>

    <!-- ==================== QUICK START ==================== -->
    <section class="py-16 md:py-24">
      <div class="mx-auto max-w-3xl px-5 sm:px-6">
        {@render heading('Self-hosting', 'Running in under 60 seconds', 'Three commands and your own zero-knowledge relay is live.')}

        <div class="space-y-3">
          {#each quickstart as step, i (step.id)}
            <div class="flex items-center gap-3 rounded-xl border border-white/[0.08] bg-[rgba(6,13,26,0.9)] px-4 py-3" use:reveal={{ delay: i * 80 }}>
              <span class="w-5 shrink-0 text-center font-mono text-xs text-dim">{step.id}</span>
              <div class="min-w-0 flex-1 overflow-x-auto whitespace-nowrap font-mono text-[13px] text-fg"><span class="text-cyan">❯</span> {step.cmd}</div>
              <button type="button" class="shrink-0 transition-colors {copiedCmd === step.id ? 'text-mint' : 'text-muted hover:text-fg'}" aria-label="Copy command" onclick={() => copyText(step.cmd, step.id)}>
                <Icon name={copiedCmd === step.id ? 'check' : 'copy'} size={14} />
              </button>
            </div>
          {/each}
        </div>
      </div>
    </section>

    <!-- ==================== COMPARISON ==================== -->
    <section class="py-16 md:py-24">
      <div class="mx-auto max-w-4xl px-5 sm:px-6">
        {@render heading('Compare', 'How cpmesh stacks up', 'Not all clipboard sync is created equal.')}

        <div class="glass hidden overflow-hidden rounded-2xl md:block" use:reveal>
          <table class="w-full border-collapse text-sm">
            <thead>
              <tr class="border-b border-white/[0.06]">
                <th class="w-[220px] px-5 py-4 text-left text-xs font-medium uppercase tracking-wider text-muted">Feature</th>
                <th class="px-4 py-4 text-center"><span class="text-gradient font-display text-sm font-bold">cpmesh</span></th>
                <th class="px-4 py-4 text-center text-xs font-medium text-muted">Apple Handoff</th>
                <th class="px-4 py-4 text-center text-xs font-medium text-muted">Windows Clipboard</th>
                <th class="px-4 py-4 text-center text-xs font-medium text-muted">Pushbullet</th>
              </tr>
            </thead>
            <tbody>
              {#each comparison as row (row.feature)}
                <tr class="border-b border-white/[0.04] last:border-0">
                  <td class="px-5 py-3.5 text-muted">{row.feature}</td>
                  <td class="bg-mint/[0.04] px-4 py-3.5 text-center">{#if row.cpmesh}<Icon name="check" size={16} class="text-mint" />{:else}<Icon name="x" size={16} class="text-dim/40" />{/if}</td>
                  <td class="px-4 py-3.5 text-center">{#if row.handoff}<Icon name="check" size={16} class="text-muted" />{:else}<Icon name="x" size={16} class="text-dim/40" />{/if}</td>
                  <td class="px-4 py-3.5 text-center">{#if row.winclip}<Icon name="check" size={16} class="text-muted" />{:else}<Icon name="x" size={16} class="text-dim/40" />{/if}</td>
                  <td class="px-4 py-3.5 text-center">{#if row.pushbullet}<Icon name="check" size={16} class="text-muted" />{:else}<Icon name="x" size={16} class="text-dim/40" />{/if}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>

        <div class="space-y-3 md:hidden">
          {#each comparison as row, i (row.feature)}
            <div class="glass flex items-center justify-between rounded-xl p-4" use:reveal={{ delay: i * 40 }}>
              <span class="text-sm text-muted">{row.feature}</span>
              <div class="ml-3 flex shrink-0 items-center gap-3">
                <Icon name="check" size={15} class="text-mint" />
                {#if !row.handoff && !row.winclip && !row.pushbullet}
                  <span class="text-[10px] font-medium uppercase tracking-wide text-dim">only cpmesh</span>
                {/if}
              </div>
            </div>
          {/each}
        </div>
      </div>
    </section>

    <!-- ==================== PRICING ==================== -->
    <section class="py-16 md:py-24" id="pricing">
      <div class="mx-auto max-w-3xl px-5 sm:px-6">
        {@render heading('Pricing', 'Free and open source', 'Dual licensed under MIT and Apache-2.0. Self-host for free with Docker — no limits, no telemetry, no strings attached.')}

        <div class="grid gap-5 sm:grid-cols-2">
          <div class="ring-card rounded-2xl p-6" style="--ring-from: rgba(42,214,160,0.6); --ring-to: rgba(73,198,229,0.35);" use:reveal>
            <span class="text-[11px] font-bold uppercase tracking-widest text-mint">Self-hosted</span>
            <div class="mt-3 flex items-baseline gap-2"><span class="font-display text-4xl font-bold tracking-tight">Free</span><span class="text-xs text-muted">forever · no limits</span></div>
            <ul class="mt-5 space-y-3">
              {#each ['Unlimited devices', 'Full clipboard history', 'Text, images, files (25 MB)', 'Your infrastructure, your rules'] as item (item)}
                <li class="flex items-center gap-2 text-sm text-fg"><Icon name="check" size={14} class="text-mint" /> {item}</li>
              {/each}
            </ul>
            <Button href={GITHUB_URL} external variant="mint" size="lg" iconRight="arrow-right" class="mt-6 w-full rounded-full">Deploy your relay</Button>
          </div>

          <div class="glass rounded-2xl p-6" use:reveal={{ delay: 100 }}>
            <span class="text-[11px] font-bold uppercase tracking-widest text-accent">Hosted relay</span>
            <div class="mt-3 flex items-baseline gap-2"><span class="font-display text-4xl font-bold tracking-tight">Coming soon</span></div>
            <p class="mt-1 text-xs text-muted">don't want to run a server? we will.</p>
            <ul class="mt-5 space-y-3">
              {#each ['Zero-config relay', 'Managed infrastructure', 'Same end-to-end encryption', 'Generous free tier planned'] as item (item)}
                <li class="flex items-center gap-2 text-sm text-fg"><Icon name="check" size={14} class="text-accent" /> {item}</li>
              {/each}
            </ul>
            <Button variant="outline" size="lg" disabled class="mt-6 w-full rounded-full">Notify me</Button>
          </div>
        </div>
      </div>
    </section>

    <!-- ==================== FINAL CTA ==================== -->
    <section class="py-20 md:py-28">
      <div class="mx-auto max-w-4xl px-5 sm:px-6" use:reveal>
        <div class="ring-card relative overflow-hidden rounded-3xl px-6 py-14 text-center md:px-12" style="--ring-from: rgba(255,122,89,0.6); --ring-to: rgba(73,198,229,0.4);">
          <div class="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_50%_120%,rgba(255,122,89,0.18),transparent_60%)]"></div>
          <div class="dot-grid pointer-events-none absolute inset-0 opacity-30 [mask-image:radial-gradient(ellipse_at_center,black,transparent_70%)]"></div>
          <div class="relative">
            <h2 class="text-gradient font-display text-[clamp(2rem,5vw,3.4rem)] font-bold leading-[1.02] tracking-tight">Your clipboard belongs to you.</h2>
            <p class="mx-auto mt-5 max-w-lg text-lg text-muted">Stop sending sensitive data through services that can read it. Get cpmesh running in under a minute.</p>
            <div class="mt-9 flex flex-wrap justify-center gap-3">
              <Button href="#/login" size="lg" iconRight="arrow-right" class="rounded-full px-8">Get started free</Button>
              <Button href={GITHUB_URL} external variant="secondary" size="lg" icon="github" class="rounded-full px-8">Star on GitHub</Button>
            </div>
            <ul class="mt-9 flex flex-wrap justify-center gap-x-6 gap-y-2 text-[13px] text-muted">
              {#each [['shield', 'MIT / Apache-2.0'], ['lock', 'E2E encrypted'], ['server', 'Self-hosted'], ['zap', 'Sub-second']] as [icon, label] (label)}
                <li class="inline-flex items-center gap-1.5"><Icon name={icon} size={13} class="text-mint" /> {label}</li>
              {/each}
            </ul>
          </div>
        </div>
      </div>
    </section>
  </main>

  <!-- ==================== FOOTER ==================== -->
  <footer class="pb-10 pt-4">
    <div class="mx-auto max-w-6xl border-t border-white/[0.06] px-5 pt-8 sm:px-6">
      <div class="flex flex-col items-center justify-between gap-6 sm:flex-row sm:items-start">
        <div class="flex items-center gap-3">
          <Logo size={28} />
          <span class="text-sm text-muted">© {new Date().getFullYear()} cpmesh</span>
        </div>
        <nav class="flex items-center gap-5 text-sm text-muted" aria-label="Footer">
          <a href={GITHUB_URL} target="_blank" rel="noopener" class="inline-flex items-center gap-1.5 transition-colors hover:text-fg"><Icon name="github" size={14} /> Source</a>
          <a href="{GITHUB_URL}/blob/main/LICENSE" target="_blank" rel="noopener" class="transition-colors hover:text-fg">License</a>
          <a href="{GITHUB_URL}/blob/main/docs/self-hosting.md" target="_blank" rel="noopener" class="transition-colors hover:text-fg">Docs</a>
          <a href="#/login" class="transition-colors hover:text-fg">Sign in</a>
        </nav>
        <div class="inline-flex items-center gap-1.5 text-xs text-dim">Built with <Icon name="heart" size={11} class="text-accent" /> in Rust & Svelte</div>
      </div>
    </div>
  </footer>
</div>

<style>
  .latency-dot {
    animation: latency 2.4s var(--ease-out-expo) infinite;
  }
  @keyframes latency {
    0% {
      left: 0%;
      opacity: 0;
    }
    8% {
      opacity: 1;
    }
    45% {
      left: calc(50% - 8px);
    }
    55% {
      left: calc(50% - 8px);
    }
    92% {
      left: calc(100% - 16px);
      opacity: 1;
    }
    100% {
      left: calc(100% - 16px);
      opacity: 0;
    }
  }

  .cipher-swap {
    animation: swap-a 5s ease-in-out infinite;
  }
  .cipher-swap-alt {
    animation: swap-b 5s ease-in-out infinite;
  }
  @keyframes swap-a {
    0%,
    38% {
      opacity: 1;
      transform: translateY(0);
    }
    48%,
    88% {
      opacity: 0;
      transform: translateY(-6px);
    }
    100% {
      opacity: 1;
      transform: translateY(0);
    }
  }
  @keyframes swap-b {
    0%,
    38% {
      opacity: 0;
      transform: translateY(6px);
    }
    48%,
    88% {
      opacity: 1;
      transform: translateY(0);
    }
    100% {
      opacity: 0;
      transform: translateY(6px);
    }
  }
</style>
