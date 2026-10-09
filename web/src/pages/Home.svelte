<script lang="ts">
  import { onMount } from 'svelte';
  import Icon from '../components/Icon.svelte';
  import Logo from '../components/Logo.svelte';
  import SyncDemo from '../components/landing/SyncDemo.svelte';
  import Button from '../components/ui/Button.svelte';
  import Badge from '../components/ui/Badge.svelte';
  import RetroGrid from '../components/magic/RetroGrid.svelte';
  import Marquee from '../components/magic/Marquee.svelte';
  import NumberTicker from '../components/magic/NumberTicker.svelte';
  import WordRotate from '../components/magic/WordRotate.svelte';
  import BorderBeam from '../components/magic/BorderBeam.svelte';
  import Meteors from '../components/magic/Meteors.svelte';
  import OrbitingCircles from '../components/magic/OrbitingCircles.svelte';
  import AnimatedList from '../components/magic/AnimatedList.svelte';
  import ScrollProgress from '../components/magic/ScrollProgress.svelte';
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
    { type: 'output', text: '✓ relay listening on :8080 · dashboard at http://localhost:39271', color: '#3ddc97' },
    { type: 'blank', text: '' },
    { type: 'prompt', text: 'cpmesh pair' },
    { type: 'output', text: '✓ paired 3 devices · ECDH keys exchanged · relay never saw them', color: '#3ddc97' },
    { type: 'blank', text: '' },
    { type: 'prompt', text: 'cpmesh status' },
    { type: 'output', text: '  macbook-pro    ● connected   12ms', color: '#3ddc97' },
    { type: 'output', text: '  work-pc        ● connected   18ms', color: '#3ddc97' },
    { type: 'output', text: '  pixel-9        ● idle', color: '#ffd93d' },
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
  const rotateWords = ['laptop.', 'phone.', 'desktop.', 'tablet.', 'everything.'];

  const stats = [
    { value: 256, suffix: '-bit', label: 'AES-GCM authenticated keys', icon: 'lock', fill: 'bg-accent' },
    { value: 1, prefix: '< ', suffix: ' s', label: 'copy-to-paste latency', icon: 'zap', fill: 'bg-cyan' },
    { value: 5, suffix: '', label: 'native platforms + web', icon: 'layers', fill: 'bg-yellow' },
    { value: 0, suffix: ' bytes', label: 'readable by the relay', icon: 'eye-off', fill: 'bg-mint' },
  ];

  const marqueeItems = ['AES-256-GCM', 'ECDH P-256', 'Zero-knowledge relay', 'Self-hosted in 60s', 'Open source', 'Sub-second sync', 'No telemetry', 'Files up to 25 MB'];

  const pains = [
    { icon: 'send', title: 'Emailing yourself', desc: 'Sending links and snippets to your own inbox. In 2026. Really.' },
    { icon: 'hard-drive', title: 'USB drives', desc: 'Carrying a flash drive between rooms like it is 2005.' },
    { icon: 'cloud', title: 'Big-cloud clipboards', desc: 'Apple, Google and Microsoft sync your clipboard — and can read every word.' },
  ];

  const steps = [
    { num: '01', icon: 'download', title: 'Install', desc: 'Run the relay with one Docker command — or skip it and use ours — then grab the native app.', fill: 'bg-cyan', shadow: 'var(--color-cyan)' },
    { num: '02', icon: 'key', title: 'Pair', desc: 'Sign in on each device. Keys are exchanged device-to-device over ECDH; the relay only forwards sealed bytes.', fill: 'bg-accent', shadow: 'var(--color-accent)' },
    { num: '03', icon: 'clipboard', title: 'Copy & paste', desc: 'That is it. Text, images and files show up on every device in under a second.', fill: 'bg-mint', shadow: 'var(--color-mint)' },
  ];

  const platforms = [
    { icon: 'windows', name: 'Windows', desc: 'Tray app, auto-start', fill: '#5ad1f0' },
    { icon: 'apple', name: 'macOS', desc: 'Menu-bar native', fill: '#fffaf0' },
    { icon: 'linux', name: 'Linux', desc: 'Wayland & X11', fill: '#ffd93d' },
    { icon: 'android', name: 'Android', desc: 'Background service', fill: '#3ddc97' },
    { icon: 'globe', name: 'Web', desc: 'Dashboard & history', fill: '#ff7a59' },
  ];

  const liveClips = [
    { icon: 'type', fill: 'bg-mint', title: 'Text from MacBook Pro', meta: '41 B · 11 ms' },
    { icon: 'image', fill: 'bg-violet', title: 'Screenshot from Pixel 9', meta: '1.2 MB · 240 ms' },
    { icon: 'link', fill: 'bg-cyan', title: 'Link from Work PC', meta: '63 B · 9 ms' },
    { icon: 'file', fill: 'bg-yellow', title: 'invoice-0423.pdf from MacBook Pro', meta: '384 KB · 120 ms' },
    { icon: 'terminal', fill: 'bg-accent', title: 'Command from Work PC', meta: '20 B · 8 ms' },
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
</script>

<svelte:head>
  <title>cpmesh — Encrypted clipboard sync across all your devices</title>
  <meta name="description" content="Copy on one device, paste on another. End-to-end encrypted with AES-256-GCM. Open source. Self-host with Docker or use our relay." />
</svelte:head>

{#snippet heading(eyebrow: string, title: string, sub?: string)}
  <div class="mx-auto mb-12 max-w-3xl text-center md:mb-16" use:reveal={{ blur: true }}>
    <span class="mb-4 inline-block rounded-sm border-2 border-ink bg-yellow px-2.5 py-1 font-head text-[10.5px] uppercase tracking-[0.2em] text-ink shadow-sm">{eyebrow}</span>
    <h2 class="font-head text-[clamp(1.9rem,3.4vw,3.2rem)] leading-[1.05] text-ink">{title}</h2>
    {#if sub}<p class="mx-auto mt-4 max-w-2xl text-[15px] leading-relaxed text-muted md:text-base">{sub}</p>{/if}
  </div>
{/snippet}

<ScrollProgress />

<div class="home relative min-h-dvh overflow-x-clip bg-bg text-ink">
  <!-- ==================== HEADER ==================== -->
  <header class="sticky top-0 z-40 border-b-2 border-ink bg-bg/92 backdrop-blur-sm">
    <div class="wrap flex h-16 items-center justify-between">
      <button type="button" class="inline-flex items-center gap-2.5 bg-transparent p-0" onclick={() => scrollToId('top')} aria-label="Back to top">
        <Logo size={34} withText textClass="text-[17px]" />
      </button>

      <nav class="hidden items-center gap-1 md:flex" aria-label="Primary">
        {#each navLinks as link (link.id)}
          <button type="button" class="rounded-md border-2 border-transparent px-3 py-1.5 font-head text-[12px] uppercase tracking-[0.08em] text-ink transition-colors hover:border-ink hover:bg-yellow" onclick={() => scrollToId(link.id)}>{link.label}</button>
        {/each}
        <a href={GITHUB_URL} target="_blank" rel="noopener" class="ml-1 inline-flex items-center gap-1.5 rounded-md border-2 border-transparent px-3 py-1.5 font-head text-[12px] uppercase tracking-[0.08em] text-ink transition-colors hover:border-ink hover:bg-yellow">
          <Icon name="github" size={15} /> GitHub
        </a>
      </nav>

      <div class="flex items-center gap-2">
        <span class="hidden sm:contents"><Button href="#/login" variant="outline" size="sm">Sign in</Button></span>
        <Button href="#/login" size="sm" iconRight="arrow-right">Get started</Button>
        <button type="button" class="ml-1 flex h-10 w-10 items-center justify-center rounded-md border-2 border-ink bg-surface text-ink shadow-xs md:hidden" aria-label="Open navigation menu" aria-expanded={mobileNavOpen} onclick={() => (mobileNavOpen = !mobileNavOpen)}>
          <Icon name="menu" size={22} strokeWidth={2.5} />
        </button>
      </div>
    </div>
  </header>

  {#if mobileNavOpen}
    <div class="dot-grid fixed inset-0 z-50 flex flex-col items-center justify-center gap-6 bg-bg animate-[fade-in_0.2s_ease-out]">
      <button type="button" class="absolute right-5 top-5 flex h-11 w-11 items-center justify-center rounded-md border-2 border-ink bg-surface shadow-sm" aria-label="Close navigation" onclick={() => (mobileNavOpen = false)}>
        <Icon name="x" size={24} strokeWidth={2.5} />
      </button>
      {#each navLinks as link (link.id)}
        <button type="button" class="font-head text-3xl text-ink transition-colors hover:text-accent" onclick={() => scrollToId(link.id)}>{link.label}</button>
      {/each}
      <a href={GITHUB_URL} target="_blank" rel="noopener" class="inline-flex items-center gap-2 font-head text-3xl text-ink hover:text-accent"><Icon name="github" size={26} /> GitHub</a>
      <Button href="#/login" size="lg" class="mt-4 px-10">Sign in</Button>
    </div>
  {/if}

  <main id="main-content">
    <!-- ==================== HERO ==================== -->
    <section class="relative overflow-hidden pb-16 pt-12 md:pb-24 md:pt-20 2xl:pt-24" id="top">
      <div class="dot-grid pointer-events-none absolute inset-0 opacity-50 [mask-image:linear-gradient(180deg,black,transparent_85%)]"></div>
      <RetroGrid class="top-auto! h-[55%]" opacity={0.6} />

      <div class="wrap relative">
        <div class="grid grid-cols-1 items-center gap-12 lg:grid-cols-[minmax(0,1.05fr)_minmax(0,1fr)] lg:gap-16 2xl:gap-24">
          <div class="text-center lg:text-left" use:reveal={{ immediate: true, blur: true }}>
            <a href="{GITHUB_URL}/releases" target="_blank" rel="noopener" class="group inline-flex items-center gap-2 rounded-md border-2 border-ink bg-surface py-1.5 pl-1.5 pr-4 text-[13px] shadow-sm transition-[transform,box-shadow] hover:-translate-x-px hover:-translate-y-px hover:shadow-md">
              <span class="rounded-sm border-2 border-ink bg-mint px-2 py-0.5 font-head text-[10.5px] uppercase tracking-wide text-ink">Open source</span>
              <span class="shiny-text font-semibold text-ink/70">MIT / Apache-2.0 · self-hostable</span>
              <Icon name="arrow-up-right" size={13} class="text-ink transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" strokeWidth={2.5} />
            </a>

            <h1 class="mt-7 font-head leading-[0.98] tracking-[-0.02em]">
              <span class="block text-[clamp(2.6rem,4.4vw,5rem)] text-ink">Copy anywhere.</span>
              <span class="block text-[clamp(2.6rem,4.4vw,5rem)] text-ink">
                Paste on your
                <span class="text-gradient"><WordRotate words={rotateWords} /></span>
              </span>
            </h1>
            <p class="mx-auto mt-6 max-w-xl text-[17px] leading-relaxed text-muted lg:mx-0 2xl:text-lg">
              One clipboard across every device you own — text, images and files —
              <span class="marker font-semibold text-ink">encrypted before it leaves your machine</span>. The relay never sees a readable byte.
            </p>

            <div class="mt-9 flex flex-wrap justify-center gap-3 lg:justify-start">
              <Button href="#/login" size="lg" iconRight="arrow-right" shine>Get started free</Button>
              <Button onclick={() => scrollToId('downloads')} variant="outline" size="lg" icon="download">Download the app</Button>
            </div>

            <ul class="mt-8 flex flex-wrap justify-center gap-x-5 gap-y-2 text-[13px] font-semibold text-muted lg:justify-start">
              {#each ['AES-256-GCM', 'Zero-knowledge relay', 'Sub-second sync', 'No telemetry'] as item (item)}
                <li class="inline-flex items-center gap-1.5"><span class="flex h-4 w-4 items-center justify-center rounded-sm border-2 border-ink bg-mint"><Icon name="check" size={10} strokeWidth={3.5} /></span> {item}</li>
              {/each}
            </ul>
          </div>

          <div class="mx-auto w-full max-w-[600px] lg:max-w-none" use:reveal={{ immediate: true, delay: 150 }}>
            <SyncDemo />
          </div>
        </div>

        <!-- Stats strip -->
        <div class="mt-16 grid grid-cols-2 gap-4 md:grid-cols-4 md:gap-5" use:reveal={{ delay: 100 }}>
          {#each stats as s (s.label)}
            <div class="panel panel-hover flex items-center gap-3 px-4 py-4">
              <span class="flex h-11 w-11 shrink-0 items-center justify-center rounded-md border-2 border-ink text-ink shadow-xs {s.fill}"><Icon name={s.icon} size={18} strokeWidth={2.4} /></span>
              <div class="min-w-0">
                <p class="font-head text-xl leading-none text-ink 2xl:text-2xl"><NumberTicker value={s.value} prefix={s.prefix ?? ''} suffix={s.suffix} /></p>
                <p class="mt-1 truncate text-[12px] font-medium text-muted">{s.label}</p>
              </div>
            </div>
          {/each}
        </div>
      </div>
    </section>

    <!-- ==================== MARQUEE BAND ==================== -->
    <section class="border-y-2 border-ink bg-ink py-3 text-yellow" aria-label="Highlights">
      <Marquee duration={36} gap="2.5rem" pauseOnHover={false} class="p-0">
        {#each marqueeItems as item (item)}
          <span class="inline-flex items-center gap-6 font-head text-sm uppercase tracking-[0.16em] whitespace-nowrap">
            {item}
            <Icon name="sparkles" size={14} class="text-accent" />
          </span>
        {/each}
      </Marquee>
    </section>

    <!-- ==================== THE PROBLEM ==================== -->
    <section class="stripes border-b-2 border-ink bg-bg-deep py-16 md:py-24">
      <div class="wrap">
        {@render heading('The problem', 'There has to be a better way.', 'Everyone moves data between devices all day. The usual options are embarrassing — or hand your clipboard to a company that can read it.')}

        <div class="grid grid-cols-1 gap-6 lg:grid-cols-2 lg:gap-8">
          <div class="flex flex-col gap-4">
            {#each pains as pain, i (pain.title)}
              <div class="panel panel-hover flex items-start gap-4 p-5" style="--panel-shadow: var(--color-rose);" use:reveal={{ delay: i * 90 }}>
                <span class="flex h-11 w-11 shrink-0 items-center justify-center rounded-md border-2 border-ink bg-rose text-ink shadow-xs"><Icon name={pain.icon} size={18} strokeWidth={2.4} /></span>
                <div>
                  <h3 class="font-head text-[15px] text-ink">{pain.title}</h3>
                  <p class="mt-1 text-sm leading-relaxed text-muted">{pain.desc}</p>
                </div>
              </div>
            {/each}
          </div>

          <div class="panel-ink relative flex flex-col justify-center overflow-hidden rounded-lg p-7 md:p-9" style="--panel-shadow: var(--color-mint);" use:reveal={{ delay: 200 }}>
            <Meteors number={10} color="#3ddc97" />
            <div class="relative">
              <div class="mb-4 inline-flex items-center gap-3">
                <Logo size={34} />
                <span class="font-head text-2xl text-cream">cpmesh</span>
              </div>
              <p class="text-[15px] leading-relaxed text-cream/80">Copy on any device. Paste on any other. The relay only ever sees encrypted noise, because your keys never leave your hardware.</p>
              <ul class="mt-6 space-y-3">
                {#each ['Zero-knowledge relay architecture', 'AES-256-GCM on-device encryption', 'Your infrastructure, your rules', 'Every platform, one clipboard'] as point (point)}
                  <li class="flex items-center gap-3 text-sm text-cream"><span class="flex h-5 w-5 shrink-0 items-center justify-center rounded-sm border-2 border-cream bg-mint text-ink"><Icon name="check" size={12} strokeWidth={3.5} /></span> {point}</li>
                {/each}
              </ul>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- ==================== HOW IT WORKS ==================== -->
    <section class="py-16 md:py-24">
      <div class="wrap">
        {@render heading('How it works', 'Up and running in three steps', 'No configuration. No key management. Install, pair, start pasting.')}

        <div class="relative grid grid-cols-1 gap-6 md:grid-cols-3 md:gap-8">
          <div class="pointer-events-none absolute left-[16%] right-[16%] top-16 hidden border-t-2 border-dashed border-ink/40 md:block"></div>
          {#each steps as step, i (step.num)}
            <article class="panel panel-hover relative overflow-hidden p-6 pt-7" style="--panel-shadow: {step.shadow};" use:reveal={{ delay: i * 120 }}>
              <span class="pointer-events-none absolute -right-1 -top-5 select-none font-head text-[6rem] leading-none text-ink/[0.06]">{step.num}</span>
              <span class="relative mb-5 inline-flex h-13 w-13 items-center justify-center rounded-md border-2 border-ink text-ink shadow-sm {step.fill}">
                <Icon name={step.icon} size={24} strokeWidth={2.3} />
              </span>
              <h3 class="font-head text-xl text-ink">{step.title}</h3>
              <p class="mt-2 text-sm leading-relaxed text-muted">{step.desc}</p>
            </article>
          {/each}
        </div>
      </div>
    </section>

    <!-- ==================== TERMINAL ==================== -->
    <section class="border-y-2 border-ink bg-bg-deep py-16 md:py-24">
      <div class="wrap grid grid-cols-1 items-start gap-10 lg:grid-cols-[minmax(0,1.2fr)_minmax(0,0.8fr)] lg:gap-14">
        <div>
          <div class="mb-8" use:reveal={{ blur: true }}>
            <span class="mb-4 inline-block rounded-sm border-2 border-ink bg-yellow px-2.5 py-1 font-head text-[10.5px] uppercase tracking-[0.2em] text-ink shadow-sm">See it in action</span>
            <h2 class="font-head text-[clamp(1.9rem,3.4vw,3.2rem)] leading-[1.05] text-ink">Three commands.<br />Zero ceremony.</h2>
          </div>

          <div class="panel-ink overflow-hidden rounded-lg" style="--panel-shadow: var(--color-accent);" use:reveal={{ onreveal: () => (terminalStarted = true) }}>
            <div class="flex items-center gap-2 border-b-2 border-cream/20 px-4 py-3">
              <span class="h-3 w-3 rounded-full border-2 border-cream/60 bg-rose"></span>
              <span class="h-3 w-3 rounded-full border-2 border-cream/60 bg-yellow"></span>
              <span class="h-3 w-3 rounded-full border-2 border-cream/60 bg-mint"></span>
              <span class="ml-3 font-mono text-[11px] text-cream/60">zsh — cpmesh</span>
              <button type="button" class="ml-auto inline-flex items-center gap-1 rounded-sm border-2 border-cream/30 px-2 py-0.5 font-mono text-[11px] text-cream/70 hover:border-cream hover:text-cream" onclick={replayTerminal}>
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
                      <div><span class="text-yellow">❯</span> <span class="text-cream">{line.text}</span></div>
                    {:else if line.type === 'comment'}
                      <div class="text-cream/50">{line.text}</div>
                    {:else if line.text.startsWith('✓')}
                      <div><span style="color: {line.color}">✓</span><span class="text-cream/80">{line.text.slice(1)}</span></div>
                    {:else if line.text.includes('●')}
                      <div><span class="text-cream/80">{line.text.split('●')[0]}</span><span style="color: {line.color}">●{line.text.split('●')[1]}</span></div>
                    {:else}
                      <div class="text-cream/80">{line.text}</div>
                    {/if}
                  </div>
                {/if}
              {/each}
              {#if terminalStep < terminalLines.length}
                <span class="ml-0.5 inline-block h-[15px] w-[8px] bg-yellow align-middle animate-[blink_1s_step-end_infinite]"></span>
              {/if}
            </div>
          </div>
        </div>

        <div class="flex flex-col gap-5 lg:pt-28">
          <div class="panel p-4" style="--panel-shadow: var(--color-cyan);" use:reveal={{ delay: 120 }}>
            <div class="mb-3 flex items-center justify-between">
              <span class="font-mono text-[11px] font-semibold text-ink">docker-compose.yml</span>
              <button type="button" class="inline-flex items-center gap-1.5 rounded-sm border-2 border-ink px-2 py-0.5 text-[11px] font-semibold shadow-xs transition-colors {copiedCmd === 'docker' ? 'bg-mint text-ink' : 'bg-surface text-ink hover:bg-yellow'}" onclick={() => copyText(dockerCompose, 'docker')}>
                <Icon name={copiedCmd === 'docker' ? 'check' : 'copy'} size={12} strokeWidth={2.5} />
                {copiedCmd === 'docker' ? 'Copied' : 'Copy'}
              </button>
            </div>
            <pre class="overflow-x-auto font-mono text-[12.5px] leading-6 text-muted"><code><span class="text-accent-deep">services</span>:
  <span class="text-ink">relay</span>:
    <span class="text-ink">image</span>: <span class="text-muted">ghcr.io/cjs0h/cpmesh:latest</span>
    <span class="text-ink">ports</span>: [<span class="text-accent-deep">"39271:8080"</span>]
    <span class="text-ink">volumes</span>: [<span class="text-accent-deep">"./data:/data"</span>]
    <span class="text-ink">restart</span>: <span class="text-muted">unless-stopped</span></code></pre>
          </div>

          <div class="space-y-3" use:reveal={{ delay: 200 }}>
            {#each quickstart as step (step.id)}
              <div class="panel flex items-center gap-3 px-4 py-3">
                <span class="flex h-6 w-6 shrink-0 items-center justify-center rounded-sm border-2 border-ink bg-yellow font-head text-[11px]">{step.id}</span>
                <div class="min-w-0 flex-1 overflow-x-auto whitespace-nowrap font-mono text-[12.5px] text-ink"><span class="text-accent-deep">❯</span> {step.cmd}</div>
                <button type="button" class="shrink-0 transition-colors {copiedCmd === step.id ? 'text-mint' : 'text-ink/50 hover:text-ink'}" aria-label="Copy command" onclick={() => copyText(step.cmd, step.id)}>
                  <Icon name={copiedCmd === step.id ? 'check' : 'copy'} size={14} strokeWidth={2.5} />
                </button>
              </div>
            {/each}
          </div>
        </div>
      </div>
    </section>

    <!-- ==================== FEATURES (bento) ==================== -->
    <section class="py-16 md:py-24" id="features">
      <div class="wrap">
        {@render heading('Why cpmesh', 'Built for people who care where their data goes')}

        <div class="grid grid-cols-1 gap-5 md:grid-cols-6 md:gap-6">
          <!-- Sub-second sync + Animated List -->
          <article class="panel relative overflow-hidden p-6 md:col-span-4" style="--panel-shadow: var(--color-cyan);" use:reveal>
            <div class="grid grid-cols-1 gap-6 md:grid-cols-2 md:items-center">
              <div>
                <span class="mb-4 inline-flex h-11 w-11 items-center justify-center rounded-md border-2 border-ink bg-cyan text-ink shadow-xs"><Icon name="zap" size={18} strokeWidth={2.4} /></span>
                <h3 class="font-head text-xl text-ink">Sub-second sync</h3>
                <p class="mt-2 text-sm leading-relaxed text-muted">WebSocket push, not polling. Your clipboard arrives on the other device before you finish switching windows.</p>
                <p class="mt-4 inline-flex items-center gap-2 rounded-sm border-2 border-ink bg-surface-2 px-2 py-1 font-mono text-[11px] text-ink"><span class="status-dot text-mint" data-live="true"></span> 12 ms p95 on LAN</p>
              </div>
              <div class="dot-grid rounded-md border-2 border-ink bg-surface-2 p-3">
                <AnimatedList items={liveClips} interval={1700}>
                  {#snippet item(clip)}
                    <div class="flex items-center gap-3 rounded-md border-2 border-ink bg-cream px-3 py-2 shadow-sm">
                      <span class="flex h-8 w-8 shrink-0 items-center justify-center rounded border-2 border-ink text-ink {clip.fill}"><Icon name={clip.icon} size={14} strokeWidth={2.5} /></span>
                      <div class="min-w-0">
                        <p class="truncate text-[12.5px] font-semibold text-ink">{clip.title}</p>
                        <p class="font-mono text-[10.5px] text-muted">{clip.meta}</p>
                      </div>
                    </div>
                  {/snippet}
                </AnimatedList>
              </div>
            </div>
          </article>

          <!-- E2E -->
          <article class="panel relative overflow-hidden p-6 md:col-span-2" style="--panel-shadow: var(--color-accent);" use:reveal={{ delay: 80 }}>
            <span class="mb-4 inline-flex h-11 w-11 items-center justify-center rounded-md border-2 border-ink bg-accent text-ink shadow-xs"><Icon name="lock" size={18} strokeWidth={2.4} /></span>
            <h3 class="font-head text-xl text-ink">End-to-end encrypted</h3>
            <p class="mt-2 text-sm leading-relaxed text-muted">AES-256-GCM happens on-device. Keys are born there and die there.</p>
            <div class="relative mt-5 h-11">
              <span class="cipher-swap absolute inset-0 flex items-center rounded-md border-2 border-ink bg-cream px-3 text-[12.5px] font-semibold text-ink shadow-sm">“Meet at 3pm — bring the deck”</span>
              <span class="cipher-swap-alt absolute inset-0 flex items-center rounded-md border-2 border-ink bg-ink px-3 font-mono text-[11px] tracking-wide text-yellow shadow-[3px_3px_0_0_#ff7a59]">8f3a 1c9e 42b7 d0e5 77aa 91f2</span>
            </div>
          </article>

          <!-- Platforms -->
          <article class="panel p-6 md:col-span-2" style="--panel-shadow: var(--color-yellow);" use:reveal={{ delay: 120 }}>
            <span class="mb-4 inline-flex h-11 w-11 items-center justify-center rounded-md border-2 border-ink bg-yellow text-ink shadow-xs"><Icon name="layers" size={18} strokeWidth={2.4} /></span>
            <h3 class="font-head text-xl text-ink">Every platform</h3>
            <p class="mt-2 text-sm leading-relaxed text-muted">Native Windows, macOS, Linux and Android clients. Plus this web dashboard.</p>
            <div class="mt-5 flex gap-2">
              {#each platforms as p (p.name)}
                <span class="flex h-10 flex-1 items-center justify-center rounded-md border-2 border-ink text-ink shadow-xs transition-transform hover:-translate-y-0.5" style="background: {p.fill};" title={p.name}><Icon name={p.icon} size={18} /></span>
              {/each}
            </div>
          </article>

          <!-- Self-host -->
          <article class="panel p-6 md:col-span-2" style="--panel-shadow: var(--color-mint);" use:reveal={{ delay: 160 }}>
            <span class="mb-4 inline-flex h-11 w-11 items-center justify-center rounded-md border-2 border-ink bg-mint text-ink shadow-xs"><Icon name="server" size={18} strokeWidth={2.4} /></span>
            <h3 class="font-head text-xl text-ink">Self-host or use ours</h3>
            <p class="mt-2 text-sm leading-relaxed text-muted">One Docker command on any box you own — or point the apps at our hosted relay.</p>
            <code class="mt-5 flex items-center gap-2 rounded-md border-2 border-ink bg-ink px-3 py-2 font-mono text-[12px] text-cream shadow-sm"><span class="text-yellow">❯</span> docker compose up -d</code>
          </article>

          <!-- History -->
          <article class="panel p-6 md:col-span-2" style="--panel-shadow: var(--color-violet);" use:reveal={{ delay: 200 }}>
            <span class="mb-4 inline-flex h-11 w-11 items-center justify-center rounded-md border-2 border-ink bg-violet text-ink shadow-xs"><Icon name="history" size={18} strokeWidth={2.4} /></span>
            <h3 class="font-head text-xl text-ink">Clipboard history</h3>
            <p class="mt-2 text-sm leading-relaxed text-muted">Browse, search and restore past clips. Encrypted at rest, under your control.</p>
            <ul class="mt-5 space-y-1.5">
              {#each [['type', 'Text', '2m'], ['image', 'Image', '14m'], ['file', 'PDF', '1h']] as [icon, label, when] (label)}
                <li class="flex items-center gap-2.5 rounded-md border-2 border-ink bg-cream px-2.5 py-1.5 text-[12px] shadow-xs"><Icon name={icon} size={12} strokeWidth={2.5} /><span class="font-semibold text-ink">{label}</span><span class="ml-auto font-mono text-dim">{when}</span></li>
              {/each}
            </ul>
          </article>

          <!-- Open source + Border Beam -->
          <article class="panel relative overflow-hidden rounded-lg p-6 md:col-span-6" use:reveal={{ delay: 240 }}>
            <BorderBeam size={120} duration={7} colorFrom="#ffd93d" colorTo="#ff7a59" borderWidth={3} />
            <div class="flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
              <div class="max-w-2xl">
                <span class="mb-4 inline-flex h-11 w-11 items-center justify-center rounded-md border-2 border-ink bg-ink text-cream shadow-xs"><Icon name="github" size={18} /></span>
                <h3 class="font-head text-xl text-ink">Open source. Every line auditable.</h3>
                <p class="mt-2 text-sm leading-relaxed text-muted">Dual-licensed MIT / Apache-2.0. Rust relay, Tauri desktop apps, Kotlin on Android. No telemetry, no tracking, no strings attached.</p>
              </div>
              <div class="flex flex-wrap items-center gap-2">
                {#each ['Rust', 'Svelte', 'Tauri', 'Kotlin', 'PostgreSQL'] as tech (tech)}
                  <Badge tone="neutral" size="md">{tech}</Badge>
                {/each}
                <Button href={GITHUB_URL} external variant="secondary" size="sm" icon="github">Star on GitHub</Button>
              </div>
            </div>
          </article>
        </div>
      </div>
    </section>

    <!-- ==================== SECURITY ==================== -->
    <section class="grid-paper border-y-2 border-ink bg-bg-deep py-16 md:py-24" id="security">
      <div class="wrap">
        {@render heading('Security', 'Zero-knowledge by design', 'Your clipboard is encrypted before it leaves your device. The relay cannot decrypt it. Nobody can — except your own devices.')}

        <div class="panel p-6 md:p-8" use:reveal>
          <div class="flex flex-col items-center justify-center gap-3 md:flex-row md:gap-2">
            {#each [
              { icon: 'laptop', label: 'Your laptop', sub: 'Hello, world!', fill: '#5ad1f0', ink: false },
              { icon: 'lock', label: 'Encrypt', sub: 'AES-256-GCM', fill: '#ff7a59', ink: false },
              { icon: 'cloud', label: 'Relay', sub: '0x7f3a…b2e1', fill: '#111111', ink: true },
              { icon: 'key', label: 'Decrypt', sub: 'ECDH P-256', fill: '#3ddc97', ink: false },
              { icon: 'smartphone', label: 'Your phone', sub: 'Hello, world!', fill: '#5ad1f0', ink: false },
            ] as node, i (node.label)}
              {#if i > 0}
                <span class="text-ink/50"><Icon name="chevron-right" size={20} strokeWidth={3} class="rotate-90 md:rotate-0" /></span>
              {/if}
              <div class="flex min-w-[128px] flex-col items-center gap-2 rounded-md border-2 border-ink px-4 py-3 shadow-sm {node.ink ? 'text-cream' : 'text-ink'}" style="background: {node.fill};">
                <Icon name={node.icon} size={24} strokeWidth={2.3} />
                <span class="font-head text-xs">{node.label}</span>
                <span class="rounded-sm border-2 px-2 py-0.5 font-mono text-[10px] {node.ink ? 'border-cream/40 bg-cream/10 text-yellow' : 'border-ink bg-cream text-ink'}">{node.sub}</span>
              </div>
            {/each}
          </div>
          <p class="mt-6 text-center text-sm text-muted">The relay only forwards sealed bytes. It holds no keys and cannot read your data. <span class="font-head text-ink">Ever.</span></p>
        </div>

        <div class="mt-6 grid grid-cols-1 gap-5 sm:grid-cols-3">
          {#each [
            { title: 'AES-256-GCM', desc: 'Authenticated encryption for every entry — confidentiality and integrity in one pass.', shadow: 'var(--color-accent)' },
            { title: 'ECDH P-256', desc: 'Elliptic-curve key agreement between devices. Each device owns its keypair; nothing shared with the server.', shadow: 'var(--color-cyan)' },
            { title: 'Zero knowledge', desc: 'Compromise the relay and all you get is ciphertext. Your data stays noise.', shadow: 'var(--color-mint)' },
          ] as card, i (card.title)}
            <div class="panel panel-hover p-5" style="--panel-shadow: {card.shadow};" use:reveal={{ delay: i * 80 }}>
              <span class="font-mono text-sm font-bold text-ink">{card.title}</span>
              <p class="mt-2 text-sm leading-relaxed text-muted">{card.desc}</p>
            </div>
          {/each}
        </div>

        <div class="panel-ink mt-6 overflow-x-auto rounded-lg p-5" use:reveal={{ delay: 120 }}>
          <pre class="font-mono text-[12px] leading-6 sm:text-[13px]"><code><span class="text-cream/50">// what happens when you copy</span>
<span class="text-cream/80">plaintext</span>  <span class="text-cream/50">=</span> <span class="text-cyan">clipboard</span>.<span class="text-cream">read</span>()
<span class="text-cream/80">shared_key</span> <span class="text-cream/50">=</span> <span class="text-accent">ECDH</span>(<span class="text-cream">my_private</span>, <span class="text-cream">peer_public</span>)
<span class="text-cream/80">nonce</span>      <span class="text-cream/50">=</span> <span class="text-cyan">random</span>(<span class="text-yellow">12</span>)
<span class="text-cream/80">ciphertext</span> <span class="text-cream/50">=</span> <span class="text-accent">AES_256_GCM</span>.<span class="text-cream">encrypt</span>(<span class="text-cream/80">shared_key</span>, <span class="text-cream/80">nonce</span>, <span class="text-cream/80">plaintext</span>)
<span class="text-cyan">relay</span>.<span class="text-cream">send</span>(<span class="text-cream/80">ciphertext</span>)  <span class="text-mint">// relay sees only noise</span></code></pre>
        </div>
      </div>
    </section>

    <!-- ==================== PLATFORMS (orbit) ==================== -->
    <section class="py-16 md:py-24" id="platforms">
      <div class="wrap grid grid-cols-1 items-center gap-12 lg:grid-cols-2 lg:gap-16">
        <div use:reveal={{ blur: true }}>
          <span class="mb-4 inline-block rounded-sm border-2 border-ink bg-yellow px-2.5 py-1 font-head text-[10.5px] uppercase tracking-[0.2em] text-ink shadow-sm">Platforms</span>
          <h2 class="font-head text-[clamp(1.9rem,3.4vw,3.2rem)] leading-[1.05] text-ink">Native on every platform</h2>
          <p class="mt-4 max-w-xl text-[15px] leading-relaxed text-muted md:text-base">Not a web wrapper. Real native clients built with Tauri and Kotlin, with system-level clipboard integration. System tray on desktop, background service on Android, and this dashboard for history.</p>
          <ul class="mt-7 grid grid-cols-1 gap-3 sm:grid-cols-2">
            {#each platforms as plat, i (plat.name)}
              <li class="panel panel-hover flex items-center gap-3 px-4 py-3" use:reveal={{ delay: i * 60 }}>
                <span class="flex h-10 w-10 shrink-0 items-center justify-center rounded-md border-2 border-ink text-ink shadow-xs" style="background: {plat.fill};"><Icon name={plat.icon} size={18} /></span>
                <div>
                  <div class="font-head text-sm text-ink">{plat.name}</div>
                  <div class="text-[12px] text-muted">{plat.desc}</div>
                </div>
              </li>
            {/each}
          </ul>
        </div>

        <div class="relative mx-auto flex aspect-square w-full max-w-[460px] items-center justify-center" use:reveal={{ delay: 120 }}>
          <div class="dot-grid absolute inset-0 rounded-full opacity-60 [mask-image:radial-gradient(circle,black,transparent_70%)]"></div>
          <div class="relative z-10 flex h-24 w-24 items-center justify-center rounded-xl border-2 border-ink bg-yellow shadow-lg animate-wiggle">
            <Logo size={56} />
          </div>
          <OrbitingCircles items={platforms} radius={190} duration={28} iconSize={52}>
            {#snippet item(plat)}
              <span class="flex h-full w-full items-center justify-center rounded-md border-2 border-ink text-ink shadow-sm" style="background: {plat.fill};" title={plat.name}><Icon name={plat.icon} size={22} /></span>
            {/snippet}
          </OrbitingCircles>
          <OrbitingCircles items={[{ icon: 'lock' }, { icon: 'zap' }, { icon: 'shield-check' }]} radius={110} duration={18} iconSize={38} reverse>
            {#snippet item(entry)}
              <span class="flex h-full w-full items-center justify-center rounded-full border-2 border-ink bg-ink text-yellow shadow-sm"><Icon name={entry.icon} size={16} strokeWidth={2.4} /></span>
            {/snippet}
          </OrbitingCircles>
        </div>
      </div>
    </section>

    <!-- ==================== DOWNLOADS ==================== -->
    <section class="border-y-2 border-ink bg-bg-deep py-16 md:py-24" id="downloads">
      <div class="wrap">
        {@render heading('Downloads', 'Get the app for your platform', 'System-tray integration, background sync and automatic reconnection included.')}

        {#if dlGroups.length > 0}
          {#if detectedGroup}
            <div class="panel panel-lg relative mb-6 overflow-hidden rounded-lg p-6 md:p-8" style="--panel-shadow: var(--color-cyan);" use:reveal>
              <BorderBeam size={140} duration={8} colorFrom="#5ad1f0" colorTo="#ff7a59" borderWidth={3} />
              <div class="flex flex-col items-start gap-5 sm:flex-row sm:items-center">
                <span class="flex h-16 w-16 shrink-0 items-center justify-center rounded-md border-2 border-ink bg-cyan text-ink shadow-sm"><Icon name={detectedGroup.icon} size={30} /></span>
                <div class="min-w-0 flex-1">
                  <div class="flex flex-wrap items-center gap-2">
                    <h3 class="font-head text-2xl text-ink">{detectedGroup.label}</h3>
                    {#if detectedGroup.platform === detectedPlatform}
                      <Badge tone="mint" icon="check" uppercase>detected</Badge>
                    {/if}
                  </div>
                  <p class="mt-1 text-sm text-muted">Latest build for {detectedGroup.label}. Install, sign in, and start syncing in under a minute.</p>
                  {#if detectedGroup.links[0]}
                    <p class="mt-1 font-mono text-[11.5px] text-dim">{detectedGroup.links[0].format ? detectedGroup.links[0].format.toUpperCase() : 'PACKAGE'}{detectedGroup.links[0].arch ? ` · ${detectedGroup.links[0].arch}` : ''}</p>
                  {/if}
                </div>
                <div class="flex w-full flex-col gap-2 sm:w-auto">
                  {#if detectedGroup.links[0]}
                    <Button href={detectedGroup.links[0].url} external size="lg" icon="download" shine>Download for {detectedGroup.label}</Button>
                  {/if}
                  {#if detectedGroup.links.length > 1}
                    <div class="flex flex-wrap justify-center gap-3">
                      {#each detectedGroup.links.slice(1) as link (link.id)}
                        <a href={link.url} target="_blank" rel="noopener" class="text-xs font-semibold text-muted underline decoration-2 underline-offset-2 hover:text-ink">{link.format ? link.format.toUpperCase() : 'Alt'}{link.arch ? ` · ${link.arch}` : ''}</a>
                      {/each}
                    </div>
                  {/if}
                </div>
              </div>
            </div>
          {/if}

          {#if secondaryGroups.length > 0}
            <div class="grid grid-cols-1 gap-5 sm:grid-cols-2 md:grid-cols-4">
              {#each secondaryGroups as group, i (group.platform)}
                <div class="panel panel-hover flex flex-col gap-3 p-5" use:reveal={{ delay: (i + 1) * 70 }}>
                  <div class="flex items-center gap-3">
                    <span class="flex h-10 w-10 shrink-0 items-center justify-center rounded-md border-2 border-ink bg-surface-2 text-ink shadow-xs"><Icon name={group.icon} size={20} /></span>
                    <div>
                      <div class="font-head text-sm text-ink">{group.label}</div>
                      <div class="text-[11.5px] text-muted">{group.links.length} build{group.links.length !== 1 ? 's' : ''}</div>
                    </div>
                  </div>
                  <div class="mt-auto flex flex-col gap-2">
                    {#if group.links[0]}
                      <Button href={group.links[0].url} external variant="outline" size="sm" icon="download" class="w-full">Download</Button>
                    {/if}
                    {#if group.links.length > 1}
                      <div class="flex flex-wrap justify-center gap-2">
                        {#each group.links.slice(1) as link (link.id)}
                          <a href={link.url} target="_blank" rel="noopener" class="text-[11px] font-semibold text-muted underline decoration-2 underline-offset-2 hover:text-ink">{link.format ? link.format.toUpperCase() : 'Alt'}{link.arch ? ` · ${link.arch}` : ''}</a>
                        {/each}
                      </div>
                    {/if}
                  </div>
                </div>
              {/each}
            </div>
          {/if}
        {:else}
          <div class="panel p-8 text-center" use:reveal>
            <span class="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-md border-2 border-ink bg-yellow text-ink shadow-sm animate-wiggle"><Icon name="package" size={22} strokeWidth={2.3} /></span>
            <p class="font-head text-lg text-ink">Installers are being prepared</p>
            <p class="mt-1 text-sm text-muted">Native clients are on the way. In the meantime, build from source on GitHub.</p>
            <Button href={GITHUB_URL} external variant="secondary" size="sm" icon="github" class="mt-5">View the repository</Button>
          </div>
        {/if}
      </div>
    </section>

    <!-- ==================== COMPARISON ==================== -->
    <section class="py-16 md:py-24">
      <div class="wrap max-w-5xl">
        {@render heading('Compare', 'How cpmesh stacks up', 'Not all clipboard sync is created equal.')}

        <div class="panel hidden overflow-hidden md:block" use:reveal>
          <table class="w-full border-collapse text-sm">
            <thead>
              <tr class="border-b-2 border-ink bg-surface-2">
                <th class="w-[240px] px-5 py-4 text-left font-head text-[11px] uppercase tracking-[0.12em] text-ink">Feature</th>
                <th class="px-4 py-4 text-center"><span class="rounded-sm border-2 border-ink bg-yellow px-2 py-0.5 font-head text-xs text-ink shadow-xs">cpmesh</span></th>
                <th class="px-4 py-4 text-center font-head text-[11px] uppercase tracking-[0.08em] text-muted">Apple Handoff</th>
                <th class="px-4 py-4 text-center font-head text-[11px] uppercase tracking-[0.08em] text-muted">Windows Clipboard</th>
                <th class="px-4 py-4 text-center font-head text-[11px] uppercase tracking-[0.08em] text-muted">Pushbullet</th>
              </tr>
            </thead>
            <tbody>
              {#each comparison as row (row.feature)}
                <tr class="border-b-2 border-ink/10 last:border-0">
                  <td class="px-5 py-3.5 font-medium text-ink">{row.feature}</td>
                  <td class="bg-mint/25 px-4 py-3.5 text-center">{#if row.cpmesh}<Icon name="check" size={18} class="text-ink" strokeWidth={3} />{:else}<Icon name="x" size={16} class="text-ink/30" />{/if}</td>
                  <td class="px-4 py-3.5 text-center">{#if row.handoff}<Icon name="check" size={16} class="text-muted" strokeWidth={2.5} />{:else}<Icon name="x" size={16} class="text-ink/30" />{/if}</td>
                  <td class="px-4 py-3.5 text-center">{#if row.winclip}<Icon name="check" size={16} class="text-muted" strokeWidth={2.5} />{:else}<Icon name="x" size={16} class="text-ink/30" />{/if}</td>
                  <td class="px-4 py-3.5 text-center">{#if row.pushbullet}<Icon name="check" size={16} class="text-muted" strokeWidth={2.5} />{:else}<Icon name="x" size={16} class="text-ink/30" />{/if}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>

        <div class="space-y-3 md:hidden">
          {#each comparison as row, i (row.feature)}
            <div class="panel flex items-center justify-between p-4" use:reveal={{ delay: i * 40 }}>
              <span class="text-sm font-medium text-ink">{row.feature}</span>
              <div class="ml-3 flex shrink-0 items-center gap-3">
                <span class="flex h-5 w-5 items-center justify-center rounded-sm border-2 border-ink bg-mint"><Icon name="check" size={12} strokeWidth={3.5} /></span>
                {#if !row.handoff && !row.winclip && !row.pushbullet}
                  <span class="font-head text-[10px] uppercase tracking-wide text-dim">only cpmesh</span>
                {/if}
              </div>
            </div>
          {/each}
        </div>
      </div>
    </section>

    <!-- ==================== PRICING ==================== -->
    <section class="stripes border-t-2 border-ink bg-bg-deep py-16 md:py-24" id="pricing">
      <div class="wrap max-w-4xl">
        {@render heading('Pricing', 'Free and open source', 'Dual licensed under MIT and Apache-2.0. Self-host for free with Docker — no limits, no telemetry, no strings attached.')}

        <div class="grid grid-cols-1 gap-6 sm:grid-cols-2 md:gap-8">
          <div class="panel panel-lg relative p-7" style="--panel-shadow: var(--color-mint);" use:reveal>
            <Badge tone="mint" uppercase size="md">Self-hosted</Badge>
            <div class="mt-4 flex items-baseline gap-2"><span class="font-head text-5xl text-ink">Free</span><span class="text-xs font-semibold text-muted">forever · no limits</span></div>
            <ul class="mt-6 space-y-3">
              {#each ['Unlimited devices', 'Full clipboard history', 'Text, images, files (25 MB)', 'Your infrastructure, your rules'] as item (item)}
                <li class="flex items-center gap-3 text-sm font-medium text-ink"><span class="flex h-5 w-5 shrink-0 items-center justify-center rounded-sm border-2 border-ink bg-mint"><Icon name="check" size={12} strokeWidth={3.5} /></span> {item}</li>
              {/each}
            </ul>
            <Button href={GITHUB_URL} external variant="mint" size="lg" iconRight="arrow-right" class="mt-7 w-full">Deploy your relay</Button>
          </div>

          <div class="panel panel-lg relative p-7" style="--panel-shadow: var(--color-accent);" use:reveal={{ delay: 100 }}>
            <Badge tone="accent" uppercase size="md">Hosted relay</Badge>
            <div class="mt-4 flex items-baseline gap-2"><span class="font-head text-4xl text-ink">Coming soon</span></div>
            <p class="mt-1 text-xs font-semibold text-muted">don't want to run a server? we will.</p>
            <ul class="mt-6 space-y-3">
              {#each ['Zero-config relay', 'Managed infrastructure', 'Same end-to-end encryption', 'Generous free tier planned'] as item (item)}
                <li class="flex items-center gap-3 text-sm font-medium text-ink"><span class="flex h-5 w-5 shrink-0 items-center justify-center rounded-sm border-2 border-ink bg-accent"><Icon name="check" size={12} strokeWidth={3.5} /></span> {item}</li>
              {/each}
            </ul>
            <Button variant="outline" size="lg" disabled class="mt-7 w-full">Notify me</Button>
          </div>
        </div>
      </div>
    </section>

    <!-- ==================== FINAL CTA ==================== -->
    <section class="border-t-2 border-ink bg-ink py-20 md:py-28">
      <div class="wrap" use:reveal>
        <div class="relative overflow-hidden rounded-lg border-2 border-cream/30 px-6 py-14 text-center md:px-12 md:py-20">
          <Meteors number={18} color="#ffd93d" />
          <div class="relative">
            <h2 class="font-head text-[clamp(2.2rem,5vw,4.6rem)] leading-[1.02] text-yellow" style="text-shadow: 4px 4px 0 #ff7a59;">Your clipboard belongs to you.</h2>
            <p class="mx-auto mt-6 max-w-xl text-lg text-cream/80">Stop sending sensitive data through services that can read it. Get cpmesh running in under a minute.</p>
            <div class="mt-9 flex flex-wrap justify-center gap-3">
              <Button href="#/login" size="lg" iconRight="arrow-right" shine class="px-8">Get started free</Button>
              <Button href={GITHUB_URL} external variant="outline" size="lg" icon="github" class="px-8">Star on GitHub</Button>
            </div>
            <ul class="mt-9 flex flex-wrap justify-center gap-x-6 gap-y-2 font-head text-[11px] uppercase tracking-[0.12em] text-cream/70">
              {#each [['shield', 'MIT / Apache-2.0'], ['lock', 'E2E encrypted'], ['server', 'Self-hosted'], ['zap', 'Sub-second']] as [icon, label] (label)}
                <li class="inline-flex items-center gap-1.5"><Icon name={icon} size={13} class="text-mint" strokeWidth={2.5} /> {label}</li>
              {/each}
            </ul>
          </div>
        </div>
      </div>
    </section>
  </main>

  <!-- ==================== FOOTER ==================== -->
  <footer class="border-t-2 border-ink bg-bg py-10">
    <div class="wrap flex flex-col items-center justify-between gap-6 sm:flex-row sm:items-start">
      <div class="flex items-center gap-3">
        <Logo size={30} />
        <span class="text-sm font-semibold text-muted">© {new Date().getFullYear()} cpmesh</span>
      </div>
      <nav class="flex items-center gap-5 font-head text-[11px] uppercase tracking-[0.1em] text-ink" aria-label="Footer">
        <a href={GITHUB_URL} target="_blank" rel="noopener" class="inline-flex items-center gap-1.5 underline decoration-2 decoration-yellow underline-offset-4 hover:decoration-ink"><Icon name="github" size={14} /> Source</a>
        <a href="{GITHUB_URL}/blob/main/LICENSE" target="_blank" rel="noopener" class="underline decoration-2 decoration-yellow underline-offset-4 hover:decoration-ink">License</a>
        <a href="{GITHUB_URL}/blob/main/docs/self-hosting.md" target="_blank" rel="noopener" class="underline decoration-2 decoration-yellow underline-offset-4 hover:decoration-ink">Docs</a>
        <a href="#/login" class="underline decoration-2 decoration-yellow underline-offset-4 hover:decoration-ink">Sign in</a>
      </nav>
      <div class="inline-flex items-center gap-1.5 text-xs font-semibold text-dim">Built with <Icon name="heart" size={11} class="text-accent" /> in Rust & Svelte</div>
    </div>
  </footer>
</div>

<style>
  /* Fluid page container: reads well on laptops, fills ultrawide displays without turning into a narrow column. */
  :global(.home .wrap) {
    width: 100%;
    max-width: 1440px;
    margin-inline: auto;
    padding-inline: 1.25rem;
  }
  @media (min-width: 640px) {
    :global(.home .wrap) {
      padding-inline: 2rem;
    }
  }
  @media (min-width: 1280px) {
    :global(.home .wrap) {
      padding-inline: 3rem;
    }
  }
  @media (min-width: 1600px) {
    :global(.home .wrap) {
      max-width: 1680px;
    }
  }
  @media (min-width: 2200px) {
    :global(.home .wrap) {
      max-width: 1880px;
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
