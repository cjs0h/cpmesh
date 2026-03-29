<script lang="ts">
  import Icon from '../components/Icon.svelte';

  const GITHUB_URL = 'https://github.com/cpmesh/cpmesh';

  // --- Download types ---
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
    for (const item of items) {
      if (!groups[item.platform]) groups[item.platform] = [];
      groups[item.platform].push(item);
    }
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

  // --- Navigation ---
  const navLinks = [
    { label: 'Features', id: 'features' },
    { label: 'Security', id: 'security' },
    { label: 'Downloads', id: 'downloads' },
    { label: 'Pricing', id: 'pricing' },
  ];

  // --- Features (6 cards) ---
  const features = [
    { icon: 'zap', title: 'Sub-second sync', desc: 'WebSocket push delivery. Your clipboard arrives before you switch windows. No polling, no delay.', color: '#49c6e5' },
    { icon: 'lock', title: 'E2E encrypted', desc: 'AES-256-GCM encryption happens on-device. The relay only sees ciphertext. Your keys never leave your hardware.', color: '#ff7a59' },
    { icon: 'monitor', title: 'Every platform', desc: 'Native clients for Windows, macOS, Linux, and Android. Plus a full web dashboard for management.', color: '#f4c95d' },
    { icon: 'cloud', title: 'Self-host or use ours', desc: 'Run your own relay with a single Docker command. Or use our hosted relay — zero config required.', color: '#2ad6a0' },
    { icon: 'shield', title: 'Open source', desc: 'Dual licensed under MIT or Apache-2.0. Every line of code is auditable. No telemetry, no tracking, no strings attached.', color: '#ff7a59' },
    { icon: 'clock', title: 'Clipboard history', desc: 'Browse, search, and restore past clipboard entries. All encrypted at rest, all under your control.', color: '#49c6e5' },
  ];

  // --- Platforms ---
  const platforms = [
    { icon: 'windows', name: 'Windows', desc: 'System tray app with auto-start', color: '#49c6e5' },
    { icon: 'apple', name: 'macOS', desc: 'Menu bar integration', color: '#f5f7fb' },
    { icon: 'linux', name: 'Linux', desc: 'Wayland & X11 support', color: '#f4c95d' },
    { icon: 'android', name: 'Android', desc: 'Background sync service', color: '#2ad6a0' },
    { icon: 'globe', name: 'Web', desc: 'Dashboard & clipboard history', color: '#ff7a59' },
  ];

  // --- Comparison ---
  const comparisonFeatures = [
    { feature: 'E2E encryption', cpmesh: true, handoff: false, winclip: false, pushbullet: false },
    { feature: 'Self-hosted option', cpmesh: true, handoff: false, winclip: false, pushbullet: false },
    { feature: 'Cross-platform', cpmesh: true, handoff: false, winclip: false, pushbullet: true },
    { feature: 'Open source', cpmesh: true, handoff: false, winclip: false, pushbullet: false },
    { feature: 'File support (25 MB)', cpmesh: true, handoff: false, winclip: false, pushbullet: true },
    { feature: 'Image support', cpmesh: true, handoff: true, winclip: true, pushbullet: true },
    { feature: 'Clipboard history', cpmesh: true, handoff: false, winclip: true, pushbullet: true },
    { feature: 'No account required', cpmesh: true, handoff: false, winclip: false, pushbullet: false },
    { feature: 'Free forever', cpmesh: true, handoff: false, winclip: true, pushbullet: false },
  ];

  // --- Terminal lines ---
  interface TerminalLine { type: 'prompt' | 'output' | 'blank'; text: string; color?: string }
  const terminalLines: TerminalLine[] = [
    { type: 'prompt', text: 'docker compose up -d' },
    { type: 'output', text: '✓ dashboard available at http://localhost:39271', color: '#2ad6a0' },
    { type: 'blank', text: '' },
    { type: 'prompt', text: 'cpmesh pair' },
    { type: 'output', text: '✓ paired 3 devices · encryption keys exchanged', color: '#2ad6a0' },
    { type: 'blank', text: '' },
    { type: 'prompt', text: 'cpmesh status' },
    { type: 'output', text: '  macbook-pro    ● connected', color: '#2ad6a0' },
    { type: 'output', text: '  windows-pc     ● connected', color: '#2ad6a0' },
    { type: 'output', text: '  pixel-phone    ● idle', color: '#f4c95d' },
    { type: 'blank', text: '' },
    { type: 'prompt', text: '# copy on macbook, paste on windows. that\'s it.' },
  ];

  const dockerCompose = `services:
  relay:
    image: ghcr.io/cpmesh/relay:latest
    ports: ["39271:8080"]
    volumes: ["./data:/data"]
    restart: unless-stopped`;

  // --- Reactive state ---
  let heroVisible = $state(true);
  let problemVisible = $state(false);
  let stepsVisible = $state(false);
  let terminalVisible = $state(false);
  let featuresVisible = $state(false);
  let securityVisible = $state(false);
  let platformsVisible = $state(false);
  let downloadsVisible = $state(false);
  let quickstartVisible = $state(false);
  let comparisonVisible = $state(false);
  let pricingVisible = $state(false);
  let ctaVisible = $state(false);

  let terminalStep = $state(0);
  let mobileNavOpen = $state(false);
  let copied = $state(false);
  let copiedCmd = $state('');

  let downloads: DownloadLink[] = $state([]);
  let detectedPlatform = $state('');
  const dlGroups = $derived(groupByPlatform(downloads, detectedPlatform));
  const detectedGroup = $derived(dlGroups.find((g) => g.platform === detectedPlatform) ?? dlGroups[0]);
  const secondaryGroups = $derived(dlGroups.filter((g) => g.platform !== detectedGroup?.platform));

  const sectionSetters: Record<string, (v: boolean) => void> = {
    hero: (v) => (heroVisible = v),
    problem: (v) => (problemVisible = v),
    steps: (v) => (stepsVisible = v),
    terminal: (v) => (terminalVisible = v),
    features: (v) => (featuresVisible = v),
    security: (v) => (securityVisible = v),
    platforms: (v) => (platformsVisible = v),
    downloads: (v) => (downloadsVisible = v),
    quickstart: (v) => (quickstartVisible = v),
    comparison: (v) => (comparisonVisible = v),
    pricing: (v) => (pricingVisible = v),
    cta: (v) => (ctaVisible = v),
  };

  // IntersectionObserver for scroll-triggered reveals
  $effect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            const id = (entry.target as HTMLElement).dataset.section;
            if (id && sectionSetters[id]) sectionSetters[id](true);
            observer.unobserve(entry.target);
          }
        }
      },
      { threshold: 0.1, rootMargin: '0px 0px -40px 0px' }
    );
    const sections = document.querySelectorAll('[data-section]');
    sections.forEach((el) => observer.observe(el));
    return () => observer.disconnect();
  });

  // Terminal typing animation
  $effect(() => {
    if (!terminalVisible) return;
    const interval = setInterval(() => {
      terminalStep++;
      if (terminalStep >= terminalLines.length) clearInterval(interval);
    }, 600);
    return () => clearInterval(interval);
  });

  // Fetch downloads and detect platform on mount
  $effect(() => {
    detectedPlatform = detectPlatform();
    fetch('/api/downloads/current')
      .then((res) => (res.ok ? res.json() : []))
      .then((data) => (downloads = data))
      .catch(() => {});
  });

  function scrollToId(id: string) {
    mobileNavOpen = false;
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  async function copyText(text: string, id: string = '') {
    try {
      await navigator.clipboard.writeText(text);
      copied = true;
      copiedCmd = id;
      setTimeout(() => { copied = false; copiedCmd = ''; }, 2000);
    } catch {}
  }
</script>

<svelte:head>
  <title>cpmesh — Encrypted clipboard sync across all your devices</title>
  <meta name="description" content="Copy on one device, paste on another. E2E encrypted with AES-256-GCM. Open source. Self-host with Docker or use our relay." />
</svelte:head>

<div class="home relative min-h-screen overflow-hidden text-home-text font-sans" style="background: radial-gradient(ellipse at 20% 0%, rgba(255,122,89,0.12), transparent 50%), radial-gradient(ellipse at 80% 5%, rgba(73,198,229,0.10), transparent 45%), linear-gradient(180deg, #081222 0%, #050d1a 40%, #030810 100%);">

  <!-- Grid overlay -->
  <div class="absolute inset-0 pointer-events-none opacity-25" style="background-image: linear-gradient(rgba(255,255,255,0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.025) 1px, transparent 1px); background-size: 72px 72px; mask-image: linear-gradient(180deg, rgba(0,0,0,0.6), transparent 70%);"></div>

  <!-- Floating orbs -->
  <div class="absolute top-[-8%] right-[-4%] w-[500px] h-[500px] rounded-full pointer-events-none opacity-[0.12]" style="background: radial-gradient(circle, rgba(255,122,89,0.4), transparent 70%); filter: blur(80px); animation: drift 10s ease-in-out infinite;"></div>
  <div class="absolute top-[40%] left-[-8%] w-[400px] h-[400px] rounded-full pointer-events-none opacity-[0.08]" style="background: radial-gradient(circle, rgba(73,198,229,0.35), transparent 70%); filter: blur(80px); animation: drift 14s ease-in-out infinite 3s;"></div>
  <div class="absolute bottom-[15%] right-[10%] w-[350px] h-[350px] rounded-full pointer-events-none opacity-[0.06]" style="background: radial-gradient(circle, rgba(42,214,160,0.3), transparent 70%); filter: blur(80px); animation: drift 12s ease-in-out infinite 6s;"></div>

  <!-- ==================== HEADER ==================== -->
  <header class="sticky top-0 z-40 backdrop-blur-[20px] border-b border-[rgba(158,178,201,0.07)]" style="background: linear-gradient(180deg, rgba(5,13,26,0.92), rgba(5,13,26,0.5));">
    <div class="max-w-6xl mx-auto px-5 sm:px-6 flex items-center justify-between h-16">
      <!-- Logo -->
      <button type="button" class="appearance-none border-0 bg-transparent text-inherit font-inherit inline-flex items-center gap-3 p-0" onclick={() => scrollToId('top')}>
        <span class="w-8 h-8 rounded-lg inline-flex items-center justify-center border border-[rgba(255,255,255,0.1)]" style="background: linear-gradient(145deg, rgba(255,122,89,0.22), rgba(73,198,229,0.16)), rgba(255,255,255,0.03);">
          <span class="w-3 h-3 rounded-full" style="background: linear-gradient(145deg, var(--color-home-accent), var(--color-home-cyan)); box-shadow: 0 0 14px rgba(255,122,89,0.4);"></span>
        </span>
        <span class="font-display text-[17px] font-extrabold tracking-tight">cpmesh</span>
      </button>

      <!-- Desktop nav -->
      <nav class="hidden md:flex items-center gap-7">
        {#each navLinks as link}
          <button type="button" class="bg-transparent border-0 text-home-muted hover:text-home-text transition-colors text-sm font-medium cursor-pointer p-0" onclick={() => scrollToId(link.id)}>{link.label}</button>
        {/each}
      </nav>

      <!-- Right side -->
      <div class="flex items-center gap-3">
        <a href={GITHUB_URL} target="_blank" rel="noopener" aria-label="GitHub" class="text-home-muted hover:text-home-text transition-colors no-underline hidden sm:inline-flex items-center gap-1.5">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
        </a>
        <a href="#/login" class="inline-flex items-center justify-center rounded-full font-bold text-[13px] py-2 px-5 no-underline hover:-translate-y-0.5 transition-transform" style="background: linear-gradient(135deg, #ffd1a2, #ff7a59 52%, #ffab59); color: #000;">Sign In</a>

        <!-- Mobile hamburger -->
        <button type="button" class="md:hidden bg-transparent border-0 text-home-text p-1 cursor-pointer" aria-label="Open navigation menu" onclick={() => (mobileNavOpen = !mobileNavOpen)}>
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
        </button>
      </div>
    </div>
  </header>

  <!-- Mobile nav overlay -->
  {#if mobileNavOpen}
    <div class="fixed inset-0 z-50 backdrop-blur-2xl flex flex-col items-center justify-center gap-8" style="background: rgba(5,13,26,0.96);">
      <button type="button" class="absolute top-5 right-5 bg-transparent border-0 text-home-text cursor-pointer p-2" aria-label="Close navigation" onclick={() => (mobileNavOpen = false)}>
        <Icon name="x" size={24} />
      </button>
      {#each navLinks as link}
        <button type="button" class="bg-transparent border-0 text-home-text font-display text-2xl font-bold cursor-pointer p-0 hover:text-home-accent transition-colors" onclick={() => scrollToId(link.id)}>{link.label}</button>
      {/each}
      <a href="#/login" class="inline-flex items-center justify-center rounded-full font-bold text-base py-3 px-8 no-underline mt-4" style="background: linear-gradient(135deg, #ffd1a2, #ff7a59 52%, #ffab59); color: #000;">Sign In</a>
    </div>
  {/if}

  <main id="main-content">

    <!-- ==================== HERO ==================== -->
    <section class="pt-20 pb-16 md:pt-32 md:pb-28" id="top" data-section="hero">
      <div class="max-w-6xl mx-auto px-5 sm:px-6 transition-all duration-1000 ease-out" class:opacity-0={!heroVisible} class:translate-y-8={!heroVisible}>
        <div class="grid grid-cols-1 lg:grid-cols-[1fr_auto] gap-12 lg:gap-16 items-center">

          <!-- Left: Text content -->
          <div class="text-center lg:text-left">
            <!-- Badge -->
            <div class="inline-flex items-center gap-2 mb-7 py-1.5 px-4 rounded-full border border-[rgba(255,255,255,0.08)] text-[13px] text-home-muted" style="background: linear-gradient(135deg, rgba(255,255,255,0.04), rgba(255,255,255,0.01));">
              <span class="w-2 h-2 rounded-full bg-home-green" style="box-shadow: 0 0 10px rgba(42,214,160,0.6); animation: pulse 3s ease-in-out infinite;"></span>
              Open source · MIT/Apache-2.0
            </div>

            <h1 class="font-display tracking-[-0.05em] leading-[0.9] m-0">
              <span class="block text-[clamp(2.6rem,7vw,5rem)]">Copy anywhere.</span>
              <span class="block text-[clamp(2.6rem,7vw,5rem)] text-transparent bg-clip-text" style="background-image: linear-gradient(135deg, #ffedc6 0%, #ff9667 40%, #49c6e5 100%);">Paste everywhere.</span>
              <span class="block text-[clamp(1.2rem,2.5vw,1.8rem)] text-home-muted mt-3 tracking-[-0.02em]">End-to-end encrypted.</span>
            </h1>

            <p class="mt-6 text-[17px] text-home-muted max-w-lg leading-relaxed mx-auto lg:mx-0">
              Sync your clipboard across every device you own. Text, images, files — all encrypted before leaving your machine. Self-host with Docker or use our relay.
            </p>

            <!-- CTAs -->
            <div class="flex flex-wrap justify-center lg:justify-start gap-4 mt-9">
              <a href="#/login" class="group inline-flex items-center gap-2.5 rounded-full font-bold py-3.5 px-7 text-[15px] no-underline hover:-translate-y-0.5 transition-all" style="background: linear-gradient(135deg, #ffd1a2, #ff7a59 52%, #ffab59); box-shadow: 0 12px 36px rgba(255,122,89,0.2); color: #000;">
                Get Started
                <Icon name="chevron-right" size={16} />
              </a>
              <a href={GITHUB_URL} target="_blank" rel="noopener" class="inline-flex items-center gap-2.5 rounded-full font-bold py-3.5 px-7 text-[15px] text-home-text no-underline border border-home-border bg-[rgba(255,255,255,0.03)] hover:-translate-y-0.5 hover:border-[rgba(158,178,201,0.26)] hover:bg-[rgba(255,255,255,0.06)] transition-all">
                <svg width="17" height="17" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
                View on GitHub
              </a>
            </div>

            <!-- Trust row -->
            <div class="flex flex-wrap justify-center lg:justify-start gap-5 mt-8 text-[13px] text-home-muted">
              <span class="inline-flex items-center gap-1.5"><span class="text-home-green"><Icon name="check" size={13} /></span> AES-256-GCM</span>
              <span class="inline-flex items-center gap-1.5"><span class="text-home-green"><Icon name="check" size={13} /></span> Self-hostable</span>
              <span class="inline-flex items-center gap-1.5"><span class="text-home-green"><Icon name="check" size={13} /></span> 5 platforms</span>
            </div>
          </div>

          <!-- Right: Floating device mockup (desktop only) -->
          <div class="hidden lg:flex relative w-[340px] h-[320px] items-center justify-center">
            <!-- Desktop device -->
            <div class="absolute top-2 left-0 w-[150px] rounded-xl border border-[rgba(73,198,229,0.2)] p-3 text-center" style="background: linear-gradient(180deg, rgba(73,198,229,0.06), rgba(11,20,35,0.9)); animation: float1 6s ease-in-out infinite;">
              <div class="text-[#49c6e5] mb-2"><Icon name="monitor" size={28} /></div>
              <div class="text-xs font-bold">Desktop</div>
              <div class="mt-2 text-[10px] text-home-muted px-2 py-1 rounded bg-[rgba(73,198,229,0.08)] font-mono truncate">Hello, world!</div>
            </div>
            <!-- Phone device -->
            <div class="absolute bottom-2 right-0 w-[130px] rounded-xl border border-[rgba(42,214,160,0.2)] p-3 text-center" style="background: linear-gradient(180deg, rgba(42,214,160,0.06), rgba(11,20,35,0.9)); animation: float2 7s ease-in-out infinite 1s;">
              <div class="text-[#2ad6a0] mb-2"><Icon name="smartphone" size={24} /></div>
              <div class="text-xs font-bold">Phone</div>
              <div class="mt-2 text-[10px] text-home-muted px-2 py-1 rounded bg-[rgba(42,214,160,0.08)] font-mono truncate">Hello, world!</div>
            </div>
            <!-- Center lock -->
            <div class="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-14 h-14 rounded-full border border-[rgba(255,122,89,0.25)] flex items-center justify-center z-10" style="background: radial-gradient(circle, rgba(255,122,89,0.12), rgba(11,20,35,0.95)); box-shadow: 0 0 40px rgba(255,122,89,0.15);">
              <span class="text-[#ff7a59]"><Icon name="lock" size={20} /></span>
            </div>
            <!-- Connecting dashed lines (SVG) -->
            <svg class="absolute inset-0 w-full h-full pointer-events-none" viewBox="0 0 340 320">
              <line x1="120" y1="75" x2="155" y2="145" stroke="rgba(158,178,201,0.12)" stroke-width="1" stroke-dasharray="5,5" />
              <line x1="185" y1="175" x2="225" y2="230" stroke="rgba(158,178,201,0.12)" stroke-width="1" stroke-dasharray="5,5" />
            </svg>
          </div>
        </div>
      </div>
    </section>

    <!-- ==================== THE PROBLEM ==================== -->
    <section class="py-16 md:py-28" data-section="problem">
      <div class="max-w-5xl mx-auto px-5 sm:px-6 transition-all duration-700 ease-out" class:opacity-0={!problemVisible} class:translate-y-6={!problemVisible}>
        <div class="text-center mb-12 md:mb-16">
          <h2 class="font-display tracking-[-0.04em] text-[clamp(1.8rem,4vw,2.8rem)] m-0">There has to be a better way.</h2>
          <p class="mt-4 text-home-muted max-w-lg mx-auto">Everyone needs to move data between devices. The current options are embarrassing.</p>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-6 md:gap-8">
          <!-- Pain cards -->
          <div class="flex flex-col gap-4">
            {#each [
              { icon: 'send', title: 'Emailing yourself', desc: 'Sending links and snippets to your own inbox. In 2026. Really.', delay: 0 },
              { icon: 'upload', title: 'USB drives', desc: 'Carrying a flash drive between rooms like it\'s 2005.', delay: 100 },
              { icon: 'cloud', title: 'Cloud sees everything', desc: 'Apple, Google, Microsoft sync your clipboard — and can read every word of it.', delay: 200 },
            ] as pain, i}
              <div
                class="rounded-xl p-5 border border-[rgba(248,113,113,0.12)] flex items-start gap-4 transition-all duration-500 ease-out"
                class:opacity-0={!problemVisible}
                class:translate-y-4={!problemVisible}
                style="background: linear-gradient(135deg, rgba(248,113,113,0.03), rgba(11,20,35,0.8)); transition-delay: {pain.delay}ms;"
              >
                <div class="w-10 h-10 rounded-lg shrink-0 inline-flex items-center justify-center bg-[rgba(248,113,113,0.08)] border border-[rgba(248,113,113,0.15)] text-[#f87171]">
                  <Icon name={pain.icon} size={18} />
                </div>
                <div>
                  <h3 class="m-0 text-[15px] font-bold text-[#f87171]/80">{pain.title}</h3>
                  <p class="mt-1 text-sm text-home-muted leading-relaxed">{pain.desc}</p>
                </div>
              </div>
            {/each}
          </div>

          <!-- Solution card -->
          <div
            class="rounded-2xl p-7 border border-[rgba(42,214,160,0.2)] flex flex-col justify-center transition-all duration-500 ease-out"
            class:opacity-0={!problemVisible}
            class:translate-y-4={!problemVisible}
            style="background: radial-gradient(ellipse at top right, rgba(42,214,160,0.06), transparent 60%), rgba(11,20,35,0.85); transition-delay: 300ms;"
          >
            <div class="inline-flex items-center gap-2 mb-4">
              <span class="text-home-green"><Icon name="lock" size={20} /></span>
              <span class="font-display text-xl font-bold tracking-tight">cpmesh</span>
            </div>
            <p class="text-home-muted text-[15px] leading-relaxed mb-5">Copy on any device. Paste on any other. The relay only sees encrypted noise — your keys never leave your hardware.</p>
            <ul class="space-y-3 list-none p-0 m-0">
              {#each ['Zero-knowledge relay architecture', 'AES-256-GCM on-device encryption', 'Your infrastructure, your rules', 'Every platform, one clipboard'] as point}
                <li class="flex items-center gap-2.5 text-sm text-home-text">
                  <span class="text-home-green shrink-0"><Icon name="check" size={14} /></span>
                  {point}
                </li>
              {/each}
            </ul>
          </div>
        </div>
      </div>
    </section>

    <!-- ==================== HOW IT WORKS - 3 STEPS ==================== -->
    <section class="py-16 md:py-28" data-section="steps">
      <div class="max-w-5xl mx-auto px-5 sm:px-6 transition-all duration-700 ease-out" class:opacity-0={!stepsVisible} class:translate-y-6={!stepsVisible}>
        <div class="text-center mb-12 md:mb-16">
          <h2 class="font-display tracking-[-0.04em] text-[clamp(1.8rem,4vw,2.8rem)] m-0">Up and running in three steps</h2>
          <p class="mt-4 text-home-muted max-w-md mx-auto">No configuration. No key management. Just install, pair, and start pasting.</p>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 md:gap-5 relative">
          {#each [
            { num: '01', icon: 'download', title: 'Install', desc: 'Self-host the relay with Docker or download the native app for your platform.', color: '#49c6e5' },
            { num: '02', icon: 'key', title: 'Pair', desc: 'Open the app on each device. Encryption keys are exchanged automatically via ECDH.', color: '#ff7a59' },
            { num: '03', icon: 'clipboard', title: 'Sync', desc: 'Copy on one device, paste on another. Sub-second. Encrypted. Invisible.', color: '#2ad6a0' },
          ] as step, i}
            <div
              class="step-card relative rounded-2xl p-6 pt-8 border border-home-border overflow-hidden transition-all duration-500 ease-out"
              class:opacity-0={!stepsVisible}
              class:translate-y-6={!stepsVisible}
              style="background: linear-gradient(180deg, rgba(255,255,255,0.03), rgba(255,255,255,0.005)), rgba(11,20,35,0.8); transition-delay: {i * 150}ms;"
            >
              <!-- Watermark number -->
              <span class="absolute top-3 right-4 font-display text-[4rem] font-bold leading-none opacity-[0.04] select-none">{step.num}</span>

              <div class="w-12 h-12 rounded-xl inline-flex items-center justify-center mb-4" style="background: color-mix(in srgb, {step.color} 12%, transparent); border: 1px solid color-mix(in srgb, {step.color} 22%, transparent); color: {step.color};">
                <Icon name={step.icon} size={22} />
              </div>
              <h3 class="m-0 font-display text-xl tracking-tight">{step.title}</h3>
              <p class="mt-2 text-sm text-home-muted leading-relaxed">{step.desc}</p>
            </div>
          {/each}

          <!-- Connecting arrows (desktop only) -->
          <div class="hidden md:flex absolute top-1/2 left-[33.33%] -translate-x-1/2 -translate-y-1/2 text-home-muted opacity-30">
            <Icon name="chevron-right" size={20} />
          </div>
          <div class="hidden md:flex absolute top-1/2 left-[66.66%] -translate-x-1/2 -translate-y-1/2 text-home-muted opacity-30">
            <Icon name="chevron-right" size={20} />
          </div>
        </div>
      </div>
    </section>

    <!-- ==================== TERMINAL DEMO ==================== -->
    <section class="py-16 md:py-28" data-section="terminal">
      <div class="max-w-3xl mx-auto px-5 sm:px-6 transition-all duration-700 ease-out" class:opacity-0={!terminalVisible} class:translate-y-6={!terminalVisible}>
        <div class="text-center mb-10">
          <h2 class="font-display tracking-[-0.04em] text-[clamp(1.8rem,4vw,2.8rem)] m-0">See it in action</h2>
        </div>

        <!-- Terminal window -->
        <div class="rounded-2xl border border-home-border overflow-hidden" style="background: rgba(8,16,30,0.95); box-shadow: 0 24px 80px rgba(0,0,0,0.35), 0 0 1px rgba(255,255,255,0.05);">
          <!-- Titlebar -->
          <div class="flex items-center gap-2 px-4 py-3 border-b border-[rgba(255,255,255,0.05)]">
            <span class="w-3 h-3 rounded-full bg-[#ff5f57]"></span>
            <span class="w-3 h-3 rounded-full bg-[#febc2e]"></span>
            <span class="w-3 h-3 rounded-full bg-[#28c840]"></span>
            <span class="ml-4 text-xs text-home-muted font-mono opacity-60">terminal</span>
          </div>

          <!-- Content -->
          <div class="p-5 font-mono text-[13px] leading-7 min-h-[260px]">
            {#each terminalLines as line, i}
              {#if terminalStep > i}
                <div class="transition-opacity duration-300" style="opacity: {terminalStep > i ? 1 : 0};">
                  {#if line.type === 'blank'}
                    <div class="h-4"></div>
                  {:else if line.type === 'prompt'}
                    <div class="text-home-muted">
                      <span class="text-[#49c6e5]">$</span>
                      {#if line.text.startsWith('#')}
                        <span class="text-[rgba(158,178,201,0.35)]"> {line.text}</span>
                      {:else}
                        <span class="text-home-text"> {line.text}</span>
                      {/if}
                    </div>
                  {:else}
                    <div>
                      {#if line.text.startsWith('✓')}
                        <span style="color: {line.color}">✓</span><span class="text-home-muted">{line.text.slice(1)}</span>
                      {:else if line.text.includes('●')}
                        <span class="text-home-muted">{line.text.split('●')[0]}</span><span style="color: {line.color}">●{line.text.split('●')[1]}</span>
                      {:else}
                        <span class="text-home-muted">{line.text}</span>
                      {/if}
                    </div>
                  {/if}
                </div>
              {/if}
            {/each}
            {#if terminalVisible && terminalStep < terminalLines.length}
              <span class="inline-block w-[7px] h-[15px] bg-home-text/70 ml-0.5 terminal-cursor"></span>
            {/if}
          </div>
        </div>

        <!-- Docker compose snippet -->
        <div class="mt-5 rounded-xl border border-home-border p-4" style="background: rgba(8,16,30,0.8);">
          <div class="flex items-center justify-between mb-3">
            <span class="text-xs text-home-muted font-mono opacity-70">docker-compose.yml</span>
            <button
              type="button"
              class="text-xs hover:text-home-text transition-colors flex items-center gap-1.5 bg-transparent border-0 cursor-pointer font-inherit {copiedCmd === 'docker' ? 'text-home-green' : 'text-home-muted'}"
              onclick={() => copyText(dockerCompose, 'docker')}
            >
              <Icon name={copiedCmd === 'docker' ? 'check' : 'copy'} size={12} />
              {copiedCmd === 'docker' ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <pre class="font-mono text-[13px] text-home-muted leading-6 m-0 overflow-x-auto"><code><span class="text-[#ff7a59]">services</span>:
  <span class="text-[#49c6e5]">relay</span>:
    <span class="text-home-text">image: ghcr.io/cpmesh/relay:latest</span>
    <span class="text-[#49c6e5]">ports</span>: [<span class="text-[#f4c95d]">"39271:8080"</span>]
    <span class="text-[#49c6e5]">volumes</span>: [<span class="text-[#f4c95d]">"./data:/data"</span>]
    <span class="text-[#49c6e5]">restart</span>: <span class="text-home-text">unless-stopped</span></code></pre>
        </div>
      </div>
    </section>

    <!-- ==================== FEATURES ==================== -->
    <section class="py-16 md:py-28" id="features" data-section="features">
      <div class="max-w-5xl mx-auto px-5 sm:px-6 transition-all duration-700 ease-out" class:opacity-0={!featuresVisible} class:translate-y-6={!featuresVisible}>
        <div class="text-center mb-12 md:mb-16">
          <h2 class="font-display tracking-[-0.04em] text-[clamp(1.8rem,4vw,2.8rem)] m-0">Why cpmesh</h2>
          <p class="mt-4 text-home-muted max-w-lg mx-auto">Built for people who care where their data goes.</p>
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
          {#each features as feat, i}
            <article
              class="rounded-2xl p-6 border border-home-border hover:-translate-y-1 transition-all duration-300 ease-out cursor-default"
              class:opacity-0={!featuresVisible}
              class:translate-y-4={!featuresVisible}
              style="background: linear-gradient(180deg, rgba(255,255,255,0.03), rgba(255,255,255,0.005)), rgba(11,20,35,0.8); border-top: 2px solid color-mix(in srgb, {feat.color} 35%, transparent); transition-delay: {i * 80}ms;"
            >
              <div class="w-11 h-11 rounded-xl inline-flex items-center justify-center mb-4" style="background: color-mix(in srgb, {feat.color} 12%, transparent); border: 1px solid color-mix(in srgb, {feat.color} 22%, transparent); color: {feat.color};">
                <Icon name={feat.icon} size={18} />
              </div>
              <h3 class="m-0 font-display text-lg tracking-tight">{feat.title}</h3>
              <p class="mt-2 text-sm text-home-muted leading-relaxed">{feat.desc}</p>
            </article>
          {/each}
        </div>
      </div>
    </section>

    <!-- ==================== SECURITY DEEP-DIVE ==================== -->
    <section class="py-16 md:py-28" id="security" data-section="security">
      <div class="max-w-5xl mx-auto px-5 sm:px-6 transition-all duration-700 ease-out" class:opacity-0={!securityVisible} class:translate-y-6={!securityVisible}>
        <div class="text-center mb-12 md:mb-16">
          <h2 class="font-display tracking-[-0.04em] text-[clamp(1.8rem,4vw,2.8rem)] m-0">
            <span class="text-transparent bg-clip-text" style="background-image: linear-gradient(135deg, #ffedc6 0%, #ff9667 50%, #49c6e5 100%);">Zero-knowledge</span> by design
          </h2>
          <p class="mt-4 text-home-muted max-w-xl mx-auto">Your clipboard is encrypted before it leaves your device. The relay cannot decrypt it. Nobody can — except your own devices.</p>
        </div>

        <!-- Encryption flow diagram -->
        <div class="rounded-2xl border border-home-border p-6 md:p-8 mb-8" style="background: radial-gradient(ellipse at center, rgba(255,122,89,0.04), transparent 60%), rgba(11,20,35,0.85);">
          <div class="flex flex-col md:flex-row items-center justify-center gap-3 md:gap-2">
            <!-- Device A -->
            <div class="flex flex-col items-center gap-2 px-4 py-3 rounded-xl border border-[rgba(73,198,229,0.2)] min-w-[120px]" style="background: rgba(73,198,229,0.04);">
              <span class="text-[#49c6e5]"><Icon name="monitor" size={24} /></span>
              <span class="text-xs font-bold">Your Laptop</span>
              <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-[rgba(73,198,229,0.1)] text-[#49c6e5]">Hello, world!</span>
            </div>

            <!-- Arrow -->
            <span class="text-home-muted opacity-40 hidden md:block"><Icon name="chevron-right" size={18} /></span>
            <span class="text-home-muted opacity-40 md:hidden rotate-90"><Icon name="chevron-right" size={18} /></span>

            <!-- Encrypt -->
            <div class="flex flex-col items-center gap-2 px-4 py-3 rounded-xl border border-[rgba(255,122,89,0.2)] min-w-[120px]" style="background: rgba(255,122,89,0.04);">
              <span class="text-[#ff7a59]"><Icon name="lock" size={22} /></span>
              <span class="text-xs font-bold text-[#ff7a59]">Encrypt</span>
              <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-[rgba(255,122,89,0.1)] text-home-muted">AES-256-GCM</span>
            </div>

            <!-- Arrow -->
            <span class="text-home-muted opacity-40 hidden md:block"><Icon name="chevron-right" size={18} /></span>
            <span class="text-home-muted opacity-40 md:hidden rotate-90"><Icon name="chevron-right" size={18} /></span>

            <!-- Relay -->
            <div class="flex flex-col items-center gap-2 px-4 py-3 rounded-xl border border-[rgba(158,178,201,0.1)] min-w-[120px] opacity-60" style="background: rgba(158,178,201,0.03);">
              <span class="text-home-muted"><Icon name="cloud" size={22} /></span>
              <span class="text-xs font-bold text-home-muted">Relay</span>
              <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-[rgba(158,178,201,0.06)] text-home-dim">0x7f3a…b2e1</span>
            </div>

            <!-- Arrow -->
            <span class="text-home-muted opacity-40 hidden md:block"><Icon name="chevron-right" size={18} /></span>
            <span class="text-home-muted opacity-40 md:hidden rotate-90"><Icon name="chevron-right" size={18} /></span>

            <!-- Decrypt -->
            <div class="flex flex-col items-center gap-2 px-4 py-3 rounded-xl border border-[rgba(42,214,160,0.2)] min-w-[120px]" style="background: rgba(42,214,160,0.04);">
              <span class="text-[#2ad6a0]"><Icon name="key" size={22} /></span>
              <span class="text-xs font-bold text-[#2ad6a0]">Decrypt</span>
              <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-[rgba(42,214,160,0.1)] text-home-muted">ECDH P-256</span>
            </div>

            <!-- Arrow -->
            <span class="text-home-muted opacity-40 hidden md:block"><Icon name="chevron-right" size={18} /></span>
            <span class="text-home-muted opacity-40 md:hidden rotate-90"><Icon name="chevron-right" size={18} /></span>

            <!-- Device B -->
            <div class="flex flex-col items-center gap-2 px-4 py-3 rounded-xl border border-[rgba(73,198,229,0.2)] min-w-[120px]" style="background: rgba(73,198,229,0.04);">
              <span class="text-[#49c6e5]"><Icon name="smartphone" size={24} /></span>
              <span class="text-xs font-bold">Your Phone</span>
              <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-[rgba(73,198,229,0.1)] text-[#49c6e5]">Hello, world!</span>
            </div>
          </div>

          <p class="text-center mt-6 text-sm text-home-muted">The relay only forwards encrypted bytes. It has no keys and cannot read your data. <span class="text-home-text font-medium">Ever.</span></p>
        </div>

        <!-- Protocol cards -->
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {#each [
            { title: 'AES-256-GCM', desc: 'Military-grade authenticated encryption for every clipboard entry. Integrity and confidentiality in one pass.', color: '#ff7a59' },
            { title: 'ECDH P-256', desc: 'Elliptic-curve key agreement between devices. Each device has its own keypair — no shared secrets.', color: '#49c6e5' },
            { title: 'Zero Knowledge', desc: 'The relay never possesses decryption keys. Compromise the server — your data remains encrypted noise.', color: '#2ad6a0' },
          ] as card}
            <div class="rounded-xl p-5 border border-home-border" style="background: rgba(11,20,35,0.8);">
              <span class="font-mono text-sm font-bold" style="color: {card.color};">{card.title}</span>
              <p class="mt-2 text-sm text-home-muted leading-relaxed">{card.desc}</p>
            </div>
          {/each}
        </div>

        <!-- Code snippet -->
        <div class="mt-6 rounded-xl border border-home-border p-5 overflow-x-auto" style="background: rgba(8,16,30,0.9);">
          <pre class="font-mono text-[12px] sm:text-[13px] leading-6 m-0"><code><span class="text-home-dim">// what happens when you copy</span>
<span class="text-home-muted">plaintext</span>  <span class="text-home-dim">=</span> <span class="text-[#49c6e5]">clipboard</span>.<span class="text-home-text">read</span>()
<span class="text-home-muted">shared_key</span> <span class="text-home-dim">=</span> <span class="text-[#ff7a59]">ECDH</span>(<span class="text-home-text">my_private</span>, <span class="text-home-text">peer_public</span>)
<span class="text-home-muted">nonce</span>      <span class="text-home-dim">=</span> <span class="text-[#49c6e5]">random</span>(<span class="text-[#f4c95d]">12</span>)
<span class="text-home-muted">ciphertext</span> <span class="text-home-dim">=</span> <span class="text-[#ff7a59]">AES_256_GCM</span>.<span class="text-home-text">encrypt</span>(<span class="text-home-muted">shared_key</span>, <span class="text-home-muted">nonce</span>, <span class="text-home-muted">plaintext</span>)
<span class="text-[#49c6e5]">relay</span>.<span class="text-home-text">send</span>(<span class="text-home-muted">ciphertext</span>)  <span class="text-[#2ad6a0]">// relay sees only noise</span></code></pre>
        </div>
      </div>
    </section>

    <!-- ==================== PLATFORMS ==================== -->
    <section class="py-16 md:py-28" id="platforms" data-section="platforms">
      <div class="max-w-4xl mx-auto px-5 sm:px-6 transition-all duration-700 ease-out" class:opacity-0={!platformsVisible} class:translate-y-6={!platformsVisible}>
        <div class="text-center mb-12 md:mb-16">
          <h2 class="font-display tracking-[-0.04em] text-[clamp(1.8rem,4vw,2.8rem)] m-0">Native on every platform</h2>
          <p class="mt-4 text-home-muted max-w-lg mx-auto">Not a web wrapper. Real native clients built with Tauri and Kotlin — with system-level clipboard integration.</p>
        </div>

        <div class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-4">
          {#each platforms as plat, i}
            <div
              class="rounded-xl p-5 border border-home-border text-center transition-all duration-500 ease-out hover:-translate-y-1 hover:border-[rgba(158,178,201,0.24)]"
              class:opacity-0={!platformsVisible}
              class:translate-y-4={!platformsVisible}
              style="background: linear-gradient(180deg, rgba(255,255,255,0.025), rgba(255,255,255,0.005)), rgba(11,20,35,0.8); transition-delay: {i * 80}ms;"
            >
              <div class="mb-3" style="color: {plat.color};">
                <Icon name={plat.icon} size={30} />
              </div>
              <div class="font-display font-bold text-sm">{plat.name}</div>
              <div class="text-[11px] text-home-muted mt-1 leading-snug">{plat.desc}</div>
            </div>
          {/each}
        </div>

        <p class="text-center mt-8 text-sm text-home-muted">System tray on desktop. Background service on Android. Full web dashboard for management and history.</p>
      </div>
    </section>

    <!-- ==================== DOWNLOADS ==================== -->
    <section class="py-16 md:py-28" id="downloads" data-section="downloads">
      <div class="max-w-4xl mx-auto px-5 sm:px-6 transition-all duration-700 ease-out" class:opacity-0={!downloadsVisible} class:translate-y-6={!downloadsVisible}>
        <div class="text-center mb-12 md:mb-16">
          <h2 class="font-display tracking-[-0.04em] text-[clamp(1.8rem,4vw,2.8rem)] m-0">Download for your platform</h2>
          <p class="mt-4 text-home-muted max-w-lg mx-auto">Get the native client for your operating system. System tray integration, background sync, and automatic reconnection included.</p>
        </div>

        {#if dlGroups.length > 0}
          <!-- Spotlight: detected / primary platform -->
          {#if detectedGroup}
            <div
              class="rounded-2xl p-6 border border-[rgba(73,198,229,0.2)] mb-6 transition-all duration-500 ease-out"
              class:opacity-0={!downloadsVisible}
              class:translate-y-4={!downloadsVisible}
              style="background: radial-gradient(ellipse at top left, rgba(73,198,229,0.06), transparent 50%), rgba(11,20,35,0.85);"
            >
              <div class="flex flex-col sm:flex-row items-start sm:items-center gap-5">
                <div class="w-14 h-14 inline-flex items-center justify-center rounded-xl bg-[rgba(73,198,229,0.12)] border border-[rgba(73,198,229,0.22)] text-[#49c6e5] shrink-0">
                  <Icon name={detectedGroup.icon} size={28} />
                </div>
                <div class="flex-1 min-w-0">
                  <div class="flex items-center gap-2 flex-wrap">
                    <h3 class="font-display text-xl tracking-tight m-0">{detectedGroup.label}</h3>
                    {#if detectedGroup.platform === detectedPlatform}
                      <span class="inline-flex items-center gap-1 py-0.5 px-2 rounded-full text-[11px] font-bold text-[#d9eee8] bg-[rgba(42,214,160,0.12)] uppercase tracking-wide">
                        <Icon name="check" size={10} /> detected
                      </span>
                    {/if}
                  </div>
                  <p class="text-sm text-home-muted mt-1">
                    Download the latest build for {detectedGroup.label} and start syncing in under a minute.
                  </p>
                  {#if detectedGroup.links[0]}
                    <div class="text-xs text-home-dim mt-1">
                      {detectedGroup.links[0].format ? detectedGroup.links[0].format.toUpperCase() : 'PACKAGE'}
                      {detectedGroup.links[0].arch ? ` · ${detectedGroup.links[0].arch}` : ''}
                    </div>
                  {/if}
                </div>
                <div class="flex flex-col gap-2 shrink-0 w-full sm:w-auto">
                  {#if detectedGroup.links[0]}
                    <a
                      href={detectedGroup.links[0].url}
                      target="_blank"
                      rel="noopener"
                      class="inline-flex items-center justify-center gap-2 rounded-full font-bold py-3 px-6 text-sm no-underline hover:-translate-y-0.5 transition-transform text-[#08111f]"
                      style="background: linear-gradient(135deg, #ffd1a2, #ff7a59 52%, #ffab59); box-shadow: 0 14px 40px rgba(255,122,89,0.22);"
                    >
                      <Icon name="download" size={15} />
                      Download for {detectedGroup.label}
                    </a>
                  {/if}
                  {#if detectedGroup.links.length > 1}
                    <div class="flex flex-wrap justify-center gap-3">
                      {#each detectedGroup.links.slice(1) as link}
                        <a href={link.url} target="_blank" rel="noopener" class="text-xs text-home-muted no-underline hover:text-home-text transition-colors">
                          {link.format ? link.format.toUpperCase() : 'Alt'}{link.arch ? ` · ${link.arch}` : ''}
                        </a>
                      {/each}
                    </div>
                  {/if}
                </div>
              </div>
            </div>
          {/if}

          <!-- Other platforms grid -->
          {#if secondaryGroups.length > 0}
            <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
              {#each secondaryGroups as group, i}
                <div
                  class="rounded-xl p-5 border border-home-border flex flex-col gap-3 transition-all duration-500 ease-out hover:-translate-y-1 hover:border-[rgba(158,178,201,0.24)]"
                  class:opacity-0={!downloadsVisible}
                  class:translate-y-4={!downloadsVisible}
                  style="background: linear-gradient(180deg, rgba(255,255,255,0.025), rgba(255,255,255,0.005)), rgba(11,20,35,0.8); transition-delay: {(i + 1) * 80}ms;"
                >
                  <div class="flex items-center gap-3">
                    <div class="w-10 h-10 inline-flex items-center justify-center rounded-lg bg-[rgba(73,198,229,0.1)] border border-[rgba(73,198,229,0.18)] text-[#49c6e5] shrink-0">
                      <Icon name={group.icon} size={20} />
                    </div>
                    <div>
                      <div class="font-display font-bold text-sm">{group.label}</div>
                      <div class="text-[11px] text-home-muted">{group.links.length} build{group.links.length !== 1 ? 's' : ''}</div>
                    </div>
                  </div>
                  <div class="mt-auto flex flex-col gap-2">
                    {#if group.links[0]}
                      <a
                        href={group.links[0].url}
                        target="_blank"
                        rel="noopener"
                        class="w-full inline-flex items-center justify-center gap-2 rounded-full font-bold py-2.5 text-xs no-underline text-home-text border border-home-border bg-[rgba(255,255,255,0.04)] hover:-translate-y-0.5 hover:border-[rgba(158,178,201,0.28)] hover:bg-[rgba(255,255,255,0.08)] transition-all"
                      >
                        <Icon name="download" size={13} />
                        Download
                      </a>
                    {/if}
                    {#if group.links.length > 1}
                      <div class="flex flex-wrap justify-center gap-2">
                        {#each group.links.slice(1) as link}
                          <a href={link.url} target="_blank" rel="noopener" class="text-[11px] text-home-muted no-underline hover:text-home-text transition-colors">
                            {link.format ? link.format.toUpperCase() : 'Alt'}{link.arch ? ` · ${link.arch}` : ''}
                          </a>
                        {/each}
                      </div>
                    {/if}
                  </div>
                </div>
              {/each}
            </div>
          {/if}
        {:else}
          <div class="rounded-2xl p-8 border border-home-border text-center" style="background: linear-gradient(180deg, rgba(255,255,255,0.025), rgba(255,255,255,0.005)), rgba(11,20,35,0.8);">
            <p class="text-home-muted">Downloads are being prepared. Check back soon for native clients.</p>
          </div>
        {/if}
      </div>
    </section>

    <!-- ==================== QUICK START ==================== -->
    <section class="py-16 md:py-28" data-section="quickstart">
      <div class="max-w-3xl mx-auto px-5 sm:px-6 transition-all duration-700 ease-out" class:opacity-0={!quickstartVisible} class:translate-y-6={!quickstartVisible}>
        <div class="text-center mb-10">
          <h2 class="font-display tracking-[-0.04em] text-[clamp(1.8rem,4vw,2.8rem)] m-0">Running in under 60 seconds</h2>
          <p class="mt-4 text-home-muted">Three commands. That's it.</p>
        </div>

        <div class="space-y-3">
          {#each [
            { num: '1', cmd: 'git clone https://github.com/cpmesh/cpmesh && cd cpmesh' },
            { num: '2', cmd: 'docker compose up -d' },
            { num: '3', cmd: 'open http://localhost:39271' },
          ] as step}
            <div class="flex items-center gap-3 rounded-xl border border-home-border px-4 py-3" style="background: rgba(8,16,30,0.85);">
              <span class="text-home-dim text-xs font-mono w-5 shrink-0 text-center">{step.num}</span>
              <div class="flex-1 font-mono text-[13px] text-home-text overflow-x-auto whitespace-nowrap">
                <span class="text-[#49c6e5]">$</span> {step.cmd}
              </div>
              <button
                type="button"
                class="shrink-0 bg-transparent border-0 cursor-pointer transition-colors {copiedCmd === step.num ? 'text-home-green' : 'text-home-muted hover:text-home-text'}"
                onclick={() => copyText(step.cmd, step.num)}
              >
                <Icon name={copiedCmd === step.num ? 'check' : 'copy'} size={14} />
              </button>
            </div>
          {/each}
        </div>
      </div>
    </section>

    <!-- ==================== COMPARISON ==================== -->
    <section class="py-16 md:py-28" data-section="comparison">
      <div class="max-w-4xl mx-auto px-5 sm:px-6 transition-all duration-700 ease-out" class:opacity-0={!comparisonVisible} class:translate-y-6={!comparisonVisible}>
        <div class="text-center mb-12 md:mb-16">
          <h2 class="font-display tracking-[-0.04em] text-[clamp(1.8rem,4vw,2.8rem)] m-0">How cpmesh compares</h2>
          <p class="mt-4 text-home-muted max-w-lg mx-auto">Not all clipboard sync is created equal.</p>
        </div>

        <!-- Desktop table -->
        <div class="hidden md:block rounded-2xl border border-home-border overflow-hidden" style="background: rgba(11,20,35,0.85);">
          <table class="w-full border-collapse text-sm">
            <thead>
              <tr class="border-b border-home-border">
                <th class="text-left py-4 px-5 text-home-muted font-medium text-xs uppercase tracking-wider w-[200px]">Feature</th>
                <th class="py-4 px-4 text-center">
                  <span class="text-transparent bg-clip-text font-bold text-sm" style="background-image: linear-gradient(135deg, #ff7a59, #49c6e5);">cpmesh</span>
                </th>
                <th class="py-4 px-4 text-center text-home-muted font-medium text-xs">Apple Handoff</th>
                <th class="py-4 px-4 text-center text-home-muted font-medium text-xs">Windows Clipboard</th>
                <th class="py-4 px-4 text-center text-home-muted font-medium text-xs">Pushbullet</th>
              </tr>
            </thead>
            <tbody>
              {#each comparisonFeatures as row}
                <tr class="border-b border-[rgba(255,255,255,0.03)] last:border-0">
                  <td class="py-3.5 px-5 text-home-muted">{row.feature}</td>
                  <td class="py-3.5 px-4 text-center bg-[rgba(42,214,160,0.03)]">
                    {#if row.cpmesh}<span class="text-home-green"><Icon name="check" size={16} /></span>{:else}<span class="text-home-dim opacity-30"><Icon name="x" size={16} /></span>{/if}
                  </td>
                  <td class="py-3.5 px-4 text-center">
                    {#if row.handoff}<span class="text-home-muted"><Icon name="check" size={16} /></span>{:else}<span class="text-home-dim opacity-30"><Icon name="x" size={16} /></span>{/if}
                  </td>
                  <td class="py-3.5 px-4 text-center">
                    {#if row.winclip}<span class="text-home-muted"><Icon name="check" size={16} /></span>{:else}<span class="text-home-dim opacity-30"><Icon name="x" size={16} /></span>{/if}
                  </td>
                  <td class="py-3.5 px-4 text-center">
                    {#if row.pushbullet}<span class="text-home-muted"><Icon name="check" size={16} /></span>{:else}<span class="text-home-dim opacity-30"><Icon name="x" size={16} /></span>{/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>

        <!-- Mobile cards -->
        <div class="md:hidden space-y-3">
          {#each comparisonFeatures as row}
            <div class="rounded-xl border border-home-border p-4 flex items-center justify-between" style="background: rgba(11,20,35,0.8);">
              <span class="text-sm text-home-muted">{row.feature}</span>
              <div class="flex items-center gap-3 shrink-0 ml-3">
                <span class="text-home-green"><Icon name="check" size={15} /></span>
                {#if !row.handoff && !row.winclip && !row.pushbullet}
                  <span class="text-[10px] text-home-dim font-medium uppercase tracking-wide">only cpmesh</span>
                {/if}
              </div>
            </div>
          {/each}
        </div>
      </div>
    </section>

    <!-- ==================== PRICING ==================== -->
    <section class="py-16 md:py-28" id="pricing" data-section="pricing">
      <div class="max-w-2xl mx-auto px-5 sm:px-6 text-center transition-all duration-700 ease-out" class:opacity-0={!pricingVisible} class:translate-y-6={!pricingVisible}>
        <h2 class="font-display tracking-[-0.04em] text-[clamp(1.8rem,4vw,2.8rem)] m-0">Free and open source</h2>
        <p class="mt-4 text-home-muted leading-relaxed max-w-lg mx-auto">
          cpmesh is dual licensed under MIT and Apache-2.0. Self-host your own relay for free with Docker.
          No limits, no telemetry, no strings attached.
        </p>

        <div class="mt-10 grid grid-cols-1 sm:grid-cols-2 gap-5 text-left">
          <!-- Self-hosted -->
          <div
            class="rounded-2xl p-6 border border-[rgba(42,214,160,0.2)] transition-all duration-500 ease-out"
            class:opacity-0={!pricingVisible}
            class:translate-y-4={!pricingVisible}
            style="background: radial-gradient(ellipse at top left, rgba(42,214,160,0.05), transparent 50%), rgba(11,20,35,0.85); transition-delay: 0ms;"
          >
            <span class="text-[11px] font-bold tracking-widest uppercase text-home-green">Self-hosted</span>
            <div class="mt-3 font-display text-3xl tracking-tight">Free</div>
            <p class="mt-1 text-xs text-home-muted">forever · no limits</p>
            <ul class="mt-5 space-y-3 list-none p-0 m-0">
              {#each ['Unlimited devices', 'Full clipboard history', 'Text, images, files (25 MB)', 'Your infrastructure, your rules'] as item}
                <li class="flex items-center gap-2 text-sm text-[#d9e5f2]"><span class="text-home-green"><Icon name="check" size={14} /></span> {item}</li>
              {/each}
            </ul>
            <a href={GITHUB_URL} target="_blank" rel="noopener" class="mt-6 w-full inline-flex items-center justify-center gap-2 rounded-full font-bold py-3 text-sm no-underline hover:-translate-y-0.5 transition-transform" style="background: linear-gradient(135deg, #80eed0, #2ad6a0 60%, #1fb888); color: #000;">
              Get started
              <Icon name="chevron-right" size={14} />
            </a>
          </div>

          <!-- Hosted relay -->
          <div
            class="rounded-2xl p-6 border border-[rgba(255,122,89,0.18)] transition-all duration-500 ease-out"
            class:opacity-0={!pricingVisible}
            class:translate-y-4={!pricingVisible}
            style="background: radial-gradient(ellipse at top right, rgba(255,122,89,0.05), transparent 50%), rgba(11,20,35,0.85); transition-delay: 100ms;"
          >
            <span class="text-[11px] font-bold tracking-widest uppercase text-[#ff7a59]">Hosted relay</span>
            <div class="mt-3 font-display text-3xl tracking-tight">Coming soon</div>
            <p class="mt-1 text-xs text-home-muted">don't want to self-host?</p>
            <ul class="mt-5 space-y-3 list-none p-0 m-0">
              {#each ['Zero config relay', 'Managed infrastructure', 'Same E2E encryption', 'Generous free tier planned'] as item}
                <li class="flex items-center gap-2 text-sm text-[#d9e5f2]"><span class="text-[#ff7a59]"><Icon name="check" size={14} /></span> {item}</li>
              {/each}
            </ul>
            <button type="button" disabled class="mt-6 w-full inline-flex items-center justify-center gap-2 rounded-full font-bold py-3 text-sm text-home-muted no-underline border border-home-border bg-[rgba(255,255,255,0.02)] cursor-not-allowed opacity-50">
              Notify me
            </button>
          </div>
        </div>
      </div>
    </section>

    <!-- ==================== FINAL CTA ==================== -->
    <section class="py-20 md:py-32" data-section="cta">
      <div class="max-w-3xl mx-auto px-5 sm:px-6 text-center transition-all duration-700 ease-out" class:opacity-0={!ctaVisible} class:translate-y-6={!ctaVisible}>
        <h2 class="font-display tracking-[-0.04em] text-[clamp(1.8rem,4.5vw,3rem)] m-0 leading-tight">
          <span class="text-transparent bg-clip-text" style="background-image: linear-gradient(135deg, #ffedc6 0%, #ff9667 45%, #49c6e5 100%);">Your clipboard belongs to you.</span>
        </h2>
        <p class="mt-5 text-lg text-home-muted max-w-lg mx-auto">Stop sending sensitive data through services that can read it. Get cpmesh running in under a minute.</p>

        <div class="flex flex-wrap justify-center gap-4 mt-10">
          <a href="#/login" class="inline-flex items-center gap-2.5 rounded-full font-bold py-3.5 px-7 text-[15px] no-underline hover:-translate-y-0.5 transition-transform" style="background: linear-gradient(135deg, #ffd1a2, #ff7a59 52%, #ffab59); box-shadow: 0 14px 40px rgba(255,122,89,0.22); color: #000;">
            Get Started
            <Icon name="chevron-right" size={16} />
          </a>
          <a href={GITHUB_URL} target="_blank" rel="noopener" class="inline-flex items-center gap-2.5 rounded-full font-bold py-3.5 px-7 text-[15px] text-home-text no-underline border border-home-border bg-[rgba(255,255,255,0.03)] hover:-translate-y-0.5 hover:bg-[rgba(255,255,255,0.06)] transition-all">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
            Star on GitHub
          </a>
        </div>

        <!-- Trust indicators -->
        <div class="flex flex-wrap justify-center gap-6 mt-9 text-[13px] text-home-muted">
          <span class="inline-flex items-center gap-1.5"><span class="text-home-green"><Icon name="shield" size={13} /></span> MIT/Apache-2.0</span>
          <span class="inline-flex items-center gap-1.5"><span class="text-home-green"><Icon name="lock" size={13} /></span> E2E Encrypted</span>
          <span class="inline-flex items-center gap-1.5"><span class="text-home-green"><Icon name="cloud" size={13} /></span> Self-Hosted</span>
          <span class="inline-flex items-center gap-1.5"><span class="text-home-green"><Icon name="zap" size={13} /></span> Sub-second</span>
        </div>
      </div>
    </section>
  </main>

  <!-- ==================== FOOTER ==================== -->
  <footer class="pb-10 pt-4">
    <div class="max-w-6xl mx-auto px-5 sm:px-6 pt-8 border-t border-[rgba(255,255,255,0.05)]">
      <div class="flex flex-col sm:flex-row items-center sm:items-start justify-between gap-6">
        <!-- Brand -->
        <div class="flex items-center gap-3">
          <span class="w-7 h-7 rounded-lg inline-flex items-center justify-center border border-[rgba(255,255,255,0.08)]" style="background: linear-gradient(145deg, rgba(255,122,89,0.18), rgba(73,198,229,0.12)), rgba(255,255,255,0.02);">
            <span class="w-2.5 h-2.5 rounded-full" style="background: linear-gradient(145deg, var(--color-home-accent), var(--color-home-cyan));"></span>
          </span>
          <span class="text-sm text-home-muted">&copy; {new Date().getFullYear()} cpmesh</span>
        </div>

        <!-- Links -->
        <div class="flex items-center gap-5 text-sm text-home-muted">
          <a href={GITHUB_URL} target="_blank" rel="noopener" class="hover:text-home-text transition-colors no-underline text-home-muted inline-flex items-center gap-1.5">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
            Source
          </a>
          <a href="{GITHUB_URL}/blob/main/LICENSE" target="_blank" rel="noopener" class="hover:text-home-text transition-colors no-underline text-home-muted">License</a>
          <a href="{GITHUB_URL}/blob/main/docs/self-hosting.md" target="_blank" rel="noopener" class="hover:text-home-text transition-colors no-underline text-home-muted">Docs</a>
        </div>

        <!-- Built with -->
        <div class="text-xs text-home-dim">
          Built with Rust & Svelte
        </div>
      </div>
    </div>
  </footer>
</div>

<style>
  .terminal-cursor {
    animation: blink 1s step-end infinite;
  }

  @keyframes blink {
    0%, 100% { opacity: 1; }
    50% { opacity: 0; }
  }

  @keyframes float1 {
    0%, 100% { transform: translateY(0) rotate(0deg); }
    50% { transform: translateY(-14px) rotate(1deg); }
  }

  @keyframes float2 {
    0%, 100% { transform: translateY(0) rotate(0deg); }
    50% { transform: translateY(-10px) rotate(-1.5deg); }
  }

  @media (prefers-reduced-motion: reduce) {
    :global(.home *) {
      animation-duration: 0.01ms !important;
      animation-iteration-count: 1 !important;
      transition-duration: 0.01ms !important;
    }
  }
</style>
