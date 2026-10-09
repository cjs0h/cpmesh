<script lang="ts">
  import { onMount } from 'svelte';
  import Icon from '../components/Icon.svelte';
  import Logo from '../components/Logo.svelte';
  import SyncDemo from '../components/landing/SyncDemo.svelte';
  import Button from '../components/ui/Button.svelte';

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
      setTimeout(() => (copiedCmd = ''), 1600);
    } catch {
      /* clipboard unavailable */
    }
  }

  // --- Content ---
  const stats = [
    { value: 'AES-256-GCM', label: 'Authenticated encryption, on device' },
    { value: '< 1 s', label: 'Copy to paste across devices' },
    { value: '5', label: 'Native platforms, plus the web' },
    { value: '0 bytes', label: 'Readable by the relay' },
  ];

  const features = [
    { icon: 'zap', title: 'Sub-second sync', desc: 'WebSocket push, not polling. A clip is on your other devices before you finish switching windows.' },
    { icon: 'lock', title: 'End-to-end encrypted', desc: 'AES-256-GCM runs on your device. Keys are exchanged peer to peer and never touch the relay.' },
    { icon: 'layers', title: 'Every platform', desc: 'Native clients for Windows, macOS, Linux and Android, and this dashboard for history and devices.' },
    { icon: 'server', title: 'Self-host or use ours', desc: 'One Docker command on hardware you own, or point the apps at the hosted relay.' },
    { icon: 'history', title: 'Clipboard history', desc: 'Browse, search and restore past clips. Encrypted at rest, deletable at any time.' },
    { icon: 'github', title: 'Open source', desc: 'MIT / Apache-2.0. Rust relay, Tauri desktop apps, Kotlin on Android. No telemetry.' },
  ];

  const steps = [
    { num: '01', title: 'Install', desc: 'Run the relay with Docker — or use ours — and install the app on each device.' },
    { num: '02', title: 'Pair', desc: 'Sign in once per device. Encryption keys are exchanged directly between your devices over ECDH.' },
    { num: '03', title: 'Copy and paste', desc: 'Text, images and files appear on every paired device in under a second.' },
  ];

  const quickstart = [
    { id: '1', cmd: 'git clone https://github.com/cjs0h/cpmesh && cd cpmesh' },
    { id: '2', cmd: 'docker compose up -d' },
    { id: '3', cmd: 'open http://localhost:39271' },
  ];

  const dockerCompose = `services:
  relay:
    image: ghcr.io/cjs0h/cpmesh:latest
    ports: ["39271:8080"]
    volumes: ["./data:/data"]
    restart: unless-stopped`;

  const flow = [
    { icon: 'laptop', label: 'Your laptop', sub: 'plaintext' },
    { icon: 'lock', label: 'Encrypt', sub: 'AES-256-GCM' },
    { icon: 'cloud', label: 'Relay', sub: 'ciphertext only' },
    { icon: 'key', label: 'Decrypt', sub: 'ECDH P-256' },
    { icon: 'smartphone', label: 'Your phone', sub: 'plaintext' },
  ];

  const protocols = [
    { title: 'AES-256-GCM', desc: 'Authenticated encryption for every clip: confidentiality and integrity in one pass, with a fresh nonce each time.' },
    { title: 'ECDH P-256', desc: 'Each device holds its own keypair. Shared keys are agreed directly between devices; the relay is never part of it.' },
    { title: 'Zero knowledge', desc: 'The relay stores and forwards sealed bytes. Compromising it yields ciphertext and nothing else.' },
  ];
</script>

<svelte:head>
  <title>cpmesh — Encrypted clipboard sync across your devices</title>
  <meta name="description" content="Copy on one device, paste on another. End-to-end encrypted with AES-256-GCM. Open source, self-hostable." />
</svelte:head>

{#snippet sectionHeader(label: string, title: string, sub?: string)}
  <div class="grid gap-6 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)] md:items-end">
    <div>
      <p class="text-[13px] font-medium text-muted">{label}</p>
      <h2 class="mt-2 text-[clamp(1.75rem,3vw,2.5rem)] font-semibold leading-[1.1] tracking-[-0.03em] text-fg">{title}</h2>
    </div>
    {#if sub}<p class="max-w-xl text-[15px] leading-relaxed text-muted md:justify-self-end md:text-right">{sub}</p>{/if}
  </div>
{/snippet}

<div class="home min-h-dvh bg-bg text-fg">
  <!-- ==================== HEADER ==================== -->
  <header class="sticky top-0 z-40 border-b border-border bg-surface">
    <div class="wrap flex h-14 items-center justify-between">
      <a href="#/" class="inline-flex items-center gap-2" aria-label="cpmesh home">
        <Logo size={24} withText textClass="text-[15px]" />
      </a>

      <nav class="hidden items-center gap-1 md:flex" aria-label="Primary">
        {#each navLinks as link (link.id)}
          <button type="button" class="rounded-md px-3 py-1.5 text-[13px] text-muted transition-colors hover:bg-surface-2 hover:text-fg" onclick={() => scrollToId(link.id)}>{link.label}</button>
        {/each}
        <a href={GITHUB_URL} target="_blank" rel="noopener" class="rounded-md px-3 py-1.5 text-[13px] text-muted transition-colors hover:bg-surface-2 hover:text-fg">GitHub</a>
      </nav>

      <div class="flex items-center gap-2">
        <span class="hidden sm:contents"><Button href="#/login" variant="ghost" size="sm">Sign in</Button></span>
        <Button href="#/login" size="sm">Get started</Button>
        <button type="button" class="ml-1 flex h-8 w-8 items-center justify-center rounded-md text-fg hover:bg-surface-2 md:hidden" aria-label="Open navigation menu" aria-expanded={mobileNavOpen} onclick={() => (mobileNavOpen = !mobileNavOpen)}>
          <Icon name={mobileNavOpen ? 'x' : 'menu'} size={18} />
        </button>
      </div>
    </div>

    {#if mobileNavOpen}
      <nav class="border-t border-border bg-surface px-5 py-3 md:hidden" aria-label="Mobile">
        <ul class="flex flex-col">
          {#each navLinks as link (link.id)}
            <li><button type="button" class="w-full py-2.5 text-left text-[15px] text-fg" onclick={() => scrollToId(link.id)}>{link.label}</button></li>
          {/each}
          <li><a href={GITHUB_URL} target="_blank" rel="noopener" class="block py-2.5 text-[15px] text-fg">GitHub</a></li>
          <li class="pt-2"><Button href="#/login" variant="secondary" class="w-full">Sign in</Button></li>
        </ul>
      </nav>
    {/if}
  </header>

  <main>
    <!-- ==================== HERO ==================== -->
    <section class="pb-16 pt-20 md:pb-20 md:pt-28" id="top">
      <div class="wrap">
        <div class="mx-auto max-w-4xl text-center">
          <p class="inline-flex items-center gap-2 text-[13px] text-muted">
            <span class="status-dot text-accent"></span>
            Open source · MIT / Apache-2.0 · Self-hostable
          </p>
          <h1 class="mt-6 text-[clamp(2.5rem,6vw,5.5rem)] font-semibold leading-[1.02] tracking-[-0.045em] text-fg">
            Copy anywhere.<br />Paste everywhere.
          </h1>
          <p class="mx-auto mt-6 max-w-2xl text-lg leading-relaxed text-muted md:text-xl">
            One clipboard across every device you own — text, images and files — encrypted before it leaves your machine. The relay never sees a readable byte.
          </p>
          <div class="mt-9 flex flex-wrap items-center justify-center gap-3">
            <Button href="#/login" size="lg" iconRight="arrow-right">Get started</Button>
            <Button onclick={() => scrollToId('downloads')} variant="secondary" size="lg">Download the app</Button>
          </div>
        </div>

        <div class="mx-auto mt-16 max-w-[1040px] md:mt-20">
          <SyncDemo />
        </div>
      </div>
    </section>

    <!-- ==================== STATS ==================== -->
    <section class="border-t border-border">
      <div class="wrap">
        <dl class="cell-grid grid-cols-2 md:grid-cols-4">
          {#each stats as s (s.label)}
            <div class="px-6 py-8">
              <dt class="text-xl font-semibold tracking-tight text-fg md:text-2xl">{s.value}</dt>
              <dd class="mt-1 text-[13px] text-muted">{s.label}</dd>
            </div>
          {/each}
        </dl>
      </div>
    </section>

    <!-- ==================== FEATURES ==================== -->
    <section class="border-t border-border py-20 md:py-28" id="features">
      <div class="wrap">
        {@render sectionHeader('Features', 'Built for people who care where their data goes', 'Fast enough to forget it is there. Encrypted so you never have to think about who else can read your clipboard.')}

        <ul class="cell-grid mt-12 grid-cols-1 sm:grid-cols-2 lg:grid-cols-3">
          {#each features as f (f.title)}
            <li class="px-6 py-7">
              <span class="text-fg"><Icon name={f.icon} size={18} strokeWidth={1.75} /></span>
              <h3 class="mt-4 text-[15px] font-medium text-fg">{f.title}</h3>
              <p class="mt-2 text-sm leading-relaxed text-muted">{f.desc}</p>
            </li>
          {/each}
        </ul>
      </div>
    </section>

    <!-- ==================== HOW IT WORKS ==================== -->
    <section class="border-t border-border bg-bg-deep py-20 md:py-28">
      <div class="wrap">
        {@render sectionHeader('How it works', 'Up and running in three steps', 'No configuration and no key management. Install, pair, and start pasting.')}

        <ol class="cell-grid mt-12 grid-cols-1 bg-surface md:grid-cols-3">
          {#each steps as step (step.num)}
            <li class="px-6 py-7">
              <span class="font-mono text-xs text-dim">{step.num}</span>
              <h3 class="mt-3 text-[15px] font-medium text-fg">{step.title}</h3>
              <p class="mt-2 text-sm leading-relaxed text-muted">{step.desc}</p>
            </li>
          {/each}
        </ol>

        <div class="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-2">
          <div class="overflow-hidden rounded-lg border border-border bg-surface">
            <div class="flex items-center justify-between border-b border-border px-4 py-2.5">
              <span class="font-mono text-xs text-muted">Self-host in three commands</span>
            </div>
            <ul class="divide-y divide-border">
              {#each quickstart as step (step.id)}
                <li class="flex items-center gap-3 px-4 py-3">
                  <span class="font-mono text-xs text-dim">{step.id}</span>
                  <code class="min-w-0 flex-1 overflow-x-auto whitespace-nowrap font-mono text-[13px] text-fg"><span class="text-dim">$</span> {step.cmd}</code>
                  <button type="button" class="shrink-0 rounded p-1 transition-colors {copiedCmd === step.id ? 'text-accent' : 'text-dim hover:text-fg'}" aria-label="Copy command" onclick={() => copyText(step.cmd, step.id)}>
                    <Icon name={copiedCmd === step.id ? 'check' : 'copy'} size={14} />
                  </button>
                </li>
              {/each}
            </ul>
          </div>

          <div class="overflow-hidden rounded-lg border border-border bg-surface">
            <div class="flex items-center justify-between border-b border-border px-4 py-2.5">
              <span class="font-mono text-xs text-muted">docker-compose.yml</span>
              <button type="button" class="inline-flex items-center gap-1.5 text-xs transition-colors {copiedCmd === 'docker' ? 'text-accent' : 'text-dim hover:text-fg'}" onclick={() => copyText(dockerCompose, 'docker')}>
                <Icon name={copiedCmd === 'docker' ? 'check' : 'copy'} size={12} />
                {copiedCmd === 'docker' ? 'Copied' : 'Copy'}
              </button>
            </div>
            <pre class="overflow-x-auto px-4 py-3 font-mono text-[13px] leading-6 text-muted"><code>{dockerCompose}</code></pre>
          </div>
        </div>
      </div>
    </section>

    <!-- ==================== SECURITY ==================== -->
    <section class="border-t border-border py-20 md:py-28" id="security">
      <div class="wrap">
        {@render sectionHeader('Security', 'Zero-knowledge by design', 'Your clipboard is encrypted before it leaves your device. The relay cannot decrypt it — nobody can, except your own devices.')}

        <!-- Flow -->
        <ol class="mt-12 flex flex-col items-stretch gap-2 md:flex-row md:items-center">
          {#each flow as node, i (node.label)}
            {#if i > 0}
              <li class="hidden flex-1 border-t border-dashed border-border-strong md:block" aria-hidden="true"></li>
              <li class="mx-auto h-5 border-l border-dashed border-border-strong md:hidden" aria-hidden="true"></li>
            {/if}
            <li class="flex items-center gap-3 rounded-lg border border-border bg-surface px-4 py-3 md:w-[172px] md:shrink-0 {node.label === 'Relay' ? 'bg-bg-deep' : ''}">
              <span class="{node.label === 'Relay' ? 'text-dim' : 'text-fg'}"><Icon name={node.icon} size={18} strokeWidth={1.75} /></span>
              <div class="min-w-0">
                <div class="text-[13px] font-medium text-fg">{node.label}</div>
                <div class="font-mono text-[11px] text-dim">{node.sub}</div>
              </div>
            </li>
          {/each}
        </ol>

        <div class="cell-grid mt-12 grid-cols-1 md:grid-cols-3">
          {#each protocols as p (p.title)}
            <div class="px-6 py-7">
              <h3 class="font-mono text-sm font-medium text-fg">{p.title}</h3>
              <p class="mt-2 text-sm leading-relaxed text-muted">{p.desc}</p>
            </div>
          {/each}
        </div>

        <pre class="mt-6 overflow-x-auto rounded-lg border border-border bg-bg-deep px-5 py-4 font-mono text-[13px] leading-6 text-muted"><code><span class="text-dim">// what happens when you copy</span>
plaintext  = clipboard.read()
shared_key = <span class="text-fg">ECDH</span>(my_private, peer_public)
nonce      = random(12)
ciphertext = <span class="text-fg">AES_256_GCM</span>.encrypt(shared_key, nonce, plaintext)
relay.send(ciphertext)  <span class="text-dim">// the relay only ever sees this</span></code></pre>
      </div>
    </section>

    <!-- ==================== DOWNLOADS ==================== -->
    <section class="border-t border-border bg-bg-deep py-20 md:py-28" id="downloads">
      <div class="wrap">
        {@render sectionHeader('Downloads', 'Get the app for your platform', 'System-tray integration, background sync and automatic reconnection are included on every platform.')}

        <div class="mt-12 overflow-hidden rounded-lg border border-border bg-surface">
          {#if dlGroups.length > 0}
            {#if detectedGroup}
              <div class="flex flex-col gap-5 border-b border-border p-6 sm:flex-row sm:items-center">
                <span class="text-fg"><Icon name={detectedGroup.icon} size={28} strokeWidth={1.5} /></span>
                <div class="min-w-0 flex-1">
                  <div class="flex flex-wrap items-center gap-2">
                    <h3 class="text-lg font-semibold tracking-tight text-fg">{detectedGroup.label}</h3>
                    {#if detectedGroup.platform === detectedPlatform}
                      <span class="rounded-full border border-border px-2 py-px text-[11px] text-muted">Detected</span>
                    {/if}
                  </div>
                  {#if detectedGroup.links[0]}
                    <p class="mt-1 font-mono text-xs text-dim">{detectedGroup.links[0].format ? detectedGroup.links[0].format.toUpperCase() : 'PACKAGE'}{detectedGroup.links[0].arch ? ` · ${detectedGroup.links[0].arch}` : ''}</p>
                  {/if}
                </div>
                <div class="flex flex-col items-stretch gap-2 sm:items-end">
                  {#if detectedGroup.links[0]}
                    <Button href={detectedGroup.links[0].url} external icon="download">Download for {detectedGroup.label}</Button>
                  {/if}
                  {#if detectedGroup.links.length > 1}
                    <div class="flex flex-wrap gap-3 sm:justify-end">
                      {#each detectedGroup.links.slice(1) as link (link.id)}
                        <a href={link.url} target="_blank" rel="noopener" class="text-xs text-muted underline underline-offset-4 hover:text-fg">{link.format ? link.format.toUpperCase() : 'Alt'}{link.arch ? ` · ${link.arch}` : ''}</a>
                      {/each}
                    </div>
                  {/if}
                </div>
              </div>
            {/if}

            {#if secondaryGroups.length > 0}
              <ul class="divide-y divide-border">
                {#each secondaryGroups as group (group.platform)}
                  <li class="flex items-center gap-4 px-6 py-4">
                    <span class="text-muted"><Icon name={group.icon} size={18} strokeWidth={1.5} /></span>
                    <div class="min-w-0 flex-1">
                      <div class="text-sm font-medium text-fg">{group.label}</div>
                      <div class="font-mono text-[11px] text-dim">
                        {#each group.links as link, i (link.id)}{i > 0 ? ' · ' : ''}{link.format ? link.format.toUpperCase() : 'Package'}{link.arch ? ` ${link.arch}` : ''}{/each}
                      </div>
                    </div>
                    {#if group.links[0]}
                      <Button href={group.links[0].url} external variant="secondary" size="sm" icon="download">Download</Button>
                    {/if}
                  </li>
                {/each}
              </ul>
            {/if}
          {:else}
            <div class="p-10 text-center">
              <p class="text-sm font-medium text-fg">Installers are being prepared</p>
              <p class="mt-1 text-sm text-muted">Native clients are on the way. In the meantime, build from source on GitHub.</p>
              <Button href={GITHUB_URL} external variant="secondary" size="sm" class="mt-5">View the repository</Button>
            </div>
          {/if}
        </div>
      </div>
    </section>

    <!-- ==================== PRICING ==================== -->
    <section class="border-t border-border py-20 md:py-28" id="pricing">
      <div class="wrap">
        {@render sectionHeader('Pricing', 'Free and open source', 'Dual licensed under MIT and Apache-2.0. Self-host for free with Docker — no limits, no telemetry.')}

        <div class="cell-grid mt-12 grid-cols-1 md:grid-cols-2">
          <div class="px-6 py-8 md:px-8">
            <p class="text-[13px] font-medium text-muted">Self-hosted</p>
            <p class="mt-3 text-4xl font-semibold tracking-tight text-fg">Free</p>
            <p class="mt-1 text-sm text-muted">Forever. No limits.</p>
            <ul class="mt-6 space-y-2.5 text-sm text-fg">
              {#each ['Unlimited devices', 'Full clipboard history', 'Text, images and files up to 25 MB', 'Your infrastructure, your rules'] as item (item)}
                <li class="flex items-center gap-2.5"><Icon name="check" size={14} class="shrink-0 text-fg" /> {item}</li>
              {/each}
            </ul>
            <Button href={GITHUB_URL} external iconRight="arrow-right" class="mt-8">Deploy your relay</Button>
          </div>
          <div class="px-6 py-8 md:px-8">
            <p class="text-[13px] font-medium text-muted">Hosted relay</p>
            <p class="mt-3 text-4xl font-semibold tracking-tight text-fg">Coming soon</p>
            <p class="mt-1 text-sm text-muted">The same encryption, without running a server.</p>
            <ul class="mt-6 space-y-2.5 text-sm text-fg">
              {#each ['Zero-config relay', 'Managed infrastructure', 'Same end-to-end encryption', 'Generous free tier planned'] as item (item)}
                <li class="flex items-center gap-2.5"><Icon name="check" size={14} class="shrink-0 text-dim" /> {item}</li>
              {/each}
            </ul>
            <Button variant="secondary" disabled class="mt-8">Notify me</Button>
          </div>
        </div>
      </div>
    </section>

    <!-- ==================== CTA ==================== -->
    <section class="border-t border-border bg-bg-deep py-20 md:py-28">
      <div class="wrap text-center">
        <h2 class="text-[clamp(2rem,4vw,3.25rem)] font-semibold leading-[1.05] tracking-[-0.04em] text-fg">Your clipboard belongs to you.</h2>
        <p class="mx-auto mt-5 max-w-xl text-base text-muted md:text-lg">Stop routing sensitive data through services that can read it. Get cpmesh running in under a minute.</p>
        <div class="mt-8 flex flex-wrap justify-center gap-3">
          <Button href="#/login" size="lg" iconRight="arrow-right">Get started</Button>
          <Button href={GITHUB_URL} external variant="secondary" size="lg" icon="github">Star on GitHub</Button>
        </div>
      </div>
    </section>
  </main>

  <!-- ==================== FOOTER ==================== -->
  <footer class="border-t border-border py-10">
    <div class="wrap flex flex-col items-start justify-between gap-6 text-[13px] text-muted sm:flex-row sm:items-center">
      <div class="flex items-center gap-3">
        <Logo size={20} />
        <span>© {new Date().getFullYear()} cpmesh</span>
      </div>
      <nav class="flex items-center gap-5" aria-label="Footer">
        <a href={GITHUB_URL} target="_blank" rel="noopener" class="hover:text-fg">Source</a>
        <a href="{GITHUB_URL}/blob/main/LICENSE" target="_blank" rel="noopener" class="hover:text-fg">License</a>
        <a href="{GITHUB_URL}/blob/main/docs/self-hosting.md" target="_blank" rel="noopener" class="hover:text-fg">Docs</a>
        <a href="#/login" class="hover:text-fg">Sign in</a>
      </nav>
      <span class="text-dim">Built with Rust and Svelte</span>
    </div>
  </footer>
</div>

<style>
  /* Fluid container: comfortable measure on laptops, grows on large monitors. */
  :global(.home .wrap) {
    width: 100%;
    max-width: 1200px;
    margin-inline: auto;
    padding-inline: 1.25rem;
  }
  @media (min-width: 640px) {
    :global(.home .wrap) {
      padding-inline: 2rem;
    }
  }
  @media (min-width: 1536px) {
    :global(.home .wrap) {
      max-width: 1360px;
    }
  }
  @media (min-width: 1920px) {
    :global(.home .wrap) {
      max-width: 1520px;
    }
  }
</style>
