<script lang="ts">
  import Icon from '../Icon.svelte';
  import Button from '../ui/Button.svelte';
  import CodeBlock from './CodeBlock.svelte';
  import {
    agentSetups,
    envVars,
    examplePrompts,
    firstRunSteps,
    MCP_PACKAGE,
    MCP_SOURCE_URL,
    normalizeServerUrl,
    DEFAULT_SERVER_URL,
    prerequisites,
    securityNotes,
    toolGroups,
    troubleshooting,
  } from '../../lib/mcp';

  /**
   * The cpmesh MCP setup guide. Rendered standalone on the public site
   * (`#/mcp`) and inside the dashboard layout (`inApp`), where the page
   * header comes from the route metadata instead of the hero.
   */
  let { inApp = false }: { inApp?: boolean } = $props();

  let serverUrl = $state(DEFAULT_SERVER_URL);
  const setups = $derived(agentSetups(serverUrl));
  const steps = $derived(firstRunSteps(serverUrl));
  const help = $derived(troubleshooting(serverUrl));
  const toolCount = toolGroups.reduce((count, group) => count + group.tools.length, 0);
  let selectedId = $state('claude-code');
  const selected = $derived(setups.find((s) => s.id === selectedId) ?? setups[0]);

  function selectByOffset(offset: number) {
    const i = setups.findIndex((s) => s.id === selectedId);
    const next = setups[(i + offset + setups.length) % setups.length];
    selectedId = next.id;
    document.getElementById(`agent-tab-${next.id}`)?.focus();
  }

  function onTabKey(e: KeyboardEvent) {
    if (e.key === 'ArrowDown' || e.key === 'ArrowRight') {
      e.preventDefault();
      selectByOffset(1);
    } else if (e.key === 'ArrowUp' || e.key === 'ArrowLeft') {
      e.preventDefault();
      selectByOffset(-1);
    }
  }

  function scrollToId(id: string) {
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  const capabilities = [
    { icon: 'send', title: 'Send to your devices', desc: 'Commands, URLs and snippets land on your phone and desktop clipboard, ready to paste.' },
    { icon: 'clipboard', title: 'Read what you copied', desc: 'The agent can pick up what you just copied on another device without you pasting it into chat.' },
    { icon: 'search', title: 'Search your history', desc: 'Find something you copied earlier across all your devices, decrypted locally.' },
    { icon: 'monitor', title: 'See your devices', desc: 'List paired devices with their online state, and remove the ones you no longer use.' },
  ];
</script>

{#snippet heading(id: string, label: string, title: string, sub?: string)}
  <div {id} class="scroll-mt-20">
    <p class="text-[13px] font-medium text-muted">{label}</p>
    <h2 class="mt-2 text-[clamp(1.5rem,2.5vw,2rem)] font-semibold leading-[1.15] tracking-[-0.03em] text-fg">{title}</h2>
    {#if sub}<p class="mt-3 max-w-2xl text-[15px] leading-relaxed text-muted">{sub}</p>{/if}
  </div>
{/snippet}

<div class="mcp-guide">
  {#if !inApp}
    <!-- Hero -->
    <section class="pb-14 pt-16 md:pb-16 md:pt-24">
      <p class="inline-flex items-center gap-2 text-[13px] text-muted">
        <Icon name="sparkles" size={14} />
        Model Context Protocol · <code class="font-mono text-[12px]">{MCP_PACKAGE}</code>
      </p>
      <h1 class="mt-5 max-w-3xl text-[clamp(2.25rem,5vw,4rem)] font-semibold leading-[1.04] tracking-[-0.04em] text-fg">
        Give your AI agent a clipboard.
      </h1>
      <p class="mt-5 max-w-2xl text-lg leading-relaxed text-muted">
        The cpmesh MCP server lets Claude, Cursor, Copilot, Codex, Gemini and any other MCP client send text to your devices and read what you copy. It joins your account as its own device, so everything stays end-to-end encrypted.
      </p>
      <div class="mt-8 flex flex-wrap gap-3">
        <Button size="lg" iconRight="arrow-right" onclick={() => scrollToId('setup')}>Set up your agent</Button>
        <Button href={MCP_SOURCE_URL} external variant="secondary" size="lg" icon="github">View source</Button>
      </div>
    </section>
  {:else}
    <div class="mb-6 flex flex-wrap gap-2">
      <Button size="sm" variant="secondary" onclick={() => scrollToId('setup')}>Setup</Button>
      <Button size="sm" variant="secondary" onclick={() => scrollToId('pairing')}>First run</Button>
      <Button size="sm" variant="secondary" onclick={() => scrollToId('tools')}>Tools</Button>
      <Button size="sm" variant="ghost" href={MCP_SOURCE_URL} external icon="github">Source</Button>
    </div>
  {/if}

  <!-- What it does -->
  <section class="space-y-8">
    {#if !inApp}
      {@render heading('what', 'What it does', 'Your clipboard, available to the agent', 'MCP is the open standard AI agents use to call tools. cpmesh-mcp adds clipboard tools to any agent that supports it.')}
    {/if}
    <ul class="cell-grid grid-cols-1 bg-surface sm:grid-cols-2 lg:grid-cols-4">
      {#each capabilities as c (c.title)}
        <li class="px-6 py-6">
          <span class="text-fg"><Icon name={c.icon} size={18} strokeWidth={1.75} /></span>
          <h3 class="mt-3 text-[15px] font-medium text-fg">{c.title}</h3>
          <p class="mt-1.5 text-sm leading-relaxed text-muted">{c.desc}</p>
        </li>
      {/each}
    </ul>
  </section>

  <!-- Setup -->
  <section class="mt-16 space-y-8 md:mt-20">
    {@render heading('setup', 'Setup', 'Add cpmesh to your agent', 'Pick your agent and copy the command or config. Every snippet uses the server URL below.')}

    <ul class="cell-grid grid-cols-1 bg-surface md:grid-cols-3">
      {#each prerequisites as p (p.title)}
        <li class="flex gap-3 px-5 py-5">
          <span class="mt-0.5 text-fg"><Icon name={p.icon} size={16} strokeWidth={1.75} /></span>
          <div>
            <h3 class="text-sm font-medium text-fg">{p.title}</h3>
            <p class="mt-1 text-[13px] leading-relaxed text-muted">{p.desc}</p>
          </div>
        </li>
      {/each}
    </ul>

    <div class="rounded-lg border border-border bg-surface p-4 sm:p-5">
      <label for="mcp-server-url" class="text-[13px] font-medium text-fg">Your cpmesh server</label>
      <p class="mt-1 text-[13px] text-muted">Snippets point to the hosted cpmesh servers at cpmesh.com. If you self-host, enter your own relay's address.</p>
      <input
        id="mcp-server-url"
        type="url"
        inputmode="url"
        autocomplete="off"
        spellcheck="false"
        placeholder={DEFAULT_SERVER_URL}
        bind:value={serverUrl}
        class="mt-3 h-10 w-full rounded-md border border-border-strong bg-surface px-3 font-mono text-[13px] text-fg outline-none transition-colors placeholder:text-dim focus:border-ink"
      />
      {#if normalizeServerUrl(serverUrl).startsWith('http://') && !/^http:\/\/(localhost|127\.0\.0\.1)/.test(normalizeServerUrl(serverUrl))}
        <p class="mt-2 text-[12px] text-warning">Use https:// for anything other than a local test server.</p>
      {/if}
    </div>

    <div class="grid gap-4 lg:grid-cols-[220px_minmax(0,1fr)]">
      <div role="tablist" aria-label="AI agent" aria-orientation="vertical" class="flex gap-1 overflow-x-auto pb-1 lg:flex-col lg:overflow-visible lg:pb-0">
        {#each setups as s (s.id)}
          {@const active = s.id === selected.id}
          <button
            type="button"
            role="tab"
            id="agent-tab-{s.id}"
            aria-selected={active}
            aria-controls="agent-panel"
            tabindex={active ? 0 : -1}
            onclick={() => (selectedId = s.id)}
            onkeydown={onTabKey}
            class="shrink-0 whitespace-nowrap rounded-md px-3 py-2 text-left text-[13px] transition-colors {active ? 'bg-ink font-medium text-white' : 'text-muted hover:bg-surface-2 hover:text-fg'}"
          >
            {s.name}
          </button>
        {/each}
      </div>

      <div id="agent-panel" role="tabpanel" aria-labelledby="agent-tab-{selected.id}" class="min-w-0 space-y-4 self-start rounded-lg border border-border bg-bg-deep p-4 sm:p-6">
        <div class="flex flex-wrap items-start justify-between gap-3">
          <div class="min-w-0">
            <div class="flex flex-wrap items-center gap-2">
              <h3 class="text-lg font-semibold tracking-tight text-fg">{selected.name}</h3>
              <span class="rounded-full border border-border px-2 py-px text-[11px] text-muted">{selected.kind}</span>
            </div>
            <p class="mt-1.5 max-w-2xl text-sm leading-relaxed text-muted">{selected.intro}</p>
          </div>
          {#if selected.installLink}
            <Button href={selected.installLink.href} size="sm" icon="download">{selected.installLink.label}</Button>
          {/if}
        </div>

        {#each selected.blocks as block (block.title)}
          <CodeBlock title={block.title} code={block.code} lang={block.lang} />
        {/each}

        {#if selected.notes.length}
          <ul class="space-y-1.5 text-[13px] leading-relaxed text-muted">
            {#each selected.notes as note (note)}
              <li class="flex gap-2"><span class="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-dim"></span><span class="min-w-0 break-words">{note}</span></li>
            {/each}
          </ul>
        {/if}

        {#if selected.docsUrl}
          <a href={selected.docsUrl} target="_blank" rel="noopener" class="inline-flex items-center gap-1.5 text-[13px] text-muted underline underline-offset-4 hover:text-fg">
            {selected.name} MCP documentation <Icon name="arrow-up-right" size={12} />
          </a>
        {/if}
      </div>
    </div>
  </section>

  <!-- First run: sign-in, then pairing -->
  <section class="mt-16 space-y-8 md:mt-20">
    {@render heading('pairing', 'First run', 'Connect the agent once', 'You approve the agent in your browser, then pair it from a device you already trust, exactly like adding a new laptop.')}
    <ol class="cell-grid grid-cols-1 bg-surface md:grid-cols-2 lg:grid-cols-4">
      {#each steps as step, i (step.title)}
        <li class="px-6 py-6">
          <span class="font-mono text-xs text-dim">0{i + 1}</span>
          <h3 class="mt-3 text-[15px] font-medium text-fg">{step.title}</h3>
          <p class="mt-1.5 text-sm leading-relaxed text-muted">{step.desc}</p>
        </li>
      {/each}
    </ol>
    <p class="text-[13px] text-muted">
      No devices yet? The agent becomes your first device: it is approved automatically and creates your encryption key.
    </p>
  </section>

  <!-- Usage -->
  <section class="mt-16 space-y-8 md:mt-20">
    {@render heading('usage', 'Usage', 'Just ask', 'Once paired, talk to your agent normally. It picks the right cpmesh tool for you.')}
    <ul class="grid gap-3 sm:grid-cols-2">
      {#each examplePrompts as ex (ex.prompt)}
        <li class="rounded-lg border border-border bg-surface px-4 py-3.5">
          <p class="text-[15px] text-fg">“{ex.prompt}”</p>
          <p class="mt-1.5 inline-flex items-center gap-1.5 font-mono text-[11px] text-dim"><Icon name="arrow-right" size={11} /> {ex.tool}</p>
        </li>
      {/each}
    </ul>
  </section>

  <!-- Tools -->
  <section class="mt-16 space-y-8 md:mt-20">
    {@render heading('tools', 'Reference', 'Tools', `${toolCount} tools, plus a cpmesh_skill prompt that gives the agent these instructions at runtime.`)}
    <div class="grid gap-4 lg:grid-cols-3">
      {#each toolGroups as group (group.title)}
        <div class="overflow-hidden rounded-lg border border-border bg-surface">
          <div class="flex items-center gap-2 border-b border-border px-4 py-3">
            <span class="text-fg"><Icon name={group.icon} size={15} strokeWidth={1.75} /></span>
            <h3 class="text-sm font-medium text-fg">{group.title}</h3>
          </div>
          <dl class="divide-y divide-border">
            {#each group.tools as tool (tool.name)}
              <div class="px-4 py-3">
                <dt class="break-all font-mono text-[12.5px] text-fg">{tool.name}</dt>
                <dd class="mt-1 text-[13px] leading-relaxed text-muted">{tool.desc}</dd>
              </div>
            {/each}
          </dl>
        </div>
      {/each}
    </div>

    <div class="overflow-hidden rounded-lg border border-border bg-surface">
      <div class="border-b border-border px-4 py-3">
        <h3 class="text-sm font-medium text-fg">Environment variables</h3>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-left text-[13px]">
          <thead class="text-muted">
            <tr class="border-b border-border">
              <th scope="col" class="px-4 py-2.5 font-medium">Variable</th>
              <th scope="col" class="px-4 py-2.5 font-medium">Default</th>
              <th scope="col" class="px-4 py-2.5 font-medium">Purpose</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-border">
            {#each envVars as v (v.name)}
              <tr>
                <td class="whitespace-nowrap px-4 py-2.5 font-mono text-[12.5px] text-fg">{v.name}</td>
                <td class="whitespace-nowrap px-4 py-2.5 font-mono text-[12.5px] text-muted">{v.def}</td>
                <td class="px-4 py-2.5 text-muted">{v.desc}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </div>
  </section>

  <!-- Security + troubleshooting -->
  <section class="mt-16 grid gap-10 md:mt-20 lg:grid-cols-2">
    <div class="space-y-6">
      {@render heading('security', 'Security', 'Same encryption as your other devices')}
      <ul class="space-y-3">
        {#each securityNotes as item (item)}
          <li class="flex gap-3 text-sm leading-relaxed text-muted">
            <span class="mt-0.5 shrink-0 text-fg"><Icon name="shield-check" size={16} strokeWidth={1.75} /></span>
            <span>{item}</span>
          </li>
        {/each}
      </ul>
    </div>
    <div class="space-y-6">
      {@render heading('troubleshooting', 'Help', 'Troubleshooting')}
      <dl class="divide-y divide-border rounded-lg border border-border bg-surface">
        {#each help as t (t.q)}
          <div class="px-4 py-3.5">
            <dt class="text-sm font-medium text-fg">{t.q}</dt>
            <dd class="mt-1 text-[13px] leading-relaxed text-muted">{t.a}</dd>
          </div>
        {/each}
      </dl>
    </div>
  </section>
</div>
