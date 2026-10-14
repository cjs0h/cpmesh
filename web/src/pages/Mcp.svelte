<script lang="ts">
  import Logo from '../components/Logo.svelte';
  import Button from '../components/ui/Button.svelte';
  import McpGuide from '../components/mcp/McpGuide.svelte';

  const GITHUB_URL = 'https://github.com/cjs0h/cpmesh';
</script>

<svelte:head>
  <title>AI agents (MCP) — cpmesh</title>
  <meta name="description" content="Connect Claude, Cursor, VS Code, GitHub Copilot, Codex, Gemini CLI and any MCP client to your end-to-end encrypted cpmesh clipboard." />
</svelte:head>

<div class="mcp-page min-h-dvh bg-bg text-fg">
  <header class="sticky top-0 z-40 border-b border-border bg-surface">
    <div class="wrap flex h-14 items-center justify-between">
      <a href="#/" class="inline-flex items-center gap-2" aria-label="cpmesh home">
        <Logo size={24} withText textClass="text-[15px]" />
      </a>
      <nav class="flex items-center gap-1" aria-label="Primary">
        <a href="#/" class="hidden rounded-md px-3 py-1.5 text-[13px] text-muted transition-colors hover:bg-surface-2 hover:text-fg sm:block">Home</a>
        <a href={GITHUB_URL} target="_blank" rel="noopener" class="hidden rounded-md px-3 py-1.5 text-[13px] text-muted transition-colors hover:bg-surface-2 hover:text-fg sm:block">GitHub</a>
        <span class="ml-1"><Button href="#/login" size="sm">Sign in</Button></span>
      </nav>
    </div>
  </header>

  <main class="wrap pb-20 md:pb-28">
    <McpGuide />
  </main>

  <footer class="border-t border-border py-10">
    <div class="wrap flex flex-col items-start justify-between gap-6 text-[13px] text-muted sm:flex-row sm:items-center">
      <div class="flex items-center gap-3">
        <Logo size={20} />
        <span>© {new Date().getFullYear()} cpmesh</span>
      </div>
      <nav class="flex items-center gap-5" aria-label="Footer">
        <a href="#/" class="hover:text-fg">Home</a>
        <a href={GITHUB_URL} target="_blank" rel="noopener" class="hover:text-fg">Source</a>
        <a href="#/login" class="hover:text-fg">Sign in</a>
      </nav>
    </div>
  </footer>
</div>

<style>
  :global(.mcp-page .wrap) {
    width: 100%;
    max-width: 1200px;
    margin-inline: auto;
    padding-inline: 1.25rem;
  }
  @media (min-width: 640px) {
    :global(.mcp-page .wrap) {
      padding-inline: 2rem;
    }
  }
  @media (min-width: 1536px) {
    :global(.mcp-page .wrap) {
      max-width: 1360px;
    }
  }
</style>
