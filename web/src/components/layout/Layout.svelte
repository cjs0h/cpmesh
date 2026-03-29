<script lang="ts">
  import Sidebar from './Sidebar.svelte';
  import Header from './Header.svelte';
  import type { Snippet } from 'svelte';

  let { children }: { children: Snippet } = $props();
</script>

<div class="flex h-screen">
  <Sidebar />
  <div class="flex-1 flex flex-col overflow-hidden">
    <Header />
    <div class="flex-1 overflow-y-auto p-6">
      {@render children()}
    </div>
  </div>
</div>
